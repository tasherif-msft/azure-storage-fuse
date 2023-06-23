/*
    _____           _____   _____   ____          ______  _____  ------
   |     |  |      |     | |     | |     |     | |       |            |
   |     |  |      |     | |     | |     |     | |       |            |
   | --- |  |      |     | |-----| |---- |     | |-----| |-----  ------
   |     |  |      |     | |     | |     |     |       | |       |
   | ____|  |_____ | ____| | ____| |     |_____|  _____| |_____  |_____


   Licensed under the MIT License <http://opensource.org/licenses/MIT>.

   Copyright © 2020-2023 Microsoft Corporation. All rights reserved.
   Author : <blobfusedev@microsoft.com>

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE
*/

package azstorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-storage-fuse/v2/common/log"
	"github.com/Azure/go-autorest/autorest/adal"

	"github.com/Azure/azure-storage-azcopy/v10/common"
)

var msiTokenHTTPClient = newMSIHTTPClient()

func newMSIHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: common.GlobalProxyLookup,
			// We use Dial instead of DialContext as DialContext has been reported to cause slower performance.
			Dial /*Context*/ : (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 10 * time.Second,
				DualStack: true,
			}).Dial, /*Context*/
			MaxIdleConns:           0, // No limit
			MaxIdleConnsPerHost:    1000,
			IdleConnTimeout:        180 * time.Second,
			TLSHandshakeTimeout:    10 * time.Second,
			ExpectContinueTimeout:  1 * time.Second,
			DisableKeepAlives:      false,
			DisableCompression:     true,
			MaxResponseHeaderBytes: 0,
			// ResponseHeaderTimeout:  time.Duration{},
			// ExpectContinueTimeout:  time.Duration{},
		},
	}
}

func (azmsi *azAuthMSI) GetNewTokenFromMSIWithEndPoint(credInfo *common.OAuthTokenInfo, endpoint string) (*adal.Token, error) {
	targetResource := common.Resource
	if credInfo.Token.Resource != "" && credInfo.Token.Resource != targetResource {
		targetResource = credInfo.Token.Resource
	}

	ctx := context.Background()

	log.Info("azAuthMSI::GetNewTokenFromMSIWithEndPoint : Getting token from %s", endpoint)

	// Try Azure VM since there was an error in trying Arc VM
	reqAzureVM, respAzureVM, errAzureVM := azmsi.queryIMDS(ctx, credInfo, endpoint, targetResource, common.IMDSAPIVersionAzureVM) //nolint:staticcheck
	if errAzureVM != nil {
		return nil, fmt.Errorf("error communicating with Arc IMDS endpoint (%s): %v", endpoint, errAzureVM)
	}

	// Arc IMDS failed with error, but Azure IMDS succeeded
	_, resp := reqAzureVM, respAzureVM //nolint:staticcheck

	defer func() { // resp and Body should not be nil
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	// Check if the status code indicates success
	// The request returns 200 currently, add 201 and 202 as well for possible extension.
	if !(common.HTTPResponseExtension{Response: resp}).IsSuccessStatusCode(http.StatusOK, http.StatusCreated, http.StatusAccepted) {
		return nil, fmt.Errorf("failed to get token from msi, status code: %v", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	result := &adal.Token{}
	if len(b) > 0 {
		b = common.ByteSliceExtension{ByteSlice: b}.RemoveBOM()
		// Unmarshal will give an error for Go version >= 1.14 for a field with blank values. Arc-server endpoint API returns blank for "not_before" field.
		// TODO: Remove fixup once Arc team fixes the issue.
		b = fixupTokenJson(b)
		if err := json.Unmarshal(b, result); err != nil {
			return nil, fmt.Errorf("failed to unmarshal response body: %v", err)
		}
	} else {
		return nil, errors.New("failed to get token from msi")
	}

	return result, nil
}

func (azmsi *azAuthMSI) queryIMDS(ctx context.Context, credInfo *common.OAuthTokenInfo, msiEndpoint string, resource string, imdsAPIVersion string) (*http.Request, *http.Response, error) {
	// Prepare request to get token from Azure Instance Metadata Service identity endpoint.
	req, err := http.NewRequest("GET", msiEndpoint, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %v", err)
	}

	params := req.URL.Query()
	params.Set("resource", resource)
	params.Set("api-version", imdsAPIVersion)

	if credInfo.IdentityInfo.ClientID != "" {
		params.Set("client_id", credInfo.IdentityInfo.ClientID)
	}
	if credInfo.IdentityInfo.ObjectID != "" {
		params.Set("object_id", credInfo.IdentityInfo.ObjectID)
	}
	if credInfo.IdentityInfo.MSIResID != "" {
		params.Set("msi_res_id", credInfo.IdentityInfo.MSIResID)
	}

	req.URL.RawQuery = params.Encode()
	req.Header.Set("Metadata", "true")

	// Set context.
	req = req.WithContext(ctx)
	// In case of some other process (Http Server) listening at 127.0.0.1:40342 , we do not want to wait forever for it to serve request
	msiTokenHTTPClient.Timeout = 10 * time.Second
	
	reqDump, _ := httputil.DumpRequest(req, true)
	log.Info("azAuthMSI::queryIMDS : Request to fetch token : %v", string(reqDump))

	// Send request
	resp, err := msiTokenHTTPClient.Do(req)
	// Unset the timeout back
	msiTokenHTTPClient.Timeout = 0
	return req, resp, err
}

func fixupTokenJson(bytes []byte) []byte {
	byteSliceToString := string(bytes)
	separatorString := `"not_before":"`
	stringSlice := strings.Split(byteSliceToString, separatorString)

	// OIDC token issuer returns an integer for "not_before" and not a string
	if len(stringSlice) == 1 {
		return bytes
	}

	if stringSlice[1][0] != '"' {
		return bytes
	}

	// If the value of not_before is blank, set to "now - 5 sec" and return the updated slice
	notBeforeTimeInteger := uint64(time.Now().Unix() - 5)
	notBeforeTime := strconv.FormatUint(notBeforeTimeInteger, 10)
	return []byte(stringSlice[0] + separatorString + notBeforeTime + stringSlice[1])
}
