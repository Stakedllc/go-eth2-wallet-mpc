// Copyright © 2020 Staked Securely LLC
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mpc

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	etypes "github.com/wealdtech/go-eth2-types"
)

func TestNewKeyService(t *testing.T) {
	tests := []struct {
		name string
		url  string
		err  error
	}{
		{
			name: "Nil",
			err:  errors.New("keyService URL '' is not absolute"),
		},
		{
			name: "NotAbsolute",
			url:  "localhost",
			err:  errors.New("keyService URL 'localhost' is not absolute"),
		},
		{
			name: "Good",
			url:  "http://localhost:8080",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			url, err := url.Parse(test.url)
			require.Nil(t, err)

			output, err := newKeyService(url)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
				assert.Equal(t, url.String(), output.URL.String())
			}
		})
	}
}

func TestNewKey(t *testing.T) {
	pubKeyStr := "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"

	// Start a local HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request METHOD
		assert.Equal(t, req.Method, "GET")
		// Test request parameters
		assert.Equal(t, req.URL.String(), "/address")
		// Send response to be tested
		rw.Write([]byte(fmt.Sprintf(`{"PubKey":"%s"}`, pubKeyStr)))
	}))
	// Close the server when test finishes
	defer server.Close()

	url, err := url.Parse(server.URL)
	require.Nil(t, err)

	ks, err := newKeyService(url)
	require.Nil(t, err)

	output, err := ks.NewKey()
	assert.Nil(t, err)

	assert.Equal(t, fmt.Sprintf("%x", output.Marshal()), pubKeyStr)
}

func TestSign(t *testing.T) {
	payload := []byte("abcd")
	pubKeyStr := "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"
	signatureStr := "b27173efced932d1e0decdbb872512d4d123835629ffd907211ffe74a86a05dc6be4a8c15f886a48daed4a975f5fffe9153297bcda99adf84b351a8d514ea7f0607ff2e678c1600381fa6beb5fbe1a864924a3e69bb938caeef2de673988265e"

	// Start a local HTTP server
	// server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
	// 	// Test request METHOD
	// 	assert.Equal(t, req.Method, "GET")
	// 	// Test request parameters
	// 	assert.Equal(t, req.URL.String(), "/address")
	// 	// Send response to be tested
	// 	rw.Write([]byte(fmt.Sprintf(`{"PubKey":"%s"}`, pubKeyStr)))
	// }))
	// // Close the server when test finishes
	// defer server.Close()

	bytes, err := hex.DecodeString(pubKeyStr)
	require.Nil(t, err)

	pubKey, err := etypes.BLSPublicKeyFromBytes(bytes)
	require.Nil(t, err)

	// url, err := url.Parse(server.URL)
	url, err := url.Parse("http://driver:8000")
	require.Nil(t, err)

	ks, err := newKeyService(url)
	require.Nil(t, err)

	output, err := ks.Sign(pubKey, payload, uint64(42))
	assert.Nil(t, err)

	assert.Equal(t, signatureStr, fmt.Sprintf("%x", output.Marshal()))
	assert.Equal(t, true, output.Verify(payload, pubKey, uint64(42)))
}
