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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"

	etypes "github.com/wealdtech/go-eth2-types"
)

type keyService struct {
	URL			url.URL
}

type newKeyResponse struct {
	PubKey		[48]byte `json:"pubKey"`
}

type signRequest struct {
	Payload 	[]byte `json:"payload"`
}

type signResponse struct {
	Signature 	string `json:"signature"`
}

// newKeyService creates a new keyService
func newKeyService(raw string) (*keyService, error) {
	url, err = url.Parse(raw)
	if err != nil {
		return nil, err
	}

	service := &keyService{
		URL: url,
	}

	return service, nil
}

func (ks *keyService) NewKey() (etypes.PublicKey, error) {
	path, err := url.Parse("")
	if err != nil {
		return nil, err
	}

	resp, err = http.Get(ks.URL.ResolveReference(path).String())
	if err != nil {
		return nil, err
	}

	var v newKeyResponse
	if err := json.Unmarshal(resp, &v); err != nil {
		return nil, err
	}

	bytes, err := hex.DecodeString(v.PubKey)
	if err != nil {
		return nil, err
	}
	key, err = etypes.BLSPublicKeyFromBytes(bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (ks *keyService) Sign(key etypes.PublicKey, payload []byte) ([]byte, error) {
	r := &signRequest{
		Payload: payload
	}

	data, err := json.Marshal(r)
    if err != nil {
        return nil, err
	}

	path, err := url.Parse(key)
	if err != nil {
		return nil, err
	}
	
	resp, err := http.Post(ks.URL.ResolveReference(path).String(), "application/json", data)
	if err != nil {
		return nil, err
	}

	var v signResponse
	if err := json.Unmarshal(resp, &v); err != nil {
		return nil, err
	}

	bytes, err := hex.DecodeString(v.Signature)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}