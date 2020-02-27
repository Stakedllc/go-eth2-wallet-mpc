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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	etypes "github.com/wealdtech/go-eth2-types"
)

type keyService struct {
	URL *url.URL
}

type publicKeyResponse struct {
	PubKey string `json:"pk"`
}

type signRequest struct {
	Payload string `json:"payload"`
	Domain  uint64 `json:"domain"`
}

type signResponse struct {
	Signature string `json:"sign"`
}

// newKeyService creates a new keyService
func newKeyService(url *url.URL) (*keyService, error) {
	if !url.IsAbs() {
		return nil, fmt.Errorf("keyService URL '%s' is not absolute", url)
	}

	return &keyService{
		URL: url,
	}, nil
}

func (ks *keyService) PublicKey() (etypes.PublicKey, error) {
	url := ks.URL

	resp, err := http.Get(url.String())
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var v publicKeyResponse
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, err
	}

	if v.PubKey == "" {
		return nil, errors.New("missing public key")
	}

	bytes, err := hex.DecodeString(v.PubKey)
	if err != nil {
		return nil, err
	}

	key, err := etypes.BLSPublicKeyFromBytes(bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (ks *keyService) Sign(payload []byte, domain uint64) (etypes.Signature, error) {
	r := &signRequest{
		Payload: fmt.Sprintf("%s", payload),
		Domain:  domain,
	}

	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	endpoint := "sign"
	url, err := ks.URL.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(url.String(), "application/json", bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var v signResponse
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, err
	}

	if v.Signature == "" {
		return nil, errors.New("missing signature")
	}

	bytes, err := hex.DecodeString(v.Signature)
	if err != nil {
		return nil, err
	}

	signature, err := etypes.BLSSignatureFromBytes(bytes)
	if err != nil {
		return nil, err
	}

	return signature, nil
}
