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
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

type keyService struct {
	url       *url.URL
	publicKey e2types.PublicKey
	version   uint
}

type signRequest struct {
	Payload string `json:"payload"`
}

type signResponse struct {
	Signature string `json:"sign"`
}

// MarshalJSON implements custom JSON marshaller.
func (ks *keyService) MarshalJSON() ([]byte, error) {
	data := make(map[string]interface{})
	data["pubkey"] = fmt.Sprintf("%x", ks.publicKey.Marshal())
	data["url"] = ks.url.String()
	data["version"] = ks.version
	return json.Marshal(data)
}

// UnmarshalJSON implements custom JSON unmarshaller.
func (ks *keyService) UnmarshalJSON(data []byte) error {
	var v map[string]interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if val, exists := v["url"]; exists {
		urlStr, ok := val.(string)
		if !ok {
			return errors.New("keyService url invalid")
		}
		url, err := url.Parse(urlStr)
		if err != nil {
			return err
		}
		ks.url = url
	} else {
		return errors.New("keyService url missing")
	}
	if val, exists := v["pubkey"]; exists {
		publicKey, ok := val.(string)
		if !ok {
			return errors.New("keyService pubkey invalid")
		}
		bytes, err := hex.DecodeString(publicKey)
		if err != nil {
			return err
		}
		ks.publicKey, err = e2types.BLSPublicKeyFromBytes(bytes)
		if err != nil {
			return err
		}
	} else {
		return errors.New("keyService pubkey missing")
	}
	if val, exists := v["version"]; exists {
		version, ok := val.(float64)
		if !ok {
			return errors.New("keyService version invalid")
		}
		ks.version = uint(version)
	} else {
		return errors.New("keyService version missing")
	}

	return nil
}

func newKeyService() *keyService {
	return &keyService{}
}

// PublicKey returns the remote public key
func (ks *keyService) PublicKey() (e2types.PublicKey, error) {
	return ks.publicKey.Copy(), nil
}

// PrivateKey remote KeyServices do not support PrivateKey access
func (ks *keyService) PrivateKey() (e2types.PrivateKey, error) {
	return nil, errors.New("keyService does not support PrivateKey access")
}

// Sign signs the payload using the remote signing service
func (ks *keyService) Sign(payload []byte) (e2types.Signature, error) {
	r := &signRequest{
		Payload: fmt.Sprintf("%x", payload),
	}

	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	pubkey, err := ks.PublicKey()
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("/%x", pubkey.Marshal())
	url, err := ks.url.Parse(endpoint)
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

	signature, err := e2types.BLSSignatureFromBytes(bytes)
	if err != nil {
		return nil, err
	}

	return signature, nil
}
