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
	url       *url.URL
	publicKey etypes.PublicKey
	version   uint
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
		ks.publicKey, err = etypes.BLSPublicKeyFromBytes(bytes)
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

// newKeyService creates a new keyService
func newKeyService(url *url.URL) (*keyService, error) {
	if !url.IsAbs() {
		return nil, fmt.Errorf("keyService URL '%s' is not absolute", url)
	}

	return &keyService{
		url: url,
	}, nil
}

func (ks *keyService) PublicKey() (etypes.PublicKey, error) {
	// url := ks.url

	// resp, err := http.Get(url.String())
	// if err != nil {
	// 	return nil, err
	// }

	// defer resp.Body.Close()
	// body, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	return nil, err
	// }

	// var v publicKeyResponse
	// if err := json.Unmarshal(body, &v); err != nil {
	// 	return nil, err
	// }

	// if v.PubKey == "" {
	// 	return nil, errors.New("missing public key")
	// }

	// bytes, err := hex.DecodeString(v.PubKey)
	// if err != nil {
	// 	return nil, err
	// }

	// remoteKey, err := etypes.BLSPublicKeyFromBytes(bytes)
	// if err != nil {
	// 	return nil, err
	// }

	// return remoteKey, nil

	// Safe to ignore the error as this is already a public key
	localKeyCopy, _ := etypes.BLSPublicKeyFromBytes(ks.publicKey.Marshal())

	return localKeyCopy, nil
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

	pubkey, err := ks.PublicKey()
	if err != nil {
		return nil, err
	}
	// endpoint := "sign"
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

	signature, err := etypes.BLSSignatureFromBytes(bytes)
	if err != nil {
		return nil, err
	}

	return signature, nil
}
