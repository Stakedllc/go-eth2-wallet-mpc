// Copyright © 2019 Weald Technology Trading
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
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalAccount(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		err        error
		id         uuid.UUID
		version    uint
		walletType string
		publicKey  []byte
	}{
		{
			name: "Nil",
			err:  errors.New("unexpected end of JSON input"),
		},
		{
			name:  "Empty",
			input: []byte{},
			err:   errors.New("unexpected end of JSON input"),
		},
		{
			name:  "Blank",
			input: []byte(""),
			err:   errors.New("unexpected end of JSON input"),
		},
		{
			name:  "NotJSON",
			input: []byte(`bad`),
			err:   errors.New(`invalid character 'b' looking for beginning of value`),
		},
		{
			name:  "MissingID",
			input: []byte(`{"name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","version":4}`),
			err:   errors.New("account ID missing"),
		},
		{
			name:  "WrongID",
			input: []byte(`{"uuid":1,"name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","version":4}`),
			err:   errors.New("account ID invalid"),
		},
		{
			name:  "BadID",
			input: []byte(`{"uuid":"c99","name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","version":4}`),
			err:   errors.New("invalid UUID length: 3"),
		},
		{
			name:  "WrongOldID",
			input: []byte(`{"id":1,"name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","version":4}`),
			err:   errors.New("account ID invalid"),
		},
		{
			name:  "BadOldID",
			input: []byte(`{"id":"c99","name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","version":4}`),
			err:   errors.New("invalid UUID length: 3"),
		},
		{
			name:  "MissingName",
			input: []byte(`{"id":"c9958061-63d4-4a80-bcf3-25f3dda22340","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","version":4}`),
			err:   errors.New("account name missing"),
		},
		{
			name:  "WrongName",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":true,"pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","version":4}`),
			err:   errors.New("account name invalid"),
		},
		{
			name:  "MissingPubKey",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","version":4}`),
			err:   errors.New("account pubkey missing"),
		},
		{
			name:  "InvalidPubKey",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":true,"version":4}`),
			err:   errors.New("account pubkey invalid"),
		},
		{
			name:  "BadPubKey",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44h","version":4}`),
			err:   errors.New(`encoding/hex: invalid byte: U+0068 'h'`),
		},
		{
			name:  "BadPubKey2",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c4c","version":4}`),
			err:   errors.New(`public key must be 48 bytes`),
		},
		{
			name:  "MissingVersion",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"}`),
			err:   errors.New(`account version missing`),
		},
		{
			name:  "BadVersion",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","version":true}`),
			err:   errors.New(`account version invalid`),
		},
		{
			name:  "WrongVersion",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","version":3}`),
			err:   errors.New(`unsupported keystore version`),
		},
		{
			name:  "MissingKeyService",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","version":4}`),
			err:   errors.New(`account keyService missing`),
		},
		{
			name:  "BadKeyService",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","keyService":"bad","version":4}`),
			err:   errors.New(`keyService URL 'bad' is not absolute`),
		},
		{
			name:  "BadKeyService2",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","keyService":"%bad%","version":4}`),
			err:   errors.New(`parse %bad%: invalid URL escape "%"`),
		},
		{
			name:       "Good",
			input:      []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","keyService":"http://localhost:8080","version":4}`),
			walletType: "multi-party",
			id:         uuid.MustParse("c9958061-63d4-4a80-bcf3-25f3dda22340"),
			publicKey:  []byte{0xa9, 0x9a, 0x76, 0xed, 0x77, 0x96, 0xf7, 0xbe, 0x22, 0xd5, 0xb7, 0xe8, 0x5d, 0xee, 0xb7, 0xc5, 0x67, 0x7e, 0x88, 0xe5, 0x11, 0xe0, 0xb3, 0x37, 0x61, 0x8f, 0x8c, 0x4e, 0xb6, 0x13, 0x49, 0xb4, 0xbf, 0x2d, 0x15, 0x3f, 0x64, 0x9f, 0x7b, 0x53, 0x35, 0x9f, 0xe8, 0xb9, 0x4a, 0x38, 0xe4, 0x4c},
			version:    4,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := newAccount()
			err := json.Unmarshal(test.input, output)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
				assert.Equal(t, test.id, output.ID())
				assert.Equal(t, test.publicKey, output.PublicKey().Marshal())
				//				assert.Equal(t, test.version, output.Version())
				//				assert.Equal(t, test.walletType, output.Type())
			}
		})
	}
}

func TestAccountSign(t *testing.T) {
	payload := []byte("abcd")
	pubKey := "88605c6f3226ac5b9d35cea6c2405879dd4f893e15d7effa69df15f24b4869221597f14412b8d8a8cb0b120a90b1197c"
	pubKeyBad := "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"

	// Start a local HTTP server
	// server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
	// 	endpoint := fmt.Sprintf("/address/%s/sign", pubKey)
	// 	endpointBad := fmt.Sprintf("/address/%s/sign", pubKeyBad)

	// 	// Test request METHOD
	// 	assert.Equal(t, req.Method, "POST")

	// 	// Test request parameters
	// 	assert.Contains(t, []string{endpoint, endpointBad}, req.URL.String())

	// 	// Test request payload
	// 	defer req.Body.Close()

	// 	body, err := ioutil.ReadAll(req.Body)
	// 	assert.Nil(t, err)

	// 	fmt.Println(body)

	// 	var data signRequest
	// 	err = json.Unmarshal(body, &data)
	// 	assert.Nil(t, err)

	// 	fmt.Println(data)

	// 	test, err := json.MarshalIndent(data, "", "  ")
	// 	assert.Nil(t, err)

	// 	fmt.Println(test)

	// 	// Send response to be tested
	// 	rw.Write([]byte(`{"Signature":"b27173efced932d1e0decdbb872512d4d123835629ffd907211ffe74a86a05dc6be4a8c15f886a48daed4a975f5fffe9153297bcda99adf84b351a8d514ea7f0607ff2e678c1600381fa6beb5fbe1a864924a3e69bb938caeef2de673988265e"}`))
	// }))
	// // Close the server when test finishes
	// defer server.Close()

	tests := []struct {
		name       string
		account    []byte
		passphrase []byte
		err        error
		verified   bool
	}{
		{
			name:       "PublicKeyMismatch",
			account:    []byte(fmt.Sprintf(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":"%s","keyService":"%s","version":4}`, pubKeyBad, "http://driver:8000")),
			passphrase: []byte(""),
			verified:   false,
		},
		{
			name:       "Verified",
			account:    []byte(fmt.Sprintf(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":"%s","keyService":"%s","version":4}`, pubKey, "http://driver:8000")),
			passphrase: []byte(""),
			verified:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			account := newAccount()
			err := json.Unmarshal(test.account, account)
			require.Nil(t, err)

			// Try to sign something - should fail because locked
			_, err = account.Sign(payload, uint64(42))
			assert.NotNil(t, err)

			// Try to unlock
			err = account.Unlock(test.passphrase)
			assert.Nil(t, err)

			// Try to sign something - should succeed because unlocked
			signature, err := account.Sign(payload, uint64(42))
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)

				verified := signature.Verify(payload, account.PublicKey(), uint64(42))
				assert.Equal(t, test.verified, verified)

				account.Lock()

				// Try to sign something - should fail because locked (again)
				_, err = account.Sign(payload, uint64(42))
				assert.NotNil(t, err)
			}
		})
	}
}
