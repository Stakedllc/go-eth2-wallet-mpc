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
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

func _signature(hexsig string) e2types.Signature {
	bytessig, err := hex.DecodeString(hexsig)
	if err != nil {
		panic(err)
	}

	sig, err := e2types.BLSSignatureFromBytes(bytessig)
	if err != nil {
		panic(err)
	}

	return sig
}

func TestNewKeyService(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		err       error
		version   uint
		url       string
		publicKey []byte
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
			name:  "MissingURL",
			input: []byte(`{"version": 1}`),
			err:   errors.New(`keyService url missing`),
		},
		{
			name:  "BadURL",
			input: []byte(`{"url": "%bad%"}`),
			err:   errors.New(`parse %bad%: invalid URL escape "%"`),
		},
		{
			name:  "MissingPubKey",
			input: []byte(`{"url": "http://localhost:8000", "version": 1}`),
			err:   errors.New(`keyService pubkey missing`),
		},
		{
			name:  "BadPubKey",
			input: []byte(`{"url": "http://localhost:8000", "pubkey": "bad", "version": 1}`),
			err:   errors.New(`encoding/hex: odd length hex string`),
		},
		{
			name:  "MissingVersion",
			input: []byte(`{"url": "http://localhost:8000", "pubkey": "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"}`),
			err:   errors.New("keyService version missing"),
		},
		{
			name:  "WrongVersion",
			input: []byte(`{"url": "http://localhost:8000", "pubkey": "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c", "version": "1"}`),
			err:   errors.New("keyService version invalid"),
		},
		{
			name:      "Good",
			input:     []byte(`{"url": "http://localhost:8000", "pubkey": "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c", "version": 1}`),
			url:       "http://localhost:8000",
			version:   1,
			publicKey: []byte{0xa9, 0x9a, 0x76, 0xed, 0x77, 0x96, 0xf7, 0xbe, 0x22, 0xd5, 0xb7, 0xe8, 0x5d, 0xee, 0xb7, 0xc5, 0x67, 0x7e, 0x88, 0xe5, 0x11, 0xe0, 0xb3, 0x37, 0x61, 0x8f, 0x8c, 0x4e, 0xb6, 0x13, 0x49, 0xb4, 0xbf, 0x2d, 0x15, 0x3f, 0x64, 0x9f, 0x7b, 0x53, 0x35, 0x9f, 0xe8, 0xb9, 0x4a, 0x38, 0xe4, 0x4c},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := newKeyService()
			err := json.Unmarshal(test.input, output)

			if test.err != nil {
				require.Error(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.url, output.url.String())
				assert.Equal(t, test.version, output.version)
				assert.Equal(t, test.publicKey, output.publicKey.Marshal())
			}
		})
	}
}

func TestSign(t *testing.T) {
	signature := _signature("a6df3773e920d6e382298e08f3e5bba17030582b9ae8207c63e87cf72c03694640323c5794c054b4dc530da0c00eaf5d109e004c53f9bbf9c6c7fb1c922ac7f73a1e34b0446fd525d9adbae1df86e1436b9de50f71af99442feb6d453fccbda2")

	// Start a local HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request METHOD
		assert.Equal(t, "POST", req.Method)

		pubKeyStr := strings.TrimPrefix(req.URL.Path, "/")
		pubKeyBytes, err := hex.DecodeString(pubKeyStr)
		require.NoError(t, err)

		_, err = e2types.BLSPublicKeyFromBytes(pubKeyBytes)
		require.NoError(t, err)

		// Send response to be tested
		rw.Write([]byte(fmt.Sprintf(`{"sign":"%x"}`, signature.Marshal())))
	}))
	// Close the server when test finishes
	defer server.Close()

	url := server.URL

	tests := []struct {
		name      string
		input     []byte
		err       error
		payload   []byte
		verified  bool
		signature e2types.Signature
	}{
		{
			name:      "PublicKeyMismatch",
			input:     []byte(fmt.Sprintf(`{"url": "%s", "pubkey": "868630f2aa3d585ff470d29e17c35ac8c5393317724ea9f842395a061dc68c938ec426c74725242a63797bf517020fa3", "version": 1}`, url)),
			payload:   []byte("test"),
			verified:  false,
			signature: signature,
		},
		{
			name:      "PayloadMismatch",
			input:     []byte(fmt.Sprintf(`{"url": "%s", "pubkey": "868630f2aa3d585ff470d29e17c35ac8c5393317724ea9f842395a061dc68c938ec426c74725242a63797bf517020fa2", "version": 1}`, url)),
			payload:   []byte("bad"),
			verified:  false,
			signature: signature,
		},
		{
			name:      "Good",
			input:     []byte(fmt.Sprintf(`{"url": "%s", "pubkey": "868630f2aa3d585ff470d29e17c35ac8c5393317724ea9f842395a061dc68c938ec426c74725242a63797bf517020fa2", "version": 1}`, url)),
			payload:   []byte("test"),
			verified:  true,
			signature: signature,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ks := newKeyService()
			err := json.Unmarshal(test.input, ks)
			require.NoError(t, err)

			pubKey, err := ks.PublicKey()
			require.NoError(t, err)

			output, err := ks.Sign(test.payload)
			require.NoError(t, err)

			if test.err != nil {
				require.Error(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.signature.Marshal(), output.Marshal())
				assert.Equal(t, test.verified, output.Verify(test.payload[:], pubKey))
			}
		})
	}
}
