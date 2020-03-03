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
	"testing"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalWallet(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		err        error
		id         uuid.UUID
		version    uint
		walletType string
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
			name:  "NotJSON",
			input: []byte(`bad`),
			err:   errors.New(`invalid character 'b' looking for beginning of value`),
		},
		{
			name:  "MissingID",
			input: []byte(`{"name":"Bad","type":"multi-party","version":1}`),
			err:   errors.New("wallet ID missing"),
		},
		{
			name:  "WrongID",
			input: []byte(`{"uuid":7,"name":"Bad","type":"multi-party","version":1}`),
			err:   errors.New("wallet ID invalid"),
		},
		{
			name:  "BadID",
			input: []byte(`{"uuid":"bad","name":"Bad","type":"multi-party","version":1}`),
			err:   errors.New("invalid UUID length: 3"),
		},
		{
			name:  "WrongOldID",
			input: []byte(`{"id":7,"name":"Bad","type":"multi-party","version":1}`),
			err:   errors.New("wallet ID invalid"),
		},
		{
			name:  "BadOldID",
			input: []byte(`{"id":"bad","name":"Bad","type":"multi-party","version":1}`),
			err:   errors.New("invalid UUID length: 3"),
		},
		{
			name:  "MissingName",
			input: []byte(`{"id":"c9958061-63d4-4a80-bcf3-25f3dda22340","type":"multi-party","version":1}`),
			err:   errors.New("wallet name missing"),
		},
		{
			name:  "WrongName",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":1,"type":"multi-party","version":1}`),
			err:   errors.New("wallet name invalid"),
		},
		{
			name:  "MissingType",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"Bad","version":1}`),
			err:   errors.New("wallet type missing"),
		},
		{
			name:  "WrongType",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"Bad","type":7,"version":1}`),
			err:   errors.New("wallet type invalid"),
		},
		{
			name:  "BadType",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"Bad","type":"hd","version":1}`),
			err:   errors.New(`wallet type "hd" unexpected`),
		},
		{
			name:  "MissingVersion",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"Bad","type":"multi-party"}`),
			err:   errors.New("wallet version missing"),
		},
		{
			name:  "WrongVersion",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"Bad","type":"multi-party","version":"1"}`),
			err:   errors.New("wallet version invalid"),
		},
		{
			name:  "MissingKeyService",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"Good","type":"multi-party","version":1}`),
			err:   errors.New(`wallet keyService missing`),
		},
		{
			name:  "BadKeyService",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"Good","type":"multi-party","keyService":{},"version":1}`),
			err:   errors.New(`keyService url missing`),
		},
		{
			name:  "BadKeyService2",
			input: []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"Good","type":"multi-party","keyService":"bad","version":1}`),
			err:   errors.New(`json: cannot unmarshal string into Go value of type map[string]interface {}`),
		},
		{
			name:       "Good",
			input:      []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"Good","type":"multi-party","keyService": {"url": "http://localhost:8000", "pubkey": "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c", "version": 1},"version":1}`),
			walletType: "multi-party",
			id:         uuid.MustParse("c9958061-63d4-4a80-bcf3-25f3dda22340"),
			version:    1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := newWallet()
			err := json.Unmarshal(test.input, output)
			if test.err != nil {
				require.Error(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.id, output.ID())
				assert.Equal(t, test.version, output.Version())
				assert.Equal(t, test.walletType, output.Type())
			}
		})
	}
}
