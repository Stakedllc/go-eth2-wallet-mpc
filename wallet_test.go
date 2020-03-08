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

package mpc_test

import (
	"testing"

	mpc "github.com/Stakedllc/go-eth2-wallet-mpc/v2"
	"github.com/stretchr/testify/assert"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
)

func TestCreateWallet(t *testing.T) {
	store := scratch.New()
	encryptor := keystorev4.New()
	wallet, err := mpc.CreateWallet("test wallet", store, encryptor, "http://localhost:8000", _byteArray("868630f2aa3d585ff470d29e17c35ac8c5393317724ea9f842395a061dc68c938ec426c74725242a63797bf517020fa2"))
	assert.Nil(t, err)

	assert.Equal(t, "test wallet", wallet.Name())
	assert.Equal(t, uint(1), wallet.Version())

	// Try to create another wallet with the same name; should error
	_, err = mpc.CreateWallet("test wallet", store, encryptor, "http://localhost:8000", _byteArray("868630f2aa3d585ff470d29e17c35ac8c5393317724ea9f842395a061dc68c938ec426c74725242a63797bf517020fa2"))
	assert.NotNil(t, err)
}
