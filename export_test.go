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

	mpc "github.com/Stakedllc/go-eth2-wallet-mpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestExportWallet(t *testing.T) {
	store := scratch.New()
	encryptor := keystorev4.New()
	wallet, err := mpc.CreateWallet("test wallet", store, encryptor, "http://localhost:8000", _byteArray("868630f2aa3d585ff470d29e17c35ac8c5393317724ea9f842395a061dc68c938ec426c74725242a63797bf517020fa2"))
	require.Nil(t, err)
	err = wallet.Unlock([]byte{})
	require.Nil(t, err)

	account1, err := wallet.CreateAccount("Account 1", []byte{})
	require.Nil(t, err)
	account2, err := wallet.CreateAccount("Account 2", []byte{})
	require.Nil(t, err)

	dump, err := wallet.(wtypes.WalletExporter).Export([]byte("dump"))
	require.Nil(t, err)

	// Import it
	store2 := scratch.New()
	wallet2, err := mpc.Import(dump, []byte("dump"), store2, encryptor)
	require.Nil(t, err)

	// Confirm the accounts are present
	account1Present := false
	account2Present := false
	for account := range wallet2.Accounts() {
		if account.ID().String() == account1.ID().String() {
			account1Present = true
		}
		if account.ID().String() == account2.ID().String() {
			account2Present = true
		}
	}
	assert.True(t, account1Present && account2Present)

	// Try to import it again; should fail
	_, err = mpc.Import(dump, []byte("dump"), store2, encryptor)
	assert.NotNil(t, err)
}
