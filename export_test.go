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
	"net/http"
	"net/http/httptest"
	"testing"

	mpc "github.com/Stakedllc/go-eth2-wallet-mpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	types "github.com/wealdtech/go-eth2-wallet-types"
)

func TestExportWallet(t *testing.T) {
	// Start a local HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request METHOD
		assert.Equal(t, req.Method, "GET")
		// Test request parameters
		assert.Equal(t, req.URL.String(), "/address")
		// Send response to be tested
		rw.Write([]byte(`{"PubKey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"}`))
	}))
	// Close the server when test finishes
	defer server.Close()

	store := scratch.New()
	encryptor := keystorev4.New()
	wallet, err := mpc.CreateWallet("test wallet", store, encryptor, server.URL)
	require.Nil(t, err)
	err = wallet.Unlock([]byte{})
	require.Nil(t, err)

	account1, err := wallet.CreateAccount("Account 1", []byte{})
	require.Nil(t, err)
	account2, err := wallet.CreateAccount("Account 2", []byte{})
	require.Nil(t, err)

	dump, err := wallet.(types.WalletExporter).Export([]byte("dump"))
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
