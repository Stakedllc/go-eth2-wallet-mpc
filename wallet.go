// Copyright 2019, 2020 Weald Technology Trading
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
	"net/url"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/wealdtech/go-ecodec"
	etypes "github.com/wealdtech/go-eth2-types"
	types "github.com/wealdtech/go-eth2-wallet-types"
	"github.com/wealdtech/go-indexer"
)

const (
	walletType = "multi-party"
	version    = 1
)

// wallet contains the details of the wallet.
type wallet struct {
	id         uuid.UUID
	name       string
	version    uint
	store      types.Store
	encryptor  types.Encryptor
	mutex      *sync.RWMutex
	unlocked   bool
	index      *indexer.Index
	keyService *keyService
}

// newWallet creates a new wallet
func newWallet() *wallet {
	return &wallet{
		mutex: new(sync.RWMutex),
		index: indexer.New(),
	}
}

// MarshalJSON implements custom JSON marshaller.
func (w *wallet) MarshalJSON() ([]byte, error) {
	data := make(map[string]interface{})
	data["uuid"] = w.id.String()
	data["name"] = w.name
	data["version"] = w.version
	data["type"] = walletType
	data["keyService"] = w.keyService.URL.String()
	return json.Marshal(data)
}

// UnmarshalJSON implements custom JSON unmarshaller.
func (w *wallet) UnmarshalJSON(data []byte) error {
	var v map[string]interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if val, exists := v["type"]; exists {
		dataWalletType, ok := val.(string)
		if !ok {
			return errors.New("wallet type invalid")
		}
		if dataWalletType != walletType {
			return fmt.Errorf("wallet type %q unexpected", dataWalletType)
		}
	} else {
		return errors.New("wallet type missing")
	}
	if val, exists := v["uuid"]; exists {
		idStr, ok := val.(string)
		if !ok {
			return errors.New("wallet ID invalid")
		}
		id, err := uuid.Parse(idStr)
		if err != nil {
			return err
		}
		w.id = id
	} else {
		// Used to be ID; remove with V2.0
		if val, exists := v["id"]; exists {
			idStr, ok := val.(string)
			if !ok {
				return errors.New("wallet ID invalid")
			}
			id, err := uuid.Parse(idStr)
			if err != nil {
				return err
			}
			w.id = id
		} else {
			return errors.New("wallet ID missing")
		}
	}
	if val, exists := v["name"]; exists {
		name, ok := val.(string)
		if !ok {
			return errors.New("wallet name invalid")
		}
		w.name = name
	} else {
		return errors.New("wallet name missing")
	}
	if val, exists := v["version"]; exists {
		version, ok := val.(float64)
		if !ok {
			return errors.New("wallet version invalid")
		}
		w.version = uint(version)
	} else {
		return errors.New("wallet version missing")
	}
	if val, exists := v["keyService"]; exists {
		urlStr, ok := val.(string)
		if !ok {
			return errors.New("wallet keyService invalid")
		}
		url, err := url.Parse(urlStr)
		if err != nil {
			return err
		}
		keyService, err := newKeyService(url)
		if err != nil {
			return err
		}
		w.keyService = keyService
	} else {
		return errors.New("wallet keyService missing")
	}

	return nil
}

// CreateWallet creates a new wallet with the given name and stores it in the provided store.
// This will error if the wallet already exists.
func CreateWallet(name string, store types.Store, encryptor types.Encryptor, keyServiceURL string) (types.Wallet, error) {
	// First, try to open the wallet.
	_, err := OpenWallet(name, store, encryptor)
	if err == nil {
		return nil, fmt.Errorf("wallet %q already exists", name)
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	url, err := url.Parse(keyServiceURL)
	if err != nil {
		return nil, err
	}
	keyService, err := newKeyService(url)
	if err != nil {
		return nil, err
	}

	w := newWallet()
	w.id = id
	w.name = name
	w.version = version
	w.store = store
	w.encryptor = encryptor
	w.keyService = keyService

	return w, w.storeWallet()
}

// OpenWallet opens an existing wallet with the given name.
func OpenWallet(name string, store types.Store, encryptor types.Encryptor) (types.Wallet, error) {
	data, err := store.RetrieveWallet(name)
	if err != nil {
		return nil, errors.Wrapf(err, "wallet %q does not exist", name)
	}
	return DeserializeWallet(data, store, encryptor)
}

// DeserializeWallet deserializes a wallet from its byte-level representation
func DeserializeWallet(data []byte, store types.Store, encryptor types.Encryptor) (types.Wallet, error) {
	wallet := newWallet()
	if err := json.Unmarshal(data, wallet); err != nil {
		return nil, errors.Wrap(err, "wallet corrupt")
	}
	wallet.store = store
	wallet.encryptor = encryptor
	if err := wallet.retrieveAccountsIndex(); err != nil {
		return nil, errors.Wrap(err, "wallet index corrupt")
	}

	return wallet, nil
}

// ID provides the ID for the wallet.
func (w *wallet) ID() uuid.UUID {
	return w.id
}

// Type provides the type for the wallet.
func (w *wallet) Type() string {
	return walletType
}

// Name provides the name for the wallet.
func (w *wallet) Name() string {
	return w.name
}

// Version provides the version of the wallet.
func (w *wallet) Version() uint {
	return w.version
}

// Lock locks the wallet.  A locked wallet cannot create new accounts.
func (w *wallet) Lock() {
	w.unlocked = false
}

// Unlock unlocks the wallet.  An unlocked wallet can create new accounts.
func (w *wallet) Unlock(passphrase []byte) error {
	w.unlocked = true
	return nil
}

// IsUnlocked reports if the wallet is unlocked.
func (w *wallet) IsUnlocked() bool {
	return w.unlocked
}

// storeWallet stores the wallet in the store.
func (w *wallet) storeWallet() error {
	data, err := json.Marshal(w)
	if err != nil {
		return err
	}

	if err := w.storeAccountsIndex(); err != nil {
		return err
	}

	if err := w.store.StoreWallet(w.ID(), w.Name(), data); err != nil {
		return err
	}

	return nil
}

// CreateAccount creates a new account in the wallet.
// The only rule for names is that they cannot start with an underscore (_) character.
func (w *wallet) CreateAccount(name string, passphrase []byte) (types.Account, error) {
	if name == "" {
		return nil, errors.New("account name missing")
	}
	if strings.HasPrefix(name, "_") {
		return nil, fmt.Errorf("invalid account name %q", name)
	}
	if !w.IsUnlocked() {
		return nil, errors.New("wallet must be unlocked to create accounts")
	}

	// Ensure that we don't already have an account with this name
	if _, err := w.AccountByName(name); err == nil {
		return nil, fmt.Errorf("account with name %q already exists", name)
	}

	a := newAccount()
	var err error
	if a.id, err = uuid.NewRandom(); err != nil {
		return nil, err
	}
	a.name = name
	privateKey, err := etypes.GenerateBLSPrivateKey()
	if err != nil {
		return nil, err
	}
	a.publicKey = privateKey.PublicKey()
	// Encrypt the private key
	a.crypto, err = w.encryptor.Encrypt(privateKey.Marshal(), passphrase)
	if err != nil {
		return nil, err
	}

	a.keyService = w.keyService
	a.encryptor = w.encryptor
	a.version = w.encryptor.Version()
	a.wallet = w

	w.index.Add(a.id, a.name)

	if err := a.storeAccount(); err != nil {
		return nil, err
	}

	return a, nil
}

// ImportAccount creates a new account in the wallet from an existing private key.
// The only rule for names is that they cannot start with an underscore (_) character.
// This will error if an account with the name already exists.
func (w *wallet) ImportAccount(name string, key []byte, passphrase []byte) (types.Account, error) {
	if name == "" {
		return nil, errors.New("account name missing")
	}
	if strings.HasPrefix(name, "_") {
		return nil, fmt.Errorf("invalid account name %q", name)
	}
	if !w.IsUnlocked() {
		return nil, errors.New("wallet must be unlocked to import accounts")
	}

	// Ensure that we don't already have an account with this name
	_, err := w.AccountByName(name)
	if err == nil {
		return nil, fmt.Errorf("account with name %q already exists", name)
	}

	a := newAccount()
	a.id, err = uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	a.name = name
	privateKey, err := etypes.BLSPrivateKeyFromBytes(key)
	if err != nil {
		return nil, err
	}
	a.publicKey = privateKey.PublicKey()
	// Encrypt the private key
	a.crypto, err = w.encryptor.Encrypt(privateKey.Marshal(), passphrase)

	a.keyService = w.keyService
	a.encryptor = w.encryptor
	a.version = w.encryptor.Version()
	a.wallet = w

	w.index.Add(a.id, a.name)

	return a, a.storeAccount()
}

// Accounts provides all accounts in the wallet.
func (w *wallet) Accounts() <-chan types.Account {
	ch := make(chan types.Account, 1024)
	go func() {
		for data := range w.store.RetrieveAccounts(w.ID()) {
			if a, err := deserializeAccount(w, data); err == nil {
				ch <- a
			}
		}
		close(ch)
	}()
	return ch
}

// Export exports the entire wallet, protected by an additional passphrase.
func (w *wallet) Export(passphrase []byte) ([]byte, error) {
	type walletExt struct {
		Wallet   *wallet    `json:"wallet"`
		Accounts []*account `json:"accounts"`
	}

	accounts := make([]*account, 0)
	for acc := range w.Accounts() {
		accounts = append(accounts, acc.(*account))
	}

	ext := &walletExt{
		Wallet:   w,
		Accounts: accounts,
	}

	data, err := json.Marshal(ext)
	if err != nil {
		return nil, err
	}

	return ecodec.Encrypt(data, passphrase)
}

// Import imports the entire wallet, protected by an additional passphrase.
func Import(encryptedData []byte, passphrase []byte, store types.Store, encryptor types.Encryptor) (types.Wallet, error) {
	type walletExt struct {
		Wallet   *wallet    `json:"wallet"`
		Accounts []*account `json:"accounts"`
	}

	data, err := ecodec.Decrypt(encryptedData, passphrase)
	if err != nil {
		return nil, err
	}

	ext := &walletExt{}
	if err := json.Unmarshal(data, ext); err != nil {
		return nil, err
	}

	ext.Wallet.mutex = new(sync.RWMutex)
	ext.Wallet.index = indexer.New()
	ext.Wallet.store = store
	ext.Wallet.encryptor = encryptor

	// See if the wallet already exists
	if _, err := OpenWallet(ext.Wallet.Name(), store, encryptor); err == nil {
		return nil, fmt.Errorf("wallet %q already exists", ext.Wallet.Name())
	}

	// Create the wallet
	if err := ext.Wallet.storeWallet(); err != nil {
		return nil, fmt.Errorf("failed to store wallet %q", ext.Wallet.Name())
	}

	// Create the accounts
	for _, acc := range ext.Accounts {
		acc.wallet = ext.Wallet
		acc.encryptor = encryptor
		acc.mutex = new(sync.RWMutex)
		if err := acc.storeAccount(); err != nil {
			return nil, fmt.Errorf("failed to store account %q", acc.Name())
		}
		ext.Wallet.index.Add(acc.id, acc.name)
	}

	return ext.Wallet, nil
}

// AccountByName provides a single account from the wallet given its name.
// This will error if the account is not found.
func (w *wallet) AccountByName(name string) (types.Account, error) {
	id, exists := w.index.ID(name)
	if !exists {
		return nil, fmt.Errorf("no account with name %q", name)
	}
	return w.AccountByID(id)
}

// AccountByID provides a single account from the wallet given its ID.
// This will error if the account is not found.
func (w *wallet) AccountByID(id uuid.UUID) (types.Account, error) {
	data, err := w.store.RetrieveAccount(w.id, id)
	if err != nil {
		return nil, err
	}
	return deserializeAccount(w, data)
}

// Store returns the wallet's store.
func (w *wallet) Store() types.Store {
	return w.store
}

// retrieveAccountsIndex retrieves the accounts index for a wallet.
func (w *wallet) retrieveAccountsIndex() error {
	serializedIndex, err := w.store.RetrieveAccountsIndex(w.id)
	if err != nil {
		// Attempt to recreate the index.
		w.index = indexer.New()
		for account := range w.Accounts() {
			w.index.Add(account.ID(), account.Name())
		}
		if err := w.storeAccountsIndex(); err != nil {
			return err
		}
	} else {
		index, err := indexer.Deserialize(serializedIndex)
		if err != nil {
			return err
		}
		w.index = index
	}
	return nil
}

// storeAccountsIndex stores the accounts index for a wallet.
func (w *wallet) storeAccountsIndex() error {
	serializedIndex, err := w.index.Serialize()
	if err != nil {
		return err
	}
	if err := w.store.StoreAccountsIndex(w.id, serializedIndex); err != nil {
		return err
	}
	return nil
}
