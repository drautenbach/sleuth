package db

import (
	"encoding/json"
	"os"
	"sleuth/internal/log"

	"github.com/dgraph-io/badger/v4"
)

type Db struct {
	dbInstance *badger.DB
}

func InitDB(path string) *Db {
	d := &Db{}
	opts := badger.DefaultOptions(path)
	var err error
	d.dbInstance, err = badger.Open(opts)
	if err != nil {
		log.Error("Failed to open BadgerDB:", err)
		os.Exit(1)
	}
	return d
}

func (d *Db) Close() {
	if d.dbInstance != nil {
		d.dbInstance.Close()
		d.dbInstance = nil
	}
}
func (d *Db) GetUsers() []UserProfile {
	prefix := []byte("user:")
	var users []UserProfile
	err := d.dbInstance.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.Key()
			v, err := item.ValueCopy(nil) // Use ValueCopy if you need to use the value outside the transaction
			if err != nil {
				return err
			}
			var up UserProfile
			if err := json.Unmarshal(v, &up); err != nil {
				return err
			}
			users = append(users, up)
			log.Info("Key: %s, Value: %s\n", k, v)
		}
		return nil
	})

	if err != nil {
		panic(err)
	}
	return users
}

func (d *Db) CreateUser(u *UserProfile) {
	d.dbInstance.Update(func(txn *badger.Txn) error {
		key := "user:" + u.UserName
		val, err := json.Marshal(u)
		if err != nil {
			return err
		}
		err = txn.Set([]byte(key), val)
		if err != nil {
			panic(err)
		}
		return nil
	})
}

func (d *Db) GetUser(username string) *UserProfile {
	var up UserProfile
	found := false
	err := d.dbInstance.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("user:" + username))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				// not found, return nil error and let caller receive nil
				return nil
			}
			return err
		}

		if err := item.Value(func(val []byte) error {
			return json.Unmarshal(val, &up)
		}); err != nil {
			return err
		}
		found = true
		return nil
	})

	if err != nil {
		panic(err)
	}
	if !found {
		return nil
	}
	return &up
}
