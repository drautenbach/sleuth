package db

import (
	"encoding/json"
	"fmt"
	"os"
	"sleuth/internal/log"
	"time"

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

func (d *Db) UpdateUser(u *UserProfile) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		user, err := txn.Get([]byte("user:" + u.UserName))
		if user == nil {
			return fmt.Errorf("user %s does not exists", u.UserName)
		}

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

func (d *Db) SetPassword(username string, password string) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		u := d.GetUser(username)
		if u == nil {
			return fmt.Errorf("user %s does not exists", username)
		}
		u.Password = password
		u.PasswordReset = time.Time{}

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

func (d *Db) CreateUser(u *UserProfile) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		user, err := txn.Get([]byte("user:" + u.UserName))
		if user != nil {
			return fmt.Errorf("user %s already exists", u.UserName)
		}

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

func (d *Db) DeleteUser(userName string) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		key := "user:" + userName

		item, err := txn.Get([]byte("user:" + userName))
		if err != nil {
			return err
		}
		if item == nil {
			return fmt.Errorf("user %s does not exist", userName)
		}
		err = txn.Delete([]byte(key))
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
