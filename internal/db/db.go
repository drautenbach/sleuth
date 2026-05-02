package db

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"sleuth/internal/constants"
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

func generateUID() (string, error) {
	b := make([]byte, 16) // 16 bytes for a simple UID
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

/****   Settings     *****/

func (d *Db) GetSettings() *Settings {
	var s Settings
	found := false
	err := d.dbInstance.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("settings:global"))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				// not found, return nil error and let caller receive nil
				return nil
			}
			return err
		}

		if err := item.Value(func(val []byte) error {
			return json.Unmarshal(val, &s)
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
		return &Settings{
			Mode:           ModeCaptive,
			DefaultRole:    "guest",
			SelfRegEnabled: true,
		}
	}
	return &s
}

func (d *Db) SaveSettings(s Settings) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		key := "settings:global"
		val, err := json.Marshal(s)
		if err != nil {
			return err
		}
		err = txn.Set([]byte(key), val)
		return err
	})
}

/****   Users     *****/

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
			//k := item.Key()
			v, err := item.ValueCopy(nil) // Use ValueCopy if you need to use the value outside the transaction
			if err != nil {
				return err
			}
			var up UserProfile
			if err := json.Unmarshal(v, &up); err != nil {
				return err
			}
			users = append(users, up)
			//log.Infof("Key: %s, Value: %s\n", k, v)
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

/****   Roles     *****/

func (d *Db) GetRole(rolename string) *Role {
	var up Role
	found := false
	err := d.dbInstance.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("role:" + rolename))
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

func (d *Db) GetRoles() []Role {
	prefix := []byte("role:")
	var roles []Role
	err := d.dbInstance.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			//k := item.Key()
			v, err := item.ValueCopy(nil) // Use ValueCopy if you need to use the value outside the transaction
			if err != nil {
				return err
			}
			var up Role
			if err := json.Unmarshal(v, &up); err != nil {
				return err
			}
			roles = append(roles, up)
			//log.Infof("Key: %s, Value: %s\n", k, v)
		}
		return nil
	})

	if err != nil {
		panic(err)
	}
	return roles
}

func (d *Db) CreateRole(u *Role) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		role, err := txn.Get([]byte("role:" + u.RoleName))
		if role != nil {
			return fmt.Errorf("role %s already exists", u.RoleName)
		}

		key := "role:" + u.RoleName
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

func (d *Db) UpdateRole(u *Role) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		role, err := txn.Get([]byte("role:" + u.RoleName))
		if role == nil {
			return fmt.Errorf("role %s does not exists", u.RoleName)
		}

		key := "role:" + u.RoleName
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

func (d *Db) DeleteRole(roleName string) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		key := "role:" + roleName

		item, err := txn.Get([]byte("role:" + roleName))
		if err != nil {
			return err
		}
		if item == nil {
			return fmt.Errorf("role %s does not exist", roleName)
		}
		err = txn.Delete([]byte(key))
		if err != nil {
			panic(err)
		}
		return nil
	})
}

/****   Devices     *****/

func (d *Db) GetDevice(macaddress string) *DeviceProfile {
	var up DeviceProfile
	found := false
	err := d.dbInstance.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("device:" + macaddress))
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

func (d *Db) GetDevices() []DeviceProfile {
	prefix := []byte("device:")
	var devices []DeviceProfile
	err := d.dbInstance.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			//k := item.Key()
			v, err := item.ValueCopy(nil) // Use ValueCopy if you need to use the value outside the transaction
			if err != nil {
				return err
			}
			var up DeviceProfile
			if err := json.Unmarshal(v, &up); err != nil {
				return err
			}
			devices = append(devices, up)
			//log.Infof("Key: %s, Value: %s\n", k, v)
		}
		return nil
	})

	if err != nil {
		panic(err)
	}
	return devices
}

func (d *Db) CreateDevice(dp *DeviceProfile) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		device, err := txn.Get([]byte("device:" + dp.MACAddress))
		if device != nil {
			return fmt.Errorf("device %s already exists", dp.MACAddress)
		}

		key := "device:" + dp.MACAddress
		val, err := json.Marshal(dp)
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

func (d *Db) UpdateDevice(dp *DeviceProfile) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		device, err := txn.Get([]byte("device:" + dp.MACAddress))
		if device == nil {
			return fmt.Errorf("device %s does not exists", dp.MACAddress)
		}

		key := "device:" + dp.MACAddress
		val, err := json.Marshal(dp)
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

func (d *Db) DeleteDevice(macAdress string) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		key := "device:" + macAdress

		item, err := txn.Get([]byte("device:" + macAdress))
		if err != nil {
			return err
		}
		if item == nil {
			return fmt.Errorf("device %s does not exist", macAdress)
		}
		err = txn.Delete([]byte(key))
		if err != nil {
			panic(err)
		}
		return nil
	})
}

/****   fwdrules     *****/

func (d *Db) CreateFwdRule(r *constants.FwdRule, expires time.Time) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		dnsKey := d.dnsKey(r.ClientIP, r.Hostname, r.QType)
		fwdKey := d.fwdKey(r.ClientIP, r.DestIPOffset, r.QType)
		dns, err := txn.Get([]byte(dnsKey))
		if dns != nil {
			return fmt.Errorf("dns rule %s:%d already exists", r.Hostname, r.QType)
		}

		fwd, err := txn.Get([]byte(fwdKey))
		if fwd != nil {
			return fmt.Errorf("forward rule %d:%d already exists", r.DestIPOffset, r.QType)
		}

		r.CacheExpiry = expires
		val, err := json.Marshal(r)
		if err != nil {
			return err
		}

		err = txn.SetEntry(badger.NewEntry([]byte(dnsKey), val))
		if err != nil {
			panic(err)
		}
		err = txn.SetEntry(badger.NewEntry([]byte(fwdKey), val))
		if err != nil {
			panic(err)
		}
		return nil
	})
}

func (d *Db) fwdKey(clientIP string, destIPOffset uint16, qtype uint16) string {
	return fmt.Sprintf("fwd:%s:%06d:%d", clientIP, destIPOffset, qtype)
}

func (d *Db) dnsKey(clientIP string, hostname string, qtype uint16) string {
	return fmt.Sprintf("dns:%s:%s:%d", clientIP, hostname, qtype)
}

func (d *Db) DeleteFwdRule(r *constants.FwdRule) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		dnsKey := d.dnsKey(r.ClientIP, r.Hostname, r.QType)
		fwdKey := d.fwdKey(r.ClientIP, r.DestIPOffset, r.QType)

		item, err := txn.Get([]byte(dnsKey))
		if err != nil {
			return err
		}
		if item != nil {
			err = txn.Delete([]byte(dnsKey))
			if err != nil {
				return err
			}
		}

		item, err = txn.Get([]byte(fwdKey))
		if err != nil {
			return err
		}
		if item != nil {
			err = txn.Delete([]byte(fwdKey))
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func (d *Db) ExtendFwdRule(r *constants.FwdRule, expires time.Time) error {
	err := d.DeleteFwdRule(r)
	if err != nil {
		return err
	}
	return d.CreateFwdRule(r, expires)
}

func (d *Db) getFwdRuleByKey(key string) *constants.FwdRule {
	var up constants.FwdRule
	found := false
	err := d.dbInstance.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
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

func (d *Db) GetFwdRuleByHostname(clientIP string, hostname string, qtype uint16) *constants.FwdRule {
	return d.getFwdRuleByKey(d.dnsKey(clientIP, hostname, qtype))
}

func (d *Db) GetFwdRulesByClient(clientIP string) []constants.FwdRule {
	return d.getFwdRulesByKey(fmt.Sprintf("fwd:%s:", clientIP))
}

func (d *Db) GetFwdRules() []constants.FwdRule {
	return d.getFwdRulesByKey("fwd:")
}

func (d *Db) getFwdRulesByKey(key string) []constants.FwdRule {
	prefix := []byte(key)
	var rules []constants.FwdRule

	err := d.dbInstance.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			//k := item.Key()
			v, err := item.ValueCopy(nil) // Use ValueCopy if you need to use the value outside the transaction
			if err != nil {
				return err
			}
			var up constants.FwdRule
			if err := json.Unmarshal(v, &up); err != nil {
				return err
			}
			rules = append(rules, up)
			//log.Infof("Key: %s, Value: %s\n", k, v)
		}
		return nil
	})

	if err != nil {
		panic(err)
	}
	return rules
}

/*             Session                            */

func (d *Db) GetSessions() []Session {
	prefix := []byte("session:")
	var sessions []Session
	err := d.dbInstance.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			//k := item.Key()
			v, err := item.ValueCopy(nil) // Use ValueCopy if you need to use the value outside the transaction
			if err != nil {
				return err
			}
			var s Session
			if err := json.Unmarshal(v, &s); err != nil {
				return err
			}
			s.Expiry = time.Unix(int64(item.ExpiresAt()), 0)
			sessions = append(sessions, s)
			//log.Infof("Key: %s, Value: %s\n", k, v)
		}
		return nil
	})

	if err != nil {
		panic(err)
	}
	return sessions
}

func (d *Db) GetSession(IP string) *Session {
	var s Session
	found := false
	key := []byte("session:" + IP)
	err := d.dbInstance.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			if err == badger.ErrKeyNotFound {
				// not found, return nil error and let caller receive nil
				return nil
			}
			return err
		}

		if err := item.Value(func(val []byte) error {
			txn.Delete(key)
			err = txn.SetEntry(badger.NewEntry(key, val).WithTTL(time.Minute * 15))
			return json.Unmarshal(val, &s)
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

	return &s
}

func (d *Db) CreateSession(s *Session) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		user, err := txn.Get([]byte("session:" + s.IP))
		if user != nil {
			return fmt.Errorf("session for %s already exists", s.IP)
		}

		key := "session:" + s.IP
		val, err := json.Marshal(s)

		if err != nil {
			return err
		}
		err = txn.SetEntry(badger.NewEntry([]byte(key), val).WithTTL(time.Minute * 15))
		if err != nil {
			panic(err)
		}
		return nil
	})
}

func (d *Db) DeleteSession(IP string) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		key := "session:" + IP

		item, err := txn.Get([]byte("session:" + IP))
		if err != nil {
			return err
		}
		if item == nil {
			return fmt.Errorf("session for %s does not exist", IP)
		}
		err = txn.Delete([]byte(key))
		if err != nil {
			panic(err)
		}
		return nil
	})
}

/***************** CRUD **************************/
func get[T any](d *Db, key string) *T {
	var result T
	err := d.dbInstance.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				// Return nil error if key not found
				return nil
			}
			return err
		}

		// Unmarshal the value into the provided type `T`
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &result)
		})
	})

	if err != nil {
		return nil
	}
	return &result
}

func getAll[T any](d *Db, keyprefix string) []T {
	prefix := []byte(keyprefix)
	var result []T
	err := d.dbInstance.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			//k := item.Key()
			v, err := item.ValueCopy(nil) // Use ValueCopy if you need to use the value outside the transaction
			if err != nil {
				return err
			}
			var up T
			if err := json.Unmarshal(v, &up); err != nil {
				return err
			}
			result = append(result, up)
			//log.Infof("Key: %s, Value: %s\n", k, v)
		}
		return nil
	})

	if err != nil {
		panic(err)
	}
	return result
}

func create[T any](d *Db, key string, record *T) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		role, err := txn.Get([]byte(key))
		if role != nil {
			return fmt.Errorf("record %s already exists", key)
		}

		val, err := json.Marshal(record)
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

func update[T any](d *Db, key string, record *T) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		role, err := txn.Get([]byte(key))
		if role == nil {
			return fmt.Errorf("record %s does not exists", key)
		}

		val, err := json.Marshal(record)
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

func delete(d *Db, key string) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		if item == nil {
			return fmt.Errorf("record %s does not exist", key)
		}
		err = txn.Delete([]byte(key))
		if err != nil {
			panic(err)
		}
		return nil
	})
}

/***************** DNS Config - Category **************************/

func (d *Db) GetDNSCategory(categoryid string) *DNSCategory {
	return get[DNSCategory](d, fmt.Sprintf("dnscategory:%s", categoryid))
}

func (d *Db) GetDNSCategories() []DNSCategory {
	return getAll[DNSCategory](d, "dnscategory:")
}

func (d *Db) CreateDNSCategory(c *DNSCategory) error {
	if c.CategoryId == "" {
		id, err := generateUID()
		if err != nil {
			return err
		}
		c.CategoryId = id
	}
	return create(d, fmt.Sprintf("dnscategory:%s", c.CategoryId), c)
}

func (d *Db) UpdateDNSCategory(c *DNSCategory) error {
	return update(d, fmt.Sprintf("dnscategory:%s", c.CategoryId), c)
}

func (d *Db) DeleteDNSCategory(categoryid string) error {
	rulesets := d.GetDNSRuleSets()
	for _, rule := range rulesets {
		if rule.CategoryId == categoryid {
			return fmt.Errorf("Category in use by %s rule set", rule.RuleSetName)
		}
	}
	return delete(d, fmt.Sprintf("dnscategory:%s", categoryid))
}

/***************** DNS Config - RuleSet **************************/

func (d *Db) GetDNSRuleSet(dnsrulesetid string) *DNSRuleSet {
	return get[DNSRuleSet](d, fmt.Sprintf("dnsruleset:%s", dnsrulesetid))
}

func (d *Db) GetDNSRuleSets() []DNSRuleSet {
	return getAll[DNSRuleSet](d, "dnsruleset:")
}

func (d *Db) CreateDNSRuleSet(c *DNSRuleSet) error {
	if c := d.GetDNSCategory(c.CategoryId); c == nil {
		return fmt.Errorf("Category does not exist")
	}
	if c.RuleSetId == "" {
		id, err := generateUID()
		if err != nil {
			return err
		}
		c.RuleSetId = id
	}
	return create(d, fmt.Sprintf("dnsruleset:%s", c.RuleSetId), c)
}

func (d *Db) UpdateDNSRuleSet(c *DNSRuleSet) error {
	if c := d.GetDNSCategory(c.CategoryId); c == nil {
		return fmt.Errorf("Category does not exist")
	}
	return update(d, fmt.Sprintf("dnsruleset:%s", c.RuleSetId), c)
}

func (d *Db) DeleteDNSRuleSet(dnsrulesetid string) error {
	return delete(d, fmt.Sprintf("dnsruleset:%s", dnsrulesetid))
}
