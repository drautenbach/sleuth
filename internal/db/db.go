package db

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"sleuth/internal/constants"
	"sleuth/internal/log"
	"slices"
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

/****   DNS fwdrules     *****/

func (d *Db) CreateDNSSession(r *constants.DNSSession) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		dnsKey := d.dnsFwdKey(r.ClientIP, r.Hostname, r.QType)
		dns, err := txn.Get([]byte(dnsKey))
		if dns != nil {
			return fmt.Errorf("dns rule %s:%d already exists", r.Hostname, r.QType)
		}

		r.LastEvent = time.Now()
		val, err := json.Marshal(r)
		if err != nil {
			return err
		}

		err = txn.SetEntry(badger.NewEntry([]byte(dnsKey), val))
		if err != nil {
			panic(err)
		}
		return nil
	})
}

func (d *Db) dnsFwdKey(clientIP string, hostname string, qtype uint16) string {
	return fmt.Sprintf("dns:%s:%d:%s", clientIP, qtype, hostname)
}

func (d *Db) DeleteDNSSession(r *constants.DNSSession) error {
	return delete(d, d.dnsFwdKey(r.ClientIP, r.Hostname, r.QType))
}

func (d *Db) UpdateDNSSession(r *constants.DNSSession) error {
	return update(d, d.dnsFwdKey(r.ClientIP, r.Hostname, r.QType), r)
}

func (d *Db) GetDNSSession(clientIP string, hostname string, qtype uint16) *constants.DNSSession {
	return get[constants.DNSSession](d, d.dnsFwdKey(clientIP, hostname, qtype))
}

func (d *Db) GetDNSSessionsForClient(clientIP string) []constants.DNSSession {
	return getAll[constants.DNSSession](d, fmt.Sprintf("dns:%s:", clientIP))
}

func (d *Db) GetDNSSessionsForClientType(clientIP string, qtype uint16) []constants.DNSSession {
	return getAll[constants.DNSSession](d, fmt.Sprintf("dns:%s:%d:", clientIP, qtype))
}

func (d *Db) GetDNSSessions() []constants.DNSSession {
	return getAll[constants.DNSSession](d, "dns:")
}

func (d *Db) DNSSessions() []constants.DNSSession {
	return getAll[constants.DNSSession](d, "dns:")
}

func (d *Db) FlushDNSSessions(clientIP string) error {
	keyprefix := fmt.Sprintf("dns:%s:", clientIP)
	prefix := []byte(keyprefix)
	err := d.dbInstance.Update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		var err error = nil
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			if err != nil {
				err = txn.Delete(it.Item().Key())
			}
		}
		return err
	})
	return err
}

func (d *Db) CreateReverseDNS(clientIP string, qtype uint16, rdns *constants.ReverseDNS) error {
	return create(d, fmt.Sprintf("rev:%s:%d:%d", clientIP, qtype, rdns.DestIPOffset), rdns, 0)
}

func (d *Db) DeleteReverseDNS(clientIP string, qtype uint16, DestIPOffset uint16) error {
	return delete(d, fmt.Sprintf("rev:%s:%d:%d", clientIP, qtype, DestIPOffset))
}

/*func (d *Db) GetReverseDNS() []constants.ReverseDNS {
	return getAll[constants.ReverseDNS](d, fmt.Sprintf("rev:"))
}*/

func (d *Db) GetReverseDNSByClientType(clientIP string, qtype uint16) []constants.ReverseDNS {
	return getAll[constants.ReverseDNS](d, fmt.Sprintf("rev:%s:%d", clientIP, qtype))
}

/*             Session                            */

func (d *Db) GetSessions() []Session {
	return getAll[Session](d, "session:")
}

func (d *Db) GetSession(IP string) *Session {
	return get[Session](d, fmt.Sprintf("session:%s", IP))
}

func (d *Db) CreateSession(s *Session) error {
	return create(d, fmt.Sprintf("session:%s", s.IP), s, time.Minute*15)
}

func (d *Db) DeleteSession(IP string) error {
	return delete(d, fmt.Sprintf("session:%s", IP))
}

/***************** CRUD **************************/
func get[T any](d *Db, key string) *T {
	var result T

	err := d.dbInstance.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			/*if err == badger.ErrKeyNotFound {
				// Return nil error if key not found
				return nil
			}*/
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

func create[T any](d *Db, key string, record *T, ttl time.Duration) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
		role, err := txn.Get([]byte(key))
		if role != nil {
			return fmt.Errorf("record %s already exists", key)
		}

		val, err := json.Marshal(record)
		if err != nil {
			return err
		}
		if ttl > 0 {
			err = txn.SetEntry(badger.NewEntry([]byte(key), val).WithTTL(ttl))
		} else {
			err = txn.Set([]byte(key), val)
		}
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

func set[T any](d *Db, key string, record *T) error {
	return d.dbInstance.Update(func(txn *badger.Txn) error {
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
	return create(d, fmt.Sprintf("dnscategory:%s", c.CategoryId), c, 0)
}

func (d *Db) EnsureDNSCategory(c *DNSCategory) error {
	if c.CategoryId == "" {
		return fmt.Errorf("Category Id required")
	}
	cat := d.GetDNSCategory(c.CategoryId)
	if cat == nil {
		return d.CreateDNSCategory(c)
	}
	return nil
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
	return create(d, fmt.Sprintf("dnsruleset:%s", c.RuleSetId), c, 0)
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

func (d *Db) UpdateDNSRules(rs *DNSRuleSet, r *[]string) error {
	err := set(d, fmt.Sprintf("dnsrules:%s", rs.RuleSetId), r)
	if err != nil {
		return err
	}
	rs.LastUpdated = time.Now()
	rs.Count = uint(len(*r))
	return update(d, fmt.Sprintf("dnsruleset:%s", rs.RuleSetId), rs)
}

func (d *Db) GetDNSRules(rulesetid string) *[]string {
	return get[[]string](d, fmt.Sprintf("dnsrules:%s", rulesetid))
}

func (d *Db) GetDnsHostRule(hostname string) *DNSHostRule {
	return get[DNSHostRule](d, fmt.Sprintf("dnsrule:%s", hostname))
}

func (d *Db) SetDnsHostRule(hr *DNSHostRule) error {
	return set(d, fmt.Sprintf("dnsrule:%s", hr.Name), hr)
}

func (d *Db) ClearDnsHostRules() error {
	prefix := []byte("dnsrule:")

	err := d.dbInstance.Update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			v, err := item.ValueCopy(nil) // Use ValueCopy if you need to use the value outside the transaction
			if err != nil {
				return err
			}
			var hr DNSHostRule
			if err := json.Unmarshal(v, &hr); err != nil {
				return err
			}

			txn.Delete(item.Key())
		}
		return nil
	})

	return err
}

func (d *Db) RemoveCategoryFromDnsHostRules(categoryId string) error {
	prefix := []byte("dnsrule:")

	err := d.dbInstance.Update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			v, err := item.ValueCopy(nil) // Use ValueCopy if you need to use the value outside the transaction
			if err != nil {
				return err
			}
			var hr DNSHostRule
			if err := json.Unmarshal(v, &hr); err != nil {
				return err
			}

			idx := slices.Index(hr.ExactCategories, categoryId)
			update := false
			if idx > -1 {
				hr.ExactCategories = slices.Delete(hr.ExactCategories, idx, idx)
				update = true
			}
			idx = slices.Index(hr.WildcardCategories, categoryId)
			if idx > -1 {
				hr.WildcardCategories = slices.Delete(hr.WildcardCategories, idx, idx)
				update = true
			}
			if update {
				if len(hr.WildcardCategories) == 0 && len(hr.ExactCategories) == 0 {
					txn.Delete(item.Key())
				} else {
					val, err := json.Marshal(hr)
					if err != nil {
						return err
					}
					err = txn.Set(item.Key(), val)
					if err != nil {
						return err
					}
				}
			}

		}
		return nil
	})

	return err
}

/***************** DNS Cache **************************

func (d *Db) CreateDNSCacheRecord(clientIP string, name string, qtype uint16, ttl uint32, rr *[]dns.RR) error {
	strs := make([]string, len(*rr))
	for i, r := range *rr {
		strs[i] = r.String()
	}

	return create(d, fmt.Sprintf("dnscache:%s:%s:%d", clientIP, name, qtype), &strs, time.Second*time.Duration(ttl))
}

func (d *Db) DeleteDNSCacheRecord(clientIP string, name string, qtype uint16, rr *[]dns.RR) error {
	return delete(d, fmt.Sprintf("dnscache:%s:%s:%d", clientIP, name, qtype))
}

func (d *Db) GetDNSCacheRecord(clientIP string, name string, qtype uint16) *[]dns.RR {
	strs := get[[]string](d, fmt.Sprintf("dnscache:%s:%s:%d", clientIP, name, qtype))
	if strs == nil {
		return nil
	}
	res := make([]dns.RR, len(*strs))
	for i, r := range *strs {

		res[i], _ = dns.NewRR(r)
	}
	return &res
}

func (d *Db) FlushDNSCacheRecords(clientIP string) error {
	keyprefix := fmt.Sprintf("dnscache:%s:", clientIP)
	prefix := []byte(keyprefix)
	err := d.dbInstance.Update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		var err error = nil
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			if err != nil {
				err = txn.Delete(it.Item().Key())
			}
		}
		return err
	})
	return err
} */

/***************** DNS Config - Profile **************************/

func (d *Db) GetDNSConfiguration(profileid string) *DNSConfiguration {
	return get[DNSConfiguration](d, fmt.Sprintf("DNSConfiguration:%s", profileid))
}

func (d *Db) GetDNSConfigurations() []DNSConfiguration {
	return getAll[DNSConfiguration](d, "DNSConfiguration:")
}

func (d *Db) CreateDNSConfiguration(p *DNSConfiguration) error {
	if p.ProfileId == "" {
		id, err := generateUID()
		if err != nil {
			return err
		}
		p.ProfileId = id[:6]
	}
	return create(d, fmt.Sprintf("DNSConfiguration:%s", p.ProfileId), p, 0)
}

func (d *Db) UpdateDNSConfiguration(p *DNSConfiguration) error {
	return update(d, fmt.Sprintf("DNSConfiguration:%s", p.ProfileId), p)
}

func (d *Db) DeleteDNSConfiguration(profileid string) error {
	/*rulesets := d.GetDNSRuleSets()
	for _, rule := range rulesets {
		if rule.CategoryId == profileid {
			return fmt.Errorf("Category in use by %s rule set", rule.RuleSetName)
		}
	}*/
	return delete(d, fmt.Sprintf("DNSConfiguration:%s", profileid))
}

/***************** HTTP Proxy **************************/

func (d *Db) GetHTTPProxyConfiguration(domain string) *HttpProxy {
	return get[HttpProxy](d, fmt.Sprintf("HttpProxy:%s", domain))
}

func (d *Db) GetHTTPProxyConfigurations() []HttpProxy {
	return getAll[HttpProxy](d, "HttpProxy:")
}

func (d *Db) CreateHTTPProxyConfiguration(p *HttpProxy) error {
	return create(d, fmt.Sprintf("HttpProxy:%s", p.DomainName), p, 0)
}

func (d *Db) UpdateHTTPProxyConfiguration(p *HttpProxy) error {
	return update(d, fmt.Sprintf("HttpProxy:%s", p.DomainName), p)
}

func (d *Db) DeleteHTTPProxyConfiguration(domain string) error {
	return delete(d, fmt.Sprintf("HttpProxy:%s", domain))
}

/***************** HTTP Proxy **************************/

func (d *Db) GetWafRule(id int) *WafRule {
	return get[WafRule](d, fmt.Sprintf("WafRule:%d", id))
}

func (d *Db) GetWafRules() []WafRule {
	return getAll[WafRule](d, "WafRule:")
}

func (d *Db) CreateWafRule(wr *WafRule) error {
	return create(d, fmt.Sprintf("WafRule:%d", wr.ID), wr, 0)
}

func (d *Db) UpdateWafRule(wr *WafRule) error {
	return update(d, fmt.Sprintf("WafRule:%d", wr.ID), wr)
}

func (d *Db) DeleteWafRule(id int) error {
	return delete(d, fmt.Sprintf("WafRule:%d", id))
}

/***************** WAF Config - Profile **************************/

func (d *Db) GetWAFConfiguration(profileid string) *WAFConfiguration {
	return get[WAFConfiguration](d, fmt.Sprintf("WAFConfiguration:%s", profileid))
}

func (d *Db) GetWAFConfigurations() []WAFConfiguration {
	return getAll[WAFConfiguration](d, "WAFConfiguration:")
}

func (d *Db) CreateWAFConfiguration(p *WAFConfiguration) error {
	return create(d, fmt.Sprintf("WAFConfiguration:%s", p.Name), p, 0)
}

func (d *Db) UpdateWAFConfiguration(p *WAFConfiguration) error {
	return update(d, fmt.Sprintf("WAFConfiguration:%s", p.Name), p)
}

func (d *Db) DeleteWAFConfiguration(profileid string) error {
	return delete(d, fmt.Sprintf("WAFConfiguration:%s", profileid))
}
