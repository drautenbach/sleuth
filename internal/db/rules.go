package db

import "time"

type DNSCategory struct {
	CategoryId   string
	CategoryName string
	Enabled      bool
}

type DNSRuleSet struct {
	RuleSetId   string
	RuleSetName string
	Description string
	CategoryId  string
	External    bool
	Source      string
	Schedule    string
	Rules       []string
	Enabled     bool
	LastUpdated time.Time
}
