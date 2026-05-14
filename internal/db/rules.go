package db

import "time"

type DNSCategory struct {
	CategoryId   uint
	CategoryName string
	Enabled      bool
}

type DNSRuleSet struct {
	RuleSetId    string
	RuleSetName  string
	Description  string
	CategoryId   uint
	CategoryName string
	External     bool
	Source       string
	Schedule     string
	//	Rules       []string
	Count       uint
	Enabled     bool
	LastUpdated time.Time
}

type DNSHostRule struct {
	Name               string
	ExactCategories    []uint
	WildcardCategories []uint
}
