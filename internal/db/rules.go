package db

import "time"

type DNSCategory struct {
	CategoryId       string
	CategoryName     string
	ParentCategoryId *string
	Enabled          bool
}

type DNSRuleSet struct {
	RuleSetId    string
	RuleSetName  string
	Description  string
	CategoryId   string
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
	DomScanCategories  []string
	ExactCategories    []string
	WildcardCategories []string
}
