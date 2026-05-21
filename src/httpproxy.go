package main

import (
	"github.com/corazawaf/coraza/v3"
)

type HttpProxy struct {
	portal *Portal
	config coraza.WAFConfig
	waf    coraza.WAF
}

func wcHttpProxyInit(portal *Portal) *HttpProxy {
	w := &HttpProxy{
		portal: portal,
	}

	return w
}

func (w *HttpProxy) ApplyWAF() error {
	var err error
	w.config = coraza.NewWAFConfig()
	w.waf, err = coraza.NewWAF(w.config)
	return err
}
