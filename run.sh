#!/bin/sh
LISTEN_ADDR=0.0.0.0:53 go run `ls src/*.go | grep -v _test.go`