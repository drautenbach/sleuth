#!/bin/sh
echo "Starting sleuth (dev container)"
LISTEN_ADDR=0.0.0.0:53 
air
go run `ls src/*.go | grep -v _test.go`