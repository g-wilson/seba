#!/bin/sh

export GOARCH=amd64
export GOOS=linux

go build ./lambdas/auth/main.go && zip auth.zip main
go build ./lambdas/accounts/main.go && zip accounts.zip main
