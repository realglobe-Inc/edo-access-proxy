package main

import (
	"github.com/realglobe-Inc/go-lib-rg/rglog"
)

var log rglog.Logger

func init() {
	log = rglog.GetLogger("github.com/realglobe-Inc/edo/edo-access-proxy")
}
