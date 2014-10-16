package main

import (
	"github.com/realglobe-Inc/edo/driver"
	"github.com/realglobe-Inc/edo/util"
	"github.com/realglobe-Inc/go-lib-rg/rglog/level"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestBoot(t *testing.T) {
	////////////////////////////////
	hndl := util.InitLog("github.com/realglobe-Inc")
	hndl.SetLevel(level.ALL)
	defer hndl.SetLevel(level.INFO)
	////////////////////////////////

	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}

	sys := &system{
		priKeyCont: driver.NewMemoryKeyValueStore(0),
		taId:       "ta-no-id",
		hashName:   "sha256",
		sessCont:   driver.NewMemoryTimeLimitedKeyValueStore(0),
	}
	go serve(sys, "tcp", "", port, "http")

	// サーバ起動待ち。
	time.Sleep(50 * time.Millisecond)

	req, err := http.NewRequest("GET", "http://localhost:"+strconv.Itoa(port)+"/", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.URL.Path = "http://localhost"
	log.Err("Aho " + req.URL.Scheme + "<>" + req.URL.Host + "<>" + req.URL.Path)
	util.LogRequest(req, true)

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Error(resp)
	}
}
