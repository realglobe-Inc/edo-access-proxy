package main

import (
	"github.com/realglobe-Inc/edo/driver"
	"github.com/realglobe-Inc/edo/util"
	"github.com/realglobe-Inc/go-lib-rg/rglog/level"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestEdoAccessProxy(t *testing.T) {
	////////////////////////////////
	hndl := util.InitLog("github.com/realglobe-Inc")
	hndl.SetLevel(level.ALL)
	defer hndl.SetLevel(level.INFO)
	////////////////////////////////

	// プロキシ先のサーバーを用意。
	destPort, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	dest, err := util.NewTestHttpServer(destPort, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	// サーバ起動待ち。
	time.Sleep(10 * time.Millisecond)

	// テストするプロキシサーバーを用意。
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

	priKey, err := util.ParseRsaPrivateKey(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzq6SrcupWm+rwSKsIVeOyoRfUc0uPvoxPAEGF5uxZ9y+oqoP
nTFCUAhDTX1lXDv4eHDPVsLuh8q75Bk0uDsYzMNtrODC/neW6U3aKXHOXpdmzrDi
hk8/elgIxnZR5Dm5Vl5EeyCENwQIdxg+knU9dkX7XwFib/RZAK2SXv1Xtgj4x6q7
VgPl3zghdr67jCjZo3zgl0SxbZcOe4Yu4YGi79+UZ14/tD9EghQGmFtFRac2xIH5
iAYDhvDVi6zJgRjevSdds1xqKI3hkQJNT3zju3wa4HhSwmMLXwPTUXeTukTU1gU5
7++SWzrUogi71aQPcv8Y1k78Li5bS/VN1WTN5QIDAQABAoIBAAFQqQxEDHrP1Rbw
gonfxb/SIc0ichXif6ezFffWfMV9aRUd4eWNJ6/crZjzoE567zTM+vTBXsUsbA+i
fWxiq+C5qZv8/iCiYCpx3V6AI+EEM5pDE93o6S19G+kvXYwHNf+vr93cshqrguZH
GDbUWiTDgzryhk7SDjLr58+E6yb0Wrnszoj/hj8kUgra2XDkJNCHt3d8u6kQwH6T
XocD7vaFwvvf3bSs1rMqmfEkI00cidsKFXGBrcYtdMXHPLsrBhta68MfQ4VAOUOd
jdmpuR9Ok6uf+F/ur/WpmT6KFd8oCqkq/LF1S+qZsatqhX/VmzIOHrBhqWljoqug
F4QnqA0CgYEA9X5PupZPGU9i4a7XefrNtCG6GziEFjcE8Dp1qC2YXSOlDTgSahc8
ez1Y09JfLVLrDtOzEP7v6kq7PqPNC5YaUJMMThrjf/cJbNsbipyveXe58BXhf75i
7IWCiVSFP+eaf/t4VXCYiDG1E6Poc/BeLiZg+rRXJKiPC2joQiXFJOsCgYEA14cI
dOW7ZtucCuCGsNg14PMCAWhzxuymCJD01kZaPsPNjik/0F6r/qzpLMrY1EPejhvR
rnc1PFDw3L9ZmNWocHbTxoOVX798xdhkU3Kal6zr7UbRwn/40eVwxUyNZN0nrlsS
z1nl2boHvKCx1EMi3nAH3fp2byBMZdPZY+/6ZG8CgYEAm4/8A9elrfsxRKOfpYs5
eJD6tq8cfFtHBNd2oSiraTHiMDs85/9rcwjP1gJ0D2uAyjd6PCXgb84FU09G6rWm
XTKhVIkTao5naZR6ol5hj44/xBSJfYJue0SrEEz/1xvzOnBms3WTIpKlFRoDfhxu
Ab6OK6/FnNQ3ONq0et4mTBsCgYByU4K835AFA8FGU8uey1HpPX522L1xa9629I2r
jC4a1SqYmnDrSwzZT0dxJzjVgBryLvePIFTw5c6eijIwzEVJQv8bcnkuDRlWqW6u
hUBT7LpJZyOllNScIqUrQ2xNcLK33j+gFgPC9tdby7II8oPwkmTZ7x4b3HoqGbJb
PNUJqQKBgQDrLYGZ7cu0MbLpN4qQ5XOrh8SMyBdOnPdX+kzyTA2UpHuJnbRehJos
J/Bva8S1mcVghERCZLtJUEVCwEsTfM+GHqKyJvKosbVeGW/tpZpyhtfGp3tGrmxn
D8/JxZKNMEyxS8BvCPYqhobhlCqwHtc6wpSWC++fU79xvFrb/X+nVQ==
-----END RSA PRIVATE KEY-----`)
	if err != nil {
		t.Fatal(err)
	}
	sys.priKeyCont.Put(sys.taId, priKey)

	// サーバ起動待ち。
	time.Sleep(10 * time.Millisecond)

	proxyUrl, err := url.Parse("http://localhost:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}}

	// 素通りする。
	dest.AddResponse(http.StatusOK, nil, nil)

	resp, err := cli.Get("http://localhost:" + strconv.Itoa(destPort) + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Error(resp)
	}

	// TA 認証する。
	dest.AddResponse(http.StatusUnauthorized, map[string][]string{
		"Set-Cookie":    []string{cookieTaSess + "=session-da-yo"},
		headerTaAuthErr: []string{"start new session"},
		headerTaToken:   []string{"token-da-yo"},
	}, nil)
	dest.AddResponse(http.StatusOK, nil, nil)

	resp, err = cli.Get("http://localhost:" + strconv.Itoa(destPort) + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Error(resp)
	}

	// 認証済み。
	dest.AddResponse(http.StatusOK, nil, nil)

	resp, err = cli.Get("http://localhost:" + strconv.Itoa(destPort) + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Error(resp)
	}
}
