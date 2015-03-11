package main

import (
	"crypto/rsa"
	"crypto/tls"
	"github.com/realglobe-Inc/edo-lib/driver"
	"github.com/realglobe-Inc/go-lib/erro"
	"net/http"
	"time"
)

type system struct {
	priKeyCont driver.KeyValueStore

	taId     string
	hashName string // 署名に使うハッシュ関数。

	sessCont   driver.VolatileKeyValueStore
	sessMargin time.Duration // 有効期限ギリギリのセッションを避けるための遊び。

	cliCont    driver.VolatileKeyValueStore
	cliExpiDur time.Duration

	threSize int // セッションを事前に検査するボディサイズの下限。

	noVerify bool // SSL 証明書を検証するか。
}

func newSystem(priKeyCont driver.KeyValueStore, taId string, hashName string, sessMargin, cliExpiDur time.Duration, threSize int, noVerify bool) *system {
	return &system{
		priKeyCont: priKeyCont,
		taId:       taId,
		hashName:   hashName,
		sessCont:   driver.NewMemoryConcurrentVolatileKeyValueStore(0, 0),
		sessMargin: sessMargin,
		cliCont:    driver.NewMemoryConcurrentVolatileKeyValueStore(0, 0),
		cliExpiDur: cliExpiDur,
		threSize:   threSize,
		noVerify:   noVerify,
	}
}

type session struct {
	id   string
	host string
	taId string
}

func (sys *system) session(uri, taId string, caStmp *driver.Stamp) (sess *session, newCaStmp *driver.Stamp, err error) {
	val, newCaStmp, err := sys.sessCont.Get(uri+"<>"+taId, caStmp)
	if err != nil {
		return nil, nil, erro.Wrap(err)
	} else if val == nil {
		return nil, newCaStmp, nil
	}
	return val.(*session), newCaStmp, nil
}

func (sys *system) addSession(sess *session, expiDate time.Time) (newCaStmp *driver.Stamp, err error) {
	return sys.sessCont.Put(sess.host+"<>"+sess.taId, sess, expiDate)
}

func (sys *system) removeSession(sess *session) (err error) {
	return sys.sessCont.Remove(sess.host + "<>" + sess.taId)
}

func (sys *system) privateKey(taId string, caStmp *driver.Stamp) (priKey *rsa.PrivateKey, newCaStmp *driver.Stamp, err error) {
	val, newCaStmp, err := sys.priKeyCont.Get(taId, caStmp)
	if err != nil {
		return nil, nil, erro.Wrap(err)
	} else if val == nil {
		return nil, newCaStmp, nil
	}

	return val.(*rsa.PrivateKey), newCaStmp, nil
}

var noVerifyTr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}

func (sys *system) client(host string) (cli *http.Client, err error) {
	val, _, err := sys.cliCont.Get(host, nil)
	if err != nil {
		return nil, erro.Wrap(err)
	}
	if val == nil {
		if sys.noVerify {
			cli = &http.Client{Transport: noVerifyTr}
		} else {
			cli = &http.Client{}
		}
	} else {
		cli = val.(*http.Client)
	}
	// 有効期限の更新。
	if _, err = sys.cliCont.Put(host, cli, time.Now().Add(sys.cliExpiDur)); err != nil {
		return nil, erro.Wrap(err)
	}
	return cli, nil
}

func (sys *system) close() error {
	if err := sys.priKeyCont.Close(); err != nil {
		return erro.Wrap(err)
	} else if err := sys.sessCont.Close(); err != nil {
		return erro.Wrap(err)
	} else if err := sys.cliCont.Close(); err != nil {
		return erro.Wrap(err)
	}
	return nil
}
