package main

import (
	"crypto/rsa"
	"github.com/realglobe-Inc/edo/driver"
	"github.com/realglobe-Inc/go-lib-rg/erro"
	"net/http"
	"time"
)

type system struct {
	priKeyCont driver.KeyValueStore

	taId     string
	hashName string // 署名に使うハッシュ関数。

	sessCont driver.TimeLimitedKeyValueStore
}

func newSystem(priKeyCont driver.KeyValueStore, taId string, hashName string) *system {
	return &system{
		priKeyCont,
		taId,
		hashName,
		driver.NewMemoryTimeLimitedKeyValueStore(0),
	}
}

type session struct {
	id   string
	uri  string
	taId string

	cli *http.Client
}

func (sys *system) session(uri, taId string, caStmp *driver.Stamp) (sess *session, newCaStmp *driver.Stamp, err error) {
	value, newCaStmp, err := sys.sessCont.Get(uri+"<>"+taId, caStmp)
	if err != nil {
		return nil, nil, erro.Wrap(err)
	} else if value == nil {
		return nil, newCaStmp, nil
	}
	return value.(*session), newCaStmp, nil
}

func (sys *system) addSession(sess *session, expiDate time.Time) (newCaStmp *driver.Stamp, err error) {
	return sys.sessCont.Put(sess.uri+"<>"+sess.taId, sess, expiDate)
}

func (sys *system) removeSession(sess *session) (err error) {
	return sys.sessCont.Remove(sess.uri + "<>" + sess.taId)
}

func (sys *system) privateKey(taId string, caStmp *driver.Stamp) (priKey *rsa.PrivateKey, newCaStmp *driver.Stamp, err error) {
	value, newCaStmp, err := sys.priKeyCont.Get(taId, caStmp)
	if err != nil {
		return nil, nil, erro.Wrap(err)
	} else if value == nil {
		return nil, newCaStmp, nil
	}

	return value.(*rsa.PrivateKey), newCaStmp, nil
}
