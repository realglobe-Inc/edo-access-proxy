// Copyright 2015 realglobe, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"github.com/realglobe-Inc/edo-lib/crypto"
	"github.com/realglobe-Inc/edo-lib/driver"
	jsonutil "github.com/realglobe-Inc/edo-lib/json"
	logutil "github.com/realglobe-Inc/edo-lib/log"
	"github.com/realglobe-Inc/edo-lib/server"
	"github.com/realglobe-Inc/go-lib/erro"
	"github.com/realglobe-Inc/go-lib/rglog"
	"github.com/realglobe-Inc/go-lib/rglog/level"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func main() {
	var exitCode = 0
	defer func() {
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	}()
	defer rglog.Flush()

	logutil.InitConsole("github.com/realglobe-Inc")

	param, err := parseParameters(os.Args...)
	if err != nil {
		log.Err(erro.Unwrap(err))
		log.Debug(err)
		exitCode = 1
		return
	}

	logutil.SetupConsole("github.com/realglobe-Inc", param.consLv)
	if err := logutil.Setup("github.com/realglobe-Inc", param.logType, param.logLv, param); err != nil {
		log.Err(erro.Unwrap(err))
		log.Debug(err)
		exitCode = 1
		return
	}

	if err := mainCore(param); err != nil {
		err = erro.Wrap(err)
		log.Err(erro.Unwrap(err))
		log.Debug(err)
		exitCode = 1
		return
	}

	log.Info("Shut down")
}

// system を準備する。
func mainCore(param *parameters) error {

	var priKeyCont driver.KeyValueStore
	switch param.priKeyContType {
	case "file":
		priKeyCont = driver.NewFileListedKeyValueStore(param.priKeyContPath,
			func(key string) string {
				return url.QueryEscape(key) + ".key"
			},
			func(path string) string {
				if !strings.HasSuffix(path, ".key") {
					return ""
				}
				key, _ := url.QueryUnescape(path[:len(path)-len(".key")])
				return key
			},
			nil,
			func(data []byte) (interface{}, error) {
				return crypto.ParsePem(data)
			},
			param.caStaleDur, param.caExpiDur)
		log.Info("Use file private key container " + param.priKeyContPath)
	default:
		return erro.New("invalid code container type " + param.priKeyContType)
	}

	sys := newSystem(
		priKeyCont,
		param.taId,
		param.hashName,
		param.sessMargin,
		param.cliExpiDur,
		param.threSize,
		param.noVerify,
	)
	defer sys.close()
	return serve(sys, param.socType, param.socPath, param.socPort, param.protType, nil)
}

// 振り分ける。
const (
	proxyApiPath = "/"
	okPath       = "/ok"
)

func serve(sys *system, socType, socPath string, socPort int, protType string, shutCh chan struct{}) error {
	routes := map[string]server.HandlerFunc{
		proxyApiPath: func(w http.ResponseWriter, r *http.Request) error {
			return proxyApi(sys, w, r)
		},
		okPath: func(w http.ResponseWriter, r *http.Request) error {
			return nil
		},
	}
	return server.TerminableServe(socType, socPath, socPort, protType, routes, shutCh, wrapper)
}

func wrapper(hndl server.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// panic時にプロセス終了しないようにrecoverする
		defer func() {
			if rcv := recover(); rcv != nil {
				responseError(w, erro.New(rcv))
				return
			}
		}()

		//////////////////////////////
		server.LogRequest(level.DEBUG, r, true)
		//////////////////////////////

		if err := hndl(w, r); err != nil {
			responseError(w, erro.Wrap(err))
			return
		}
	}
}

func responseError(w http.ResponseWriter, err error) {
	var v struct {
		Stat int    `json:"status"`
		Msg  string `json:"message"`
	}
	switch e := erro.Unwrap(err).(type) {
	case *server.Error:
		log.Err(e.Message())
		log.Debug(e)
		v.Stat = e.Status()
		v.Msg = e.Message()
	default:
		log.Err(e)
		log.Debug(err)
		v.Stat = http.StatusInternalServerError
		v.Msg = e.Error()
	}

	buff, err := json.Marshal(&v)
	if err != nil {
		err = erro.Wrap(err)
		log.Err(erro.Unwrap(err))
		log.Debug(err)
		// 最後の手段。たぶん正しい変換。
		buff = []byte(`{status="` + jsonutil.StringEscape(strconv.Itoa(v.Stat)) +
			`",message="` + jsonutil.StringEscape(v.Msg) + `"}`)
	}

	// エラー起源を追加。
	w.Header().Set(headerAccProxErr, v.Msg)

	w.Header().Set("Content-Type", contTypeJson)
	w.Header().Set("Content-Length", strconv.Itoa(len(buff)))
	w.WriteHeader(v.Stat)
	if _, err := w.Write(buff); err != nil {
		err = erro.Wrap(err)
		log.Err(erro.Unwrap(err))
		log.Debug(err)
	}
	return
}
