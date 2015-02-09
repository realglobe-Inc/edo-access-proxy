package main

import (
	"github.com/realglobe-Inc/edo/driver"
	"github.com/realglobe-Inc/edo/util"
	"github.com/realglobe-Inc/edo/util/crypto"
	"github.com/realglobe-Inc/go-lib-rg/erro"
	"github.com/realglobe-Inc/go-lib-rg/rglog"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var exitCode = 0

func exit() {
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func main() {
	defer exit()
	defer rglog.Flush()

	util.InitConsoleLog("github.com/realglobe-Inc")

	param, err := parseParameters(os.Args...)
	if err != nil {
		log.Err(erro.Unwrap(err))
		log.Debug(err)
		exitCode = 1
		return
	}

	util.SetupConsoleLog("github.com/realglobe-Inc", param.consLv)
	if err := util.SetupLog("github.com/realglobe-Inc", param.logType, param.logLv, param.logPath, param.fluAddr, param.fluTag); err != nil {
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

	log.Info("Shut down.")
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
				return crypto.ParsePrivateKey(data)
			},
			param.caStaleDur, param.caExpiDur)
		log.Info("Use file private key container " + param.priKeyContPath + ".")
	default:
		return erro.New("invalid code container type " + param.priKeyContType + ".")
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
	return serve(sys, param.socType, param.socPath, param.socPort, param.protType)
}

// 振り分ける。
const (
	proxyApiPath = "/"
)

func serve(sys *system, socType, socPath string, socPort int, protType string) error {
	routes := map[string]util.HandlerFunc{
		proxyApiPath: wrapper(func(w http.ResponseWriter, r *http.Request) error {
			return proxyApi(sys, w, r)
		}),
	}
	return util.Serve(socType, socPath, socPort, protType, routes)
}

func wrapper(f func(http.ResponseWriter, *http.Request) error) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		if err := f(w, r); err != nil {
			err = erro.Wrap(err)
			var msg string
			for baseErr := err; msg == ""; {
				switch e := erro.Unwrap(baseErr).(type) {
				case *util.HttpStatusError:
					if e.Cause() == nil {
						msg = e.Message()
					} else {
						baseErr = e.Cause()
					}
				case *erro.Tracer:
					baseErr = e.Cause()
				default:
					msg = e.Error()
				}
			}
			w.Header().Set(headerAccProxErr, msg)
			return err
		}
		return nil
	}
}
