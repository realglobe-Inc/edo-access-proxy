package main

import (
	"github.com/realglobe-Inc/edo/driver"
	"github.com/realglobe-Inc/edo/util"
	"github.com/realglobe-Inc/go-lib-rg/erro"
	"github.com/realglobe-Inc/go-lib-rg/rglog"
	"net/http"
	"os"
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

	hndl := util.InitLog("github.com/realglobe-Inc")

	param, err := parseParameters(os.Args...)
	if err != nil {
		log.Err(erro.Unwrap(err))
		log.Debug(err)
		exitCode = 1
		return
	}

	hndl.SetLevel(param.consLv)
	if err := util.SetupLog("github.com/realglobe-Inc", param.logType, param.logLv, param.acpLogPath, param.fluAddr, param.acpFluTag); err != nil {
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
		priKeyCont = driver.NewFileKeyValueStore(param.priKeyContPath, func(before string) string {
			return before + ".pem"
		}, nil, func(data []byte) (interface{}, error) {
			return util.ParseRsaPrivateKey(string(data))
		}, param.caExpiDur)
		log.Info("Use file code container " + param.priKeyContPath + ".")
	default:
		return erro.New("invalid code container type " + param.priKeyContType + ".")
	}

	sys := newSystem(
		priKeyCont,
		param.taId,
		param.hashName,
	)
	return serve(sys, param.acpSocType, param.acpSocPath, param.acpSocPort, param.acpProtType)
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
	const headerAccProxErr = "X-Edo-Access-Proxy-Error"

	return func(w http.ResponseWriter, r *http.Request) error {
		if err := f(w, r); err != nil {
			err = erro.Wrap(err)
			w.Header().Set(headerAccProxErr, "error")
			return err
		}
		return nil
	}
}
