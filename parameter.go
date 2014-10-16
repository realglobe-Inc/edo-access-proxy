package main

import (
	"flag"
	"fmt"
	"github.com/realglobe-Inc/edo/util"
	"github.com/realglobe-Inc/go-lib-rg/erro"
	"github.com/realglobe-Inc/go-lib-rg/file"
	"github.com/realglobe-Inc/go-lib-rg/rglog/level"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type parameters struct {
	// 画面表示ログ。
	consLv level.Level

	// 追加ログ。
	logType string
	logLv   level.Level

	// ファイルログ。
	acpLogPath string

	// fluentd ログ。
	fluAddr   string
	acpFluTag string

	// 秘密鍵置き場。
	priKeyContType string

	// ファイルベース秘密鍵置き場。
	priKeyContPath string

	// ソケット。
	acpSocType string

	// UNIX ソケット。
	acpSocPath string

	// TCP ソケット。
	acpSocPort int

	// プロトコル。
	acpProtType string

	// キャッシュの有効期間。
	caExpiDur time.Duration

	// 称する TA の ID。
	taId string

	// 署名に使うハッシュ関数。
	hashName string
}

func parseParameters(args ...string) (param *parameters, err error) {

	flags := util.NewFlagSet("edo-access-proxy parameters", flag.ExitOnError)
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  "+args[0]+" [{FLAG}...]")
		fmt.Fprintln(os.Stderr, "FLAG:")
		flags.PrintDefaults()
	}

	param = &parameters{}

	flags.Var(level.Var(&param.consLv, level.INFO), "consLv", "Console log level.")
	flags.StringVar(&param.logType, "logType", "", "Extra log type.")
	flags.Var(level.Var(&param.logLv, level.ALL), "logLv", "Extra log level.")
	flags.StringVar(&param.acpLogPath, "acpLogPath", filepath.Join(os.TempDir(), "edo-access-proxy.log"), "File log path.")
	flags.StringVar(&param.fluAddr, "fluAddr", "localhost:24224", "fluentd address.")
	flags.StringVar(&param.acpFluTag, "acpFluTag", "edo.access-proxy", "fluentd tag.")

	flags.StringVar(&param.priKeyContType, "priKeyContType", "file", "Private key container type.")
	flags.StringVar(&param.priKeyContPath, "priKeyContPath", filepath.Join("sandbox", "private-key"), "Private key container directory.")

	flags.StringVar(&param.acpSocType, "acpSocType", "tcp", "Socket type.")
	flags.StringVar(&param.acpSocPath, "acpSocPath", filepath.Join(os.TempDir(), "edo-access-proxy"), "UNIX socket path.")
	flags.IntVar(&param.acpSocPort, "acpSocPort", 8002, "TCP socket port.")

	flags.StringVar(&param.acpProtType, "acpProtType", "http", "Protocol type.")

	flags.DurationVar(&param.caExpiDur, "caExpiDur", time.Hour, "Cache expiration duration.")

	flags.StringVar(&param.taId, "taId", "", "TA ID.")
	flags.StringVar(&param.hashName, "hashName", "sha1", "Sign hash type.")

	var config string
	flags.StringVar(&config, "f", "", "Config file path.")

	// 実行引数を読んで、設定ファイルを指定させてから、
	// 設定ファイルを読んで、また実行引数を読む。
	flags.Parse(args[1:])
	if config != "" {
		if exist, err := file.IsExist(config); err != nil {
			return nil, erro.Wrap(err)
		} else if !exist {
			log.Warn("Config file " + config + " is not exist.")
		} else {
			buff, err := ioutil.ReadFile(config)
			if err != nil {
				return nil, erro.Wrap(err)
			}
			flags.CompleteParse(strings.Fields(string(buff)))
		}
	}
	flags.Parse(args[1:])

	if l := len(flags.Args()); l > 0 {
		log.Warn("Ignore extra parameters ", flags.Args(), ".")
	}

	return param, nil
}
