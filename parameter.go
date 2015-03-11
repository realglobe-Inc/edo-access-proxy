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
	"flag"
	"fmt"
	"github.com/realglobe-Inc/go-lib/erro"
	"github.com/realglobe-Inc/go-lib/rglog/level"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type parameters struct {
	// 画面表示ログ。
	consLv level.Level

	// 追加ログ種別。
	logType string
	// 追加ログ表示重要度。
	logLv level.Level
	// ログファイルパス。
	logPath string
	// fluentd アドレス。
	fluAddr string
	// fluentd 用タグ。
	fluTag string

	// 秘密鍵置き場。
	priKeyContType string
	// ファイルベース秘密鍵置き場。
	priKeyContPath string

	// ソケット種別。
	socType string
	// UNIX ソケット。
	socPath string
	// TCP ソケット。
	socPort int

	// プロトコル種別。
	protType string

	// キャッシュを最新とみなす期間。
	caStaleDur time.Duration
	// キャッシュを廃棄するまでの期間。
	caExpiDur time.Duration

	// 称する TA の ID。
	taId string

	// 署名に使うハッシュ関数。
	hashName string

	// 有効期限ギリギリのセッションを避けるための遊び。
	sessMargin time.Duration

	// 同一ホスト用の http.Client の保持期間。
	cliExpiDur time.Duration

	// セッションを事前に検査するボディサイズの下限。
	threSize int

	// SSL 証明書を検証しない。
	noVerify bool
}

func parseParameters(args ...string) (param *parameters, err error) {

	const label = "edo-access-proxy"

	flags := flag.NewFlagSet(label+" parameters", flag.ExitOnError)
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
	flags.StringVar(&param.logPath, "logPath", filepath.Join(filepath.Dir(os.Args[0]), "log", label+".log"), "File log path.")
	flags.StringVar(&param.fluAddr, "fluAddr", "localhost:24224", "fluentd address.")
	flags.StringVar(&param.fluTag, "fluTag", "edo."+label, "fluentd tag.")

	flags.StringVar(&param.priKeyContType, "priKeyContType", "file", "Private key container type.")
	flags.StringVar(&param.priKeyContPath, "priKeyContPath", filepath.Join(filepath.Dir(os.Args[0]), "private_keys"), "Private key container directory.")

	flags.StringVar(&param.socType, "socType", "tcp", "Socket type.")
	flags.StringVar(&param.socPath, "socPath", filepath.Join(filepath.Dir(os.Args[0]), "run", label+".soc"), "UNIX socket path.")
	flags.IntVar(&param.socPort, "socPort", 16050, "TCP socket port.")
	flags.StringVar(&param.protType, "protType", "http", "Protocol type.")

	flags.DurationVar(&param.caStaleDur, "caStaleDur", 5*time.Minute, "Cache fresh duration.")
	flags.DurationVar(&param.caExpiDur, "caExpiDur", 30*time.Minute, "Cache expiration duration.")

	flags.StringVar(&param.taId, "taId", "", "Default TA ID.")
	flags.StringVar(&param.hashName, "hashName", "sha256", "Sign hash type.")

	flags.DurationVar(&param.sessMargin, "sessMargin", time.Minute, "Margin for session expiration duration.")
	flags.DurationVar(&param.cliExpiDur, "cliExpiDur", 10*time.Minute, "Client expiration duration.")
	flags.IntVar(&param.threSize, "threSize", 8192, "Maximum byte size of request body for skipping session check.")
	flags.BoolVar(&param.noVerify, "noVerify", false, "Skipping SSL verification.")

	var config string
	flags.StringVar(&config, "f", "", "Config file path.")

	// 実行引数を読んで、設定ファイルを指定させてから、
	// 設定ファイルを読んで、また実行引数を読む。
	flags.Parse(args[1:])
	if config != "" {
		if buff, err := ioutil.ReadFile(config); err != nil {
			if !os.IsNotExist(err) {
				return nil, erro.Wrap(err)
			}
			log.Warn("Config file " + config + " is not exist.")
		} else {
			flags.Parse(strings.Fields(string(buff)))
		}
	}
	flags.Parse(args[1:])

	if l := len(flags.Args()); l > 0 {
		log.Warn("Ignore extra parameters ", flags.Args(), ".")
	}

	return param, nil
}

func (param *parameters) LogFilePath() string       { return param.logPath }
func (param *parameters) LogFileLimit() int64       { return 10 * (1 << 20) }
func (param *parameters) LogFileNumber() int        { return 10 }
func (param *parameters) LogFluentdAddress() string { return param.fluAddr }
func (param *parameters) LogFluentdTag() string     { return param.fluTag }
