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
	// 画面ログ。
	consLv level.Level
	// 追加ログ。
	logType string
	logLv   level.Level
	// ファイルログ。
	logPath string
	logSize int64
	logNum  int
	// fluentd ログ。
	logAddr string
	logTag  string

	// ソケット。
	socType string
	// UNIX ソケット。
	socPath string
	// TCP ソケット。
	socPort int
	// プロトコル。
	protType string

	// IdP としての ID。
	selfId string
	// 署名方式。
	sigAlg string
	// 署名鍵の ID。
	sigKid string
	// related_users 用ハッシュ関数。
	hashAlg string

	// URI
	pathOk   string
	pathProx string

	// セッション。
	sessLabel   string
	sessDbExpIn time.Duration
	// JWT の ID (jti)。
	jtiLen   int
	jtiExpIn time.Duration
	// ボディをバッファするメモリサイズ。
	fileThres int

	// バックエンドの指定。

	// redis
	redTimeout   time.Duration
	redPoolSize  int
	redPoolExpIn time.Duration
	// mongodb
	monTimeout time.Duration

	// 鍵 DB。
	keyDbType  string
	keyDbPath  string
	keyDbAddr  string
	keyDbTag   string
	keyDbExpIn time.Duration

	// web データ DB。
	webDbType  string
	webDbAddr  string
	webDbTag   string
	webDbExpIn time.Duration

	// IdP 情報 DB。
	idpDbType string
	idpDbAddr string
	idpDbTag  string
	idpDbTag2 string

	// アクセストークン DB。
	tokDbType string
	tokDbAddr string
	tokDbTag  string

	// セッション DB。
	sessDbType string
	sessDbAddr string
	sessDbTag  string

	// その他のオプション。

	// 転送先の SSL 証明書を検証しない。
	noVeri bool
	debug  bool
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

	flags.Var(level.Var(&param.consLv, level.INFO), "consLv", "Console log level")
	flags.StringVar(&param.logType, "logType", "", "Extra log: Type")
	flags.Var(level.Var(&param.logLv, level.ALL), "logLv", "Extra log: Level")
	flags.StringVar(&param.logPath, "logPath", filepath.Join(filepath.Dir(os.Args[0]), "log", label+".log"), "Extra log: File path")
	flags.Int64Var(&param.logSize, "logSize", 10*(1<<20) /* 10 MB */, "Extra log: File size limit")
	flags.IntVar(&param.logNum, "logNum", 10, "Extra log: File number limit")
	flags.StringVar(&param.logAddr, "logAddr", "localhost:24224", "Extra log: Fluentd address")
	flags.StringVar(&param.logTag, "logTag", label, "Extra log: Fluentd tag")

	flags.StringVar(&param.socType, "socType", "tcp", "Socket type")
	flags.StringVar(&param.socPath, "socPath", filepath.Join(filepath.Dir(os.Args[0]), "run", label+".soc"), "Unix socket path")
	flags.IntVar(&param.socPort, "socPort", 1605, "TCP socket port")
	flags.StringVar(&param.protType, "protType", "http", "Protocol type")

	flags.StringVar(&param.selfId, "selfId", "https://idp.example.org", "TA ID")
	flags.StringVar(&param.sigAlg, "sigAlg", "RS256", "Signature algorithm")
	flags.StringVar(&param.sigKid, "sigKid", "", "Signature key ID")
	flags.StringVar(&param.hashAlg, "hashAlg", "SHA256", "Hash algorithm")

	flags.StringVar(&param.pathOk, "pathOk", "/ok", "OK URI")
	flags.StringVar(&param.pathProx, "pathProx", "/", "Proxy URI")

	flags.StringVar(&param.sessLabel, "sessLabel", "Edo-Cooperation", "Session label")
	flags.DurationVar(&param.sessDbExpIn, "sessDbExpIn", 14*24*time.Hour, "Session keep duration")
	flags.IntVar(&param.jtiLen, "jtiLen", 20, "JWT ID length")
	flags.DurationVar(&param.jtiExpIn, "jtiExpIn", 6*time.Hour, "JWT expiration duration")
	flags.IntVar(&param.fileThres, "fileThres", 1<<17 /* 128 KB */, "Threshold to use file buffer")

	flags.DurationVar(&param.redTimeout, "redTimeout", 30*time.Second, "redis timeout duration")
	flags.IntVar(&param.redPoolSize, "redPoolSize", 10, "redis pool size")
	flags.DurationVar(&param.redPoolExpIn, "redPoolExpIn", time.Minute, "redis connection keep duration")
	flags.DurationVar(&param.monTimeout, "monTimeout", 30*time.Second, "mongodb timeout duration")

	flags.StringVar(&param.keyDbType, "keyDbType", "redis", "Key DB type")
	flags.StringVar(&param.keyDbPath, "keyDbPath", filepath.Join(filepath.Dir(os.Args[0]), "key"), "Key DB directory")
	flags.StringVar(&param.keyDbAddr, "keyDbAddr", "localhost:6379", "Key DB address")
	flags.StringVar(&param.keyDbTag, "keyDbTag", "key", "Key DB tag")
	flags.DurationVar(&param.keyDbExpIn, "keyDbExpIn", 5*time.Minute, "Key DB expiration duration")

	flags.StringVar(&param.webDbType, "webDbType", "redis", "Web data DB type")
	flags.StringVar(&param.webDbAddr, "webDbAddr", "localhost:6379", "Web data DB address")
	flags.StringVar(&param.webDbTag, "webDbTag", "web", "Web data DB tag")
	flags.DurationVar(&param.webDbExpIn, "webDbExpIn", 7*24*time.Hour, "Web data keep duration")

	flags.StringVar(&param.idpDbType, "idpDbType", "mongo", "IdP DB type")
	flags.StringVar(&param.idpDbAddr, "idpDbAddr", "localhost", "IdP DB address")
	flags.StringVar(&param.idpDbTag, "idpDbTag", "edo", "IdP DB tag")
	flags.StringVar(&param.idpDbTag2, "idpDbTag2", "idp", "IdP DB sub tag")

	flags.StringVar(&param.tokDbType, "tokDbType", "redis", "Access token DB type")
	flags.StringVar(&param.tokDbAddr, "tokDbAddr", "localhost:6379", "Access token DB address")
	flags.StringVar(&param.tokDbTag, "tokDbTag", "token", "Access token DB tag")

	flags.StringVar(&param.sessDbType, "sessDbType", "redis", "Session DB type")
	flags.StringVar(&param.sessDbAddr, "sessDbAddr", "localhost:6379", "Session DB address")
	flags.StringVar(&param.sessDbTag, "sessDbTag", "session", "Session DB tag")

	flags.BoolVar(&param.noVeri, "noVeri", false, "Skip SSL verification")
	flags.BoolVar(&param.debug, "debug", false, "Debug mode")

	var config string
	flags.StringVar(&config, "c", "", "Config file path")

	// 実行引数を読んで、設定ファイルを指定させてから、
	// 設定ファイルを読んで、また実行引数を読む。
	flags.Parse(args[1:])
	if config != "" {
		if buff, err := ioutil.ReadFile(config); err != nil {
			if !os.IsNotExist(err) {
				return nil, erro.Wrap(err)
			}
			log.Warn("Config file " + config + " is not exist")
		} else {
			flags.Parse(strings.Fields(string(buff)))
		}
	}
	flags.Parse(args[1:])

	if l := len(flags.Args()); l > 0 {
		log.Warn("Ignore extra parameters ", flags.Args())
	}

	return param, nil
}

func (param *parameters) LogFilePath() string       { return param.logPath }
func (param *parameters) LogFileLimit() int64       { return param.logSize }
func (param *parameters) LogFileNumber() int        { return param.logNum }
func (param *parameters) LogFluentdAddress() string { return param.logAddr }
func (param *parameters) LogFluentdTag() string     { return param.logTag }

func (param *parameters) SocketType() string   { return param.socType }
func (param *parameters) SocketPort() int      { return param.socPort }
func (param *parameters) SocketPath() string   { return param.socPath }
func (param *parameters) ProtocolType() string { return param.protType }
