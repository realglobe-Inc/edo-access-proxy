<!--
Copyright 2015 realglobe, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->


# edo-access-proxy

TA 間連携プロトコルを代行するサーバープログラム。


## 1. インストール

[go] が必要。
go のインストールは http://golang.org/doc/install を参照のこと。

go をインストールしたら、

```shell
go get github.com/realglobe-Inc/edo-access-proxy
go install github.com/realglobe-Inc/edo-access-proxy
```

適宜、依存ライブラリを `go get` すること。


## 2. 実行

以下ではバイナリファイルが `${GOPATH}/bin/edo-access-proxy` にあるとする。
パスが異なる場合は適宜置き換えること。


### 2.1. 鍵ファイルの設置

称する TA の秘密鍵を、秘密鍵ディレクトリに置く。

```
<秘密鍵ディレクトリ>/
├── <適当な名前>.json   // JWK 形式。
├── <適当な名前>.key    // PEM 形式。
├── <適当な名前>.pem    // PEM 形式。
...
```

鍵ディレクトリのパスは起動オプションで指定する。
初期値はバイナリファイルのあるディレクトリにある key ディレクトリである。


### 2.2. 起動

単独で実行できる。

```shell
${GOPATH}/bin/edo-access-proxy
```


### 2.3. 起動オプション

|オプション名|初期値|値|
|:--|:--|:--|
|-keyDbPath|実行ファイルのあるディレクトリの key|鍵ディレクトリのパス|
|-noVeri|`false`|通信先の SSL 証明書を検証しないかどうか|

その他は `-h` で確認すること。


### 2.4. デーモン化

単独ではデーモンとして実行できないため、[Supervisor] 等と組み合わせて行う。


## 3. 動作仕様

TA 間連携プロトコルを代行する。


### 3.1. エンドポイント

|エンドポイント名|初期パス|機能|
|:--|:--|:--|
|TA 間連携プロキシ|/|[TA 間連携プロキシ機能](/api/proxy)を参照|


## 4. API

[GoDoc](http://godoc.org/github.com/realglobe-Inc/edo-access-proxy)


## 5. ライセンス

Apache License, Version 2.0


<!-- 参照 -->
[Supervisor]: http://supervisord.org/
[go]: http://golang.org/
