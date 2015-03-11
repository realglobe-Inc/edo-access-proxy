# edo-access-proxy

edo-auth TA 認証を通過するための処理を代行するサーバープログラム。

プロキシリクエストを受け取ったら、プロキシ先とのセッションを確立してから、リクエストを転送する。


## 1. インストール

go が必要。
go のインストールは http://golang.org/ を見よ。

go をインストールしたら、

```shell
go get github.com/realglobe-Inc/edo-toolkit
go install github.com/realglobe-Inc/edo-toolkit/edo-access-proxy
```

適宜、依存ライブラリを `go get` すること。


## 2. 実行

以下ではバイナリファイルが `${GOPATH}/bin/edo-access-proxy` にあるとする。
パスが異なる場合は適宜置き換えること。


### 2.1. 秘密鍵ファイルの設置

称する TA の秘密鍵を、&lt;称する TA の ID&gt;.key という名前で秘密鍵ディレクトリに置く。

```
<秘密鍵ディレクトリ>/
├── <称する TA 1 の ID>.key
├── <称する TA 2 の ID>.key
...
```

秘密鍵ディレクトリのパスは起動オプションで指定する。
初期値はバイナリファイルのあるディレクトリにある private_keys ディレクトリである。


### 2.2. 起動

単独で実行できる。

```shell
${GOPATH}/bin/edo-access-proxy
```


### 2.3. 起動オプション

|オプション名|初期値|値|
|:--|:--|:--|
|-priKeyContPath|バイナリファイルのあるディレクトリの private_keys ディレクトリ|秘密鍵ディレクトリのパス|
|-socPort|16050|待ち受けポート番号|
|-taId||デフォルトで称する TA の ID|

その他のオプションは以下で確認すること。

```shell
${GOPATH}/bin/edo-access-proxy -h
```


### 2.4. デーモン化

単独ではデーモンとして実行できないため、supervisor 等と組み合わせて行う。


## 3. 動作仕様

edo-auth TA 認証を通過するための処理を代行する。


### 3.1. 概要

リクエストを受け取ったら、指定された転送先 URI を edo-auth TA 認証を備えた TA であるとみなし、必要なら前処理を行い、リクエストヘッダを整備して転送する。


### 3.2. リクエストの受け取り

転送先が指定された HTTP リクエストを受け取る。

転送先はヘッダ、もしくは、web プロキシ形式で指定する。

以下では、edo-access-proxy を 16050 番ポート待ち受けで起動し、転送先 URI が https://to.example.org/api/self-destruction または http://to.example.org/api/self-destruction であるとして例を挙げる。


#### 3.2.1. ヘッダによる転送先指定

以下のヘッダを用いる。

|ヘッダ名|値|
|:--|:--|
|X-Edo-Access-Proxy-Uri|転送先 URI|

リクエスト URI は / とする。


##### 3.2.1.1. ヘッダによる転送先指定の例

```HTTP
GET / HTTP/1.1
Host: localhost:16050
X-Edo-Access-Proxy-Uri: https://to.example.org/api/self-destruction
```


#### 3.2.2. web プロキシ形式の転送先指定

転送先が HTTP の場合 (HTTPS でない場合)、リクエスト URI でも指定できる。
主にテスト用。


##### 3.2.2.1. web プロキシ形式の転送先指定の例

```HTTP
GET http://to.example.org/api/self-destruction HTTP/1.1
Host: localhost:16050
```


#### 3.2.3. リクエストオプション

複数の TA として使い分ける場合向けに、称する TA の ID をリクエストごとに指定できる。
指定はヘッダで行う。

|ヘッダ名|値|
|:--|:--|
|X-Edo-Ta-Id|称する TA の ID|


### 3.3. 転送

最多で 2 回、転送先にリクエストを送る。
リクエストボディが小さい場合は、1 回だけで済むことがあるが、2 回送ることになったときはリクエストボディも 2 回送られる。
リクエストボディが大きい場合は、必ず 2 回リクエストを送ることになるが、リクエストボディの転送は 1 回しか行わない。


#### 3.3.1. 消費したリクエストヘッダの削除

リクエストが以下のヘッダを持つなら、それらを削除する。

|ヘッダ名|
|:--|
|X-Edo-Ta-Id|
|X-Access-Proxy-Uri|


#### 3.3.2. 確立済みセッションの利用

称する TA として転送先 URI との間に既に確立されたセッションがあるなら、リクエストに以下の Cookie を加える。

|Cookie ラベル|値|
|:--|:--|
|X-Edo-Auth-Ta-Session|セッション ID|


#### 3.3.3. セッション検査への切り替え

リクエストボディが一定サイズ以上ならば、リクエストメソッドを HEAD に変更し、リクエストボディを取り置く。


#### 3.3.4. 1 回目の転送

リクエストを転送する。


#### 3.3.5. 1 回目の転送レスポンスの検査

1 回目の転送のレスポンスが 401 Unauthorized ステータスかつ以下のヘッダと Set-Cookie を含むかどうかでその後の動作が変わる。

|ヘッダ名|値|
|:--|:--|
|X-Edo-Auth-Ta-Token|何らかの文字列|
|X-Edo-Auth-Ta-Error|"start new session"|

|Set-Cookie ラベル|値|
|:--|:--|
|X-Edo-Auth-Ta-Session|セッション ID|


401 かつ含む場合、認証ヘッダの追加を行ってから、2 回目の転送を行う。

そうでない場合、1 回目がセッション検査なら、2 回目の転送を行う。
セッション検査でなければ、レスポンスを返送する。



#### 3.3.6. 認証ヘッダの追加

称する TA の秘密鍵で 1 回目の転送レスポンスの X-Edo-Auth-Ta-Token の値に署名し、リクエストに以下のヘッダと Cookie を加える。

|ヘッダ名|値|
|:--|:--|
|X-Edo-Auth-Ta-Id|称する TA の ID|
|X-Edo-Auth-Ta-Token-Sign|1 回目の転送レスポンスの X-Edo-Auth-Ta-Token の値への署名|
|X-Edo-Auth-Hash-Function|X-Edo-Auth-Ta-Token-Sign の署名に使ったハッシュ関数|

|Cookie|値|
|:--|:--|
|X-Edo-Auth-Ta-Session|1 回目の転送レスポンスの X-Edo-Auth-Ta-Session の値|


#### 3.3.7. 2 回目の転送

セッション検査のためにメソッドを HEAD にしたり、リクエストボディを取り置いていた場合は元に戻し、リクエストを転送する。


#### 3.3.8. 2 回目の転送レスポンスの検査

2 回目の転送のレスポンスが X-Edo-Auth-Ta-Error を含まなければ、称する TA と転送先を紐付けてセッションを保存する。


#### 3.3.9. レスポンスの返送

転送レスポンスをそのまま返送する。


### 3.4 エラーレスポンス

edo-access-proxy にてエラーが発生した場合、レスポンスに以下のヘッダを加える。

|ヘッダ名|値|
|:--|:--|
|X-Edo-Access-Proxy-Error|適当なメッセージ|

+ 転送先に届かない場合、404 Not Found を返す。
+ 称する TA の秘密鍵が無い場合、403 Forbidden を返す。
+ セッションの確立に失敗した場合、その時のレスポンスを返す。


## ライセンス

Apache License, Version 2.0
