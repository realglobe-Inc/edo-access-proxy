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


# TA 間連携プロキシ機能

TA 間連携を代行する。

## 1. 動作仕様

以降の動作記述において、箇条書きに以下の構造を持たせることがある。

* if
    * then
* else if
    * then
* else


### 1.1. 概要

1. リクエストを受け取る。
2. 関連するアカウントが属す全ての IdP について次の 1, 2 を行う。
    1. IdP に、仲介リクエストを送る。
    2. IdP から、仲介コードを受け取る。
3. 連携先 TA に、全ての仲介コードと共にリクエストを転送する。
4. 連携先 TA からレスポンスを受け取る。
5. レスポンスを転送する。

```
+--------+                    +--------+
|        |----(1) request---->|        |                     +--------+
|        |                    |        |----(2-1) coop.----->|        |
|        |                    |        |          request    |  IdP   |
|        |                    |        |                     |        |
|        |                    |        |<---(2-2) code-------|        |
|        |                    | access |                     +--------+
|        |                    | proxy  |         ...            ...
|        |                    |        |
|        |                    |        |                     +--------+
|        |                    |        |----(3) request----->|        |
|        |                    |        |        +codes       |   TA   |
|        |                    |        |                     |        |
|        |                    |        |<---(4) response-----|        |
|        |<---(5) response----|        |                     +--------+
+--------+                    +--------+
```


### 1.2. リクエストの受け取り

以下のヘッダを利用する。

* X-Access-Proxy-Users
    * 必須。
      アカウントタグからアカウント情報へのマップをクレームセットとする `alg` が `none` な JWT。
* X-Access-Proxy-To
    * 必須。
      転送先 URI。
* X-Access-Proxy-To-Id
    * 転送先 TA の ID が X-Access-Proxy-To の値からパス以下を除いた部分でない場合は必須。
      転送先 TA の ID。

アカウント情報は以下を含む。

* **`at_tag`**
    * 処理の主体なら必須。
      そうでなければ無し。
      アクセストークンタグ。
* **`iss`**
    * 処理の主体でないアカウントなら必須。
      アカウントが属す IdP の ID。
* **`sub`**
    * 処理の主体でないアカウントなら必須。
      アカウント ID。

X-Access-Proxy-Users に処理の主体が含まれない、または、複数の処理の主体が含まれる場合、エラーを返す。


#### 1.2.1. リクエスト例

```http
GET / HTTP/1.1
Host: localhost:16050
X-Access-Proxy-To: https://to.example.org/api/writer/profile
X-Access-Proxy-Users: eyJhbGciOiJub25lIn0.eyJyZWFkZXIiOnsiYXRfdGFnIjoiMkV5d2gxWjR0WiJ9
    LCJ3cml0ZXIiOnsiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5vcmciLCJzdWIiOiIwN0JGRjFE
    MzcwNkQxNjlEIn19.
```

改行とインデントは表示の都合による。

クレームセットの内容は、

```json
{
    "reader": {
        "at_tag": "2Eywh1Z4tZ"
    },
    "writer": {
        "iss": "https://idp.example.org",
        "sub": "07BFF1D3706D169D"
    }
}
```


### 1.3. IdP への仲介リクエスト

[TA 間連携プロトコル]も参照のこと。

* X-Access-Proxy-Users に含まれるアカウントが処理の主体のみ、かつ、アカウントタグ、アクセストークンタグ、転送先 TA に紐付く、期限に余裕のあるセッションがある場合、
    * 転送へ。
* そうでなければ、X-Access-Proxy-Users のアカウントタグで IdP に仲介リクエストを送る。


### 1.4. IdP からの仲介コード受け取り

[TA 間連携プロトコル]を参照のこと。

1 つでもエラーであれば、エラーを返す。


### 1.5. リクエストの転送

[TA 間連携プロトコル]を参照のこと。

リクエストから X-Access-Proxy-Users, X-Access-Proxy-To, X-Access-Proxy-To-Id ヘッダを削除する。
仲介コードは HTTP ヘッダにて付加する。


### 1.6. レスポンスの受け取り

* Cookie に Edo-Cooperation がある場合、
    * アカウントタグ、アクセストークンタグ、転送先 TA に紐付けて保存する。
* そうでなく、セッションを利用した上での [TA 間連携プロトコル]のエラーだった場合、
    * セッションを削除する。
      IdP への仲介リクエストからやり直す。


### 1.7. レスポンスの転送

特別な処理は無し。


### 1.8. エラーレスポンス

エラーは [OAuth 2.0 Section 5.2] の形式で返す。
edo-access-proxy にてエラーが発生した場合、レスポンスに以下のヘッダを加える。

|ヘッダ名|値|
|:--|:--|
|X-Access-Proxy-Error|適当なメッセージ|


<!-- 参照 -->
[OAuth 2.0 Section 5.2]: http://tools.ietf.org/html/rfc6749#section-5.2
[TA 間連携プロトコル]: https://github.com/realglobe-Inc/edo/blob/master/ta_cooperation.md
