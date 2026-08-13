# Phase 0: Secure Enclave SSH feasibility spike

実施日: 2026-08-14
環境: macOS 26.5.2 (25F84), OpenSSH 10.2p1

## 結論

元設計の「Secure Enclave署名を実行できるprocessは`macop-agent`だけ」「要求元applicationをUnix socket越しに認証できる」「agent forwardingを常に禁止できる」という3つの保証は、CTK identityと標準OpenSSH agent protocolを使う構成では成立しない。

Phase 4のcustom agent実装は開始しない。Apple純正`ssh-keychain.dylib`を使う薄いwrapperへ要件を縮小する案を推奨する。要求元application単位の排他認可が必須なら、CTK identity・stable agent socket・素のSSH/IDE互換を同時に前提にせず、agent専用access groupと認証済みIPCを使う別プロダクト設計として再spikeする。

## 実機確認

### 1. CTK identityの署名経路は`macop-agent`に排他化できない

- `man sc_auth`は、CTK identityとprivate keyをSSHから`ssh-keychain(8)` library経由で使用できると明記している。
- `man ssh-keychain`は、`/usr/lib/ssh-keychain.dylib`がCryptoTokenKit tokenのidentityをSSH toolsへ提供するPKCS#11 / Secure Key moduleであり、`ssh -o PKCS11Provider=/usr/lib/ssh-keychain.dylib ...`で直接利用できると説明している。
- `/usr/lib/ssh-keychain.dylib`のimport symbolには`SecIdentityCopyPrivateKey`と`SecKeyCreateSignature`が含まれていた。したがって、このApple純正providerは公開鍵列挙専用ではなく署名経路でもある。
- このMacには既存CTK identityがなく、`sc_auth list-ctk-identities -t ssh -e b64`は空、`ssh-keygen -D /usr/lib/ssh-keychain.dylib`は`cannot read public key from pkcs11`だった。不要なidentityを作らず、実署名・Touch ID・GitHub接続試験はここで停止した。

この時点で、`sc_auth create-ctk-identity`で作るidentityについて`macop-agent`だけが`SecKeyCreateSignature`を呼べる、という元の排他性は否定される。`macop-agent`のsocket policyを強化しても、別processがApple純正providerから同じidentityへ到達する経路は閉じられない。

### 2. `LOCAL_PEERPID`は直接peerを識別できるが、元要求者は識別できない

一時Unix socketで`LOCAL_PEERPID`と`LOCAL_PEERCRED`を取得したところ、直接接続では期待したPID/UIDを取得できた。

```text
expected_pid=28191 peer_pid=28191 peer_uid=501
```

元clientとagentの間にrelay processを置くと、agentが観測したのは元clientではなくrelayだった。

```text
origin_pid=29499 relay_pid=29498 agent_observed_pid=29498
```

code signature validationで確認できるのも、この直接peerの実行コードである。親process chainは観測情報であり、agent protocol requestへ暗号学的に結び付いていない。relay、agent forwarding、協調processを越えて「利用者が操作した元application」を証明する認証情報にはならない。

### 3. `SSH_AUTH_SOCK`とagent forwarding

- `SSH_AUTH_SOCK` / `IdentityAgent`はsocketの場所を選ぶためのcapability locatorであり、接続元applicationのidentityを伝えるprotocolではない。
- OpenSSH agentの基本sign requestには元applicationやremote hostの認証済みidentityが含まれない。
- `ForwardAgent`の既定値は`no`で、このMacの`ssh -G github.com`も`forwardagent no`だった。しかし利用者のhost設定、`ssh -A`、別のforwarderで上書きでき、agent側から常に`no`へ固定することはできない。
- OpenSSHのdestination constraints / session bindingはforwardingリスクを減らせるが、協調するSSH実装に依存する。macOSの`ssh-agent(1)`と`ssh-add(1)`も、別toolによるsocket forwardingや再forwardを完全には防げないと明記している。

したがって、`ForwardAgent=no`はwrapperが起動する`ssh`へ明示し、`doctor`で実効設定を診断できる推奨・検査項目にはできるが、stable socketを公開するcustom agent全体の強制保証にはできない。

## 設計変更案

### 推奨: Apple providerを使う薄いSSH wrapper

- `macop ssh create/list/public-key/delete`は`sc_auth`と`ssh-keychain.dylib`を安全にラップする。
- `macop ssh run/test`は`PKCS11Provider=/usr/lib/ssh-keychain.dylib`、対象identityの公開鍵hash、`ForwardAgent=no`を明示してApple純正`ssh`を起動する。
- `p-256-ne -t bio`によりprivate keyのnon-exportabilityと署名時のローカル認証を得る。
- `macop-agent`、要求元application表示、application単位cache、stable `SSH_AUTH_SOCK`をMVPから外す。
- 素のSSH/IDEからproviderを直接設定する利用は可能だが、`macop`による要求元application認証は主張しない。

この案はApple純正経路、秘密鍵fileなし、既存の`macop ssh` CLI入口を維持できる。一方、同一user session内のprocessからidentity利用要求を排他的に制御する保証は持たない。

### 代替: 排他認可を別設計として再spike

要求元application単位の保証を必須にする場合は、次をすべて再検証する。

- `sc_auth` CTK identityではなく、署名serviceだけが取得できるaccess groupにSecure Enclave keyを生成できるcode-signing / entitlement / provisioning条件
- raw OpenSSH agent socketのPID推定ではなく、XPC audit tokenまたは相互認証したclient protocolでcaller identityを結び付ける方法
- 素のSSH/IDEとの互換を失わずに、認証済みclientから短命・一回限りのagent capabilityを渡す方法
- forwarded requestを拒否できるsession bindingと、非協調clientをfail closedにする条件

source build + ad-hoc signing、stable agent socket、任意の素のSSH/IDE、application単位の強い排他認可を同時に満たせるとは現時点で判断しない。

## Phase gate

- Phase 0: 完了（元設計は不採用）
- Phase 4 custom agent: blocked by design。実装しない
- Phase 1/2/3/5の非SSH部分: 継続可能
- Phase 4: 推奨案を採用するか、代替案の追加spikeを承認してから再計画する

## 参照

- ローカルmanual: `sc_auth(8)`, `ssh-keychain(8)`, `ssh-agent(1)`, `ssh-add(1)`, `ssh_config(5)`
- 実機binary: `/usr/lib/ssh-keychain.dylib`, `/usr/bin/ssh`
- [macop design](./macop-design.md)
