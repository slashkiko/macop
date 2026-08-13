# Phase 0: Secure Enclave SSH feasibility spike

実施日: 2026-08-14
環境: macOS 26.5.2 (25F84), Apple OpenSSH 10.2p1

## 結論

元設計の「Secure Enclave署名を実行できるprocessは`macop-agent`だけ」という排他性は成立しない。Apple純正`ssh-keychain.dylib`から同じCTK identityへ到達できるためである。この迂回は許容し、macopの保証を「macop-agent経由の要求に対するapplication別承認」へ限定する。

共用のstable `SSH_AUTH_SOCK`から元applicationを推定する方式も採用しない。一方、Phase 0bの実機spikeにより、macopが新規起動したapplicationへセッション専用socketを渡し、起動PID・bundle identity・session nonce・process ancestryを検証する方式は成立する見込みを得た。外部relayと終了済みsessionは拒否でき、Apple OpenSSH 10.2はAgent Forwardingを`session-bind@openssh.com`の`forwarding=1`としてagentへ通知した。

したがってPhase 4は、Apple provider wrapperに加えて、**verified-session agentを条件付きで採用する**。ただし強い承認UXを提供するのはmacopが検証済みsessionを作れるapplicationに限り、共用socket、既存起動済みapplication、非協調SSH clientを同等に扱わない。

## Phase 0a: 元設計の限界

### 1. CTK identityの署名経路は`macop-agent`に排他化できない

- `man sc_auth`は、CTK identityとprivate keyをSSHから`ssh-keychain(8)` library経由で使用できると明記している。
- `man ssh-keychain`は、`/usr/lib/ssh-keychain.dylib`がCryptoTokenKit tokenのidentityをSSH toolsへ提供するPKCS#11 / Secure Key moduleであり、`ssh -o PKCS11Provider=/usr/lib/ssh-keychain.dylib ...`で直接利用できると説明している。
- `/usr/lib/ssh-keychain.dylib`のimport symbolには`SecIdentityCopyPrivateKey`と`SecKeyCreateSignature`が含まれていた。したがって、このApple純正providerは公開鍵列挙専用ではなく署名経路でもある。
- このMacには既存CTK identityがなく、`sc_auth list-ctk-identities -t ssh -e b64`は空、`ssh-keygen -D /usr/lib/ssh-keychain.dylib`は`cannot read public key from pkcs11`だった。不要なidentityを作らず、実署名・Touch ID・GitHub接続試験は実施していない。

この結果は、「macop-agentだけが署名できる」という主張を否定する。ただし、macop-agentを選択した要求に独自の承認policyを適用することは妨げない。

### 2. 共用socketでは直接peerより前を認証できない

一時Unix socketで`LOCAL_PEERPID`と`LOCAL_PEERCRED`を取得したところ、直接接続では期待したPID/UIDを取得できた。

```text
expected_pid=28191 peer_pid=28191 peer_uid=501
```

元clientとagentの間にrelay processを置くと、agentが観測したのは元clientではなくrelayだった。

```text
origin_pid=29499 relay_pid=29498 agent_observed_pid=29498
```

したがって、共用socketの接続後に親process chainだけをたどり、「利用者が操作した元application」を復元する設計は成立しない。code signatureで確認できるのも直接peerの実行コードであり、relay以前のapplicationをagent requestへ暗号学的に結び付けない。

### 3. `ForwardAgent=no`は共用agent全体から強制できない

- `SSH_AUTH_SOCK` / `IdentityAgent`はsocket locatorであり、接続元applicationのidentityを伝えるprotocolではない。
- OpenSSH agentの基本sign requestには元applicationやremote hostの認証済みidentityが含まれない。
- `ForwardAgent`の既定値は`no`だが、利用者のhost設定、`ssh -A`、別のforwarderで上書きできる。
- destination constraints / session bindingは防御を強化するが、協調するSSH実装に依存する。

`ForwardAgent=no`はwrapperが起動する`ssh`には明示できるが、共用socketを公開するagent全体の保証にはならない。

## Phase 0b: verified-session agent spike

### 1. application別のセッション専用socket

画面を持たない最小`.app`を作り、`NSWorkspace.OpenConfiguration`から次の値を渡して新規instanceを起動した。

- application固有の`SSH_AUTH_SOCK`
- 推測困難なsession nonceを模した環境変数
- `createsNewApplicationInstance = true`

launcherが取得した`NSRunningApplication.processIdentifier`と、socket接続中に`LOCAL_PEERPID`で取得した直接peer PIDは一致した。bundle IDとsession nonceも一致した。

```text
launched_pid=56818 peer_pid=56818 pid_match=yes
bundle=local.macop.phase0b.probe token_match=yes
```

これにより、「macopが作ったsessionへ紐付くapplication」という表示は可能である。任意の既存applicationを事後に識別したという意味ではない。

session nonceはsession相関と取り違え防止に使うが、環境変数の秘匿性だけを認証境界にしない。同一userによる値の観測を想定し、root PID・開始時刻・process ancestry・code identityとの一致を必須にする。

### 2. process ancestryと外部relay拒否

`LOCAL_PEERPID`、`proc_pidinfo(PROC_PIDTBSDINFO)`による親子関係、登録root PIDの開始時刻を使った一時proxyで次を確認した。`SecCodeCopyGuestWithAttributes`にPIDを渡し、直接peerのcode identifierを取得できることも確認した。

```text
case=authorized-direct-child result=ALLOW
case=authorized-descendant-relay result=ALLOW
case=external-relay-known-path result=DENY
case=orphan-after-root-exit result=DENY
```

この判定は、登録applicationの正規な子プロセスを許可しつつ、socket pathを知る同一userの外部processと、root終了後に孤児化したprocessを拒否できる。登録application自身の侵害、process injection、登録process tree内に生成された悪意あるrelayは防御境界外である。

### 3. Agent Forwardingの検出

127.0.0.1だけで待ち受ける一時`sshd`を起動し、Apple OpenSSH 10.2から`ssh -A`で接続してforwarded agent socketへ`ssh-add -l`を送った。agent protocolを観測した結果、通常接続とforwarded接続は`session-bind@openssh.com`の末尾flagで区別できた。

```text
local SSH connection:     session-bind@openssh.com forwarding=0
forwarded agent request:  session-bind@openssh.com forwarding=1
```

verified modeでは、署名要求より前の有効なsession bindingを必須にし、`forwarding=1`を拒否する。`session-bind@openssh.com`を送らないclientや、独自forwarderは検証済みとして扱わずfail closedにする。この条件がSourcetreeなど対象clientと両立するかは製品別に確認が必要である。

## 採用する設計境界

### Apple provider wrapper

- `macop ssh create/list/public-key/delete`は`sc_auth`と`ssh-keychain.dylib`を安全にラップする。
- `macop ssh run/test`は対象identityと`ForwardAgent=no`を明示してApple純正`ssh`を起動する。
- `p-256-ne -t bio`によりprivate keyのnon-exportabilityと署名時のローカル認証を得る。
- Apple providerからの直接利用は許容し、macopのapplication別承認が適用されるとは主張しない。

### verified-session agent

- 共用のstable `SSH_AUTH_SOCK`は公開しない。
- macopがapplicationまたはshell sessionごとに短命なproxy socketとsession nonceを作る。
- sessionはroot PID・開始時刻・bundle ID・code requirement・鍵fingerprint・期限へ結び付ける。
- proxyは直接peerが登録rootまたは生存中の子孫であることを毎接続時に確認する。
- agentは署名前にOpenSSH session bindingを検証し、`forwarding=1`またはbindingなしを拒否する。
- 承認画面にはapplication、検証状態、鍵名とfingerprint、対象session、期限を表示する。
- 画面には「この承認はmacop-agent経由だけに適用され、Apple providerからの直接利用は制御しない」と明記する。
- cache keyに少なくともsession ID、root PIDと開始時刻、code identity、鍵fingerprintを含める。
- session nonce単独、socket pathのランダム性単独を接続元認証として扱わない。

## 未検証事項とPhase 4開始条件

- SourcetreeはこのMacに未インストールのため、macopからの新規起動、専用`SSH_AUTH_SOCK`利用、`session-bind@openssh.com`対応を未確認。
- Terminalのタブ単位shell integrationと、タブ終了時のsession失効を未確認。
- 実CTK identityを使ったTouch ID、署名、GitHub SSH E2Eを未実施。
- 正式配布時のcode requirement、Developer ID signing、XPC boundaryを未確定。
- PID再利用への対策は開始時刻との組み合わせを設計したが、長時間stress testは未実施。

Phase 4では、まず最小agent protocol、session registry、Sourcetreeまたは対象GUI client、Terminal shell integrationを順に実装・検証する。対象clientがsession bindingに非対応なら、承認画面上で「検証済み」と表示せず、そのclientをverified modeの対象外にする。既存のApple純正`op`互換動作と公開CLI契約は変更しない。

## Phase gate

- Phase 0a: 完了。「macop-agentだけが署名できる」と共用socketによる要求元推定は不採用
- Phase 0b: 完了。verified-session agentは条件付きGo
- Phase 4 Apple provider wrapper: Go
- Phase 4 verified-session agent: 段階実装へ進行可能。製品別互換性と実CTK E2Eは未完了
- Phase 1/2/3/5の非SSH部分: 継続可能

## 参照

- ローカルmanual: `sc_auth(8)`, `ssh-keychain(8)`, `ssh-agent(1)`, `ssh-add(1)`, `ssh_config(5)`
- 実機binary: `/usr/lib/ssh-keychain.dylib`, `/usr/bin/ssh`, `/usr/sbin/sshd`
- [Apple NSWorkspace.OpenConfiguration](https://developer.apple.com/documentation/appkit/nsworkspace/openconfiguration)
- [Apple SecCodeCopyGuestWithAttributes](https://developer.apple.com/documentation/security/seccodecopyguestwithattributes%28_%3A_%3A_%3A_%3A%29)
- [OpenSSH agent protocol](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent)
- [macop design](./macop-design.md)
