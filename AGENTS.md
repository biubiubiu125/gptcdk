# AGENTS.md

本文件约束 `gptcdk` 仓库里的协作方式，作用域为整个仓库。
用户当前指令优先；更深目录若存在 `AGENTS.md`，则在其范围内补充或覆盖本文件。

## 当前版本

- 当前版本是 `1.1.0`，以根目录 `package.json` 为准；`apps/server/package.json` 与 `apps/web/package.json` 必须与它一致。
- 数据库只使用 PostgreSQL。`SchemaMigration` 的版本号仍是 `1`。`stagedCredential`、`refreshHeld`、`remoteMembersJson` 和其它 Team 相关列都在这个版本门外面用 `ADD COLUMN IF NOT EXISTS` 补齐，不要为这些列再插一条版本记录。

## 兑换与找回

- 公开兑换不调用 OpenAI。同一张卡再次兑换只重导出当前库里的凭据，不重新占库存。
- 找回在卡级咨询锁内刷新。新凭据先落库，文件找回的 `refreshHeld` 保持到 HTTP 响应 `finish` 才解除。连接在响应写完前断开时不解除持有，下一次找回不得拿旧 `refresh_token` 再刷新。账密找回不刷新，成功也不解除已有持有。
- 前台兑换和找回不接受邮箱 TXT。显式 `format=email` 整次拒绝，不占库存，也不刷新。后台导出的邮箱 TXT 仍只有四段或六段，不附带 OpenAI 凭据。库存行比四段长且第四段已是完整邮箱 token 时，追加备注账密前先收成四段；token 自身含分隔符时不截断。邮箱取件导出和公开文件里的 `source_line` 只保留四段邮箱凭据；库存里更长的 `mailbox.line` 不能把 ChatGPT 密码或 2FA 带出去。
- 只有 OpenAI 返回 `invalid_grant` 时，才把账号标成 `invalid`。HTTP 400、401、`invalid_client`、`unauthorized_client` 和地区 403 都不标失效。微软邮箱刷新仍按原错误码处理。
- 当前凭据和暂存都写不进去时，后台刷新结果要带 `unsavedCredential`。公开找回失败可以在响应里给出已换到的凭据，但不能因此解除持有。
- 前台不放管理入口。后台路径是 `/biubiubiu`，旧 `/admin` 只做跳转。登录不加限流、锁定或验证码。

## Team

- 公开兑换不调用 OpenAI，也不走 SOCKS。Team 库存和普通库存分开。账密有 2FA 时是 `账号----密码----2FA`，没有时是 `账号----密码`，不留空段。普通库存读 `notes` 里的 ChatGPT 密码，Team 只读密文。没有密码不能下账密，失败不占新库存。首次账密只交付本卡账号，忽略 `limit`。重复导出或找回时，归属里任一账号停用、封禁或失效，整卡失败，不输出密码。找回账密也不刷新。Team 卡额度为 0 也可以下账密；文件还没生成时，文件兑换返回「文件还没生成」，不换号。`kicked` 一律返回「该账号已被踢出空间」。
- 母号只保存 session。一个母号可以有多个 ChatGPT 空间，不能按邮箱唯一；同一个非空 `openaiWorkspaceId` 不能绑两行。多空间必须点选，不能悄悄换空间。更换 session 时，邮箱必须和已绑定母号一致。
- 只贴 access token 可以保存，页面必须标明不能自动续期。`sessionToken` 或可回放的网页 cookie 才算可续期。续期只把 `sessionToken` 当作 `__Secure-next-auth.session-token` 回放到 `.chatgpt.com` 的 `/api/auth/session`，不带 Authorization。
- 子号按三列入库：`邮箱----ChatGPT密码----2FA`。正好六列时只取第 1、5、6 列。四列取件凭据拒绝。密码和 2FA 只进 `TeamSecret`。公开文件不带密码、2FA 和 session。
- 分配按空位从少到多，空位相同用更早的 `createdAt`。同一母号两次邀请至少隔 10 分钟；只有邀请请求实际发出后才写 `lastInviteAt`。邀请失败只停当前母号，不打断其他母号。
- 邀请返回 200 不等于已加入。席位已满、空间停用或空间不存在要停住后续邀请。公式算出的空位不能单独清掉 `seat_full`。
- 踢出必须先有完整名单。人还在名单里不删资料。确认不在后才删密码、2FA、token、`rawJson`、用量和邮箱，并把状态改成 `kicked`。已确认离开但本地还在的，下次踢人用踢前完整快照补删。
- 完整快照才覆盖 `remoteMembersJson`。名单不完整时仍显示上次完整名单，但不能踢人。踢出选中必须输入「踢出选中」，只踢普通成员，不踢所有者或母号，踢完不自动分配。
- 协议换到的 session 即使这次调用失败也要留下，下次再用。缺设备号时补上。
- 代理顺序是子号、母号、全局。只接受 SOCKS。三者都空就失败，不直连。协议服务不连数据库，不发布端口。
- 不读子号邮箱，不按用量自动踢人，不做定时轮转。`oai-client-*` 观察头只转发已有值，不自行编造。
