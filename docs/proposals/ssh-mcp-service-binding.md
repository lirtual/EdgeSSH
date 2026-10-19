# EdgeSSH × SSH MCP：内部 Service Binding 复用主机凭据（提案 / 未批准）

> 2026-10-19 · **Design-only / Draft**。不批准实现、合并、部署、生产凭据读取，也不修改当前 `edgessh` 的生产行为。本提案面向 [lirtual/mcp-workers #83](https://github.com/lirtual/mcp-workers/issues/83)、[#95](https://github.com/lirtual/mcp-workers/issues/95)、[实现 PR #96](https://github.com/lirtual/mcp-workers/pull/96)。所有已完成的 G0–G4 和云端确定失败回执/真实代码回滚证据继续复用，不重复验收。

## 问题与实证

- EdgeSSH `scripts/deployment-secrets.ts:prepareEncryptionSecret` 首次在没有原 Secret 和加密主机记录时生成 `randomBytes(32).toString('base64')`，通过 `scripts/deploy.ts` 的 Wrangler 标准输入保存到 **EdgeSSH 专属 Worker Secret**；其后部署仅检测名称并保留。Cloudflare API 无法读回明文。现有 GitHub 仓库级 Actions Secret 名单也不含 `ENCRYPTION_KEY`；不能假定操作者持有备份。
- 已确认现有 EdgeSSH D1 中存在 CloudCone 的加密记录。现有独立 `ssh-mcp-g5-lab` 的 D1 只有合成数据，无法凭自己的测试密钥解密生产密文；**既不能复制生产密文再用测试密钥，也不能无端轮换生产密钥**。
- 旧 [mcp-workers 固定规格 §Q22=B](https://github.com/lirtual/mcp-workers/issues/83) 约定“EdgeSSH 零修改、独立 MCP Worker 自行读取生产 D1 + 复制根密钥”。现在密钥自动生成且不可取回，这条发布路径并不可直接实施。**变更架构必须由用户重新批准，不能把本提案冒充原规格已经授权。**
- SSH MCP 已独立实现并验证 Worker SSH/PTY/SFTP 引擎、host-key pin、目标检查和 Durable Object 原子回执。没有理由在 EdgeSSH 里再实现一套 SSH 命令执行器。

## 备选方案与决定建议

| 方案 | 影响 | 结论 |
| --- | --- | --- |
| 继续寻找/复制 `ENCRYPTION_KEY`，MCP 直绑 EdgeSSH D1 | 自动生成的现有明文无法通过 GitHub/Cloudflare API 取回；扩大全部主机凭据和登录签名根密钥的暴露面 | **不采用**；禁止轮换生产密钥 |
| 让 EdgeSSH 直接执行 MCP 的任意 Exec、PTY、SFTP，再把结果发回 MCP | 需要在当前 WebSocket 主导的 SSHSessionDO 之外新建执行接口与回执协调，重复已通过的 MCP 实现 | **不采用** |
| 在 EdgeSSH 增加受限的**具名 WorkerEntrypoint RPC 凭据代理**，SSH MCP 保留自己的 SSH/DO 实现 | 只改 EdgeSSH 的最小 D1 SELECT + 解密桥接代码；无需导出根密钥或另建 Worker/数据库 | **建议采用，待批准** |

### 逻辑链路

```text
ChatGPT → 已认证 SSH MCP Worker (/mcp)
  → MCP-owned SQLite DO (operation_id / admission / receipts)
  → EDGE_SSH_BROKER named Service Binding RPC
     → Existing EdgeSSH Worker: HostBrokerEntrypoint
        → existing D1 workspace_state + hosts SELECT
        → existing EdgeSSH ENCRYPTION_KEY (只在 EdgeSSH 内部解密)
        → 返回单个被允许主机的短暂连接材料
  → MCP 已通过验证的 SSH 引擎 → 既有公网 SSH 目标
```

Cloudflare 文档支持 Service Binding 指向同账户 Worker 的 **named `WorkerEntrypoint`**，调用不经公网 URL；独立业务入口仍使用原来 `src/worker.ts` 的默认 HTTP/WS 处理。参见 [RPC (WorkerEntrypoint)](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/rpc/) 与 [Service bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/)。

## 最小接口（草案，不构成代码授权）

仅在 EdgeSSH 新增一个具名的 `HostBrokerEntrypoint extends WorkerEntrypoint`，调用方通过 `services = [{ binding: "EDGE_SSH_BROKER", service: "edgessh", entrypoint: "HostBrokerEntrypoint" }]` 绑定，不新增公网 HTTP 路由。保留 EdgeSSH 现有 `default fetch`、`SSHSessionDO` 和 `wrangler.toml` 的现有域名、DB、DO、认证行为。

只提供三个受限方法（接口可在实现评审时合并，但不得扩展权限）：

1. `listHostMetadata(brokerToken, {cursor?, limit?})`：从固定 workspace 的 D1 **SELECT**，返回经过允许列表筛选的、无凭据的主机元数据；分页/大小有上限；不能复用有 `refreshLocation` 写回副作用的 `hostsRoute(GET)`。
2. `getHostMetadata(brokerToken, hostId)`：返回**一个**允许主机的无凭据视图，用于 MCP `get_host`，不得为元数据请求取出密码或私钥。
3. `resolveHostForConnection(brokerToken, hostId)`：仅为允许主机的**一次实际 SSH 操作**重新 SELECT、解密、校验并返回 `{id,host,port,username,authMethod,password? / privateKey?, fingerprint}`。不得返回 `ENCRYPTION_KEY`、整行密文、初始命令、用户 Cookie 或其他主机。MCP 端仅在内存中用于当前 SSH 握手，不写 D1、DO、日志或工具输出；完成即关闭连接，不缓存凭据。托管 Shell 每次新输入仍需重新检查主机删除/凭据/指纹变化，不能只信首次解析。

EdgeSSH 使用现有 `workspaceState(env)` 得到固定 `accountId`，`SELECT id, encrypted_payload, updated_at FROM hosts WHERE id=? AND account_id=?`，沿用 `decryptHost` 的 `edgessh:v1:${accountId}:${hostId}` AES-GCM AAD；不加入任何 D1 写语句、表迁移或自动迁移。错误只回传有限枚举 `broker_forbidden / host_not_found / host_untrusted / broker_unavailable`，拒绝返回密文、内部堆栈、Secret 值。

## 必须满足的安全边界

1. **双层启用与最小权限：** EdgeSSH 仅在独立 `MCP_BROKER_TOKEN` 正确、且主机 ID 位于明确允许列表（首轮仅 CloudCone）时才允许访问；不增加 `MCP_BROKER_ENABLED` 开关；空白/无效允许列表即全部拒绝。MCP 端独立 Bearer 认证、对首轮 CloudCone 仅允许 `pwd`、`printf`、SFTP 指定只读路径；其他 Shell/SFTP 写入和 PTY 均拒绝。**启用全功能属于另一项发布决定**。
2. **明确调用方授权：** Service Binding 是同 Cloudflare 账户内部能力，而**不是**“只有某个 Worker 能绑定”的不可伪造身份。不能仅依据 Host ID 或自称 caller 名称授权。因此 EdgeSSH 与 MCP Worker 分别持有一个新的、与 `ENCRYPTION_KEY` 完全无关的 `MCP_BROKER_TOKEN`；RPC 每次鉴权并在失败时不解密。专门令牌的安全创建、部署、禁用和轮换需要单独验收，值不写仓库、GitHub 日志或聊天。
3. **root 凭据的真实风险：** 方案保证**根加密密钥不离开 EdgeSSH**，但 `resolveHostForConnection` 的返回值包含选定主机的 root 密码或 SSH 私钥，**会短暂进入 SSH MCP Worker 的内存**。这是新的敏感信任边界，并不等于“凭据永远不离开 EdgeSSH”。根账号仍具备所有系统权限；上层只读命令白名单限制常规工具调用，不是 root OS 级隔离。上线前必须明确接受该风险，不能声称与 EdgeSSH 原环境等价。
4. **Host-key pin：** 无已保存有效 SHA256 指纹一律拒绝 SSH；`ssh-keyscan` 的远程候选值不是可信确认来源。原始主机更新、删除、指纹改变之后不得继续接受旧凭据。
5. **失败关闭、无重试副作用：** Broker 缺失、禁用、RPC/Secret 验证失败、解密失败、D1 读取失败均在 SSH 创建前拒绝；MCP 原有原子回执先于任何有副作用操作；unknown/歧义效果不得自动重新执行。拒绝 RPC 时不能落下实际 SSH 会话。
6. **禁用无需回滚数据库：** 清除允许主机列表、撤销独立令牌或移除 Service Binding，即阻断新凭据操作；现有已建立的 SSH 会话不能仅凭禁用配置保证实时终止，需按 MCP DO 已有会话生命周期处理。回退 EdgeSSH 代码不会修改主机表、工作区或 Cookie；回退 MCP 不应丢失 unknown 墓碑。

## 实施范围（仅待审批，当前没有任何应用代码变更）

- **EdgeSSH：** 一份 broker 模块、`src/worker.ts` 具名导出、`src/types.ts` 的可选绑定类型、少量安全测试。**不修改** `hostsRoute` 的 HTTP 行为、不新增公共路径、不改变 `SSHSessionDO`/Access/OAuth、`ENCRYPTION_KEY` 生命周期、D1 表结构和现有主机资料。
- **mcp-workers：** 主机读取适配为 `synthetic D1` 或 `Service Binding broker` 二选一；前者用于 G0–G5 合成回归，后者仅在发布授权后启用；保留已通过的 SSH 引擎与 DO 回执、Portal Bearer。禁止生产根密钥与生产 D1 再次直接绑定到 MCP。
- **CI：** 复用两仓库现有 CI；不因这项方案新增工作流或重复此前成功的 G0–G4。
- **操作者权限：** 实施 PR 可以保持 Draft，**不得在未授权时合并、发布生产 EdgeSSH、开通 broker 或真实 root SSH/SFTP 测试**。在取得“生产代码部署/启用 + CloudCone 只读验收”的明确授权后再进行阶段门禁。

## 验收与切换门禁（最小集）

- [ ] 本提案及相对于 Q22=B 的架构修订已由操作者批准。
- [ ] 在纯合成/本地测试中：默认禁用、错误令牌、其他主机、未固定指纹、解密异常全部 fail-closed；元数据没有凭据；broker 只有固定 SQL SELECT 且不触发位置回填或 D1 写入。
- [ ] 对新的 RPC 调用者令牌做独立生成、两个 Worker 的正确配置、禁用/轮换后立即拒绝新调用的验证；日志和回执不含任何凭据。
- [ ] 对已有 MCP DO / 直接 SSH 引擎执行一次针对 broker 主机切换的集成测试，包括主机删除、凭据/指纹更新、运行中操作失败与不确定结果；旧 G0–G4 仅复用未变部分。
- [ ] 通过正常 EdgeSSH Actions 发布流程前后，旧 WebSSH、文件管理/SSH 会话与管理员认证仍可工作，不触及已有 D1 主机记录和 AES Secret。
- [ ] 取得单独生产 SSH 授权后，**只对 CloudCone** 实测 `pwd`、`printf`、SFTP 固定路径只读，成功与失败均只记录脱敏结果；不把 root 凭据或输出敏感内容记录到 PR。
- [ ] 禁用 broker、撤销新的 RPC 令牌、移除 MCP Service Binding 后，新调用 fail-closed；EdgeSSH 原有功能继续正常；已有 DO known/unknown 回执按实际状态保留。

**明确非目标：** 不新增 Worker/Queue/D1、远程 Agent、通用凭据导出 REST API、从 Cloudflare 恢复不可读的自动生成密钥、服务器端全套独立 SSH 引擎、隐藏的生产代码修改、基于网络扫描自动信任 SSH host key。
