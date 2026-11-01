# WorkBuddy HY3 显式输入捕获适配

`source-memory.mjs` 是原生 desktop-queue 的小范围实验适配器；不是通用记忆服务。每次创建独立 Git 工作区和原生新会话，通过原生接口与数据库读回选择 HY3，提交一个任务，并绑定实际队列请求与原生输出文件。通用生成输入只接受 `trace_id/template_id/template/sources`，不接受测试问题或评分标签。

本项目使用外部开源网关：

- Windows fork：[wuxuanren2008-ux/codex-workbuddy-gateway-windows](https://github.com/wuxuanren2008-ux/codex-workbuddy-gateway-windows)，固定 `e68e3bce8c7fd577b93191add90beb74481dc136`。
- 上游模型选择桥：[dudu555-djiao/codex-workbuddy-gateway](https://github.com/dudu555-djiao/codex-workbuddy-gateway)，固定 `fbaaa2ef6d6cb59f48b953a1f27058202a81553f`。

实际运行环境使用 Node 24.22.2。外部源码及其依赖、账号配置、原生应用、前台网关注册均不随仓库分发，也不由本脚本自动安装或设置开机启动。路径约定见源码顶部：项目内 `.runtime/gateways/`。正常登录与官方可用通道是前置；本模块不解析、解密或导出登录令牌。

安全默认的输入检查形式如下；`--check` 不创建会话或目录，也不提交模型任务：

```text
node experiments/workbuddy_gateway_20261101/source-memory.mjs input.json --out results/new_source_capture --workspace results/new_source_workspace --check
```

移除 `--check` 会执行真实原生任务，必须由实验驱动先完成授权、输入与预算冻结。输出目录和工作区须全新且互相分离；失败或未知结果不自动重发。工具可用于队列传输和指定文件写入，因此不能称“零工具模型请求”；底层模型请求数和费用未知时保持 null。

观察器仅对同一任务 `sync/snapshot` 的已知队列 busy 错误作有界元数据重读，每次最多2次、整次helper最多4次。`send/wake/pump` 不进入这个重读机制。未知错误停止并保存安全分类。前一次观察失败及晚到输出没有被升级为成功；新版已完成一条真实 M/R 时序资格。

`source-memory.test.mjs` 的6项离线检查使用合成队列，需要上述固定外部源码依赖，不是仅克隆本仓库即能运行的零依赖测试。云端或当前应用会话不参与测试。仓库 CI 的标准库可携带复算入口见 [公开包](../../benchmarks/pre_delivery_revocation_metadata_20261101/README.md)。

实际队列业务输入、原生新会话及文件的绑定不证明供应商隐藏上下文为空、任意工具均未访问其他材料或记忆语义全部正确。公开结论及未通过项见 [真实链报告](../../docs/首次交付前撤权_公开元数据成果与研究边界_2026-11-01.md)。
