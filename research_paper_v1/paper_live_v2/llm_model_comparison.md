# 真实模型配置与平台比较

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


当前主资格已完成 60/60 个项目内管线；独立统计单位是10个合成业务项目。
每项目有双向×3次执行重复；raw/summary/multi_source为项目内记忆表示，不是独立项目。

| 平台路径 | 实际模型元数据 | 已预留任务 | 有效解析结果 | 原始严格JSON有效/无效 | 可观测调用 |
|---|---|---:|---:|---|---|
| WorkBuddy 5.9.3 原生 ask/零工具 | hy3-x | 241 | 240 | 229/11 | 240个原生用户请求；物理供应商请求数未知 |
| DeepSeek Harness 0.2.1-rc.3 官方SDK/零工具 | deepseek-flash | 246 | 240 | 140/100 | 240个已记录物理SDK请求 |

WorkBuddy `hy3-x` 是安装版本已验证的混元积分通道。本轮没有声称读取到了逐任务扣分。Harness SDK具有真实供应商请求/响应及用量回执，但桌面桥接离线，本轮未把它描述成桌面工具读写。
已知Harness用量的峰时公式估值合计 0.778320 CNY；并非账户实付账单。WorkBuddy费用与完整端到端实付费用为未知。

模型端接收的是Host在独立进程关闭重开后读取的接收库正文。模型未直接访问SQLite；Trusted Host负责真实持久化与授权事务。WorkBuddy上游完整系统提示不可观测；提交的完整业务指令逐任务保存在contract.json/native/input.json。SDK业务system/user指令和实际HTTP请求体保存在回执指向的私有ledger。

同族跨平台附加对照见 same_family_control.md；WorkBuddy与Harness的后端build不能完全核验为相同，不能把平台差异归因为模型差异。

格式错误按原始输出统计；只对固定schema内未转义引号、完整对象之后多余闭括号进行另存的无损结构适配，不改事实、不覆盖失败。预检使用联合表示接收上下文的8个推理任务仅留在raw_experiment_data/live，排除主质量比较。

证据入口：raw_experiment_data/live_summary.json；qualification_isolated_v1/*；harness_preflight.json；preflight/workbuddy/envelope.json。
