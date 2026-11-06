# 可复现性与版本报告

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


日期2026-11-06，Asia/Shanghai。历史真实模型材料、当前本地机制实验、AI辅助评价和概念架构图分别标注。公共仓库main经只读查询为`23031a667396c43a1e7b89124136edc19184bd86`；本轮无GitHub写操作。下载目录没有本地Git元数据，当前新增文件以SHA清单固定，不伪造提交号。

## 1. 原始资产核查

`experiments/paper_final_support/audit_assets.py`读取11个核心模块、六份指定报告、限定公开原始结果及132个实际SQLite数据库。数据库只用`mode=ro`，quick_check全部ok，读前后字节hash相同。[资产审计](evidence/core_asset_audit.json)含具体文件和函数行号。源码机械全文/AST读取与关键控制路径语义检查分别实施；不声称读取供应商所有隐式上下文或私人账户日志。

历史12项目、96条件、768题级字段、1360来源与72=24包×3类型等数据从公开包复用。Stage1/2/3结论和负结果保留；没有重新运行1296枚举、6720补证方法行或旧付费模型。

后续为解决AI疑难，额外只读了受控source result、memory产物、failed_completion/protocol摘要和Host表，记录于`evidence/ai_evaluation/local_source_trace.json`。这些是实际本机原件溯源，不是重跑模型或窥探供应商隐藏状态；不读取账户或凭据。无法公开的受控本地路径与原件需要作者决定脱敏发布方式，公共包本身不能独立重建全部额外轨迹。输入hash逐项保留，不修改原件。

## 2. 当前真实完成的运行

|运行|路径|真实输出及角色|
|---|---|---|
|开发smoke|`evidence/cpu/qualification_smoke_v1/`|210行开发记录，保留旧指标定义，不与正式220行相加|
|固定故障/消融|`evidence/cpu/run_20261106_v2/`|22场景×10配置=220行；独立效应oracle；code/config/raw保留|
|性能专用修复|`evidence/cpu/run_20261106_perf_v3/`|144首操作与各自重试；仅修测量器，不重跑220资格数据|
|新适配检查|`experiments/paper_final_v1/test_durable_delivery.py`|8项检查通过；不是8独立业务项目|
|AI全量评价|`evidence/ai_evaluation/`|preliminary/crosscheck/contextual review/final分开；真人标签不伪填|
|论文图|`figures/`|8张图，各PNG/PDF/SVG；数值来自原始结果，概念图按代码合同绘制|

实际命令和失败见CPU的EXECUTION_LOG/README和`evidence/human/execution_log.md`。v2性能RSS测量因Windows句柄类型失败，错误保留后改测量器，只执行perf阶段。当前runner哈希不替代旧资格v2的冻结code。

## 3. 重跑方式

仓库根目录，Python3.11，现有NumPy1.26.4/Matplotlib3.10.0；不为复现强行升级环境。详细CLI以[CPU README](../../experiments/paper_final_v1/README.md)和[评价说明](human_evaluation.md)为准。使用新run_id和新目录，不覆盖已封存的raw。

```powershell
D:/python3.11/python.exe -B -X utf8 -m unittest experiments.paper_final_v1.test_durable_delivery -v
D:/python3.11/python.exe -B -X utf8 experiments/paper_final_support/make_figures.py
```

上面分别是本轮已执行的适配测试与制图入口说明。完整CPU运行使用README中的新run_id；不要从旧snapshot启动任何商业客户端。图脚本会更新派生图，但不改raw，若需保留逐版图应使用新输出目录。

AI评价入口读取已有回答，不调用外部付费judge。A为AI设计确定规则，B为实际Codex上下文复核，第二角色仍是同族AI；不能将其写成独立供应商模型或人类评价。48题双真人验证集与原768空白材料保持独立，不填AI结果。

## 4. 验证的边界

完整事务参照与Host共享原成熟verifier，不是独立实现复现；独立性来自固定输入、事件次序和持久效果oracle。并发/进程故障是执行过的指定trace，不是所有调度证明。过程CPU/working set是测量进程资源，不能解释为商业模型成本。

数值图显示全部性能长尾；不比较不等安全的file和Host就声称Host更慢无价值。缺失阶段0编码与测得0分别解释；Windows CPU时钟粒度限制保留。Python分配峰值与RSS概念分开。

## 5. 复现与公开发布尚缺

没有真实商业平台的免费一键原生重跑，也不公开账户/私有会话。新ACK适配尚未接入封存商业驱动，因此当前证据是“旧真实客户端＋新受控交付核心”的分层证据。正文明确该边界，若要声称新适配已在商业端到端验证，需要另行独立真实运行及费用决定。

最终发布前还需人类作者审查数据/代码许可证、AI使用声明、分区/学校要求与投稿。没有因仓库公开而推断完整代码许可；新的源码与文献实现许可分别记录。最终产物回执检查文件、hash、链接、图源和引用key，不把文件检查通过当论文科学贡献通过。
