# Agent 记忆安全迁移与权限保持研究原型

本项目研究：Agent A 将记忆交给 Agent B，或将记忆迁入另一种后端后，怎样保留读取、转交和撤权约束，同时让合法用户继续完成任务。

已实现记忆来源核验、隐私标注、迁移规划、同步假名化、核权恢复和双轨评测。当前是由多个受控实验入口组成的研究原型，整体效果、原生稳定性及论文创新仍未验收。

[项目图文汇报](docs/DeepSeek使用与日志清理_图文汇报_2026-10-25.md) · [自包含 HTML](docs/reports/deepseek_role_and_cleanup_20261025.html) · [详细任务结构与成果](docs/项目阶段收尾与任务汇报_2026-10-25.md)

HTML 内嵌流程图，下载后可用浏览器离线打开。

## 工作流程

![记忆构建、核权迁移、假名化使用与恢复](docs/assets/project_closeout_flow_20261025.svg)

1. 准备原始材料和服务端业务规则，区分事实内容与授权依据。
2. 本地摘录或选择记忆事实，核对具体原文位置和内容哈希。
3. 识别敏感片段，分别认证访问授权与隐私标签。
4. 检查用户、执行 Agent、源规则、接收范围及目标限制，规划获准副本。
5. 迁移时校验来源和标签；标签失效时按指定模式重新检测。
6. 使用记忆时，同时替换问题和记忆中的敏感值，恢复表留在本机内存。
7. 模型回答后再次核权，验证代号与来源，再恢复允许展示的原值。
8. 分开评估底层权限、模型任务效果、撤权及旧任务重放。

有权读取不自动代表有权导出或共享；标签认证只证明绑定和完整性，不证明检测没有漏项。假名化保留恢复能力和部分关系结构，不等于完全匿名化。

## 模型与实验范围

| 环节 | 实际实现 |
|---|---|
| 迁移和授权 | 本地程序、研究 ACL 网关与明确配置的目标 API |
| 历史云端问答 | DeepSeek Flash，共 85 次真实请求：21 次三组上下文对照、64 次提示与隐私对照 |
| 近期本地开发实验 | Qwen3 4B 用于事实构建、标注或回答，GLiNER 用于实体检测 |
| 原生后端桥接 | 受控 Mem0 本地 SDK→Open WebUI 精确事实迁移，使用真实存储和本地嵌入模型 |

DeepSeek 使用程序核验后冻结的记忆回答；85 次请求不是 85 次独立迁移，也不表示两个自主 DeepSeek Agent 在线协商搬运记忆。

本地模型任务链主要是同进程角色与签名 JSON 交接。原生桥接另行执行，不含生成式模型，尚未与问答合成同一条端到端验收。

## 当前成果与限制

| 内容 | 已有证据与边界 |
|---|---|
| 工程回归 | 最近一次完整离线回归为 1,028 项通过；该数字是历史记录，不表示本次文档整理重新运行了测试 |
| 合法问答 | 最新已暴露开发材料中，默认严格答对 26/32；同输出格式兼容后为次要成绩 30/32，不是新独立验收 |
| 生成时强标注 | 一批 8 故事中修复 4 道任务的注册名称漏遮；不能推广为所有敏感信息均受保护 |
| 生命周期 | 21 项受控见证通过；完整标准基线也通过，未证明新算法优势 |
| 原生桥接 | 保留 v3 的 25/29 失败；后续同序诊断 29/29，根因及稳定修复尚未证明 |
| 论文目标 | 原检测门槛未通过；新独立 64 题目标尚未执行，强基线优势与创新尚未成立 |

未证明收益的模式没有切换为默认。原始失败与完整分母保留；工程测试数、格式修复或阻断后的零披露都不能代替整体效果。

聚合结果见 [benchmarks](benchmarks/)，研究边界与近邻比较见 [主线验收与竞品核验](docs/论文目标_主线验收与竞品核验_2026-10-25.md)。

## 快速运行：无需模型或密钥

建议使用 Python 3.12。以下基本演示仅依赖标准库，不需要原始数据、GPU 或收费凭证。输出目录须尚未存在。

```powershell
git clone https://github.com/Caixianseng/memory-migration-permission-pilot.git
cd memory-migration-permission-pilot

# 统一研究模块的受控演示
python -B -X utf8 -m memory_migration_study demo --output results/my_demo

# 加入明确标记的人工故障诊断
python -B -X utf8 -m memory_migration_study demo --output results/my_diagnostics --diagnostics

# 假名化与核权恢复演示
python -B -X utf8 examples/privacy_roundtrip_demo.py

# 离线工程测试，不代表模型效果测试
python -B -X utf8 -m unittest discover -s tests -q
```

默认演示使用固定程序回答器，只验证实验流程；真实模型指标保持未测。人为注入的故障用于验证测试器，不能当作自然发现的厂商漏洞。

## 真实数据、模型与后端入口

真实模型回放入口为显式启用的 `llm-replay`；它读取已核验的原生上下文快照，答案和权限评分标签留在本机。付费连接器默认关闭，配置凭证并启用后才发起请求。

`public-pilot` 需要本机原始交接资料；`native-webui-public` 还需要固定原生环境。示例：

```powershell
python -B -X utf8 -m memory_migration_study public-pilot --legacy-project memory_migration_permission_149tests_20261021/memory_migration_permission_pilot --output results/my_public_study

.\.venv-native-webui\Scripts\python.exe -B -X utf8 -m memory_migration_study native-webui-public --legacy-project memory_migration_permission_149tests_20261021/memory_migration_permission_pilot --output results/my_native_study
```

这些本机资产不随克隆提供。详细前提见 [研究模块运行说明](docs/研究模块运行说明_2026-10-21.md)、[实验实现契约](docs/具体实验方案与实现契约_2026-10-21.md) 和 [原生目标接入说明](docs/原生目标接入与阶段裁决_2026-10-22.md)。

## 旧原型与本地数据

`memory_migration_pilot` 是独立的早期参考后端原型，通过本地 HTTP 检查 `read` 和 `list`。它使用自建 SQLite 执行器，不调用大模型，也不代表真实产品迁移成绩。

```powershell
# 使用仓库自编数据；Windows 也可双击“运行示例.cmd”
python -B -X utf8 run_pilot.py --data-root examples/data --dataset synthetic

# 使用已有本地数据；Windows 也可双击“运行测试.cmd”
python -B -X utf8 run_pilot.py --data-root datasets/datasets --dataset gatemem --episodes-per-domain 2 --limit 120

# 其他受控配额与输出设置
python -B -X utf8 run_pilot.py --dataset synthetic --quota 1 --budgets 0 5 10 20
```

旧原型中 GateMem 与合成材料上的 ACL 是明确施加的实验条件，不是原基准的天然权限；PrivacyLens 与 AgentLeak 只做文件资格审计，不自动转换成权限真值。`--quota` 是人为实验限制，不是已确认的厂商限制。`--limit 0` 或 `--episodes-per-domain 0` 可扩大输入，但会增加测试矩阵和时间。

## 目录与分发边界

| 目录 | 用途 |
|---|---|
| `memory_migration_study/` | 统一授权、记忆构建、隐私保护及研究评测组件 |
| `memory_migration_pilot/` | 早期参考后端与受控探测原型 |
| `scripts/`、`tests/` | 实验入口、独立核验工具与工程测试 |
| `examples/`、`configs/` | 自编样例、冻结研究材料和无密钥配置 |
| `docs/`、`benchmarks/` | 图文说明、研究裁决和公开聚合结果 |
| `results/`、`datasets/`、`.runtime/` | 本机实验输出、原始数据及模型资产，不随仓库分发 |

原始交接包、虚拟环境、数据库及模型凭据也不随仓库分发。文档中的本机证据引用用于研究定位，克隆后不自动具备；上游数据和算法分别遵循原始许可。

本项目可用于受控实验与复核。任意平台互通、任意语义摘要的权限继承、通用业务工具授权和全面语义隐私保护均不属于已完成能力。
