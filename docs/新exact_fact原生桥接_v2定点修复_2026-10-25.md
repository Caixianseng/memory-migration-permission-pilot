# 原生exact-fact桥接v2：关闭导入期模型发现

2026-10-25。v1为一次真实运行失败（L0）：17项内容/权限检查通过，但目标进程在导入期尝试连接本地Ollama的11434/12434端口，四次连接均被guard阻断。`results/native_exact_fact_bridge_20261025_v1`保持原样，不将内容检查通过写成协议执行成功。

本机固定OpenWebUI0.12.3的`config.py` SHA256为`03cad3c2f13921d34354bea8f882aabb4e788262a45c097314ea83983501f284`。本机243–305行与[官方v0.12.3源码](https://github.com/open-webui/open-webui/blob/v0.12.3/backend/open_webui/config.py#L294)一致：`ENABLE_OLLAMA_API=false`没有包住导入期`_resolve_ollama_base_url`；未显式提供URL时仍探测两端口。没有使用主线最新版本替代本机证据。

v2仅改新native脚本：原legacy configure之后、任何`open_webui`导入及lifespan之前，显式关闭Ollama/OpenAI API，并将`OLLAMA_BASE_URL`、`OLLAMA_BASE_URLS`及旧API URL设为端口9的明确不可用地址；这样跳过自动发现。guard仍拒绝9、11434、12434、11435及外网，未加入端口白名单。新拒绝事件附代码位置调用栈。导入后核对原生配置常量及本机配置源码hash；本地MiniLM、原生记忆与身份接口保持。

v2运行前归档整个当前`memory_migration_study/*.py`、四个native脚本与两个legacy接口文件，冻结清单及哈希；执行后同时检查源清单、源码/归档、模型/DLL/配置等资产。仍逐文件核验SDK安装清单，不复制第三方依赖或模型。v1仅有八份源码归档，不回填成v2范围。

离线fake检查包括配置发生在legacy清空环境之后、导入之前；迟配拒绝；禁止端口仍被拦；原记忆和本地嵌入配置保留。真实v2尚待root审阅及统一包冻结后执行，使用新目录：

```powershell
.\.venv-native-webui\Scripts\python.exe -B -X utf8 scripts/run_native_exact_fact_bridge.py --output results/native_exact_fact_bridge_20261025_v2
```

验收仍包含完整17项及零未授权网络、零生成请求。源撤权到目标清理前的可见性继续单列；显式删除全部副本的结果不能冒充自动跨系统撤权。
