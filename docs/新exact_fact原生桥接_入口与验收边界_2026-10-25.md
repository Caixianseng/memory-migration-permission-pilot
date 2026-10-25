# 新exact-fact原生桥接：入口与验收边界

2026-10-25。新增脚本不修改`memory_migration_study`或正在运行的模型实验入口。本阶段已完成离线fake合同测试；**尚未运行本次真实原生桥接**，不存在新的原生实验通过结论。

## 导入期bind的归因

`results/native_mem0_import_bind_trace_20261025.json`记录唯一被拦的bind为`(::1,0)`，调用栈为隔离目录中urllib3 2.8.0的`util/connection.py:_has_ipv6`。核对[官方2.8.0源码](https://github.com/urllib3/urllib3/blob/2.8.0/src/urllib3/util/connection.py#L115)：模块导入时调用该函数探测IPv6 bind能力，随后关闭socket，失败被捕获；没有listen/connect。这解释了本次副作用，不把它改写成“导入完全无副作用”。原安装收据保留。

新运行器会观察并允许回环port=0的bind。Windows标准库`socket.socketpair`的fallback也会创建短暂内部回环对；例外只按当前标准库函数的**实际code对象**识别，不允许任意回环连接。其余连接仅允许源研究网关的动态端口；端口9、模型服务及外网没有授权。出口guard不是对恶意本地原生扩展的进程沙箱。

## 可执行入口

先审阅源码及fake结果，待主流程冻结阶段结束后，使用全新输出目录：

```powershell
.\.venv-native-webui\Scripts\python.exe -B -X utf8 scripts/run_native_exact_fact_bridge.py --output results/native_exact_fact_bridge_run_01
```

该命令实际加载本地MiniLM用于存储嵌入，启动仅回环的Mem0研究网关，在另一子进程以内置FastAPI TestClient运行原生WebUI；**没有大模型问答、模型下载或付费API**。嵌入是真实模型计算，不写成“全部模型调用为0”。源码/包清单/模型与DLL哈希在运行前写入plan。

- `scripts/native_exact_fact_source.py`：只在源子进程加入`.runtime/native_mem0_sdk_v1/site-packages`。Mem0固定2.2.1，本地HuggingFace MiniLM384、`infer=False`、新本地Qdrant/SQLite。LLM地址为不可用的`127.0.0.1:9`，额外禁止生成方法调用。复用149工程`Principal/BoundIdentity/RecordACL/gateway_server`，动态撤权通过受信ACL引用更新。
- `scripts/native_exact_fact_target.py`：**不加入源SDK overlay**，固定OpenWebUI0.12.3。先调用既有隔离configure，再导入原生app；复用NativeRecorder、独立原生用户登录、whoami、add/search/list及按ID删除。认证响应、JWT与密码不保存。
- `scripts/run_native_exact_fact_bridge.py`：受信host用真实MemoryLabelAuthority核签名、exact内容/range、用户、Agent和epoch；每次迁移/旧job重放先实际读取当前源网关。目标RPC仅收到fact文本，不收到完整source/未迁移canary、grant对象或密钥。原生响应完整留存，host边车保存fact→全部target IDs。

子进程第三方stderr不持久化，防止异常日志泄露凭据；操作失败仅保存固定错误类型、阶段和代码位置。worker输入在内存中通过JSON-line RPC交换，普通协议收据只保存输入/响应摘要；完整source仅在受信host/source子进程及其受控本机数据库。

## 本轮严格检查

1. 同一主fact向两个合法原生用户分别复制；旁路用户读/list/已知ID/search均不能获得它。另有一份仍合法源控制和目标resident。
2. 内容、范围、错误用户、错误Agent、目标不支持的`per_agent_native_acl`均在任何native add之前拒绝，随后检查目标仍为空。用户级原生隔离不冒充原生Agent身份。
3. 原始list/search/error响应中不得出现未迁移source canary；已迁入fact原文必须完整，不只检查HTTP成功。
4. 撤源grant后，**先记录清理前目标仍可见**，再以每个copy的实际owner身份逐ID删除。该阶段不能宣传源撤权自动传到目标。
5. 删除后重新检查全部旧IDs、list/search，核实实际不可见；旧job读当前源被拒、不得重建；resident与仍合法控制保留。

失败保留原始响应、worker收据和逐阶段checkpoint；不因HTTP200、空失败或部分清理而算成功。未声明任意Agent协议、跨组织密钥互通、原子撤权、防崩溃/回滚或已交付明文遗忘。新脚本及标准HMAC/ACL护栏本身不构成论文创新。

离线检查：`python -B -m unittest tests.test_native_exact_fact_bridge -v`。fake材料不计原生实测，也不计独立研究病例。
