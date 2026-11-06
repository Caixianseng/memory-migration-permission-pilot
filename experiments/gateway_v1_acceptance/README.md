# Gateway V1 固定工程验收

状态：代码已编写，尚未执行。主线程在检查并冻结`contract.json`、`runner.py`、独立`verify.py`的字节摘要后，统一执行一次。缺少`freeze_manifest.json`或源码与冻结摘要不符时，runner拒绝开始。

只在**全新输出目录**运行：

```powershell
& 'D:/python3.11/python.exe' -B -X utf8 experiments/gateway_v1_acceptance/runner.py --run --output 'D:/agent安全论文/agent-memory-gateway-v1-work/runs/fixed_v1'
```

本轮规模固定：8个场景×ACL/强事务/Gateway=24行；10个独立合成项目×3方案×6次正常交付=180行。R8每行内含两种篡改probe，不算额外独立场景。无模型调用、无网络服务请求、不重跑旧264+120或768/720。

## 三方案与共同判据

- `acl`：当前版本/epoch/ACL以及packet摘要、lineage和seal的同等预检查；接收库局部事务与seal消费分开，无成熟已提交确认adapter。这是明确的非原子预检查基线，不代表所有ACL实现。
- `transaction`：直接调用原版`agent_memory_gateway.delivery.deliver`。
- `gateway`：调用`GatewayService.commit_transfer`。它与强事务方案使用相同delivery/store安全核心。

共同安全oracle在contract独立定义。记录ACL实际PASS/FAIL，**不要求它一定失败**。强事务与Gateway须满足所有固定判据；两者安全结果相同是合理预期，不自动产生算法优势结论。

## 真正触发的八个调度

1. R1：在receiver首条业务DML执行之前真实退出。
2. R2：已经执行receiver业务DML，但COMMIT trace执行之前退出；记录writer的in_transaction和total_changes。
3. R3：公开commit函数成功返回后、ACK sink写入前真实退出。
4. R4：先实际写入ACK sink，再重复完整同包。
5. R5：同一初步权限检查通过，独立撤权子进程COMMIT完成，然后才进入导入操作。强事务最终核验保持原样。
6. R6：已提交但ACK未知包与旧未交付包，经过version/权限变化后，在两个新进程中按持久manifest恢复。此manifest由Harness管理，不声称产品已有自主队列扫描器。
7. R7：两进程对同transfer_id/完整同包完成预检查后经同一barrier并发；必须区分新commit与已有确认。
8. R8：首次交付前改正文保留摘要，以及正文/内部摘要均重算但没有新可信seal；各自使用独立初始数据库。

所有进程有硬超时；不自动重试、不补造失败结果。初始化数据库、source事实和spool模板在方法间复制，payload和权限条件相同。旧实验数据库从不作为可写输入。

## 输出接口

- `config.json`：冻结contract原始字节。
- `config_lock.json`：contract、runner与freeze-manifest摘要及开始时间。
- `code_version.json`、`code/`：生产核心版本与本轮执行源码副本。
- `raw_regression.jsonl`：24个scenario-method行；`expected`是共同oracle，`checks`、`passed`与基线能力分开。
- `raw_performance.jsonl`：180个正常提交行；每project-method在同一数据目录连续6次。
- `performance_method_summaries.json`：30份project-method初始/最终receiver、sender、policy、spool尺寸及逻辑SQL/业务行数。
- `regression/<R>/<method>/data/agents/B.sqlite`和`policy.sqlite`：原始状态；R8位于data下两个probe目录。
- `performance/<P>/<method>/data/`：各项目、方法的状态。没有在方法间共享可写数据库。
- worker的`failpoint.json`、`process_exit.json`、`result.json`、实际`ack.json`：退出边界与响应证据。
- `completion.json`：实际行数、各项文件/SQLite摘要、执行中核心是否变化。完成不等于所有方案都通过。

## 计时和计数边界

worker包装`sqlite3.connect`的trace callback，因此同时覆盖store连接和receiver.retrieve直接打开的mode=ro绑定核验连接。before/after快照和R5预检查/barrier在计时外，计时前清空计数；生产方法自身的连接初始化、检查、落盘、关闭到元数据返回计入。ACK sink fsync和子进程启动不计入Host提交时延。

SQL数是可见的SQLite**逻辑语句/trace事件**，不是物理I/O、磁盘读写次数或数据库内部成本。`physical_IO_operations`明确为null。尺寸取实际文件字节数，不按页数或调用次数估计。快照中的observer_in_transaction来自只读观测连接；失效注入点另记真实writer状态。commit返回后writer已关闭时状态为unknown，不伪装读取已关闭连接。

本目录不启动商业Agent、HTTP/TestClient或论文流程。独立checker由另一执行者维护；主线程在运行后调用它只读核验，不重演调度。
