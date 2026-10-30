# Qoder原生静态记忆写入的有限适配器

本目录是独立新入口，不修改已冻结的无工具问答适配器。目标仅为让真实Qoder用原生Write把明确给出的四条合成事实写到新项目AGENTS，再从实际文件进入后续迁移。不是Auto-Memory、自由记忆抽取或原生ACL迁移。

## 接口

```python
from experiments.qoder_source_generation_20261030.writer import (
    prepare_run, metadata_init, execute_generation, verify_generation,
)

plan = prepare_run("results/qoder_source_generation_20261030/new_run", facts)
# facts必须是四条单行合成事实；此步只冻结输入、配置、hash并初始化新Git。
metadata = metadata_init("results/qoder_source_generation_20261030/new_run")
# 只发initialize控制请求，不发用户prompt；失败保留失败，不自动改配置重试。
# 后面的真实执行必须由主任务明确触发，适配器默认不运行模型。
receipt = execute_generation("results/qoder_source_generation_20261030/new_run", execute=True)
```

prepare不会写AGENTS。模型唯一输出文件是`run/workspace/AGENTS.md`，内容必须严格等于`"\n".join(facts)+"\n"`。input.json是明确合成的冻结输入，不是私人日志。事件日志只保存白名单元数据、调用id、内容hash和成功/失败标记，不保存完整CLI输出、thinking、环境、凭证或私人材料。

原生argv固定模型选择器DeepSeek-Flash、project设置来源、仅Write、dont_ask、空MCP、关闭技能/Agent/用户与项目自动记忆、2轮、每轮最多128输出token、请求重试0。256是两轮配置上限，额外检查原生汇总usage；不声称供应商原子金额上限或统计了所有HTTP。默认登录由原生客户端沿用，适配器不复制认证文件；这不表示客户端本身不访问认证元数据。

当前实现版本为`qoder-native-static-source-v3`。首个真实任务在v1遇到`duplicate_native_init`，没有观察到Write/源文件，也没有Harness调用；失败原件与对应源字节保留在旧run，不修改成成功。v2是协议生命周期修复；v3仅补齐四项标准Windows路径环境变量及明确usage报告口径，不增加新研究故事或放宽权限、内容、字节及评分规格。

## v3的有限环境修复及尚未复现的根因

`joint_run02`已观察到唯一Write、成功工具结果、guard claim和143字节AGENTS的hash一致，但工作区额外出现字面`%SystemDrive%/ProgramData/Microsoft/Windows/Caches/`下四个db。因此整个源端验收仍失败，目标Harness调用为0；不能把“文件已经写出”改称全流程合格。v2四份源码在修复前复制到旧run的frozen_source，全部与旧plan哈希相符；旧计划、响应与文件保持原状。

本轮切换为零模型环境诊断，保留完整对照：

| 新探针目录 | 对照操作 | 观测 |
|---|---|---|
| `results/qoder_source_generation_20261030/environment_probes_20261030/run01` | Node版本、Python空操作、Qoder帮助；各比较旧白名单和补齐四标准变量 | 六个探针均未在新工作区创建文件 |
| 同上`run02` | 原生initialize-only元数据，两环境各一新项目 | 都qualified、0用户提示、新工作区额外文件0 |
| 同上`run03` | 依据本机exec Hook实际参数镜像Node spawn→Python guard命令链 | 两环境都输出正常`{}`并exit0，新工作区额外文件0；没有调用模型或原生Write |
| 同上`run03` | 同一Windows `ExpandEnvironmentStringsW`调用，不实际创建展开路径 | 旧环境保留`%SystemDrive%`，得到相对路径；补齐后展开为`C:\ProgramData\...`绝对路径 |

官方[ExpandEnvironmentStringsW说明](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-expandenvironmentstringsw)指出找不到变量时原占位保持不展开。本机API对照支持缺变量会导致字面相对路径这一机制；**没有在零模型启动或Hook链中复现原生Write阶段的四个缓存文件，尚未确定是Qoder哪个具体组件创建它们。** Hook链镜像依据本机字符24352xxx的exec分支：`args`存在时直接`child_process.spawn(command,args,{cwd,env,stdio:pipe,shell:false,detached:false,windowsHide:true})`，不额外增加shell或Hook选项。未读取缓存db内容或用户其他项目材料。

v3只在新writer的显式环境白名单增加`SYSTEMDRIVE`、`PROGRAMDATA`、`ALLUSERSPROFILE`、`COMSPEC`四个已存在的非敏感Windows标准变量；继续排除API密钥、任意私人环境项及全量环境继承。原有无工具`qoder_native.py`是封存包装器，本轮不改其环境白名单或哈希。额外文件门禁保留，不允许这些db成为合格输出。此修复是环境完整性修正，是否解决实际Write运行仍需主任务决定的新登记，本文不预告成功。

原生aggregate曾在非空Write内容时报告`output_tokens=0`。v3 receipt明确记录`reported_output_tokens`，同时`actual_output_tokens=null`、`actual_output_tokens_verified=false`；0不证明实际调用免费或实际tokens为0。2轮×128是配置上限，仍拒绝非法或缺失usage字段，但不将该0当作独立供应商计量。API钱包观察与Qoder credits必须分开报告。

## 1.1.77双初始化的源码依据

入口SHA-256仍为`9a8fb19bb7f2dfe8d9d9933cb356fd21e789544316bacadc4f6c9b760bd41315`。以下是UTF-8解码字符串的字符偏移：

- 32062586附近：控制initialize路径执行`sdk.init_message`，调用`VA()`，后者通过`tLt()`发送system/init。
- 30459369附近：首次用户提交在session hooks启动后调用`emitInitMessage()`。
- 30473815附近：`emitInitMessage()`产生`kind:"sessionSnapshot"`。
- 32142078附近：会话快照经`uFs()`再次编码为system/init。

因此v2允许恰一次首次用户提示之后、任何工具之前的重新init；两次都完整核验工具、工作区、权限模式、模型、版本和空扩展。第二次不重发提示。若原生session_id改变，事件明确登记，且仅在没有Write claim、没有AGENTS时重绑guard。第三次或工具后的init拒绝；失败事件也保留安全白名单证据。verify_generation重放同样的生命周期并使用最后一次合法session核对guard，不把v1 plan套用为v2。

## 原生Hook stdin字段的源码依据

六项严格字段有本机实现依据，不只是手工夹具约定：

- 23485961附近：工具拦截入口调用`firePreToolUseEvent(t.name, args, t.callId, ...)`，把真实工具名、输入与调用id传入Hook系统。
- 25613357附近：`firePreToolUseEvent`用`createBaseInput("PreToolUse")`，再增加`tool_use_id`、`tool_name`、`tool_input`。
- 25626115附近：`createCoreBaseInput`从当前config填入`session_id`、`cwd`和`hook_event_name`；同时包含transcript_path等元数据，但本适配器不读取该路径内容或保存这些无关字段。
- 24355797附近：原生Hook执行器向子进程stdin写入`JSON.stringify(input)`并关闭stdin。

这是该版本的静态实现核验；是否真正触发Hook仍以新运行的guard审计与claim为准，字段存在不等于已经执行成功。

## 门禁与验收

路径许可为本轮项目`.qoder/settings.json`的`Edit(/AGENTS.md)`，不能用全局Write允许，也不能禁止所有Read，因为Write有内部同路径读取检查。模型工具集合独立限定为Write。

PreToolUse通过exec形式运行本目录guard.py。合格事件输出`{}`并exit0，无allow/ask覆盖，继续原生许可判决；非法事件输出明确deny并exit2。检查会话、工作区、唯一目标、无链接、目标不存在、严格四行hash，原子消费一份Write能力。门禁审计未落盘即拒绝；Hook自身未运行、异常或被原生忽略时，最终验收也不得返回ok。

运行器先读取并验证真实system/init的工具集合、permissionMode、cwd、版本、模型和空扩展，再发送唯一合成prompt。初始化元数据不符时无提示投递。只有唯一原生tool_use、成功tool_result、门禁记录、能力claim、最终usage和实际新文件hash全对应，execute_generation才返回status=ok；模型说“已保存”或主机代写文件均不合格。

可信主机、无外部并发换链是边界；Hooks不是OS沙箱。CLI事件是客户端回执，不是独立远程执行证明。过程事件/usage缺失时保留failed，而不是自行补真值。generation_attempt.json以独占创建，失败后不得复用同一run重新调用。

官方依据：[Hooks输出与exec协议](https://docs.qoder.com/cli/hooks)、[工具与路径权限](https://docs.qoder.com/cli/permissions)。安装代码对应版本和字符位置见[工具边界核查](../../docs/Qoder来源写入隔离与工具边界核查_2026-10-30.md)。初始协议和安全行为由夹具测试核对；测试成功不是新原生模型实验成功。

## 无模型测试

```powershell
python -B -m unittest discover -s tests -p test_qoder_source_generation.py -v
```

测试中的文件与原生事件是临时目录内的手工模拟，明确不能作为真实生成或迁移成绩。实际层级A和后续Harness效果由新的主实验另行记录。
