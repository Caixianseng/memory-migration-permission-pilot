# WorkBuddy → Harness 的本地主机交接重放

`broker.py`使用已有通用`NativeAgentBroker`，登记真实的WorkBuddy/Harness角色名称；不借用旧Qoder身份。主机根据调用者提供的完整输入来源，按保守AND规则更新派生物许可：撤S01交接许可后，四源混合物M停止交付，三源重建物R仍可交付。读取权不随交接权撤销。

```powershell
python -B -S -m unittest experiments.workbuddy_harness_20261101.test_broker -v
```

四项离线测试覆盖身份、旧包阻断与读权保持、R正文保持和错误来源清单。它不调用模型。

`build_handoff`在收到两个已有输出后执行主机顺序重放，无法证明生成时的在线撤权；调用者负责提供生成输入的可核验轨迹。此次WorkBuddy输出由用户从可见聊天转交，不能标为自动导出或产品原生ACL。此后接收端的确切AGENTS加载和一次真实模型调用另有记录。

当前安装的WorkBuddy随附CLI可启动，但独立进程缺少GUI管理的加密凭据bootstrap；自动生成入口尚未取得成功响应。没有解密或复制令牌、禁用订阅门控、伪造成功或改用其他模型冒充HY3。公开复算材料见[评分回收与后续实验](../../benchmarks/review_followup_20261101/README.md)。
