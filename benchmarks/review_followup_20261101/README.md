# 评分回收与十次真实 Harness 对照

本包包含两份明确披露AI辅助的返回标签，以及五个PersonaMem开发案例的10次真实目标调用。两份标签均不符合独立盲评声明；它们的统计只用于诊断，不是人工金标。

在任意目录用Python 3.12运行本文件夹内的 `python -I -B -S reproduce.py`，无需API密钥、第三方包或模型。程序重算固定BM25选源、实际载荷与回答绑定、保存的token用量、保守费用估算、固定AI标签和辅助标签差异。哈希验证仅证明包内一致性，不是供应商签名，也不证明语义真值。

原文臂10道合法题：9项完整支持、1项称谓限定待审。BM25臂：7项完整支持、3项UNKNOWN，其中2项缺实际证据、1项有充分证据仍未答；两臂各5个缺证控制全部UNKNOWN。分类来自非盲AI初审，五故事的30条回答不是30个独立样本。

本批是原文/检索的目标端基线，不补算Qoder生成失败；用户随后要求发送端改用WorkBuddy HY3，相关运行状态见client_status.json。自动化后台入口与桌面聊天操作分别记录，不能因退出码0或创建文件就认定模型成功。

## 文件

- assisted_review_summary.json、paired_assisted_labels.json：匿名辅助标签与差异。
- experiment.json：公开资料投影、确切输入、原始回答、保存回执计数和AI语义分类。
- client_status.json：实际客户端执行状态。
- DATA_ATTRIBUTION.md：来源、固定版本及许可。
- manifest.json：当前制品摘要；reproduce.py是标准库离线入口。

没有包含评分者姓名、署名原包、账户余额、API密钥或本机绝对路径配置。费用0.047572元是按该批固定4元/百万输入、8元/百万输出的保守估算，实际账单未知。完整SDK正文未保存，传输大小依赖保存的guard观察。

## WorkBuddy HY3→Harness 单例

workbuddy_handoff.json 保存两份用户从WorkBuddy可见聊天转交输出后的自动核权与一次真实Harness调用。发送/接收身份分别为workbuddy和deepseek-harness；旧混合包被拒，新三源产物可交付。目标回答Penang、赠送条件、UNKNOWN，708 token。来源自动生成轨迹没有原生捕获，不代表全自动WorkBuddy新任务已接通，也不是产品原生在线撤权。主对照仍为上述五故事10次；两批不合并分母。
