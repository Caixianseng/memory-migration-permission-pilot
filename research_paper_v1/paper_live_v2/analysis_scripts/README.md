# 离线重分析

> 发布范围（2026-11-06）：本分支公开报告、代码、聚合统计和科研图表。新增商业模型的逐条输入/输出、来源记忆及运行记录尚未纳入发布，等待具体公开授权。报告中的完成数量指本地实际实验，不表示原始材料已全部公开。


在本目录执行 `D:/python3.11/python.exe run_analysis.py`，只重算已保存数据，不调用商业模型，不重新执行协议故障，不改变原始回答或gold。

源代码实际维护于仓库的 `experiments/paper_live_v2/`。本目录中的同名副本用于查看版本，`run_analysis.py`是可执行入口；不要直接运行含包相对导入的版本副本。

重新运行会更新派生统计报告。原始source/receiver contracts、模型输出、native envelope、SDK receipt、原始失败和冻结项目不会被此入口修改。原始数据中的manifest自引用哈希错误显式保留并报告；其他gold/input哈希单独核验。

原文对照另执行仓库入口 `D:/python3.11/python.exe experiments/paper_live_v2/exact_original_quality.py`；同族控制的离线收尾入口为 `experiments/paper_live_v2/same_family_control/finalize_control.py`。具体参数见对应执行说明。
