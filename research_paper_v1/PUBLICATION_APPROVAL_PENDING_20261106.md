# 待批准的原始研究资料公开范围

当前分支不包含新增逐条模型提示词、原始输出、记忆/权限交付行和不透明压缩研究数据，避免通过重复字段或另一份文件间接公开被拒材料。本地原始实验和完整公开候选包保持不变。

自动审批明确拒绝过以下文件；已停止公开，不通过换编码、分片或其他通道绕过：

- `research_paper_v1/stage2_evidence_gap/evidence/dataset.json.gz`
- `research_paper_v1/stage2_evidence_gap/evidence/raw_smoke_v3.jsonl.gz`
- `benchmarks/live_research_public_20261106/main_jobs/LIVE-P07.jobs.jsonl`
- `benchmarks/live_research_public_20261106/supplemental_cases/exact_original.jsonl`

两份压缩档案被认为内容不透明；已另行完成六档全量检查，覆盖1,527,459个字段及1,056,674个字符串，三份数据集与种子生成器逐字节一致。该核验不等于公开审批已解除。

两份模型记录被认为包含完整提示词、输出、实验标识、受控敏感标记及运行/供应商元数据，现有一般性上传指令不足以授权具体公开。候选包中的敏感审计码是受控合成数据；原生会话/账号目录及凭据未包含在候选包中。

需要研究者明确确认：是否批准公开整套已脱敏原始实验包，包括完整模型提示词/输出、实验用模拟受限码、脱敏运行元数据，以及已核验合成档案。没有该决定前只发布当前可独立审查的材料。
