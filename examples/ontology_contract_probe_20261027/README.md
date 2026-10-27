# CUSTOMER 本体合同开发 probe

日期：2026-10-27。16 个独立合成正文（英文 8、中文 8），分别在两份冻结本体下运行，形成 32 个 cells。本组仅用于合同开发与题意核对，不是新的 64 条正式验收集，不用于估计一般检测 precision/recall；尚无模型运行结果。

## 文件隔离

- `runtime.json` 仅保存 schema_version 与正文字符串数组 texts。实际 detector 只接收 texts[i] 与宿主生成的 trusted policy，不接收数组下标、语言、现象、关系标签、实体词典或参考跨度。
- `evaluation.json` 仅供独立 scorer 使用，按 text_index 和正文 SHA-256 对齐；保存精确跨度、判定和合同哈希。禁止将其元数据、标签或 rationale 拼入 detector prompt、NER labels、hypotheses、缓存答案或待测正文。
- 两份 policy 应共用同一业务范围：正文中的 we/us/our company、我们/本公司指写作者所在公司。只保护 CUSTOMER；其余 instructions 相同，差异仅来自 sensitivity_contract.py 中的固定 category_contract。应通过 bind_category_contract 选择 profile，禁止用正文或 gold 构造定义。

## 冻结定义和三值判定

`strict_customer_relation` 需要可见正文明确肯定该具体组织是本业务范围内的客户、client 或 buyer。当前和肯定的历史/前客户均保护；当前已不是客户，不抹去肯定的历史关系。仅明确 not/never-customer 而无肯定客户证据时不标 CUSTOMER。已出现具体组织、却缺失或含混客户关系时必须 needs_review；其空跨度不算成功阴性，不构成安全放行。

`any_specific_organization` 保护全部具体组织名称，包括非客户和历史客户。角色、定义、组织类别和普通词的普通用法不是组织名；可见文本明确其为某组织真实登记名时，即使名字正好是普通词，也按该位置标记。

这里的 sensitive/not_sensitive 只表示相应 CUSTOMER 合同内的判定；not_sensitive 不表示组织公开或整段内容安全。needs_review 单独核对，不混入 clean-negative 成功数。

## 覆盖与计数

每种语言各有：明确当前客户、买方与明确非客户混合、明确非客户供应商、纠正后的否定客户声明、无具体实体的角色定义、普通词与真实组织名同词异位置、肯定历史关系但当前已终止、具体组织而客户关系未说明。

普通词对照在英文将普通用法置前、真实登记名置后；中文次序相反。参考跨度只标组织名所在位置，不按表面字符串全局替换。中文和英文为独立撰写的合成正文，不是逐条翻译。

30 个 cells 有确定性 sensitive/not_sensitive 参考；另 2 个 strict cells 要求 needs_review。两条无关系正文在 broad profile 下均可确定为 sensitive，因此不能把两份 policy 下的 4 个 cells 都称未知。

所有名称和句子在本任务中新写；作者未读取旧 heldout、fresh64 或旧 gold，也未按旧错例改写正文。独立参考只在 root 冻结上述定义之后创建。当前验证只涵盖文件结构、计数、精确位置和哈希，不构成模型能力证据。
