# Fixed public source material for grouping v1

Source: [bowen-upenn/PersonaMem-v2](https://huggingface.co/datasets/bowen-upenn/PersonaMem-v2/tree/ed956dea41521fc4499acbc63f966e0fd3c053ba), revision `ed956dea41521fc4499acbc63f966e0fd3c053ba`, CC BY 4.0. Attribution and license also appear in the unmodified upstream `upstream/README.md`. The data are public synthetic persona conversations, not private user histories. No upstream author endorsement is implied.

Selection was fixed before observing grouping results: numeric persona IDs 0–5, same `250911_213118` chat-history release, first eight complete adjacent user/assistant exchanges per persona. IDs found in prior public experiments (173, 366, 479, 605, 931, 944, 962, 990, 995) were excluded. No selection used D1 outcomes. Persons 0 and 1 are development; persons 2–5 are reserved checks. Related material from a persona must remain in its assigned partition. These four reserved cases support an exploratory check, not a large independent validation set.

`cases.jsonl` contains six independent **persona clusters**, each with eight chronological **exchange sources**, a total of 48 sources and 96 selected messages. An exchange is not an independent natural conversation. The original system persona prompt is not included. Full user/assistant text, including quoted drafts and assistant suggestions, retains role markers; assistant assertions are not silently converted into user facts. Source references record message indices, JSON pointers, content hashes, rendered character offsets and the raw-file hash.

`upstream_manifest.json` records the fixed repository revision, selection rule, public download host, and tree entries. Files were retrieved through `hf-mirror.com` because the original host timed out on this machine. Every raw history and README is byte-for-byte checked against the fixed tree's Git blob SHA1; SHA256 and lengths appear in `data_validation.json`. The mirror is a transport source, not the dataset owner. No credentials or upstream benchmark question/answer files are acquired.

`evaluation_only/questions.json` is a separate, AI-drafted set of 18 study-specific questions (three per persona). Every first question requires at least two source facts; every third question has only S01 support and is expected to become `UNKNOWN` when S01 export permission is absent. Permission changes are controlled study events supplied by the host, not permissions native to PersonaMem. `support_sets` lists alternative complete supports where two source exchanges repeat a fact. A question is legal-answerable if at least one complete support set remains permitted; if it has none, the required response is `UNKNOWN`, not reconstruction from withdrawn material.

All reference answers are AI-drafted exploratory references and `human_gold` remains null. `required_phrases` are diagnostic lexical hints only; spelling, paraphrase, numerals and multilingual equivalents require semantic review. They must not be reported as independent human accuracy or treated as a general safety gold standard. Any question about a draft or assistant reply refers to that text, not an independently verified real-world fact. Withdrawing a generic public fact does not make an identical fact produced from prior model knowledge proof of a secret-data leak; the hard security check is the actual delivery dependency closure.

Source generation and planning consume `cases.jsonl` sources, never the evaluation-only questions, references or support sets. Target queries can consume question text, but reference answers and support annotations remain evaluation-only. Keep the full upstream histories out of source/target prompts; only the registered eight exchanges are part of a story.

Recheck without network or model calls from the repository root:

```powershell
python -B -X utf8 experiments/revocation_grouping_v1/prepare_data.py --offline
```

The script refuses to overwrite different frozen material. Future amendments require a separately versioned dataset and a recorded reason, retaining this version and any existing results.
