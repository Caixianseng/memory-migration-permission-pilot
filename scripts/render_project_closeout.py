"""Render the authored project closeout locally, without network or JavaScript.

Requires the already installed Python-Markdown package. The static SVG is a
documented architectural illustration, not an experiment or a result chart.
"""
from __future__ import annotations

import argparse
import hashlib
import html
from html.parser import HTMLParser
import os
from pathlib import Path
import re
from urllib.parse import quote, unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "docs" / "项目阶段收尾与任务汇报_2026-10-25.md"
DEFAULT_OUTPUT = ROOT / "results" / "project_closeout_20261025" / "index.html"
FLOW = ROOT / "docs" / "assets" / "project_closeout_flow_20261025.svg"


def relative_url(path: Path, directory: Path) -> str:
    """Return a file link relative to the HTML, including spaces/CJK safely."""
    try:
        return quote(Path(os.path.relpath(path.resolve(), directory.resolve())).as_posix(), safe="/:")
    except ValueError:  # Different Windows drives cannot have a relative path.
        return path.resolve().as_uri()


class RelocateLinks(HTMLParser):
    """Keep document-relative local evidence links valid in a generated report."""

    def __init__(self, source_parent: Path, output_parent: Path):
        super().__init__(convert_charrefs=False)
        self.source_parent, self.output_parent = source_parent, output_parent
        self.parts: list[str] = []

    def _url(self, value: str) -> str:
        if not value or value.startswith("#"):
            return value
        parsed = urlsplit(value)
        # Existing absolute URLs, mail links and file URIs remain untouched.
        if parsed.scheme or parsed.netloc:
            return value
        if not parsed.path:
            return value
        file_path = self.source_parent / unquote(parsed.path)
        new = relative_url(file_path, self.output_parent)
        if parsed.query:
            new += "?" + parsed.query
        if parsed.fragment:
            new += "#" + parsed.fragment
        return new

    def _tag(self, tag, attrs, ending):
        rewritten = []
        for key, value in attrs:
            if value is None:
                rewritten.append(key)
            else:
                if key in {"href", "src"}:
                    value = self._url(value)
                rewritten.append(f'{key}="{html.escape(value, quote=True)}"')
        self.parts.append("<" + tag + (" " + " ".join(rewritten) if rewritten else "") + ending)

    def handle_starttag(self, tag, attrs):
        self._tag(tag, attrs, ">")

    def handle_startendtag(self, tag, attrs):
        self._tag(tag, attrs, " />")

    def handle_endtag(self, tag):
        self.parts.append(f"</{tag}>")

    def handle_data(self, data):
        self.parts.append(data)

    def handle_entityref(self, name):
        self.parts.append(f"&{name};")

    def handle_charref(self, name):
        self.parts.append(f"&#{name};")

    def handle_comment(self, data):
        self.parts.append("<!--" + data + "-->")


CSS = """
:root{color-scheme:light;--ink:#17263b;--muted:#56667b;--line:#dce4ee;--accent:#155c89}
*{box-sizing:border-box}body{margin:0;background:#edf2f7;color:var(--ink);font:16px/1.8 'Segoe UI','Microsoft YaHei',sans-serif}
.shell{max-width:1320px;margin:32px auto;background:#fff;box-shadow:0 8px 32px #132d4612;border:1px solid var(--line);border-radius:18px;overflow:hidden}
.banner{padding:26px 48px 20px;background:#173c56;color:#fff}.eyebrow{font-size:13px;letter-spacing:.12em;color:#bde1f3}.banner p{margin:5px 0;color:#d7e7f0}
main{padding:18px 48px 48px}h1{font-size:30px;line-height:1.45;margin:20px 0}h2{font-size:24px;margin:42px 0 14px;padding-top:14px;border-top:2px solid var(--line);scroll-margin-top:20px}h3{font-size:19px;margin:26px 0 10px}p{margin:12px 0}a{color:var(--accent);text-decoration-thickness:1px;text-underline-offset:3px;overflow-wrap:anywhere}
strong{color:#173c56}blockquote{margin:18px 0;padding:10px 20px;background:#f2f7fb;border-left:4px solid #4b8bac}blockquote p{margin:5px 0}
table{border-collapse:collapse;width:100%;display:block;overflow:auto;font-size:14px;margin:18px 0}th,td{border:1px solid var(--line);padding:10px 13px;vertical-align:top}th{background:#eaf2f8;text-align:left}tr:nth-child(even){background:#fafcfe}code{font-family:Consolas,'Microsoft YaHei',monospace;font-size:.9em;background:#eef3f7;padding:2px 4px;border-radius:3px;overflow-wrap:anywhere}pre{background:#f2f5f9;padding:18px;overflow:auto;border:1px solid var(--line);border-radius:8px;line-height:1.55}pre code{padding:0;background:none;font-size:13px;white-space:pre-wrap;word-break:break-word}
ul,ol{padding-left:1.65em}li{margin:5px 0}figure{margin:18px 0 24px;padding:18px;background:#f8fbfd;border:1px solid var(--line);border-radius:12px}figure img{width:100%;height:auto;display:block}figcaption{font-size:13px;color:var(--muted);margin-top:10px}details{margin:16px 0;border:1px solid var(--line);border-radius:8px;padding:12px 16px}summary{cursor:pointer;color:var(--accent);font-weight:600}.toc-box{background:#f8fafc;padding:18px 24px;border:1px solid var(--line);border-radius:10px;margin:18px 0}.toc-box h2{font-size:17px;border:0;padding:0;margin:0 0 8px}.toc-box ul{margin:4px 0}.toc-box .toc{font-size:14px}.provenance{padding:18px 48px;background:#f5f8fb;font-size:12px;color:var(--muted);border-top:1px solid var(--line);overflow-wrap:anywhere}
@media(max-width:760px){.shell{margin:0;border:0;border-radius:0}.banner,main,.provenance{padding-left:20px;padding-right:20px}h1{font-size:25px}h2{font-size:21px}figure{padding:4px}}
@media print{@page{size:A4;margin:16mm}body{background:#fff;font-size:10pt}.shell{margin:0;max-width:none;border:0;box-shadow:none}.banner{background:#fff;color:#173c56;padding:0 0 8px}.banner p,.eyebrow{color:#56667b}main{padding:0}.toc-box{display:none}h2{font-size:16pt;break-after:avoid}h3{font-size:12pt;break-after:avoid}table{display:table;font-size:8pt}tr,figure{break-inside:avoid}a{color:#173c56}pre{font-size:8pt}.provenance{padding:10px 0}details{break-inside:avoid}}
"""


def render(source: Path, output: Path) -> dict:
    try:
        import markdown
    except ImportError as error:
        raise RuntimeError("缺少现有依赖 Python-Markdown；未自动安装或访问网络。") from error
    source, output = source.resolve(), output.resolve()
    if source == output:
        raise ValueError("输出文件不能覆盖 Markdown 源文件。")
    if not FLOW.is_file():
        raise FileNotFoundError(f"缺少本地流程图：{FLOW}")
    raw = source.read_bytes()
    text = raw.decode("utf-8-sig")
    heading = re.search(r"^#\s+(.+)$", text, re.M)
    title = heading.group(1).strip() if heading else "项目阶段收尾与任务汇报"
    mermaid_count = 0

    def diagram_source(match):
        nonlocal mermaid_count
        mermaid_count += 1
        return ('\n<details class="diagram-source"><summary>查看可编辑 Mermaid 流程源 '
                + str(mermaid_count) + '</summary><pre><code>'
                + html.escape(match.group(1)) + '</code></pre></details>\n')

    text = re.sub(r"^```mermaid\s*\n(.*?)^```\s*$", diagram_source, text, flags=re.M | re.S)
    converter = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists"], output_format="html5")
    body = converter.convert(text)
    relocate = RelocateLinks(source.parent, output.parent)
    relocate.feed(body)
    relocate.close()
    svg_url = relative_url(FLOW, output.parent)
    source_url = relative_url(source, output.parent)
    digest = hashlib.sha256(raw).hexdigest()
    # The authored report may already place the same figure next to its prose.
    # Avoid adding a duplicate cover figure in that case.
    flow_figure = "" if FLOW.name in body else f'''<figure><img src="{html.escape(svg_url, quote=True)}" alt="Agent安全记忆权限迁移研究模块流程：构建并标注记忆，核权迁移，检索与同步假名化，模型回答后再次核权恢复；撤权及重放单独检查。">
<figcaption>模块衔接总览。模型任务链与原生后端实验分开验收；图示不表示已完成通用生产系统。</figcaption></figure>'''
    page = f'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' file: data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{html.escape(title)}</title><style>{CSS}</style></head><body><div class="shell">
<header class="banner"><div class="eyebrow">AGENT MEMORY · PROJECT CLOSEOUT</div><p>项目结构 · 实际成果 · 完整流程 · 待完成事项</p></header>
<main>{flow_figure}
<nav class="toc-box" aria-label="汇报目录"><h2>阅读目录</h2>{converter.toc}</nav>
{''.join(relocate.parts)}</main>
<footer class="provenance">本页由本地 Markdown 生成，不加载远程脚本、字体或模型。<br>
源文档：<a href="{html.escape(source_url, quote=True)}">{html.escape(source.name)}</a><br>源文档 SHA-256：{digest}</footer>
</div></body></html>'''
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(page, encoding="utf-8")
    return {"output": str(output), "source_sha256": digest, "mermaid_sources_preserved": mermaid_count,
            "remote_assets": 0, "javascript": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    import json
    try:
        result = render(args.input, args.output)
    except (OSError, UnicodeError, ValueError, RuntimeError) as error:
        parser.exit(1, f"无法生成本地收尾报告：{error}\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
