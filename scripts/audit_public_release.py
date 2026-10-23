"""Inspect staged Git blobs before publishing, without printing matching secrets."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def audit(root):
    def git(*args):
        return subprocess.check_output(["git", "-c", f"safe.directory={root.as_posix()}", *args], cwd=root)
    names = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").decode("utf-8").split("\0")
    rows = []
    for name in filter(None, names):
        data = git("show", ":" + name)
        problems = []
        if name.split("/")[0] in {"results", "datasets", ".runtime", ".git", ".venv-native-webui", "memory_migration_permission_149tests_20261021"}:
            problems.append("private_or_generated_directory")
        if Path(name).suffix.lower() in {".zip", ".exe", ".dll", ".sqlite", ".sqlite3", ".db", ".key", ".pem", ".ipynb"} or Path(name).name.startswith(".env"):
            problems.append("non_release_asset")
        if len(data) > 2 * 1024 * 1024:
            problems.append("oversized_file")
        if re.search(rb"(?i)\b(?:sk-[A-Za-z0-9]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b", data):
            problems.append("credential_format_detected")
        if re.search(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=]{32,}", data):
            problems.append("private_key_detected")
        if re.search(rb"(?i)(?:wxid_[A-Za-z0-9_]+|xwechat_files[/\\])", data):
            problems.append("personal_attachment_path")
        try:
            data.decode("utf-8-sig")
        except UnicodeDecodeError:
            problems.append("non_utf8_asset")
        rows.append({"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "problems": problems})
    return {"status": "passed" if rows and not any(r["problems"] for r in rows) else "blocked",
            "staged_files": len(rows), "files": rows,
            "scope": "Staged blob formats, known credential patterns and private asset exclusions; not a comprehensive secret-detection proof."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.root.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": result["status"], "files": result["staged_files"],
                      "problems": [{"path": r["path"], "problems": r["problems"]} for r in result["files"] if r["problems"]]}, ensure_ascii=False))
    raise SystemExit(0 if result["status"] == "passed" else 1)
