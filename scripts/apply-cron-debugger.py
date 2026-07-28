from pathlib import Path
import base64
import gzip
import hashlib

EXPECTED = "542f3ca6fcf6bfbcbe2bd6fc602e496785dc16b1ba433a106c02dcdbce368b88"


def replace_once(source: str, old: str, new: str, label: str) -> str:
    if new in source:
        return source
    if source.count(old) != 1:
        raise SystemExit(f"{label} insertion point changed: found {source.count(old)}")
    return source.replace(old, new, 1)

parts = sorted(Path(".agent/cron-debug").glob("part-*"))
if len(parts) != 4:
    raise SystemExit(f"expected four cron debugger payload segments, found {len(parts)}")
encoded = "".join(part.read_text().strip() for part in parts)
source_bytes = gzip.decompress(base64.b64decode(encoded, validate=True))
actual = hashlib.sha256(source_bytes).hexdigest()
if actual != EXPECTED:
    raise SystemExit(f"cron debugger digest mismatch: {actual}")
Path("src/cron_debug.rs").write_bytes(source_bytes)

main = Path("src/main.rs")
source = main.read_text()
source = replace_once(
    source,
    "mod cluster_insight;\n",
    "mod cluster_insight;\nmod cron_debug;\n",
    "cron module",
)
source = replace_once(
    source,
    "    let app = Router::new()\n",
    "    let app = cron_debug::cron_admin_routes(Router::new())\n",
    "cron router",
)
main.write_text(source)

views = Path("src/views.rs")
source = views.read_text()
source = replace_once(
    source,
    '                        a href="/cluster" { "Cluster" }\n                        a href="/notices" { "Notices" }',
    '                        a href="/cluster" { "Cluster" }\n                        a href="/crons" { "Crons" }\n                        a href="/notices" { "Notices" }',
    "cron navigation",
)
source = replace_once(
    source,
    '                p { a href="/infra" { "Cluster & infra ops →" } }\n                p { a href="/audit" { "Operator audit →" } }',
    '                p { a href="/infra" { "Cluster & infra ops →" } }\n                p { a href="/crons" { "Cron debugger →" } }\n                p { a href="/audit" { "Operator audit →" } }',
    "dashboard cron link",
)
views.write_text(source)
