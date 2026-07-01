"""End-to-end smoke test: run one hunt through the full orchestrator and print it.

Exercises routing → branches → correlate → synthesize with whatever provider and
ES mode the environment selects. Good for validating a live ES cluster and/or an
Ollama model in one shot.

Usage (from repo root):
    python scripts/smoke_hunt.py
    python scripts/smoke_hunt.py "Is 198.51.100.10 malicious?"
"""

from __future__ import annotations

import sys

from dotenv import load_dotenv

load_dotenv()

from orchestrator.config import settings  # noqa: E402
from orchestrator.supervisor import run_hunt  # noqa: E402

# A "both"-route payload: an nmap host + an ATT&CK kill chain + a known-bad IP.
DEFAULT_QUESTION = """<?xml version="1.0"?><nmaprun><host>
<status state="up"/><address addr="10.0.0.50" addrtype="ipv4"/>
<hostnames><hostname name="web01"/></hostnames>
<ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port></ports>
<os><osmatch name="Windows 7" accuracy="92"/></os></host></nmaprun>
Kill chain: T1566.001 -> T1059.001 -> T1071.001 -> T1041. 198.51.100.10 is the C2."""


def main() -> int:
    question = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_QUESTION
    print(f"provider={settings.provider} model={settings.default_model} es_mode={settings.es_mode}\n")
    print("Running hunt...\n")
    report = run_hunt(question, thread_id="smoke")
    print("=" * 70)
    print(report)
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
