#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
export COPYFILE_DISABLE=1
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
find .venv -name '._*' -delete || true
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install -r requirements.txt
mkdir -p data
exec python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
