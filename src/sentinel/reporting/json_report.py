import json
from pathlib import Path
from sentinel.models import ScanResult

def write_json(result: ScanResult, path: Path):
    path.write_text(json.dumps(result.to_dict(),indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
