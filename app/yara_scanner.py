from pathlib import Path
import hashlib
import json
import yara

PROJECT_DIR = Path.home() / "ai-soc-triage"
RULE_FILE = PROJECT_DIR / "rules" / "lab_test.yar"
SAMPLE_FILE = PROJECT_DIR / "sample"/ "benign_test.txt"

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb" ) as file:
         for block in iter(lambda: file.read(8192), b""):
             sha256.update(block)
    return sha256.hexdigest()

rules = yara.compile(filepath=str(RULE_FILE))
matches = rules.match(str(SAMPLE_FILE))
file_hash = calculate_sha256(SAMPLE_FILE)

result =  {
    "file_name": SAMPLE_FILE.name,
    "file_path": str(SAMPLE_FILE),
    "sha256": file_hash,
    "yara_scanned": True,
    "match_count": len(matches),
    "matches": [
         {
              "rule": match.rule,
              "namespace": match.namespace,
              "tags": list(match.tags),
              "metadata": dict(match.meta)
         }
          for match in matches
       ]
}

print(json.dumps(result, indent=2))
