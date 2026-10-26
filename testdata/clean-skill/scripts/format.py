import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
path.write_text(json.dumps(json.loads(path.read_text()), indent=2) + "\n")
