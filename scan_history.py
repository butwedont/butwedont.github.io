import json
import os
from datetime import datetime
from typing import Dict, Optional

class ScanHistory:
    def __init__(self, history_file: str = "scan_history.json"):
        self.history_file = history_file
        self.history = self._load_history()

    def _load_history(self) -> Dict:
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_history(self):
        with open(self.history_file, 'w') as f:
            json.dump(self.history, f, indent=2)

    def mark_as_scanned(self, repo_name: str, findings_count: int, scan_type: str):
        self.history[repo_name] = {
            'last_scan': datetime.now().isoformat(),
            'findings_count': findings_count,
            'scan_type': scan_type
        }
        self._save_history()

    def is_scanned(self, repo_name: str) -> bool:
        return repo_name in self.history

    def get_last_scan_time(self, repo_name: str) -> Optional[str]:
        if repo_name in self.history:
            return self.history[repo_name]['last_scan']
        return None
