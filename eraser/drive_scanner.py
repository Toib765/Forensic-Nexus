import subprocess
import json
import os

class DriveScanner:
    def __init__(self):
        self.system_mounts = ["/", "/boot", "/boot/efi", "/var", "/etc", "/usr", "/root"]

    def is_system_disk(self, mountpoints):
        if not mountpoints: return False
        return any(m in self.system_mounts for m in mountpoints if m)

    def scan_drives(self):
        try:
            res = subprocess.run(["lsblk", "-J", "-o", "NAME,PATH,SIZE,TYPE,MOUNTPOINT"], capture_output=True, text=True, check=True)
            devices = json.loads(res.stdout).get("blockdevices", [])
        except Exception:
            return []  # No fake fallbacks. Genuinely return empty if lsblk fails.

        drives = []
        for dev in devices:
            if dev.get("type") in ["disk", "loop"]:
                drives.append({
                    "name": dev.get("name"),
                    "path": dev.get("path"),
                    "size_gb": dev.get("size"),
                    "type": dev.get("type").upper(),
                    "safe_for_erasure": not self.is_system_disk(dev.get("mountpoint"))
                })
            for part in dev.get("children", []):
                drives.append({
                    "name": part.get("name"),
                    "path": part.get("path"),
                    "size_gb": part.get("size"),
                    "type": "PARTITION",
                    "safe_for_erasure": not self.is_system_disk(part.get("mountpoint"))
                })
        
        return [d for d in drives if d["safe_for_erasure"]]
