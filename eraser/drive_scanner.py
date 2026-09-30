import json
import subprocess
from typing import ClassVar


class DriveScanner:
    SYSTEM_MOUNTS: ClassVar[set[str]] = {
        "/",
        "/boot",
        "/boot/efi",
        "/etc",
        "/usr",
        "/var",
        "/root",
    }

    @staticmethod
    def _root_device():
        try:
            result = subprocess.run(
                ["findmnt", "-no", "SOURCE", "/"],
                capture_output=True,
                text=True,
                check=True,
            )
            source = result.stdout.strip()
            return source if source.startswith("/dev/") else None
        except (OSError, subprocess.SubprocessError):
            return None

    def _is_system_device(self, device, root_device):
        mountpoint = device.get("mountpoint")
        mounts = mountpoint if isinstance(mountpoint, list) else [mountpoint]

        if any(m in self.SYSTEM_MOUNTS for m in mounts if m):
            return True

        path = device.get("path") or ""

        if root_device and (path == root_device or root_device.startswith(path)):
            return True

        return False

    def _record(self, device, device_type, root_device):
        path = device.get("path")
        mountpoint = device.get("mountpoint")
        mounted = bool(mountpoint)
        read_only = bool(device.get("ro"))
        system_device = self._is_system_device(device, root_device)

        if system_device:
            reason = "contains active system filesystem"
        elif mounted:
            reason = "currently mounted"
        elif read_only:
            reason = "read-only device"
        else:
            reason = None

        return {
            "name": device.get("name"),
            "path": path,
            "size": device.get("size"),
            "type": device_type,
            "model": device.get("model"),
            "serial": device.get("serial"),
            "mountpoint": mountpoint,
            "mounted": mounted,
            "read_only": read_only,
            "safe_for_erasure": not (system_device or mounted or read_only),
            "unsafe_reason": reason,
        }

    def scan_drives(self):
        try:
            result = subprocess.run(
                [
                    "lsblk",
                    "-J",
                    "-o",
                    "NAME,PATH,SIZE,TYPE,MOUNTPOINT,RO,MODEL,SERIAL",
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            devices = json.loads(result.stdout).get(
                "blockdevices",
                [],
            )

        except (
            OSError,
            subprocess.SubprocessError,
            json.JSONDecodeError,
        ):
            return []

        root_device = self._root_device()
        drives = []

        for device in devices:
            if device.get("type") in {"disk", "loop"}:
                drives.append(
                    self._record(
                        device,
                        device.get("type", "").upper(),
                        root_device,
                    )
                )

            for partition in device.get("children") or []:
                drives.append(
                    self._record(
                        partition,
                        "PARTITION",
                        root_device,
                    )
                )

        return drives
