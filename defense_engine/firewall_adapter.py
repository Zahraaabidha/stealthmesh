import platform
import subprocess


class FirewallAdapter:
    """
    Thin wrapper around OS firewall commands.
    For demo only – be careful on real systems.
    """

    def __init__(self, rule_prefix: str = "StealthMesh"):
        self.rule_prefix = rule_prefix

    def _is_windows(self) -> bool:
        return platform.system().lower().startswith("win")

    def block_ip(self, ip: str) -> None:
        if not self._is_windows():
            print(f"[Firewall] (demo) Would block IP on non-Windows: {ip}")
            return

        rule_name = f"{self.rule_prefix}_BLOCK_{ip}"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in", "action=block",
            f"remoteip={ip}"
        ]
        try:
            subprocess.run(cmd, check=False)
            print(f"[Firewall] Added block rule for {ip}")
        except Exception as e:
            print(f"[Firewall] Failed to block {ip}: {e}")

    def unblock_ip(self, ip: str) -> None:
        if not self._is_windows():
            print(f"[Firewall] (demo) Would unblock IP on non-Windows: {ip}")
            return

        rule_name = f"{self.rule_prefix}_BLOCK_{ip}"
        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ]
        try:
            subprocess.run(cmd, check=False)
            print(f"[Firewall] Removed block rule for {ip}")
        except Exception as e:
            print(f"[Firewall] Failed to unblock {ip}: {e}")
