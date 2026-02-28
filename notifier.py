"""
NotificationManager – sends desktop alerts.
On macOS uses osascript (built-in, no dependencies).
On other platforms falls back to plyer, then silently does nothing.
"""
import subprocess
import sys


def _mac_notify(title: str, message: str):
    """Use AppleScript to show a macOS notification (always available)."""
    # Escape quotes to avoid AppleScript injection
    t = title.replace('"', '\\"')
    m = message.replace('"', '\\"')
    try:
        subprocess.Popen(
            ['osascript', '-e',
             f'display notification "{m}" with title "{t}"'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def _plyer_notify(title: str, message: str):
    try:
        from plyer import notification
        notification.notify(title=title, message=message,
                            app_name="SafeClick", timeout=5)
    except Exception:
        pass


def _do_notify(title: str, message: str):
    if sys.platform == 'darwin':
        _mac_notify(title, message)
    else:
        _plyer_notify(title, message)


class NotificationManager:
    def show_alert(self, url: str, confidence: float):
        _do_notify(
            "⚠ PHISHING URL DETECTED",
            f"Dangerous URL blocked!\n{url[:70]}\nConfidence: {confidence:.0%}"
        )

    def show_suspicious(self, url: str, confidence: float):
        _do_notify(
            "⚠ Suspicious URL",
            f"Proceed with caution!\n{url[:70]}\nConfidence: {confidence:.0%}"
        )

    def show_safe(self, url: str, confidence: float):
        _do_notify(
            "✓ Safe URL",
            f"URL appears safe.\n{url[:70]}\nConfidence: {confidence:.0%}"
        )
