import re
import threading
import time

try:
    import pyperclip
    PYPERCLIP_AVAILABLE = True
except ImportError:
    PYPERCLIP_AVAILABLE = False

_URL_RE = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', re.IGNORECASE)


class ClipboardMonitor:
    """Polls the clipboard every 0.5 s and fires on_url_detected for new URLs."""

    def __init__(self, on_url_detected):
        self.on_url_detected = on_url_detected
        self._running = False
        self._thread = None
        self._last_content = ''

    def start_monitoring(self):
        if self._running or not PYPERCLIP_AVAILABLE:
            return
        self._running = True
        try:
            self._last_content = pyperclip.paste()
        except Exception:
            self._last_content = ''
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                content = pyperclip.paste()
                if content != self._last_content:
                    self._last_content = content
                    for url in self._extract_urls(content):
                        self.on_url_detected(url)
            except Exception:
                pass
            time.sleep(0.5)

    @staticmethod
    def _extract_urls(text: str):
        urls = []
        for url in _URL_RE.findall(text):
            url = url.rstrip('.,;:)')
            if not url.startswith('http'):
                url = 'http://' + url
            urls.append(url)
        return urls
