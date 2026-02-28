import re
import os
import pickle
import urllib.parse
from typing import List, Tuple

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models', 'model.pkl')

SUSPICIOUS_TLDS = {
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.link',
    '.work', '.party', '.review', '.date', '.kim', '.country', '.stream',
    '.download', '.racing', '.win', '.bid', '.loan', '.trade',
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'short.io', 'tr.im', 'cli.gs', 'dlvr.it', 'su.pr',
}

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 'bank',
    'paypal', 'netflix', 'amazon', 'apple', 'microsoft', 'google', 'ebay',
    'confirm', 'password', 'credential', 'billing', 'suspend', 'limited',
]


class FeatureExtractor:
    """Extracts 35 numerical features from a URL for ML classification."""

    _ip_pattern = re.compile(
        r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    )

    def extract_all(self, url: str) -> List[float]:
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path
            query = parsed.query

            # Strip port from domain for subdomain analysis
            domain_clean = domain.split(':')[0] if ':' in domain else domain
            parts = domain_clean.split('.')
            num_subdomains = max(0, len(parts) - 2)
            tld = ('.' + parts[-1]) if parts else ''

            features = [
                # --- Length features ---
                len(url),                                               # 1
                len(domain_clean),                                      # 2
                len(path),                                              # 3
                len(query),                                             # 4

                # --- Character count features ---
                url.count('.'),                                         # 5
                url.count('-'),                                         # 6
                url.count('_'),                                         # 7
                url.count('/'),                                         # 8
                url.count('?'),                                         # 9
                url.count('='),                                         # 10
                url.count('@'),                                         # 11
                url.count('&'),                                         # 12
                url.count('%'),                                         # 13
                url.count('#'),                                         # 14
                sum(c.isdigit() for c in url),                         # 15
                sum(not c.isalnum() and c not in ':/?=&.#-_~%@+'
                    for c in url),                                      # 16

                # --- Binary / presence features ---
                1 if url.lower().startswith('https') else 0,           # 17 has_https
                1 if self._ip_pattern.search(domain_clean) else 0,    # 18 has_ip
                1 if ':' in domain else 0,                             # 19 has_port
                1 if domain_clean.startswith('www.') else 0,          # 20 has_www
                1 if tld in SUSPICIOUS_TLDS else 0,                    # 21 suspicious_tld
                1 if '@' in url else 0,                                # 22 at_in_url
                1 if '//' in path else 0,                              # 23 double_slash
                1 if '-' in domain_clean else 0,                       # 24 hyphen_domain
                1 if any(s in domain_clean for s in URL_SHORTENERS)
                  else 0,                                               # 25 url_shortener

                # --- Count features ---
                num_subdomains,                                         # 26
                len(path.split('/')),                                   # 27 path_depth
                len(tld),                                               # 28 tld_length

                # --- Ratio features ---
                sum(c.isdigit() for c in url) / max(len(url), 1),     # 29
                sum(c.isdigit() for c in domain_clean)
                    / max(len(domain_clean), 1),                        # 30

                # --- Keyword / semantic features ---
                # Only flag if keyword appears in URL but NOT as the registrable domain
                # (prevents legitimate brand sites like google.com from self-triggering)
                1 if any(
                    kw in url.lower()
                    and (len(parts) < 2 or kw != parts[-2].lower())
                    for kw in SUSPICIOUS_KEYWORDS
                ) else 0,                                               # 31 suspicious_kw
                1 if len(url) > 75 else 0,                             # 32 is_long_url
                1 if num_subdomains > 2 else 0,                        # 33 many_subdomains
                url.lower().count('login') + url.lower().count('signin'),  # 34
                url.lower().count('secure') + url.lower().count('verify'), # 35
            ]
            return features
        except Exception:
            return [0.0] * 35


class URLClassifier:
    """Loads (or trains) a Random Forest model and classifies URLs."""

    def __init__(self):
        self.model = None
        self.extractor = FeatureExtractor()
        self._load_or_train()

    def _load_or_train(self):
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, 'rb') as f:
                self.model = pickle.load(f)
        else:
            self._train_and_save()

    def _train_and_save(self):
        import sys
        project_root = os.path.dirname(os.path.dirname(__file__))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from models.train_model import train_model
        self.model = train_model()
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(self.model, f)

    def predict(self, url: str) -> Tuple[str, float]:
        """Return (status, confidence).  status ∈ {'safe','suspicious','phishing'}."""
        f = self.extractor.extract_all(url)

        # Hard rules that always override the ML model
        override = self._rule_override(f)
        if override:
            return override

        if self.model is None:
            return self._heuristic_predict(f)

        proba = self.model.predict_proba([f])[0]
        pred = self.model.predict([f])[0]
        confidence = float(max(proba))

        if pred == 1:
            return ('phishing' if confidence >= 0.80 else 'suspicious', confidence)
        return 'safe', confidence

    @staticmethod
    def _rule_override(f: List[float]):
        """Return a forced verdict when strong heuristic signals are present."""
        has_https      = bool(f[16])
        has_ip         = bool(f[17])
        susp_tld       = bool(f[20])
        url_shortener  = bool(f[24])
        susp_kw        = bool(f[30])
        login_count    = f[33]
        sec_words      = f[34]

        # Raw IP address → always suspicious at minimum
        if has_ip:
            return ('phishing', 0.91)

        # Suspicious TLD + keyword  (e.g. paypal-verify.xyz/login)
        if susp_tld and susp_kw:
            return ('phishing', 0.93)

        # Suspicious TLD + no HTTPS
        if susp_tld and not has_https:
            return ('phishing', 0.88)

        # Suspicious TLD alone → at least suspicious
        if susp_tld:
            return ('suspicious', 0.75)

        # URL shortener
        if url_shortener:
            return ('suspicious', 0.72)

        # Brand keyword + no HTTPS + login/verify words
        if susp_kw and not has_https and (login_count >= 1 or sec_words >= 1):
            return ('phishing', 0.85)

        return None  # let ML decide

    def _heuristic_predict(self, f: List[float]) -> Tuple[str, float]:
        score = 0
        if not f[16]: score += 2   # no https
        if f[30]:     score += 1   # suspicious keyword
        if f[31]:     score += 1   # long url
        if f[25] > 2: score += 2   # many subdomains
        if score >= 5:
            return 'phishing', 0.85
        elif score >= 3:
            return 'suspicious', 0.65
        return 'safe', 0.85
