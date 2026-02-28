"""
Trains a Random Forest classifier on synthetic URL feature data.
Run directly:  python models/train_model.py
Or imported by core/classifier.py when model.pkl is missing.
"""
import os
import random
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')


# ---------------------------------------------------------------------------
# Feature vector helpers  (must mirror FeatureExtractor.extract_all order)
# ---------------------------------------------------------------------------

def _legit():
    """Legitimate, well-formed URLs (HTTPS, clean TLD, no phishing keywords).
    Covers the full realistic range: short pages, long article/video IDs, etc."""
    url_len = random.randint(20, 90)       # real URLs can reach 80+ with IDs
    dom_len = random.randint(5, 22)
    # Some legit URLs have numeric IDs (e.g. /questions/123456)
    num_digits = random.randint(0, 12)
    ratio_d = num_digits / max(url_len, 1)
    return [
        url_len,                        # 1  url_length
        dom_len,                        # 2  domain_length
        random.randint(0, 40),          # 3  path_length
        random.randint(0, 25),          # 4  query_length
        random.randint(1, 4),           # 5  num_dots
        random.randint(0, 1),           # 6  num_hyphens
        0,                              # 7  num_underscores
        random.randint(1, 5),           # 8  num_slashes
        random.randint(0, 1),           # 9  num_question_marks
        random.randint(0, 2),           # 10 num_equals
        0,                              # 11 num_at_signs
        random.randint(0, 2),           # 12 num_ampersands
        0,                              # 13 num_percent
        0,                              # 14 num_hash
        num_digits,                     # 15 num_digits
        random.randint(0, 2),           # 16 num_special_chars
        1,                              # 17 has_https  (legit sites use HTTPS)
        0,                              # 18 has_ip
        0,                              # 19 has_port
        random.randint(0, 1),           # 20 has_www
        0,                              # 21 suspicious_tld
        0,                              # 22 at_in_url
        0,                              # 23 double_slash
        0,                              # 24 hyphen_domain
        0,                              # 25 url_shortener
        random.randint(0, 1),           # 26 num_subdomains
        random.randint(1, 5),           # 27 path_depth
        3,                              # 28 tld_length (.com / .org / .net)
        ratio_d,                        # 29 ratio_digits_url (reflects real IDs)
        random.uniform(0.0, 0.06),      # 30 ratio_digits_domain
        0,                              # 31 suspicious_kw
        0,                              # 32 is_long_url
        0,                              # 33 many_subdomains
        0,                              # 34 login_count
        0,                              # 35 security_words_count
    ]


def _phishing_long():
    """Long, heavily obfuscated phishing URL."""
    url_len = random.randint(80, 180)
    dom_len = random.randint(20, 50)
    return [
        url_len,
        dom_len,
        random.randint(10, 60),
        random.randint(5, 40),
        random.randint(4, 10),
        random.randint(2, 6),
        random.randint(0, 3),
        random.randint(3, 8),
        random.randint(0, 2),
        random.randint(0, 5),
        random.randint(0, 1),
        random.randint(0, 4),
        random.randint(0, 4),
        random.randint(0, 1),
        random.randint(5, 20),
        random.randint(3, 12),
        random.randint(0, 1),           # phishing may or may not use https
        random.randint(0, 1),
        random.randint(0, 1),
        0,
        random.randint(0, 1),
        random.randint(0, 1),
        random.randint(0, 1),
        random.randint(0, 1),
        random.randint(0, 1),
        random.randint(1, 5),
        random.randint(2, 8),
        random.randint(2, 6),
        random.uniform(0.08, 0.35),
        random.uniform(0.08, 0.35),
        1,                              # suspicious keyword present
        1,                              # is_long_url
        random.randint(0, 1),
        random.randint(1, 3),
        random.randint(0, 2),
    ]


def _phishing_suspicious_tld():
    """Short/medium phishing URL with a suspicious TLD (.xyz, .tk, .ml …)."""
    url_len = random.randint(25, 80)
    dom_len = random.randint(10, 35)
    return [
        url_len,
        dom_len,
        random.randint(0, 25),
        random.randint(0, 15),
        random.randint(2, 6),
        random.randint(1, 4),
        random.randint(0, 2),
        random.randint(1, 5),
        random.randint(0, 1),
        random.randint(0, 2),
        0,
        random.randint(0, 2),
        random.randint(0, 2),
        0,
        random.randint(1, 10),
        random.randint(1, 6),
        random.randint(0, 1),           # may have https
        0,
        0,
        0,
        1,                              # suspicious TLD  ← key signal
        0,
        0,
        random.randint(0, 1),
        0,
        random.randint(0, 2),
        random.randint(1, 4),
        random.randint(2, 5),           # tld_length for .xyz / .top etc.
        random.uniform(0.03, 0.25),
        random.uniform(0.03, 0.25),
        random.randint(0, 1),           # may or may not have keyword
        0,                              # NOT necessarily long
        0,
        random.randint(0, 1),
        random.randint(0, 1),
    ]


def _phishing_keyword_no_https():
    """Phishing URL with brand keywords but no HTTPS."""
    url_len = random.randint(30, 90)
    dom_len = random.randint(12, 40)
    return [
        url_len,
        dom_len,
        random.randint(5, 30),
        random.randint(0, 20),
        random.randint(2, 7),
        random.randint(1, 4),
        random.randint(0, 2),
        random.randint(1, 5),
        random.randint(0, 2),
        random.randint(0, 3),
        0,
        random.randint(0, 2),
        random.randint(0, 2),
        0,
        random.randint(2, 15),
        random.randint(1, 8),
        0,                              # NO https  ← key signal
        0,
        0,
        0,
        random.randint(0, 1),
        0,
        0,
        random.randint(0, 1),
        random.randint(0, 1),
        random.randint(0, 2),
        random.randint(1, 5),
        random.randint(2, 5),
        random.uniform(0.03, 0.20),
        random.uniform(0.03, 0.20),
        1,                              # suspicious keyword ← key signal
        random.randint(0, 1),
        0,
        random.randint(1, 2),
        random.randint(1, 2),
    ]


def _phishing_ip():
    """Phishing URL using a raw IP address."""
    url_len = random.randint(20, 70)
    return [
        url_len,
        random.randint(7, 15),          # IP addr length
        random.randint(0, 25),
        random.randint(0, 15),
        random.randint(3, 7),
        random.randint(0, 2),
        0,
        random.randint(1, 4),
        random.randint(0, 1),
        random.randint(0, 2),
        0,
        random.randint(0, 2),
        0,
        0,
        random.randint(5, 15),
        random.randint(1, 4),
        random.randint(0, 1),
        1,                              # has_ip  ← key signal
        random.randint(0, 1),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        random.randint(1, 3),
        1,
        random.uniform(0.15, 0.45),
        random.uniform(0.15, 0.45),
        random.randint(0, 1),
        0,
        0,
        random.randint(0, 1),
        random.randint(0, 1),
    ]


def _phishing_shortener():
    """URL shortener used to hide a phishing destination."""
    url_len = random.randint(18, 35)
    return [
        url_len,
        random.randint(5, 12),
        random.randint(4, 10),
        0,
        random.randint(1, 3),
        0,
        0,
        random.randint(1, 3),
        0,
        0,
        0,
        0,
        0,
        0,
        random.randint(3, 10),
        0,
        random.randint(0, 1),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,                              # url_shortener  ← key signal
        0,
        2,
        3,
        random.uniform(0.05, 0.30),
        0.0,
        0,
        0,
        0,
        0,
        0,
    ]


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

_PHISHING_GENERATORS = [
    _phishing_long,
    _phishing_suspicious_tld,
    _phishing_keyword_no_https,
    _phishing_ip,
    _phishing_shortener,
]


def generate_synthetic_data(n=15_000):
    X, y = [], []
    for _ in range(n):
        if random.random() < 0.5:
            X.append(_legit())
            y.append(0)
        else:
            gen = random.choice(_PHISHING_GENERATORS)
            X.append(gen())
            y.append(1)
    return np.array(X, dtype=float), np.array(y)


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train_model():
    print("Training Random Forest classifier on synthetic data...")
    X, y = generate_synthetic_data(15_000)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    clf = RandomForestClassifier(
        n_estimators=200, max_depth=None,
        min_samples_leaf=2, random_state=42, n_jobs=-1
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print(f"  Accuracy : {accuracy_score(y_test, y_pred):.4f}")
    print(f"  Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"  Recall   : {recall_score(y_test, y_pred):.4f}")
    return clf


if __name__ == '__main__':
    import pickle
    model = train_model()
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    print(f"Model saved → {MODEL_PATH}")
