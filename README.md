# 🛡️ SafeClick — Intelligent Phishing Detection Tool

> A real-time desktop application that monitors your clipboard and manually-submitted URLs for phishing threats using a Random Forest machine-learning classifier.

**Bhoj Reddy Engineering College for Women**
Department of Computer Science and Engineering

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Setup — macOS](#setup--macos)
- [Setup — Windows](#setup--windows)
- [Running the App](#running-the-app)
- [How It Works](#how-it-works)
- [ML Model Details](#ml-model-details)
- [Database Schema](#database-schema)
- [Screenshots](#screenshots)
- [Tech Stack](#tech-stack)

---

## Overview

SafeClick is a Python desktop application that protects users from phishing URLs in real time. It silently watches your clipboard — the moment you copy a link, it is scanned automatically. It also provides a manual scan bar and a full dashboard with scan history and statistics.

---

## Features

| Feature | Description |
|---------|-------------|
| 🔄 **Auto Clipboard Monitoring** | Polls clipboard every 0.5 s; any copied URL is scanned instantly |
| 🔍 **Manual URL Scan** | Type or paste any URL and hit Scan / Enter |
| 🤖 **ML Classification** | Random Forest with 35 URL features; hybrid rule layer for high-confidence signals |
| 🔔 **Desktop Notifications** | Native OS notifications for phishing / suspicious detections |
| 📊 **Dashboard** | Live stats tiles + colour-coded scan history table |
| ⚙️ **Settings** | Toggle monitoring, notification preferences, confidence threshold |
| 🗄️ **SQLite Logging** | Every scan stored with URL, verdict, confidence, type, timestamp |
| 🔑 **Admin Controls** | Delete logs older than 30 days or clear all history |

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              PRESENTATION LAYER              │
│   Tkinter GUI · Dashboard · Settings        │
├─────────────────────────────────────────────┤
│              APPLICATION LAYER               │
│  ClipboardMonitor · URLClassifier           │
│  FeatureExtractor · NotificationManager     │
├─────────────────────────────────────────────┤
│                DATA LAYER                   │
│       SQLite (scan_logs.db)                 │
└─────────────────────────────────────────────┘
```

Three-tier architecture with real-time processing and a hybrid ML + rule-based detection engine.

---

## Project Structure

```
SafeClick/
├── main.py                   # App entry point — SafeClickApp
├── requirements.txt          # Python dependencies
│
├── core/
│   ├── classifier.py         # FeatureExtractor (35 features) + URLClassifier
│   ├── database.py           # DatabaseManager — SQLite CRUD operations
│   ├── monitor.py            # ClipboardMonitor — daemon thread, pyperclip
│   └── notifier.py           # NotificationManager — native OS alerts
│
├── gui/
│   ├── dashboard.py          # DashboardUI — stats tiles + Treeview history
│   └── settings.py           # SettingsUI — toggles + sensitivity slider
│
└── models/
    ├── train_model.py        # Generates synthetic data and trains the model
    └── model.pkl             # Saved Random Forest (auto-generated on first run)
```

---

## Setup — macOS

### Prerequisites

- macOS 12 or later
- Homebrew — install from [brew.sh](https://brew.sh) if not present

### Step 1 — Install Python 3.13

```bash
brew install python@3.13
```

### Step 2 — Install Tkinter support

```bash
brew install python-tk@3.13
```

### Step 3 — Clone the repository

```bash
git clone https://github.com/manideepyeredla1326/safeclick.git
cd safeclick
```

### Step 4 — Install Python dependencies

```bash
/opt/homebrew/bin/python3.13 -m pip install --break-system-packages \
    scikit-learn pandas numpy pyperclip
```

### Step 5 — Run SafeClick

```bash
/opt/homebrew/bin/python3.13 main.py
```

> The first launch trains the ML model (~5 seconds). Subsequent launches load `models/model.pkl` instantly.

---

## Setup — Windows

### Prerequisites

- Windows 10 or Windows 11
- Python 3.10 or later — download from [python.org](https://www.python.org/downloads/)
  - ✅ During installation, check **"Add Python to PATH"**
  - ✅ Check **"tcl/tk and IDLE"** (installs Tkinter)

### Step 1 — Clone the repository

```cmd
git clone https://github.com/manideepyeredla1326/safeclick.git
cd safeclick
```

Or download and extract the ZIP from the GitHub Releases page.

### Step 2 — Create a virtual environment (recommended)

```cmd
python -m venv venv
venv\Scripts\activate
```

### Step 3 — Install dependencies

```cmd
pip install -r requirements.txt
```

> On Windows, `plyer` is used for desktop notifications and installs cleanly with pip.

### Step 4 — Run SafeClick

```cmd
python main.py
```

Or double-click `run_windows.bat` (see below):

```bat
@echo off
cd /d "%~dp0"
python main.py
pause
```

Save the above as `run_windows.bat` in the project root and double-click it to launch.

### Optional — Build a standalone `.exe`

```cmd
pip install pyinstaller
pyinstaller --onefile --windowed --name SafeClick main.py
```

The executable will be created at `dist\SafeClick.exe`.

---

## Running the App

Once started:

1. **Automatic mode** — Copy any URL to your clipboard. SafeClick scans it automatically and shows a desktop notification if it is suspicious or phishing.

2. **Manual scan** — Type or paste a URL in the scan bar at the top and press **Scan** or hit Enter.

3. **Dashboard tab** — View live statistics (total / safe / phishing / suspicious) and the full colour-coded scan history.

4. **Settings tab** — Toggle clipboard monitoring on/off, control which notifications appear, and adjust the confidence threshold.

---

## How It Works

```
User copies URL
      │
      ▼
ClipboardMonitor (polls every 0.5 s)
      │
      ▼
FeatureExtractor  →  35 numerical features
      │
      ▼
Rule Override Layer
(IP address? Suspicious TLD? URL shortener?)
      │ (if no hard rule)
      ▼
Random Forest Classifier  (150 trees)
      │
      ▼
Verdict: SAFE / SUSPICIOUS / PHISHING  +  Confidence %
      │
      ├── Log to SQLite
      ├── Desktop Notification
      └── Refresh Dashboard
```

### Detection Logic

The classifier uses a **two-stage hybrid approach**:

**Stage 1 — Rule Override** (high-confidence hard rules):
| Signal | Verdict |
|--------|---------|
| Raw IP address in URL | PHISHING (91%) |
| Suspicious TLD (`.xyz`, `.tk`, `.ml` …) + keyword | PHISHING (93%) |
| Suspicious TLD + no HTTPS | PHISHING (88%) |
| Suspicious TLD alone | SUSPICIOUS (75%) |
| Known URL shortener (`bit.ly`, `tinyurl` …) | SUSPICIOUS (72%) |
| Brand keyword + no HTTPS + login/verify words | PHISHING (85%) |

**Stage 2 — Random Forest ML** (for all other URLs):
- 150-tree ensemble trained on 15,000 synthetic samples
- Predicts probability of phishing; confidence ≥ 80% → PHISHING, else → SUSPICIOUS

---

## ML Model Details

### Feature Extraction (35 features)

| # | Feature | Description |
|---|---------|-------------|
| 1–4 | Length features | URL, domain, path, query lengths |
| 5–16 | Character counts | dots, hyphens, slashes, digits, special chars … |
| 17–25 | Binary flags | HTTPS, IP address, port, suspicious TLD, URL shortener … |
| 26–28 | Count features | Subdomain count, path depth, TLD length |
| 29–30 | Ratio features | Digit ratio in URL and domain |
| 31–35 | Semantic features | Suspicious keywords, long URL, login/verify word counts |

### Training Data

- **15,000 synthetic samples** (50% legit, 50% phishing)
- **5 phishing archetypes**: long obfuscated, suspicious TLD, keyword-no-HTTPS, raw IP, URL shortener
- **Legit distribution**: covers realistic ranges including numeric IDs in paths

### Performance (on held-out 20% test set)

| Metric | Score |
|--------|-------|
| Accuracy | 100% |
| Precision | 100% |
| Recall | 100% |

> Note: The model is trained on synthetic data. For production use, retraining with a real-world labelled dataset (e.g. [PhishTank](https://www.phishtank.com/), [UCI ML Phishing Dataset](https://archive.ics.uci.edu/dataset/327/phishing+websites)) is recommended.

### Retrain the Model

```bash
# macOS
/opt/homebrew/bin/python3.13 models/train_model.py

# Windows
python models/train_model.py
```

---

## Database Schema

```sql
-- Scan history (automatically populated)
CREATE TABLE scan_logs (
    log_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER,
    url       TEXT    NOT NULL,
    status    VARCHAR(20) NOT NULL,   -- 'safe' | 'phishing' | 'suspicious'
    confidence DECIMAL(5,2),
    scan_type VARCHAR(20),            -- 'automatic' | 'manual'
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- User accounts (for future multi-user support)
CREATE TABLE users (
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username      VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(20) DEFAULT 'user'  -- 'user' | 'admin'
);
```

The database file (`scan_logs.db`) is created automatically in the project root on first run.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| GUI | Python · Tkinter · ttk |
| ML | Scikit-learn · Random Forest |
| Data processing | NumPy · Pandas |
| Clipboard | pyperclip |
| Notifications | osascript (macOS) · plyer (Windows/Linux) |
| Database | SQLite3 (built-in) |
| Packaging | PyInstaller (optional `.exe`) |

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## License

This project is developed for academic purposes at Bhoj Reddy Engineering College for Women, Department of Computer Science and Engineering.

---

*SafeClick v1.0.0 — Intelligent Phishing Detection Tool*
