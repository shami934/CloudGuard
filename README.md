# CloudGuard: Intelligent Cloud Monitoring & Automated Remediation System

A modern, production-grade cloud monitoring and automated remediation platform built with Python, Flask, HTML, CSS, JavaScript, and SQLite.

## Project layout

```
cloud-monitoring/
├── app.py              # Flask app entry point
├── database.py         # SQLite helpers (placeholder)
├── requirements.txt    # Python packages
├── README.md
├── templates/
│   └── base.html       # Shared HTML layout
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── app.js
├── database/           # SQLite files will go here
└── logs/               # App logs will go here
```

## Setup

1. Create a virtual environment:

   ```bash
   python -m venv venv
   ```

2. Activate it:

   - Windows (PowerShell): `.\venv\Scripts\Activate.ps1`
   - macOS / Linux: `source venv/bin/activate`

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the app:

   ```bash
   python app.py
   ```

5. Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.
