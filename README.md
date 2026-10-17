# RoadWatch

Citizens report vehicles that endanger others (smoke, rash driving, road rage) with photo/video proof and
automatic location. Police review reports on a dashboard. Stack: Flask + MongoDB + HTML/CSS/JS.

## Run it
1. Install Python 3.10+ and MongoDB Community Server (and MongoDB Compass, optional).
2. In this folder:
   ```
   python -m venv .venv
   .venv\Scripts\activate          (Windows)   |   source .venv/bin/activate   (Mac/Linux)
   pip install -r requirements.txt
   copy .env.example .env          (Windows)   |   cp .env.example .env        (Mac/Linux)
   python create_police.py         (creates the first police login)
   python app.py
   ```
3. Open http://127.0.0.1:5000

With `SMTP_USER` empty in `.env`, OTP codes are printed in the terminal (dev mode).
To send real emails, set SMTP_* (for Gmail use an App Password).

## Structure
- `app.py`          all routes, OTP, uploads, police actions
- `ai_hooks.py`     `analyze_report()` - plug your AI model here later
- `create_police.py` create police accounts
- `templates/`, `static/`  HTML, CSS, JS
- `uploads/`        private media (served only to the uploader and police)

## MongoDB collections (database `roadwatch`)
users, reports (GeoJSON `location`, 2dsphere index), posts, otps (auto-expire via TTL index)
