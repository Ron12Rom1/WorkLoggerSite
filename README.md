# Work Logger

Log work hours, position, hourly pay, tips, and notes. View analytics by month and by position. Built with Flask + SQLite.

## Quickstart (Windows PowerShell)

```bash
py -3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000/` in your browser.

## Features
- Add, edit, delete shifts (date, position, hours, hourly rate, tips, notes)
- Totals and effective hourly rate on the list page
- Analytics page with monthly and position charts

## Data
- SQLite file: `shifts.db` in the project folder
- To reset: stop the app and delete `shifts.db`
- For production, change `SECRET_KEY` in `app.py`


