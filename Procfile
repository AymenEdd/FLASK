release: python init_db.py
web: gunicorn app:app --bind 0.0.0.0:$PORT --log-level debug --access-logfile - --error-logfile -