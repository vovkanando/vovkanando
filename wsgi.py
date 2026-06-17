"""
WSGI entry point. Use this for production hosting (Render, Railway, gunicorn, etc).
Run with: gunicorn wsgi:app
"""
from server import app, init_db

init_db()

if __name__ == "__main__":
    app.run()
