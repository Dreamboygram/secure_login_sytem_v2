"""WSGI entry point used by Gunicorn and Flask-Migrate."""

from app import create_app

app = create_app()
application = app

if __name__ == "__main__":
    app.run()
