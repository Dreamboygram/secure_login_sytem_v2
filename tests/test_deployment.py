from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_render_start_command_applies_migrations_before_gunicorn():
    content = (ROOT / "render.yaml").read_text(encoding="utf-8")
    start_command = next(
        line.strip()
        for line in content.splitlines()
        if line.strip().startswith("startCommand:")
    )

    assert "flask --app wsgi:app db upgrade" in start_command
    assert "gunicorn" in start_command
    assert start_command.index("db upgrade") < start_command.index("gunicorn")
