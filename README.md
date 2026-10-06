# Kim's Security App - Steganography Gallery

Flask app that hides a message file inside a file using bit-level
LSB-style steganography (start bit S, period L, mode C = fixed or cycle).

## Run

```
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 , register an account, log in, and use **Create**.

Optional environment variables: `APP_SECRET_KEY` (session key; otherwise one is
generated and saved in `instance/secret_key`) and `FLASK_DEBUG=0` to turn off debug mode.

## Files

- `app.py` routes, `db.py` SQLite, `stego_utils.py` embed/extract, `storage.py` per-user files
- `templates/`, `static/css/style.css`
- Runtime data is created on first run in `instance/` and `uploads/`.
