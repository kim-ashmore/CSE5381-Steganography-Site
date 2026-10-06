"""
app.py
------
Steganography web app: accounts, a public gallery of stego files, and
owner-only extraction of the hidden message.
"""

import functools
import io
import json
import os
import uuid
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash,
    send_file, send_from_directory, abort, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import db
import storage
from stego_utils import embed_bytes, extract_bytes, SteganographyError

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = UPLOAD_DIR / "outputs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "webp"}
MAX_UPLOAD_MB = 25


def _load_secret_key():
    """Env var wins; otherwise persist a random key so sessions survive restarts."""
    env_key = os.environ.get("APP_SECRET_KEY")
    if env_key:
        return env_key
    key_path = BASE_DIR / "instance" / "secret_key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        return key_path.read_bytes()
    key = os.urandom(32)
    key_path.write_bytes(key)
    return key


app = Flask(__name__)
app.secret_key = _load_secret_key()
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

db.init_db()


@app.template_filter("is_image")
def is_image(filename):
    return filename.rsplit(".", 1)[-1].lower() in IMAGE_EXTENSIONS if "." in filename else False


# ---------- Auth helpers ----------

def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.")
            return redirect(url_for("login", next=request.full_path.rstrip("?")
                                    if request.method == "GET" else None))
        return view(*args, **kwargs)
    return wrapped


@app.before_request
def load_logged_in_user():
    user_id = session.get("user_id")
    g.user = None
    if user_id:
        conn = db.get_db()
        g.user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()
        if g.user is None:          # account was deleted elsewhere
            session.clear()


def owns(record):
    return bool(g.user) and record["user_id"] is not None and record["user_id"] == g.user["id"]


def remove_output_file(record):
    names = [record["output_filename"]]
    if record["preview_filename"]:
        names.append(record["preview_filename"])
    for name in names:
        try:
            (OUTPUT_DIR / name).unlink()
        except OSError:
            pass


# ---------- Home / auth pages ----------

@app.route("/")
def index():
    if g.user:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        security_question = request.form.get("security_question", "").strip()
        security_answer = request.form.get("security_answer", "")

        error = None
        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."
        elif password != confirm:
            error = "Passwords do not match."

        if error is None:
            conn = db.get_db()
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if existing:
                error = f"Username '{username}' is already taken."
            else:
                conn.execute(
                    "INSERT INTO users (username, password_hash, security_question, "
                    "security_answer_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                    (
                        username,
                        generate_password_hash(password),
                        security_question or None,
                        generate_password_hash(security_answer) if security_answer else None,
                        db.now(),
                    ),
                )
                conn.commit()
                conn.close()
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))
            conn.close()

        flash(error, "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = db.get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Incorrect username or password.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            nxt = request.args.get("next", "")
            # only follow local paths, never an external URL
            if nxt.startswith("/") and not nxt.startswith("//"):
                return redirect(nxt)
            return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        action = request.form.get("action")
        conn = db.get_db()

        if action == "change_password":
            current = request.form.get("current_password", "")
            new = request.form.get("new_password", "")
            confirm = request.form.get("confirm_new_password", "")
            if not check_password_hash(g.user["password_hash"], current):
                flash("Current password is incorrect.", "error")
            elif new != confirm:
                flash("New passwords do not match.", "error")
            elif not new:
                flash("New password cannot be empty.", "error")
            else:
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(new), g.user["id"]),
                )
                conn.commit()
                flash("Password updated.", "success")

        elif action == "delete_account":
            confirm_username = request.form.get("confirm_username", "")
            if confirm_username != g.user["username"]:
                flash("Type your exact username to confirm account deletion.", "error")
            else:
                conn.close()
                # Remove files from disk before the rows disappear (FK cascade).
                for record in db.get_stego_files_for_user(g.user["id"]):
                    remove_output_file(record)
                conn = db.get_db()
                for row in conn.execute(
                    "SELECT file_path FROM files WHERE user_id = ?", (g.user["id"],)
                ).fetchall():
                    try:
                        os.remove(row["file_path"])
                    except OSError:
                        pass
                conn.execute("DELETE FROM users WHERE id = ?", (g.user["id"],))
                conn.commit()
                conn.close()
                session.clear()
                flash("Account deleted.", "success")
                return redirect(url_for("register"))

        conn.close()

    return render_template("account.html")


@app.route("/dashboard")
@login_required
def dashboard():
    my_posts = db.get_stego_files_for_user(g.user["id"])
    return render_template("dashboard.html", my_posts=my_posts)


# ---------- Stego: create ----------

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "GET":
        return render_template("file_upload.html")

    carrier = request.files.get("carrier")
    message = request.files.get("message")

    if carrier is None or carrier.filename == "":
        flash("Please select a carrier file.", "error")
        return redirect(url_for("upload"))
    if message is None or message.filename == "":
        flash("Please select a message file.", "error")
        return redirect(url_for("upload"))

    mode = request.form.get("mode", "fixed")
    if mode not in ("fixed", "cycle"):
        flash("Unknown mode.", "error")
        return redirect(url_for("upload"))

    try:
        start_bit = int(request.form.get("start_bit", 0))
        period = int(request.form.get("period", 8)) if mode == "fixed" else 0
    except ValueError:
        flash("S and L must be valid integers.", "error")
        return redirect(url_for("upload"))

    cycle_values = None
    cycle_values_json = None

    if mode == "cycle":
        cycle_string = request.form.get("cycle_values", "").strip()
        if not cycle_string:
            flash("Cycle mode requires values such as 8,16,28,8.", "error")
            return redirect(url_for("upload"))
        try:
            cycle_values = [int(v.strip()) for v in cycle_string.split(",") if v.strip()]
            if not cycle_values:
                raise ValueError
        except ValueError:
            flash("Cycle values must be comma-separated positive integers.", "error")
            return redirect(url_for("upload"))
        if any(v <= 0 for v in cycle_values):
            flash("Cycle values must be comma-separated positive integers.", "error")
            return redirect(url_for("upload"))
        cycle_values_json = json.dumps(cycle_values)
        period = cycle_values[0]      # stored for reference; cycle_values drive the pattern

    try:
        stego_bytes = embed_bytes(
            carrier_data=carrier.read(),
            message_data=message.read(),
            start_bit=start_bit,
            period=period,
            mode=mode,
            cycle_values=cycle_values,
        )
    except SteganographyError as exc:
        flash(str(exc), "error")
        return redirect(url_for("upload"))

    safe_carrier = secure_filename(carrier.filename) or "carrier"
    token = uuid.uuid4().hex
    output_filename = f"stego_{token}_{safe_carrier}"
    (OUTPUT_DIR / output_filename).write_bytes(stego_bytes)

    # Compressed formats (PNG/JPEG/...) are usually corrupted by embedding, so
    # the gallery shows an untouched copy of the carrier instead. Only the
    # stego file itself is protected behind login.
    preview_filename = None
    if is_image(safe_carrier):
        preview_filename = f"preview_{token}_{safe_carrier}"
        carrier.seek(0)
        (OUTPUT_DIR / preview_filename).write_bytes(carrier.read())

    record_id = db.add_stego_file(
        user_id=g.user["id"],
        original_filename=carrier.filename,
        message_filename=message.filename,
        output_filename=output_filename,
        start_bit=start_bit,
        period=period,
        mode=mode,
        cycle_values=cycle_values_json,
        preview_filename=preview_filename,
    )

    flash("Message hidden successfully. Your stego file is now in the gallery.", "success")
    return redirect(url_for("photo_detail", record_id=record_id))


# ---------- Stego: public gallery ----------

@app.route("/gallery")
def gallery():
    records = db.get_all_stego_files()
    return render_template("gallery.html", records=records)


@app.route("/photo/<int:record_id>")
def photo_detail(record_id):
    record = db.get_stego_file(record_id)
    if record is None:
        flash("Stego file not found.", "error")
        return redirect(url_for("gallery"))
    if not (OUTPUT_DIR / record["output_filename"]).exists():
        flash("The stego file no longer exists.", "error")
        return redirect(url_for("gallery"))

    return render_template(
        "photo_detail.html",
        record=record,
        title=record["original_filename"],
        is_owner=owns(record),
    )


@app.route("/preview/<filename>")
def preview_image(filename):
    """Public: serve the untouched carrier image shown in the gallery."""
    if not filename.startswith("preview_"):
        abort(404)
    resp = send_from_directory(OUTPUT_DIR, secure_filename(filename))
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/stego-image/<filename>")
@login_required
def stego_image(filename):
    """Login required: serve the stego file inline (fallback preview for older posts)."""
    if not filename.startswith("stego_"):
        abort(404)
    resp = send_from_directory(OUTPUT_DIR, secure_filename(filename))
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/download/<filename>")
@login_required
def download(filename):
    if not filename.startswith("stego_"):
        abort(404)
    return send_from_directory(OUTPUT_DIR, secure_filename(filename), as_attachment=True)


@app.route("/extract/<int:record_id>", methods=["POST"])
@login_required
def extract(record_id):
    record = db.get_stego_file(record_id)
    if record is None:
        flash("Stego file not found.", "error")
        return redirect(url_for("gallery"))
    if not owns(record):
        abort(403)

    stego_path = OUTPUT_DIR / record["output_filename"]
    if not stego_path.exists():
        flash("The stego file no longer exists.", "error")
        return redirect(url_for("gallery"))

    try:
        cycle_values = json.loads(record["cycle_values"]) if record["cycle_values"] else None
        message_bytes = extract_bytes(
            stego_path.read_bytes(),
            record["start_bit"],
            record["period"],
            record["mode"],
            cycle_values,
        )
    except (SteganographyError, ValueError) as exc:
        flash(f"Extraction failed: {exc}", "error")
        return redirect(url_for("photo_detail", record_id=record_id))

    return send_file(
        io.BytesIO(message_bytes),
        as_attachment=True,
        download_name=secure_filename(record["message_filename"]) or "extracted_message",
    )


@app.route("/photo/<int:record_id>/delete", methods=["POST"])
@login_required
def delete_photo(record_id):
    record = db.get_stego_file(record_id)
    if record is None:
        flash("Stego file not found.", "error")
    elif not owns(record):
        abort(403)
    else:
        remove_output_file(record)
        db.delete_stego_file(record_id)
        flash("Stego file deleted.", "success")
    return redirect(url_for("gallery"))


@app.errorhandler(413)
def too_large(error):
    flash(f"The uploaded files are too large. Maximum request size is {MAX_UPLOAD_MB} MB.", "error")
    return redirect(url_for("upload"))


# ---------- Personal file storage ----------

@app.route("/files", methods=["GET", "POST"])
@login_required
def files_list():
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded or uploaded.filename == "":
            flash("Choose a file first.", "error")
        else:
            data = uploaded.read()
            upload_dir = storage.user_upload_dir(g.user["id"])
            fname = storage.unique_name(uploaded.filename)
            path = storage.save_bytes(upload_dir, fname, data)
            conn = db.get_db()
            conn.execute(
                "INSERT INTO files (user_id, label, file_kind, file_path, meta, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (g.user["id"], uploaded.filename, "original", path, None, db.now()),
            )
            conn.commit()
            conn.close()
            flash(f"Uploaded '{uploaded.filename}'.", "success")
        return redirect(url_for("files_list"))

    conn = db.get_db()
    files = conn.execute(
        "SELECT * FROM files WHERE user_id = ? ORDER BY created_at DESC", (g.user["id"],)
    ).fetchall()
    conn.close()
    return render_template("files_list.html", files=files)


@app.route("/files/download/<int:file_id>")
@login_required
def download_file(file_id):
    conn = db.get_db()
    file_row = conn.execute(
        "SELECT * FROM files WHERE id = ? AND user_id = ?", (file_id, g.user["id"])
    ).fetchone()
    conn.close()
    if file_row is None:
        abort(404)
    return send_file(file_row["file_path"], as_attachment=True, download_name=file_row["label"])


@app.route("/files/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    conn = db.get_db()
    file_row = conn.execute(
        "SELECT * FROM files WHERE id = ? AND user_id = ?", (file_id, g.user["id"])
    ).fetchone()
    if file_row:
        try:
            os.remove(file_row["file_path"])
        except OSError:
            pass
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.commit()
    conn.close()
    return redirect(url_for("files_list"))


# ---------- Public-key viewer (for keys stored in the keys table) ----------

@app.route("/tools/keys/view-public/<int:key_id>")
@login_required
def view_public_key(key_id):
    conn = db.get_db()
    key = conn.execute(
        "SELECT * FROM keys WHERE id = ? AND user_id = ? "
        "AND key_kind IN ('rsa_public','dh_public')",
        (key_id, g.user["id"]),
    ).fetchone()
    conn.close()
    if key is None:
        abort(404)
    pem_text = storage.read_bytes(key["file_path"]).decode("utf-8")
    return render_template("view_public_key.html", key=key, pem_text=pem_text)


if __name__ == "__main__":
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "1") == "1",
        host="127.0.0.1",
        port=5000,
    )
