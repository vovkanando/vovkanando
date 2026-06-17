import sqlite3, hashlib, secrets, os, base64, json, re
from flask import Flask, request, session, redirect, url_for, render_template, jsonify, send_from_directory
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'nfc-platform-secret-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB

DB_PATH = os.path.join(os.path.dirname(__file__), 'data.db')
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─── DATABASE ────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                email     TEXT UNIQUE NOT NULL,
                password  TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS cards (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                code       TEXT UNIQUE NOT NULL,
                user_id    INTEGER REFERENCES users(id),
                activated  INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS profiles (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                card_code  TEXT UNIQUE NOT NULL REFERENCES cards(code),
                first_name TEXT DEFAULT '',
                last_name  TEXT DEFAULT '',
                role       TEXT DEFAULT '',
                company    TEXT DEFAULT '',
                phone      TEXT DEFAULT '',
                email      TEXT DEFAULT '',
                tg         TEXT DEFAULT '',
                ig         TEXT DEFAULT '',
                wa         TEXT DEFAULT '',
                vk         TEXT DEFAULT '',
                li         TEXT DEFAULT '',
                photo      TEXT DEFAULT '',
                theme      TEXT DEFAULT 'dark',
                updated_at TEXT DEFAULT (datetime('now'))
            );
        ''')
    print("✅ Database ready")

def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def gen_code(length=8):
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return ''.join(secrets.choice(chars) for _ in range(length))

# ─── AUTH HELPERS ─────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

# ─── PUBLIC ROUTES ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/c/<code>')
def view_card(code):
    """Public card page — shown when NFC is tapped"""
    db = get_db()
    profile = db.execute(
        'SELECT * FROM profiles WHERE card_code = ?', (code,)
    ).fetchone()
    card = db.execute('SELECT * FROM cards WHERE code = ?', (code,)).fetchone()

    if not card:
        return render_template('404.html'), 404

    if not card['activated'] or not profile:
        return redirect(url_for('activate_page', code=code))

    return render_template('card.html', p=dict(profile), code=code)

@app.route('/activate/<code>', methods=['GET'])
def activate_page(code):
    """First-time activation page"""
    db = get_db()
    card = db.execute('SELECT * FROM cards WHERE code = ?', (code,)).fetchone()
    if not card:
        return render_template('404.html'), 404
    if card['activated']:
        # Already activated — redirect to edit if logged in, else card
        if session.get('card_code') == code or session.get('role') == 'admin':
            return redirect(url_for('dashboard'))
        return redirect(url_for('view_card', code=code))
    return render_template('activate.html', code=code)

# ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET'])
def login_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    email    = (data.get('email') or '').strip().lower()
    password = data.get('password', '')
    code     = (data.get('code') or '').strip().upper()

    if not email or not password or not code:
        return jsonify(error='Заполни все поля'), 400
    if len(password) < 6:
        return jsonify(error='Пароль минимум 6 символов'), 400

    db = get_db()
    card = db.execute('SELECT * FROM cards WHERE code = ?', (code,)).fetchone()
    if not card:
        return jsonify(error='Код карты не найден'), 404
    if card['user_id']:
        return jsonify(error='Этот код уже используется'), 409

    existing = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    if existing:
        return jsonify(error='Email уже зарегистрирован'), 409

    with db:
        cur = db.execute('INSERT INTO users (email, password) VALUES (?,?)', (email, hash_pw(password)))
        user_id = cur.lastrowid
        db.execute('UPDATE cards SET user_id=? WHERE code=?', (user_id, code))

    session['user_id'] = user_id
    session['email']   = email
    session['card_code'] = code
    return jsonify(ok=True, redirect=url_for('activate_fill', code=code))

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email    = (data.get('email') or '').strip().lower()
    password = data.get('password', '')

    db = get_db()

    # Admin login
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@nfc.local')
    admin_pass  = os.environ.get('ADMIN_PASS',  'admin123')
    if email == admin_email and password == admin_pass:
        session['user_id'] = 0
        session['email']   = email
        session['role']    = 'admin'
        return jsonify(ok=True, redirect=url_for('admin_panel'))

    user = db.execute('SELECT * FROM users WHERE email=? AND password=?',
                      (email, hash_pw(password))).fetchone()
    if not user:
        return jsonify(error='Неверный email или пароль'), 401

    card = db.execute('SELECT code FROM cards WHERE user_id=?', (user['id'],)).fetchone()
    session['user_id']   = user['id']
    session['email']     = email
    session['card_code'] = card['code'] if card else None
    return jsonify(ok=True, redirect=url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ─── ACTIVATION FILL ──────────────────────────────────────────────────────────

@app.route('/setup/<code>', methods=['GET'])
@login_required
def activate_fill(code):
    if session.get('card_code') != code and session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    db = get_db()
    profile = db.execute('SELECT * FROM profiles WHERE card_code=?', (code,)).fetchone()
    return render_template('setup.html', code=code,
                           p=dict(profile) if profile else {})

# ─── DASHBOARD ────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    code = session.get('card_code')
    if not code:
        return render_template('no_card.html')
    db = get_db()
    profile = db.execute('SELECT * FROM profiles WHERE card_code=?', (code,)).fetchone()
    card    = db.execute('SELECT * FROM cards WHERE code=?', (code,)).fetchone()
    if not card['activated']:
        return redirect(url_for('activate_fill', code=code))
    return render_template('dashboard.html', code=code,
                           p=dict(profile) if profile else {}, email=session['email'])

# ─── API: SAVE PROFILE ────────────────────────────────────────────────────────

@app.route('/api/profile/<code>', methods=['POST'])
@login_required
def api_save_profile(code):
    if session.get('card_code') != code and session.get('role') != 'admin':
        return jsonify(error='Нет доступа'), 403

    data = request.get_json()

    # Handle base64 photo
    photo_path = data.get('photo', '')
    if photo_path and photo_path.startswith('data:image'):
        try:
            header, b64 = photo_path.split(',', 1)
            ext = 'jpg' if 'jpeg' in header else 'png'
            fname = f"{code}.{ext}"
            fpath = os.path.join(UPLOAD_FOLDER, fname)
            with open(fpath, 'wb') as f:
                f.write(base64.b64decode(b64))
            photo_path = f"/static/uploads/{fname}"
        except Exception as e:
            photo_path = ''

    db = get_db()
    existing = db.execute('SELECT id FROM profiles WHERE card_code=?', (code,)).fetchone()

    fields = dict(
        first_name = data.get('first_name','')[:60],
        last_name  = data.get('last_name','')[:60],
        role       = data.get('role','')[:80],
        company    = data.get('company','')[:80],
        phone      = data.get('phone','')[:30],
        email      = data.get('email','')[:80],
        tg         = data.get('tg','')[:80],
        ig         = data.get('ig','')[:80],
        wa         = data.get('wa','')[:80],
        vk         = data.get('vk','')[:80],
        li         = data.get('li','')[:80],
        theme      = data.get('theme','dark')[:20],
        updated_at = datetime.now().isoformat(),
    )
    if photo_path:
        fields['photo'] = photo_path

    with db:
        if existing:
            sets = ', '.join(f"{k}=?" for k in fields)
            db.execute(f"UPDATE profiles SET {sets} WHERE card_code=?",
                       (*fields.values(), code))
        else:
            fields['card_code'] = code
            cols = ', '.join(fields.keys())
            vals = ', '.join('?' for _ in fields)
            db.execute(f"INSERT INTO profiles ({cols}) VALUES ({vals})",
                       tuple(fields.values()))
        db.execute('UPDATE cards SET activated=1 WHERE code=?', (code,))

    return jsonify(ok=True)

# ─── ADMIN ────────────────────────────────────────────────────────────────────

@app.route('/admin')
@admin_required
def admin_panel():
    db = get_db()
    cards = db.execute('''
        SELECT c.code, c.activated, c.created_at,
               u.email,
               p.first_name, p.last_name, p.company
        FROM cards c
        LEFT JOIN users u ON u.id = c.user_id
        LEFT JOIN profiles p ON p.card_code = c.code
        ORDER BY c.id DESC
    ''').fetchall()
    total    = len(cards)
    active   = sum(1 for c in cards if c['activated'])
    inactive = total - active
    return render_template('admin.html', cards=cards,
                           total=total, active=active, inactive=inactive)

@app.route('/api/admin/generate', methods=['POST'])
@admin_required
def api_generate_codes():
    data  = request.get_json()
    count = min(int(data.get('count', 1)), 100)
    db    = get_db()
    codes = []
    with db:
        for _ in range(count):
            for attempt in range(10):
                code = gen_code()
                exists = db.execute('SELECT 1 FROM cards WHERE code=?', (code,)).fetchone()
                if not exists:
                    db.execute('INSERT INTO cards (code) VALUES (?)', (code,))
                    codes.append(code)
                    break
    return jsonify(ok=True, codes=codes)

@app.route('/api/admin/delete/<code>', methods=['DELETE'])
@admin_required
def api_delete_card(code):
    db = get_db()
    with db:
        db.execute('DELETE FROM profiles WHERE card_code=?', (code,))
        db.execute('DELETE FROM cards WHERE code=?', (code,))
    return jsonify(ok=True)

@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# ─── START ────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 NFC Platform running on http://localhost:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)

# ─── SHORTCUT API ─────────────────────────────────────────────────────────────
# Called by iOS Shortcut via simple GET request — no login required
# URL: /api/setup?code=ABC123&name=Ivan+Petrov&role=Manager&phone=...

@app.route('/api/setup', methods=['GET'])
def api_shortcut_setup():
    code    = request.args.get('code','').strip().upper()
    name    = request.args.get('name','').strip()
    role    = request.args.get('role','').strip()
    company = request.args.get('company','').strip()
    phone   = request.args.get('phone','').strip()
    email   = request.args.get('email','').strip()
    tg      = request.args.get('tg','').strip()
    ig      = request.args.get('ig','').strip()
    wa      = request.args.get('wa','').strip()

    if not code:
        return jsonify(error='Нет кода карты'), 400

    db   = get_db()
    card = db.execute('SELECT * FROM cards WHERE code=?', (code,)).fetchone()
    if not card:
        return jsonify(error='Код карты не найден'), 404

    # Split full name into first/last
    parts      = name.split(' ', 1)
    first_name = parts[0] if parts else ''
    last_name  = parts[1] if len(parts) > 1 else ''

    existing = db.execute('SELECT id FROM profiles WHERE card_code=?', (code,)).fetchone()

    fields = dict(
        first_name = first_name[:60],
        last_name  = last_name[:60],
        role       = role[:80],
        company    = company[:80],
        phone      = phone[:30],
        email      = email[:80],
        tg         = tg[:80],
        ig         = ig[:80],
        wa         = wa[:80],
        theme      = 'dark',
        updated_at = datetime.now().isoformat(),
    )

    with db:
        if existing:
            sets = ', '.join(f"{k}=?" for k in fields)
            db.execute(f"UPDATE profiles SET {sets} WHERE card_code=?",
                       (*fields.values(), code))
        else:
            fields['card_code'] = code
            cols = ', '.join(fields.keys())
            vals = ', '.join('?' for _ in fields)
            db.execute(f"INSERT INTO profiles ({cols}) VALUES ({vals})",
                       tuple(fields.values()))
        db.execute('UPDATE cards SET activated=1 WHERE code=?', (code,))

    # Return plain text so Shortcut can show it as notification
    return f"OK. Визитка для {name} активирована!", 200, {'Content-Type': 'text/plain'}
