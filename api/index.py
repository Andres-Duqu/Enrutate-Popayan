import os
import sys
import datetime
import hashlib
import hmac
import json
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ------------------------------------------------------------------------------
# CONFIGURACIÓN
# ------------------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "").strip()
JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "enrutate_jwt_secret_popayan_2026_default")

# Cliente Supabase SDK
supabase_client = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        from supabase import create_client
        supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        print(f"Aviso SDK Supabase: {e}")


def _get_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }


def _check_pw(plain: str, hashed: str) -> bool:
    if not hashed:
        return False
    if plain == hashed:
        return True
    try:
        from werkzeug.security import check_password_hash
        if hashed.startswith(("scrypt:", "pbkdf2:")):
            return check_password_hash(hashed, plain)
    except Exception:
        pass
    if len(hashed) == 64:
        legacy = hashlib.sha256(plain.encode("utf-8")).hexdigest()
        return hmac.compare_digest(legacy, hashed)
    return False


def _hash_pw(plain: str) -> str:
    try:
        from werkzeug.security import generate_password_hash
        return generate_password_hash(plain)
    except Exception:
        return hashlib.sha256(plain.encode("utf-8")).hexdigest()


def _get_user_db(username: str):
    # 1. Via REST directo (el más rápido y compatible con Supabase)
    if SUPABASE_URL and SUPABASE_KEY:
        for table in ["usuarios_api", "users"]:
            try:
                url = f"{SUPABASE_URL}/rest/v1/{table}?username=eq.{username}&select=*"
                r = requests.get(url, headers=_get_headers(), timeout=5)
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, list) and len(data) > 0:
                        return data[0]
            except Exception as e:
                print(f"Error REST get_user: {e}")

    # 2. Via SDK Supabase
    if supabase_client:
        for table in ["usuarios_api", "users"]:
            try:
                res = supabase_client.table(table).select("*").eq("username", username).execute()
                if res.data and len(res.data) > 0:
                    return res.data[0]
            except Exception:
                pass

    # 3. Via PostgreSQL DATABASE_URL
    if DATABASE_URL:
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor, connect_timeout=5, sslmode="require")
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM public.usuarios_api WHERE username = %s LIMIT 1", (username,))
                row = cur.fetchone()
                if row:
                    return dict(row)
            conn.close()
        except Exception:
            pass

    return None


def _create_jwt(user: dict) -> str:
    exp = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    payload = {
        "sub": str(user.get("id", 1)),
        "username": user.get("username", ""),
        "role": user.get("role", "USUARIO"),
        "full_name": user.get("full_name", user.get("username", "")),
        "exp": exp
    }
    try:
        import jwt
        return jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    except Exception:
        raw = f"{user.get('username')}:{user.get('role')}:{int(exp.timestamp())}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ==============================================================================
# ENDPOINTS
# ==============================================================================

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["GET"])
def health(path):
    return jsonify({
        "servicio": "EnRutate Popayán API Gateway",
        "status": "online",
        "supabase_configurado": bool(SUPABASE_URL and SUPABASE_KEY),
        "supabase_url": SUPABASE_URL,
        "database_url_configurado": bool(DATABASE_URL)
    }), 200


@app.route("/login", methods=["POST"])
@app.route("/api/login", methods=["POST"])
@app.route("/api/servicio_monitoreo/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if not username or not password:
        return jsonify({
            "success": False,
            "error": "Campos requeridos",
            "mensaje": "Debe ingresar usuario y contraseña."
        }), 400

    user = _get_user_db(username)
    if not user or not _check_pw(password, user.get("password_hash", "")):
        return jsonify({
            "success": False,
            "error": "Credenciales inválidas",
            "mensaje": "Usuario o contraseña incorrectos."
        }), 401

    token = _create_jwt(user)
    return jsonify({
        "success": True,
        "token": token,
        "tipo": "Bearer",
        "username": user.get("username"),
        "role": user.get("role", "USUARIO"),
        "full_name": user.get("full_name", user.get("username")),
        "api_key": user.get("api_key", "")
    }), 200


@app.route("/register", methods=["POST"])
@app.route("/api/register", methods=["POST"])
@app.route("/api/servicio_monitoreo/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if not username or not password:
        return jsonify({
            "success": False,
            "error": "Campos requeridos",
            "mensaje": "Debe enviar usuario y contraseña."
        }), 400

    if len(password) < 6:
        return jsonify({
            "success": False,
            "error": "Contraseña muy corta",
            "mensaje": "La contraseña debe tener al menos 6 caracteres."
        }), 400

    if _get_user_db(username):
        return jsonify({
            "success": False,
            "error": "Usuario duplicado",
            "mensaje": f"El usuario '{username}' ya está registrado."
        }), 409

    hashed = _hash_pw(password)
    user_payload = {
        "username": username,
        "password_hash": hashed,
        "full_name": f"Usuario {username.capitalize()}",
        "role": "USUARIO"
    }

    created_user = None
    ultimo_error = ""

    # 1. Inserción directa REST (compatible con claves sb_secret_ y claves legadas eyJ...)
    if SUPABASE_URL and SUPABASE_KEY:
        for table in ["usuarios_api", "users"]:
            try:
                url = f"{SUPABASE_URL}/rest/v1/{table}"
                r = requests.post(url, headers=_get_headers(), json=user_payload, timeout=6)
                if r.status_code in (200, 201):
                    res_data = r.json()
                    created_user = res_data[0] if isinstance(res_data, list) and len(res_data) > 0 else user_payload
                    break
                else:
                    ultimo_error = f"HTTP {r.status_code}: {r.text}"
            except Exception as e:
                ultimo_error = str(e)

    # 2. Inserción via SDK Supabase
    if not created_user and supabase_client:
        try:
            res = supabase_client.table("usuarios_api").insert(user_payload).execute()
            if res.data:
                created_user = res.data[0]
        except Exception as e:
            ultimo_error = str(e)

    # 3. Inserción via PostgreSQL DATABASE_URL
    if not created_user and DATABASE_URL:
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor, connect_timeout=5, sslmode="require")
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO public.usuarios_api (username, password_hash, full_name, role) "
                    "VALUES (%s, %s, %s, %s) RETURNING *",
                    (username, hashed, user_payload["full_name"], "USUARIO")
                )
                row = cur.fetchone()
                conn.commit()
                if row:
                    created_user = dict(row)
            conn.close()
        except Exception as e:
            ultimo_error = str(e)

    if not created_user:
        return jsonify({
            "success": False,
            "error": "Error al registrar usuario",
            "mensaje": f"No se pudo guardar en Supabase. Detalle: {ultimo_error}"
        }), 500

    token = _create_jwt(created_user)
    return jsonify({
        "success": True,
        "token": token,
        "username": username,
        "role": "USUARIO",
        "mensaje": "Usuario registrado exitosamente."
    }), 201


@app.route("/me", methods=["GET"])
@app.route("/api/me", methods=["GET"])
@app.route("/api/servicio_monitoreo/me", methods=["GET"])
def me():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "No autorizado"}), 401

    token = auth_header.split(" ", 1)[1].strip()
    try:
        import jwt
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return jsonify({
            "success": True,
            "username": payload.get("username"),
            "role": payload.get("role"),
            "full_name": payload.get("full_name")
        })
    except Exception:
        return jsonify({"error": "Token inválido o expirado"}), 401


if __name__ == "__main__":
    app.run(debug=True, port=5000)
