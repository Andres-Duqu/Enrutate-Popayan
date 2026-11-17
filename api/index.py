import os
import sys
import datetime
import hashlib
import hmac
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ------------------------------------------------------------------------------
# CONFIGURACIÓN Y VARIABLES DE ENTORNO
# ------------------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip()
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "").strip()
JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "enrutate_jwt_secret_popayan_2026_default")

# Intenta inicializar cliente Supabase de forma segura
supabase = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        from supabase import create_client
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        print(f"Aviso: No se pudo conectar via Supabase REST: {e}")

# Intenta conexión directa a PostgreSQL (si existe DATABASE_URL)
def _get_pg_conn():
    if not DATABASE_URL:
        return None
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        kwargs = {"cursor_factory": RealDictCursor, "connect_timeout": 8}
        if "sslmode" not in DATABASE_URL.lower():
            kwargs["sslmode"] = "require"
        return psycopg2.connect(DATABASE_URL, **kwargs)
    except Exception as e:
        print(f"Error conectando a Postgres: {e}")
        return None


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


def _get_user(username: str):
    # 1. Probar via PostgreSQL (DATABASE_URL)
    conn = _get_pg_conn()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, username, password_hash, full_name, role, api_key "
                    "FROM public.usuarios_api WHERE username = %s LIMIT 1",
                    (username,)
                )
                user = cur.fetchone()
                if user:
                    return dict(user)
        except Exception:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT id, username, password_hash, full_name, role, api_key "
                        "FROM public.users WHERE username = %s LIMIT 1",
                        (username,)
                    )
                    user = cur.fetchone()
                    if user:
                        return dict(user)
            except Exception:
                pass
        finally:
            conn.close()

    # 2. Probar via Supabase REST
    if supabase:
        for tbl in ["usuarios_api", "users"]:
            try:
                res = supabase.table(tbl).select("*").eq("username", username).execute()
                if res.data and len(res.data) > 0:
                    return res.data[0]
            except Exception:
                continue

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
        # Fallback de token si pyjwt tuviera algún problema
        raw = f"{user.get('username')}:{user.get('role')}:{int(exp.timestamp())}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ==============================================================================
# ENDPOINTS
# ==============================================================================

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["GET"])
def health(path):
    conn = _get_pg_conn()
    pg_ok = False
    if conn:
        pg_ok = True
        conn.close()

    return jsonify({
        "servicio": "EnRutate Popayán API Gateway",
        "status": "online",
        "database_url_activa": pg_ok,
        "supabase_client_activo": bool(supabase),
        "path_solicitado": path
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

    user = _get_user(username)
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

    if _get_user(username):
        return jsonify({
            "success": False,
            "error": "Usuario duplicado",
            "mensaje": f"El usuario '{username}' ya está registrado."
        }), 409

    hashed = _hash_pw(password)
    created_user = {
        "username": username,
        "password_hash": hashed,
        "full_name": f"Usuario {username.capitalize()}",
        "role": "USUARIO"
    }

    # 1. Guardar via PostgreSQL (DATABASE_URL)
    conn = _get_pg_conn()
    guardado = False
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO public.usuarios_api (username, password_hash, full_name, role) "
                    "VALUES (%s, %s, %s, %s) RETURNING id",
                    (username, hashed, created_user["full_name"], "USUARIO")
                )
                nuevo_id = cur.fetchone()
                conn.commit()
                created_user["id"] = nuevo_id["id"] if nuevo_id else 1
                guardado = True
        except Exception as e:
            conn.rollback()
            print(f"Error al insertar en Postgres: {e}")
        finally:
            conn.close()

    # 2. Guardar via Supabase REST (Fallback)
    if not guardado and supabase:
        try:
            res = supabase.table("usuarios_api").insert(created_user).execute()
            if res.data:
                created_user["id"] = res.data[0].get("id", 1)
            guardado = True
        except Exception:
            try:
                res = supabase.table("users").insert(created_user).execute()
                guardado = True
            except Exception:
                pass

    if not guardado:
        return jsonify({
            "success": False,
            "error": "Error al guardar usuario",
            "mensaje": "No se pudo registrar en la base de datos. Verifica la conexión a Supabase."
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
