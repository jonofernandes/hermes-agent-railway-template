import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

from itsdangerous import BadSignature, SignatureExpired, TimestampSigner
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse
from starlette.routing import Route

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = secrets.token_urlsafe(16)
    print(f"Generated admin password: {ADMIN_PASSWORD}")

HERMES_HOME = os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))
ENV_FILE_PATH = Path(HERMES_HOME) / ".env"
PAIRING_DIR = Path(HERMES_HOME) / "pairing"
TEMPLATE_PATH = Path(__file__).parent / "templates" / "index.html"
CODE_TTL_SECONDS = 3600

_COOKIE_NAME = "hermes_session"
_SIGNER = TimestampSigner(
    hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest(),
    salt="hermes-railway",
)
_SESSION_MAX_AGE = 86400 * 7

PROVIDER_KEYS = [
    "OPENROUTER_API_KEY", "DEEPSEEK_API_KEY", "DASHSCOPE_API_KEY",
    "GLM_API_KEY", "KIMI_API_KEY", "MINIMAX_API_KEY", "HF_TOKEN",
]
CHANNEL_KEYS = {
    "Telegram": "TELEGRAM_BOT_TOKEN",
    "Discord": "DISCORD_BOT_TOKEN",
    "Slack": "SLACK_BOT_TOKEN",
    "WhatsApp": "WHATSAPP_ENABLED",
    "Email": "EMAIL_ADDRESS",
    "Mattermost": "MATTERMOST_TOKEN",
    "Matrix": "MATRIX_ACCESS_TOKEN",
}

SECRET_PATTERN = re.compile(r"(KEY|TOKEN|PASSWORD|SECRET)", re.IGNORECASE)
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


# ---------------------------------------------------------------------------
# .env helpers
# ---------------------------------------------------------------------------

def read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    result = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        result[key] = value
    return result


def write_env_file(path: Path, data: dict[str, str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for k, v in data.items():
        if v:
            escaped = v.replace('"', '\\"')
            lines.append(f'{k}="{escaped}"')
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def mask_value(key: str, value: str) -> str:
    if SECRET_PATTERN.search(key) and value:
        return (value[:8] + "***") if len(value) > 8 else "***"
    return value


def _is_masked(value: str) -> bool:
    return value.endswith("***")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _check_basic(username: str, password: str) -> bool:
    return (
        hmac.compare_digest(username, ADMIN_USERNAME)
        and hmac.compare_digest(password, ADMIN_PASSWORD)
    )


def _make_session_cookie() -> str:
    return _SIGNER.sign(b"ok").decode()


def _validate_session_cookie(value: str) -> bool:
    try:
        _SIGNER.unsign(value, max_age=_SESSION_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired):
        return False


def _is_authenticated(request: Request) -> bool:
    cookie = request.cookies.get(_COOKIE_NAME)
    if cookie and _validate_session_cookie(cookie):
        return True
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode("ascii")
            username, _, password = decoded.partition(":")
            if _check_basic(username, password):
                return True
        except Exception:
            pass
    return False


def _auth_response():
    return PlainTextResponse(
        "Unauthorized",
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="hermes"'},
    )


def _set_session_cookie(request: Request, response):
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("basic ") and not request.cookies.get(_COOKIE_NAME):
        response.set_cookie(
            _COOKIE_NAME,
            _make_session_cookie(),
            max_age=_SESSION_MAX_AGE,
            httponly=True,
            samesite="lax",
        )


# ---------------------------------------------------------------------------
# Gateway manager
# ---------------------------------------------------------------------------

class GatewayManager:
    def __init__(self):
        self.process: asyncio.subprocess.Process | None = None
        self.state = "stopped"
        self.logs: deque[str] = deque(maxlen=500)
        self.start_time: float | None = None
        self.restart_count = 0
        self._read_tasks: list[asyncio.Task] = []

    async def start(self):
        if self.process and self.process.returncode is None:
            return
        self.state = "starting"
        try:
            env = os.environ.copy()
            env["HERMES_HOME"] = HERMES_HOME
            env.update(read_env_file(ENV_FILE_PATH))

            self.process = await asyncio.create_subprocess_exec(
                "hermes", "gateway",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )
            self.state = "running"
            self.start_time = time.time()
            task = asyncio.create_task(self._read_output())
            self._read_tasks.append(task)
        except Exception as e:
            self.state = "error"
            self.logs.append(f"Failed to start gateway: {e}")

    async def stop(self):
        if not self.process or self.process.returncode is not None:
            self.state = "stopped"
            return
        self.state = "stopping"
        self.process.terminate()
        try:
            await asyncio.wait_for(self.process.wait(), timeout=10)
        except asyncio.TimeoutError:
            self.process.kill()
            await self.process.wait()
        self.state = "stopped"
        self.start_time = None

    async def restart(self):
        await self.stop()
        self.restart_count += 1
        await self.start()

    async def _read_output(self):
        try:
            while self.process and self.process.stdout:
                line = await self.process.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                cleaned = ANSI_ESCAPE.sub("", decoded)
                self.logs.append(cleaned)
        except asyncio.CancelledError:
            return
        if self.process and self.process.returncode is not None and self.state == "running":
            self.state = "error"
            self.logs.append(f"Gateway exited with code {self.process.returncode}")

    def get_status(self) -> dict:
        pid = None
        if self.process and self.process.returncode is None:
            pid = self.process.pid
        uptime = None
        if self.start_time and self.state == "running":
            uptime = int(time.time() - self.start_time)
        return {
            "state": self.state,
            "pid": pid,
            "uptime": uptime,
            "restart_count": self.restart_count,
        }


gateway = GatewayManager()


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

async def health(request: Request):
    return JSONResponse({"status": "ok", "gateway": gateway.state})


async def index(request: Request):
    if not _is_authenticated(request):
        return _auth_response()
    try:
        content = TEMPLATE_PATH.read_text()
    except FileNotFoundError:
        content = "<h1>UI template not found</h1>"
    response = HTMLResponse(content)
    _set_session_cookie(request, response)
    return response


async def api_config_get(request: Request):
    if not _is_authenticated(request):
        return _auth_response()
    env = read_env_file(ENV_FILE_PATH)
    masked = {k: mask_value(k, v) for k, v in env.items()}
    return JSONResponse(masked)


async def api_config_put(request: Request):
    if not _is_authenticated(request):
        return _auth_response()
    try:
        new_data: dict = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    existing = read_env_file(ENV_FILE_PATH)
    merged = dict(existing)

    for k, v in new_data.items():
        if not isinstance(v, str):
            continue
        v = v.strip()
        if not v:
            merged.pop(k, None)
        elif _is_masked(v):
            pass  # preserve existing value
        else:
            merged[k] = v

    write_env_file(ENV_FILE_PATH, merged)
    return JSONResponse({"ok": True})


async def api_config(request: Request):
    if request.method == "GET":
        return await api_config_get(request)
    return await api_config_put(request)


async def api_status(request: Request):
    if not _is_authenticated(request):
        return _auth_response()
    env = read_env_file(ENV_FILE_PATH)
    providers = {key: bool(env.get(key)) for key in PROVIDER_KEYS}
    channels = {name: bool(env.get(key)) for name, key in CHANNEL_KEYS.items()}
    return JSONResponse({
        "gateway": gateway.get_status(),
        "providers": providers,
        "channels": channels,
    })


async def api_logs(request: Request):
    if not _is_authenticated(request):
        return _auth_response()
    return JSONResponse({"logs": list(gateway.logs)})


async def api_gateway_start(request: Request):
    if not _is_authenticated(request):
        return _auth_response()
    asyncio.create_task(gateway.start())
    return JSONResponse({"ok": True})


async def api_gateway_stop(request: Request):
    if not _is_authenticated(request):
        return _auth_response()
    asyncio.create_task(gateway.stop())
    return JSONResponse({"ok": True})


async def api_gateway_restart(request: Request):
    if not _is_authenticated(request):
        return _auth_response()
    asyncio.create_task(gateway.restart())
    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# Pairing
# ---------------------------------------------------------------------------

def _load_pairing_json(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_pairing_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _pairing_platforms(suffix: str) -> list[str]:
    if not PAIRING_DIR.exists():
        return []
    return [
        f.stem.rsplit(f"-{suffix}", 1)[0]
        for f in PAIRING_DIR.glob(f"*-{suffix}.json")
    ]


async def api_pairing_pending(request: Request):
    if not _is_authenticated(request):
        return _auth_response()
    now = time.time()
    results = []
    for platform in _pairing_platforms("pending"):
        pending = _load_pairing_json(PAIRING_DIR / f"{platform}-pending.json")
        for code, info in pending.items():
            age = now - info.get("created_at", now)
            if age > CODE_TTL_SECONDS:
                continue
            results.append({
                "platform": platform,
                "code": code,
                "user_id": info.get("user_id", ""),
                "user_name": info.get("user_name", ""),
                "age_minutes": int(age / 60),
            })
    return JSONResponse({"pending": results})


async def api_pairing_approve(request: Request):
    if not _is_authenticated(request):
        return _auth_response()
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    platform = body.get("platform", "")
    code = body.get("code", "").upper().strip()
    if not platform or not code:
        return JSONResponse({"error": "platform and code required"}, status_code=400)

    pending_path = PAIRING_DIR / f"{platform}-pending.json"
    pending = _load_pairing_json(pending_path)
    if code not in pending:
        return JSONResponse({"error": "Code not found or expired"}, status_code=404)

    entry = pending.pop(code)
    _save_pairing_json(pending_path, pending)

    approved_path = PAIRING_DIR / f"{platform}-approved.json"
    approved = _load_pairing_json(approved_path)
    approved[entry["user_id"]] = {
        "user_name": entry.get("user_name", ""),
        "approved_at": time.time(),
    }
    _save_pairing_json(approved_path, approved)

    return JSONResponse({"ok": True, "user_id": entry["user_id"], "user_name": entry.get("user_name", "")})


async def api_pairing_deny(request: Request):
    if not _is_authenticated(request):
        return _auth_response()
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    platform = body.get("platform", "")
    code = body.get("code", "").upper().strip()
    if not platform or not code:
        return JSONResponse({"error": "platform and code required"}, status_code=400)

    pending_path = PAIRING_DIR / f"{platform}-pending.json"
    pending = _load_pairing_json(pending_path)
    if code in pending:
        del pending[code]
        _save_pairing_json(pending_path, pending)

    return JSONResponse({"ok": True})


async def api_pairing_approved(request: Request):
    if not _is_authenticated(request):
        return _auth_response()
    results = []
    for platform in _pairing_platforms("approved"):
        approved = _load_pairing_json(PAIRING_DIR / f"{platform}-approved.json")
        for user_id, info in approved.items():
            results.append({
                "platform": platform,
                "user_id": user_id,
                "user_name": info.get("user_name", ""),
                "approved_at": info.get("approved_at", 0),
            })
    return JSONResponse({"approved": results})


async def api_pairing_revoke(request: Request):
    if not _is_authenticated(request):
        return _auth_response()
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    platform = body.get("platform", "")
    user_id = body.get("user_id", "")
    if not platform or not user_id:
        return JSONResponse({"error": "platform and user_id required"}, status_code=400)

    approved_path = PAIRING_DIR / f"{platform}-approved.json"
    approved = _load_pairing_json(approved_path)
    if user_id in approved:
        del approved[user_id]
        _save_pairing_json(approved_path, approved)

    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# Auto-start
# ---------------------------------------------------------------------------

async def auto_start_gateway():
    env_vars = read_env_file(ENV_FILE_PATH)
    has_provider = any(env_vars.get(key) for key in PROVIDER_KEYS)
    if has_provider:
        asyncio.create_task(gateway.start())


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

routes = [
    Route("/health", health),
    Route("/", index),
    Route("/api/config", api_config, methods=["GET", "PUT"]),
    Route("/api/status", api_status),
    Route("/api/logs", api_logs),
    Route("/api/gateway/start", api_gateway_start, methods=["POST"]),
    Route("/api/gateway/stop", api_gateway_stop, methods=["POST"]),
    Route("/api/gateway/restart", api_gateway_restart, methods=["POST"]),
    Route("/api/pairing/pending", api_pairing_pending),
    Route("/api/pairing/approve", api_pairing_approve, methods=["POST"]),
    Route("/api/pairing/deny", api_pairing_deny, methods=["POST"]),
    Route("/api/pairing/approved", api_pairing_approved),
    Route("/api/pairing/revoke", api_pairing_revoke, methods=["POST"]),
]


@asynccontextmanager
async def lifespan(app):
    await auto_start_gateway()
    yield
    await gateway.stop()


app = Starlette(
    routes=routes,
    middleware=[],
    lifespan=lifespan,
)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8080"))

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info", loop="asyncio")
    server = uvicorn.Server(config)

    def handle_signal():
        loop.create_task(gateway.stop())
        server.should_exit = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, handle_signal)

    loop.run_until_complete(server.serve())
