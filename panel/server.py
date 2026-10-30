# -*- coding: utf-8 -*-
"""hw2api 网关面板：账户池管理 / 手动导入 / API Key 管理 / 指标监控
配合 hw2api 网关（Go）使用；账户凭据由外部工具产出后在此手动导入。"""
import asyncio
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone

import sqlite3
import urllib.request

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
GW_DIR = os.path.join(ROOT, "gateway")
ACCT_DIR = os.path.join(ROOT, "accounts")
AUTHS_DIR = os.path.join(ACCT_DIR, "auths")
GW_AUTHS = os.path.join(GW_DIR, "auths")
PANEL_CFG = os.path.join(HERE, "panel_config.json")
LOG_DIR = os.path.join(ROOT, "logs")
os.makedirs(AUTHS_DIR, exist_ok=True)
os.makedirs(GW_AUTHS, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

DEFAULT_CFG = {
    "gateway": {
        "listen": "127.0.0.1:7866",
        # 首次启动若未配置则自动生成随机 key（打印到日志并写入配置）
        "api_key": "",
        "binary": "hw2api",  # Windows 构建为 hw2api.exe
        "upstream_proxy": "",          # 留空=本机直连（仅 CN 网络可用）；海外服务器填 CN 出口代理
    },
}


def load_cfg():
    if os.path.exists(PANEL_CFG):
        cfg = json.load(open(PANEL_CFG, encoding="utf-8"))
    else:
        cfg = dict(DEFAULT_CFG)
        import secrets as _s
        cfg["gateway"]["api_key"] = "sk-hw2api-" + _s.token_hex(20)
        save_cfg(cfg)
        print("[hw2api] 首次启动，已生成主 API Key:", cfg["gateway"]["api_key"])
    cfg.setdefault("gateway", {}).setdefault("api_keys", [])
    return cfg


def save_cfg(cfg):
    json.dump(cfg, open(PANEL_CFG, "w", encoding="utf-8"), ensure_ascii=False, indent=2)



app = FastAPI(title="hw2api panel")

# ── 面板登录鉴权（/v1/* 与 /api/auth/login 豁免） ──
import hashlib
import hmac as hmac_mod
import secrets as _secrets

AUTH_COOKIE = "hw2api_session"


def _auth_secret():
    cfg = load_cfg()
    return cfg.get("panel_auth", {}).get("secret") or "hw2api-default-secret"


def _make_session(user):
    exp = str(int(time.time()) + 7 * 86400)
    sig = hmac_mod.new(_auth_secret().encode(), ("%s|%s" % (user, exp)).encode(),
                       hashlib.sha256).hexdigest()
    return "%s|%s|%s" % (user, exp, sig)


def _check_session(token):
    try:
        user, exp, sig = token.split("|")
        if int(exp) < time.time():
            return None
        want = hmac_mod.new(_auth_secret().encode(), ("%s|%s" % (user, exp)).encode(),
                            hashlib.sha256).hexdigest()
        return user if hmac_mod.compare_digest(want, sig) else None
    except Exception:
        return None


@app.post("/api/auth/login")
async def auth_login(body: dict):
    cfg = load_cfg()
    pa = cfg.get("panel_auth") or {}
    user = str(body.get("user") or "")
    pwd = str(body.get("password") or "")
    want_u = pa.get("user") or "admin"
    # 密码：配置优先，其次 PANEL_ADMIN_PASSWORD 环境变量，再次 admin（首次登录前建议改掉）
    want_p = pa.get("password") or os.environ.get("PANEL_ADMIN_PASSWORD") or "admin"
    okk = _secrets.compare_digest(user, want_u) and _secrets.compare_digest(pwd, want_p)
    if not okk:
        raise HTTPException(401, "用户名或密码错误")
    resp = JSONResponse({"ok": True, "user": user})
    resp.set_cookie(AUTH_COOKIE, _make_session(user), max_age=7 * 86400,
                    httponly=True, samesite="lax")
    return resp


@app.post("/api/auth/logout")
async def auth_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(AUTH_COOKIE)
    return resp


@app.get("/api/auth/whoami")
async def auth_whoami(request: Request):
    u = _check_session(request.cookies.get(AUTH_COOKIE, ""))
    return {"user": u}


@app.middleware("http")
async def auth_guard(request: Request, call_next):
    p = request.url.path
    if (p.startswith("/api") and not p.startswith("/api/auth/")) or p == "/api":
        u = _check_session(request.cookies.get(AUTH_COOKIE, ""))
        if not u:
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)

# ── SQLite 持久化（请求日志 + 余额历史） ──
DB_PATH = os.path.join(HERE, "data", "panel.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
_db = sqlite3.connect(DB_PATH, check_same_thread=False)
_db.execute("""CREATE TABLE IF NOT EXISTS requests(
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, model TEXT, account TEXT,
    total_ms REAL, ttft_ms REAL, prompt INTEGER, completion INTEGER,
    credits REAL, ok INTEGER, stream INTEGER)""")
_db.execute("""CREATE TABLE IF NOT EXISTS balances(
    ts REAL, uid TEXT, remain REAL, used REAL, total REAL, tokens INTEGER)""")
_db.commit()


def db_log_request(model, account, total_ms, ttft_ms, prompt, completion, credits, ok, stream):
    try:
        _db.execute("INSERT INTO requests(ts,model,account,total_ms,ttft_ms,prompt,completion,credits,ok,stream) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (time.time(), model, account, total_ms, ttft_ms, prompt, completion, credits, 1 if ok else 0, 1 if stream else 0))
        _db.commit()
    except Exception:
        pass


def db_log_balance(uid, remain, used, total, tokens):
    try:
        _db.execute("INSERT INTO balances(ts,uid,remain,used,total,tokens) VALUES(?,?,?,?,?,?)",
                    (time.time(), uid, remain, used, total, tokens))
        _db.commit()
    except Exception:
        pass


# 每千 token 积分估算系数（按模型 ratio 标定；GLM-5.2 实测 0.00055/token）
CREDITS_PER_TOKEN = 0.00055


# ── 账号余额采集（读网关回写的新鲜凭据，签名调 statistics） ──
BAL_CACHE = {"accounts": {}, "ts": 0}

from hw_sign import sign_request as hw_sign_request  # noqa: E402


def fetch_account_balance(auth_file):
    try:
        a = json.load(open(auth_file, encoding="utf-8"))
        url = "https://snap-access.cn-north-4.myhuaweicloud.com/snap-manager/v1/statistics/plugin"
        hdrs = hw_sign_request("GET", url, {"Accept": "application/json"}, b"",
                               a["access_key_id"], a["secret_access_key"], a.get("cloud_dragon_token", ""))
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, timeout=20) as r:
            j = json.loads(r.read().decode("utf-8", "ignore"))
        out = {"uid": a.get("user_id", ""), "phone": a.get("user_name", "")}
        for m in j.get("metrics", []):
            n = m.get("name")
            if n == "usageTotalPackageCredit":
                out.update({"remain": m.get("package_credit_remain"),
                            "used": m.get("package_credit_used"),
                            "total": m.get("package_credit_amount")})
            elif n == "usageTokenChatMessages":
                out["tokens"] = m.get("usage_token_num", 0)
            elif n == "usageBasicPackageCredit":
                out["basic_remain"] = m.get("package_credit_remain")
        return out
    except Exception as e:
        return {"error": str(e)[:120]}


def balance_collector():
    while True:
        snap = {}
        for f in os.listdir(GW_AUTHS):
            if f.endswith(".json"):
                r = fetch_account_balance(os.path.join(GW_AUTHS, f))
                if "remain" in r:
                    snap[r["uid"] or f] = r
                    db_log_balance(r.get("uid", f), r.get("remain"), r.get("used"),
                                   r.get("total"), r.get("tokens", 0))
        BAL_CACHE["accounts"] = snap
        BAL_CACHE["ts"] = time.time()
        time.sleep(60)


threading.Thread(target=balance_collector, daemon=True).start()


# ───────────────────────── 网关进程管理 ─────────────────────────

class GatewayProc:
    def __init__(self):
        self.proc = None
        self.log_lines = deque(maxlen=400)
        self.start_ts = 0

    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self):
        if self.running():
            return {"ok": True, "note": "already running"}
        cfg = load_cfg()
        gw = cfg["gateway"]
        binary = os.path.join(GW_DIR, gw["binary"])
        if not os.path.exists(binary):
            raise HTTPException(500, "gateway binary not found: %s" % binary)
        env = dict(os.environ)
        env["CA2A_API_KEY"] = gw["api_key"]
        env["CA2A_LISTEN"] = gw["listen"]
        env["CA2A_AUTH_DIR"] = os.path.abspath(GW_AUTHS)
        env["CA2A_STATE_FILE"] = os.path.join(GW_DIR, "data", "state.json")
        if gw.get("upstream_proxy"):
            env["HTTPS_PROXY"] = gw["upstream_proxy"]
            env["HTTP_PROXY"] = gw["upstream_proxy"]
        os.makedirs(os.path.join(GW_DIR, "data"), exist_ok=True)
        self.log_lines.clear()
        self.proc = subprocess.Popen([binary], cwd=GW_DIR, env=env,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        self.start_ts = time.time()

        def pump():
            for raw in iter(self.proc.stdout.readline, b""):
                line = raw.decode("utf-8", "ignore").rstrip()
                self.log_lines.append("[%s] %s" % (datetime.now().strftime("%H:%M:%S"), line))
        threading.Thread(target=pump, daemon=True).start()
        return {"ok": True}

    def stop(self):
        if self.running():
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except Exception:
                self.proc.kill()
        self.proc = None
        return {"ok": True}

    def restart(self):
        self.stop()
        time.sleep(1)
        return self.start()


gw_proc = GatewayProc()


def gw_base():
    return "http://" + load_cfg()["gateway"]["listen"]


def remote_panel():
    return (load_cfg()["gateway"].get("remote_panel") or "").rstrip("/")


async def gw_health():
    if gw_proc.running():
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                r = await c.get(gw_base() + "/healthz")
                return {"up": r.status_code == 200}
        except Exception as e:
            return {"up": False, "error": str(e)[:120]}
    rp = remote_panel()
    if rp:
        try:
            cfg = load_cfg()
            async with httpx.AsyncClient(timeout=10) as c:
                # 远程面板需要登录才能查状态
                r = await c.post(rp + "/api/auth/login", json={
                    "user": cfg.get("panel_auth", {}).get("user", "admin"),
                    "password": cfg.get("panel_auth", {}).get("password", "")}, timeout=8)
                r2 = await c.get(rp + "/api/status", timeout=8)
                j = r2.json()
                h = (j.get("gateway") or {}).get("health") or {}
                return {"up": bool(h.get("up")), "remote": True,
                        "accounts": len(j.get("accounts", []))}
        except Exception as e:
            return {"up": False, "error": "remote: " + str(e)[:100]}
    return {"up": False}


# ───────────────────────── 注册任务管理 ─────────────────────────

def import_accounts():
    """accounts/auths/*.json -> gateway/auths/
    增量且永不复活死号：只拷目标缺失的文件；本地归档区(dead_auths)里的
    死号绝不拷回（refresh_token 单次有效，旧文件回灌会把服务器上已轮换
    的账号打回废 token，即「注册飞号」事故根因）。"""
    n = 0
    dead_dir = os.path.join(GW_DIR, "dead_auths")
    dead = set()
    if os.path.isdir(dead_dir):
        dead = {f for f in os.listdir(dead_dir) if f.endswith(".json")}
    for f in os.listdir(AUTHS_DIR):
        if f.endswith(".json") and f not in dead:
            src = os.path.join(AUTHS_DIR, f)
            dst = os.path.join(GW_AUTHS, f)
            if os.path.exists(dst):
                continue  # 已在网关目录：保留现值（可能是更新过的轮换凭据）
            shutil.copy2(src, dst)
            n += 1
    return n


# ───────────────────────── 指标采集 ─────────────────────────

class Metrics:
    def __init__(self):
        self.requests = deque(maxlen=2000)   # {ts, model, ttft_ms, total_ms, ok, cached_tok, prompt_tok, completion_tok}
        self.minute_events = deque(maxlen=120)  # 每秒桶

    def record(self, **kw):
        kw["ts"] = time.time()
        self.requests.append(kw)

    def snapshot(self):
        now = time.time()
        reqs = list(self.requests)
        recent = [r for r in reqs if now - r["ts"] < 600]
        ok = [r for r in recent if r.get("ok")]
        ttfts = sorted(r["ttft_ms"] for r in ok if r.get("ttft_ms"))
        totals = sorted(r["total_ms"] for r in ok)
        prompt = sum(r.get("prompt_tok") or 0 for r in recent)
        cached = sum(r.get("cached_tok") or 0 for r in recent)
        completion = sum(r.get("completion_tok") or 0 for r in recent)
        rpm = len([r for r in reqs if now - r["ts"] < 60])
        # 30 秒粒度的最近 10 分钟序列（用于图表）
        series = []
        for i in range(20):
            hi = now - i * 30
            lo = hi - 30
            bucket = [r for r in reqs if lo <= r["ts"] < hi]
            ttft_vals = sorted(r["ttft_ms"] for r in bucket if r.get("ttft_ms"))
            series.append({
                "t": int(hi), "n": len(bucket),
                "ttft": ttft_vals[len(ttft_vals)//2] if ttft_vals else None,
            })
        series.reverse()

        def pct(a, p):
            if not a:
                return None
            return a[min(len(a) - 1, int(len(a) * p))]

        return {
            "rpm": rpm, "tpm": len(recent),
            "req_10m": len(recent),
            "ok_10m": len(ok),
            "sla": (len(ok) / len(recent)) if recent else None,
            "ttft_p50": pct(ttfts, 0.5), "ttft_p95": pct(ttfts, 0.95),
            "total_p50": pct(totals, 0.5),
            "cache_hit": (cached / prompt) if prompt else None,
            "prompt_tok": prompt, "cached_tok": cached, "completion_tok": completion,
            "series": series,
            "models": sorted({r.get("model") for r in recent if r.get("model")}),
        }


metrics = Metrics()


# ───────────────────────── REST API ─────────────────────────

@app.get("/api/config")
async def get_config():
    return load_cfg()


@app.post("/api/config")
async def set_config(cfg: dict):
    save_cfg(cfg)
    return {"ok": True}


# ───────────────────────── API Keys 管理（多 key 随机生成） ─────────────────────────
# 主 key（gateway.api_key）永不可删：面板→网关内部调用与运维通道。
# api_keys 为对外发放的随机 key 列表，可随时生成/吊销；/v1 校验「主key ∪ 列表」。

def _all_keys(cfg):
    keys = [cfg["gateway"]["api_key"]]
    keys += [k.get("key", "") for k in cfg["gateway"].get("api_keys", [])]
    return [k for k in keys if k]


_key_last_used = {}   # key -> unix ts（内存态，重启清零）


@app.get("/api/keys")
async def list_keys():
    cfg = load_cfg()
    ks = []
    for k in cfg["gateway"].get("api_keys", []):
        ks.append({**k, "last_used": _key_last_used.get(k.get("key", ""))})
    return {"master": cfg["gateway"]["api_key"], "keys": ks}


@app.post("/api/keys")
async def create_key(req: dict):
    import secrets as _secrets
    name = (req.get("name") or "").strip()[:24] or "未命名"
    key = "sk-hw2api-" + _secrets.token_hex(20)
    cfg = load_cfg()
    cfg["gateway"].setdefault("api_keys", [])
    cfg["gateway"]["api_keys"].append(
        {"key": key, "name": name, "created": int(time.time())})
    save_cfg(cfg)
    return {"ok": True, "key": key, "name": name}


@app.post("/api/keys/revoke")
async def revoke_key(req: dict):
    key = (req.get("key") or "").strip()
    cfg = load_cfg()
    before = len(cfg["gateway"].get("api_keys", []))
    cfg["gateway"]["api_keys"] = [
        k for k in cfg["gateway"].get("api_keys", []) if k.get("key") != key]
    if len(cfg["gateway"]["api_keys"]) == before:
        return JSONResponse({"error": "key not found"}, status_code=404)
    save_cfg(cfg)
    _key_last_used.pop(key, None)
    return {"ok": True}


# ───────────────────────── 账户手动导入 ─────────────────────────
# 凭据为单文件一个 JSON 对象（网关 auths 格式），必要字段：
#   user_id / refresh_token / access_key_id / secret_access_key / cloud_dragon_token
#   （PKCE code_verifier 与 dpop_private_key 用于网关自动续期，强烈建议带上）
# 支持两种入参：
#   {"files": [{"name": "codearts-xxx.json", "content": {...}}]}
#   {"text": "<多个 JSON 对象依次粘贴，可带换行>"}
# 导入语义=纯添加：已存在的同名凭据跳过、绝不覆盖（保护服务器上已轮换的
# refresh_token——它是单次有效的，覆盖旧值等于杀死该账号）。

REQUIRED_FIELDS = ("user_id", "refresh_token", "access_key_id",
                   "secret_access_key", "cloud_dragon_token")


def _parse_import_payload(req):
    items = []
    for f in (req.get("files") or []):
        c = f.get("content")
        if isinstance(c, str):
            try:
                c = json.loads(c)
            except Exception:
                items.append((f.get("name", "?"), None, "content 不是合法 JSON"))
                continue
        items.append((f.get("name") or "paste.json", c, None))
    text = (req.get("text") or "").strip()
    if text:
        dec = json.JSONDecoder()
        i, n = 0, len(text)
        while i < n:
            while i < n and text[i] in " \t\r\n,;":
                i += 1
            if i >= n:
                break
            try:
                obj, end = dec.raw_decode(text, i)
            except Exception as e:
                items.append(("paste#%d" % (len(items) + 1), None, "第 %d 段解析失败: %s" % (len(items) + 1, str(e)[:60])))
                break
            items.append(("paste#%d" % (len(items) + 1), obj, None))
            i = end
    return items


@app.post("/api/accounts/import")
async def import_accounts_manual(req: dict):
    items = _parse_import_payload(req)
    if not items:
        return JSONResponse({"error": "没有可导入的内容（files 或 text 至少给一个）"}, status_code=400)
    imported, skipped, invalid = [], [], []
    for name, obj, err in items:
        if err or not isinstance(obj, dict):
            invalid.append({"name": name, "reason": err or "不是 JSON 对象"})
            continue
        missing = [k for k in REQUIRED_FIELDS if not obj.get(k)]
        if missing:
            invalid.append({"name": name, "reason": "缺少字段: " + ",".join(missing)})
            continue
        fname = "codearts-%s.json" % obj["user_id"]
        dst = os.path.join(GW_AUTHS, fname)
        if os.path.exists(dst):
            skipped.append(fname)   # 纯添加：已存在不覆盖
            continue
        json.dump(obj, open(dst, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        # 同时归档到 accounts/auths 留底
        try:
            json.dump(obj, open(os.path.join(AUTHS_DIR, fname), "w", encoding="utf-8"),
                      ensure_ascii=False, indent=2)
        except Exception:
            pass
        imported.append(fname)
    # 触发网关热重载（不重启进程，进行中的流不断）
    reload_msg = ""
    if imported:
        try:
            cfg = load_cfg()
            r = httpx.post(gw_base() + "/admin/api/reload",
                           headers={"Authorization": "Bearer " + cfg["gateway"]["api_key"]},
                           timeout=30)
            reload_msg = (r.json().get("message") or "")[:60]
        except Exception as e:
            reload_msg = "reload 失败: %s" % str(e)[:60]
    return {"ok": True, "imported": imported, "skipped": skipped,
            "invalid": invalid, "reload": reload_msg}


@app.get("/api/status")
async def status():
    cfg = load_cfg()
    health = await gw_health()
    accounts = []
    for f in sorted(os.listdir(AUTHS_DIR)):
        if not f.endswith(".json"):
            continue
        try:
            a = json.load(open(os.path.join(AUTHS_DIR, f), encoding="utf-8"))
            accounts.append({
                "file": f,
                "user_id": a.get("user_id", ""),
                "phone": a.get("user_name", ""),
                "ak": (a.get("access_key_id") or "")[:12],
                "expiration": a.get("expiration", ""),
                "has_refresh": bool(a.get("refresh_token")),
            })
        except Exception:
            pass
    if not gw_proc.running() and health.get("remote"):
        health = dict(health)
        health["accounts_n"] = health.get("accounts", 0)
    return {
        "gateway": {"running": gw_proc.running(), "health": health, "remote": bool(health.get("remote")),
                    "listen": cfg["gateway"]["listen"], "uptime": int(time.time() - gw_proc.start_ts) if gw_proc.running() else 0},
        "accounts": accounts,
        "metrics": metrics.snapshot(),
    }


@app.get("/api/gateway/logs")
async def gateway_logs():
    return {"lines": list(gw_proc.log_lines)}


@app.post("/api/gateway/{action}")
async def gateway_ctl(action: str):
    if action == "start":
        return gw_proc.start()
    if action == "stop":
        return gw_proc.stop()
    if action == "restart":
        return gw_proc.restart()
    raise HTTPException(404)


@app.websocket("/api/ws")
async def ws_hud(ws: WebSocket):
    """前端 HUD：状态与日志的推送流"""
    await ws.accept()
    last_logs = 0
    try:
        while True:
            health = await gw_health()
            payload = {
                "t": time.time(),
                "gw": {"running": gw_proc.running(), "health": health},
                "metrics": metrics.snapshot(),
            }
            await ws.send_json(payload)
            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass


# ───────────────────────── 账号/日志/模型 API ─────────────────────────

@app.get("/api/accounts/detail")
async def accounts_detail():
    # 合并三层：网关实时状态(overview) + 余额缓存 + 本地 auths 文件
    overview = {}
    try:
        async with httpx.AsyncClient(timeout=6) as c:
            r = await c.get(gw_base() + "/admin/api/overview",
                            headers={"Authorization": "Bearer " + load_cfg()["gateway"]["api_key"]})
            if r.status_code == 200:
                j = r.json()
                for a in j.get("accounts", []):
                    overview[a.get("uid") or a.get("name")] = a
    except Exception:
        pass
    out = []
    for f in sorted(os.listdir(GW_AUTHS)):
        if not f.endswith(".json"):
            continue
        try:
            a = json.load(open(os.path.join(GW_AUTHS, f), encoding="utf-8"))
        except Exception:
            continue
        uid = a.get("user_id", "")
        ov = overview.get(uid, {})
        bal = BAL_CACHE["accounts"].get(uid, {})
        # 消费曲线（最近 24h 每 10min 采样的 used 序列）
        curve = []
        try:
            rows = _db.execute(
                "SELECT ts, used FROM balances WHERE uid=? AND ts>? ORDER BY ts",
                (uid, time.time() - 86400)).fetchall()
            if rows:
                step = 600
                buckets = {}
                for ts, used in rows:
                    buckets[int(ts // step)] = used
                curve = [{"t": k * step, "used": v} for k, v in sorted(buckets.items())]
        except Exception:
            pass
        out.append({
            "uid": uid, "phone": a.get("user_name", ""),
            "ak": (a.get("access_key_id") or "")[:12],
            "expiration": a.get("expiration", ""),
            "has_refresh": bool(a.get("refresh_token")),
            "gw": {"disabled": ov.get("disabled", None), "cooling": ov.get("cooling", None),
                   "until": ov.get("until", ""), "concurrent": ov.get("active_concurrent", 0),
                   "err_count": ov.get("err_count", 0), "reason": ov.get("reason", ""),
                   "checkin": ov.get("checkin", None)},
            "balance": {"remain": bal.get("remain"), "used": bal.get("used"),
                        "total": bal.get("total"), "tokens": bal.get("tokens", 0)},
            "curve": curve,
        })
    return {"accounts": out, "bal_ts": BAL_CACHE["ts"],
            "total_remain": sum(b.get("remain") or 0 for b in BAL_CACHE["accounts"].values()),
            "total_used": sum(b.get("used") or 0 for b in BAL_CACHE["accounts"].values())}


@app.get("/api/requests")
async def requests_log(limit: int = 100, offset: int = 0, day: str = ""):
    q = "SELECT id,ts,model,account,total_ms,ttft_ms,prompt,completion,credits,ok,stream FROM requests"
    args = []
    if day:
        try:
            d0 = datetime.strptime(day, "%Y-%m-%d").timestamp()
            q += " WHERE ts>=? AND ts<?"
            args += [d0, d0 + 86400]
        except Exception:
            pass
    q += " ORDER BY id DESC LIMIT ? OFFSET ?"
    args += [max(1, min(limit, 500)), max(0, offset)]
    rows = _db.execute(q, args).fetchall()
    total = _db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
    return {"rows": [
        {"id": r[0], "ts": r[1], "model": r[2], "account": r[3],
         "total_ms": r[4], "ttft_ms": r[5], "prompt": r[6], "completion": r[7],
         "credits": r[8], "ok": bool(r[9]), "stream": bool(r[10])} for r in rows],
        "total": total}


@app.get("/api/requests/daily")
async def requests_daily():
    rows = _db.execute("""SELECT date(ts,'unixepoch','localtime') d, COUNT(*),
        SUM(prompt), SUM(completion), SUM(credits), AVG(ttft_ms)
        FROM requests GROUP BY d ORDER BY d DESC LIMIT 14""").fetchall()
    return [{"day": r[0], "n": r[1], "prompt": r[2] or 0, "completion": r[3] or 0,
             "credits": round(r[4] or 0, 2), "ttft_avg": r[5]} for r in rows]


@app.get("/api/models")
async def models_list():
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.get(gw_base() + "/v1/models",
                            headers={"Authorization": "Bearer " + load_cfg()["gateway"]["api_key"]})
            return r.json()
    except Exception as e:
        raise HTTPException(502, str(e)[:150])


@app.get("/api/automation")
async def automation_status():
    """从网关日志解析自动化事件（刷新/签到/保活）"""
    events = {"refresh": [], "checkin": [], "keepalive": []}
    for line in list(gw_proc.log_lines)[-400:]:
        if "token account=" in line:
            m = re.search(r"token account=(\S+) ok (\S+) remaining=(\S+)", line)
            if m:
                events["refresh"].append({"acct": m.group(1), "ok": m.group(2) == "ok",
                                          "remaining": m.group(3), "line": line[:150]})
        if "checkin" in line:
            events["checkin"].append(line[:150])
        if "keepalive" in line.lower():
            events["keepalive"].append(line[:150])
    for k in events:
        events[k] = events[k][-12:]
    watch = {}
    try:
        async with httpx.AsyncClient(timeout=6) as c:
            r = await c.get(gw_base() + "/admin/api/overview",
                            headers={"Authorization": "Bearer " + load_cfg()["gateway"]["api_key"]})
            if r.status_code == 200:
                watch = r.json().get("schedule", {})
    except Exception:
        pass
    return {"events": events, "watch": watch,
            "logs_recent": list(gw_proc.log_lines)[-30:]}


# ───────────────────────── /v1 透传（带指标） ─────────────────────────

@app.api_route("/v1/{path:path}", methods=["GET", "POST", "OPTIONS"])
async def v1_passthrough(path: str, request: Request):
    cfg = load_cfg()
    gw_key = cfg["gateway"]["api_key"]
    auth = request.headers.get("authorization", "")
    req_key = auth.replace("Bearer ", "")
    # 多 key 鉴权：主 key（面板→网关内部）+ 面板发放的随机 key 列表
    if req_key not in _all_keys(cfg):
        return JSONResponse({"error": {"message": "invalid api key"}}, status_code=401)
    if req_key != gw_key:
        _key_last_used[req_key] = time.time()
    base = gw_base() if gw_proc.running() else (remote_panel() or gw_base())
    url = "%s/v1/%s" % (base, path)
    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in ("host", "content-length", "authorization", "connection")}
    headers["Authorization"] = "Bearer " + gw_key
    body = await request.body()
    method = request.method

    is_chat = path == "chat/completions" and method == "POST"
    t0 = time.time()
    ttft_ms = None
    model = None
    account = ""
    prompt_tok = cached_tok = completion_tok = 0
    ok = False

    async def gen_stream():
        nonlocal ttft_ms, ok, model, prompt_tok, cached_tok, completion_tok
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream(method, url, headers=headers, content=body) as r:
                account = r.headers.get("x-hw2api-account", "")
                if r.status_code >= 400:
                    text = (await r.aread()).decode("utf-8", "ignore")
                    metrics.record(model=model, ttft_ms=None, total_ms=(time.time()-t0)*1000,
                                   ok=False)
                    yield text.encode()
                    return
                ok = True
                first = True
                sse_buf = b""
                async for chunk in r.aiter_bytes():
                    if first:
                        ttft_ms = (time.time() - t0) * 1000
                        first = False
                    sse_buf += chunk
                    # 解析 usage（最后一块）
                    for line in sse_buf.split(b"\n"):
                        if line.startswith(b"data:"):
                            try:
                                j = json.loads(line[5:].strip() or b"null")
                                if isinstance(j, dict):
                                    model = model or j.get("model")
                                    u = j.get("usage") or {}
                                    if u:
                                        prompt_tok = u.get("prompt_tokens") or prompt_tok
                                        completion_tok = u.get("completion_tokens") or completion_tok
                                        pd = u.get("prompt_tokens_details") or {}
                                        cached_tok = pd.get("cached_tokens") or cached_tok
                            except Exception:
                                pass
                    if len(sse_buf) > 262144:
                        sse_buf = sse_buf[-4096:]
                    yield chunk
                total_ms = (time.time()-t0)*1000
                metrics.record(model=model, ttft_ms=ttft_ms, total_ms=total_ms,
                               ok=ok, prompt_tok=prompt_tok, cached_tok=cached_tok,
                               completion_tok=completion_tok)
                db_log_request(model, account or "-", total_ms, ttft_ms,
                               prompt_tok, completion_tok,
                               round((prompt_tok + completion_tok) * CREDITS_PER_TOKEN, 4),
                               ok, True)

    want_stream = False
    if is_chat:
        try:
            j = json.loads(body)
            model = j.get("model")
            want_stream = bool(j.get("stream"))
        except Exception:
            pass
    if is_chat and want_stream:
        return StreamingResponse(gen_stream(), media_type="text/event-stream")
    # 非流式 / 其他端点
    async with httpx.AsyncClient(timeout=300) as client:
        r = await client.request(method, url, headers=headers, content=body)
        if is_chat and r.status_code == 200:
            try:
                j = json.loads(r.content)
                u = j.get("usage") or {}
                pd = u.get("prompt_tokens_details") or {}
                total_ms = (time.time()-t0)*1000
                metrics.record(model=j.get("model"), ttft_ms=total_ms,
                               total_ms=total_ms, ok=True,
                               prompt_tok=u.get("prompt_tokens"), cached_tok=pd.get("cached_tokens"),
                               completion_tok=u.get("completion_tokens"))
                db_log_request(j.get("model"), r.headers.get("x-hw2api-account", "-"),
                               total_ms, total_ms,
                               u.get("prompt_tokens") or 0, u.get("completion_tokens") or 0,
                               round(((u.get("prompt_tokens") or 0) + (u.get("completion_tokens") or 0)) * CREDITS_PER_TOKEN, 4),
                               True, False)
            except Exception:
                pass
        return JSONResponse(json.loads(r.content) if r.headers.get("content-type", "").startswith("application/json") else r.text,
                            status_code=r.status_code)


@app.get("/")
async def index():
    return FileResponse(os.path.join(HERE, "static", "index.html"))


@app.on_event("startup")
async def _startup():
    # 启动即同步账号凭据并拉起网关（面板重启不再丢网关）。
    # 本地与服务器共用这份代码：本地严禁拉起网关（双网关会用同一个
    # refresh_token 互相轮换踩死账号，即「注册飞号」事故根因），
    # 仅服务器 systemd 设 PANEL_AUTOSTART_GW=1 显式开启。
    import os as _os
    try:
        n = import_accounts()
        print("imported %d credentials" % n)
    except Exception as e:
        print("import failed:", e)
    if _os.environ.get("PANEL_AUTOSTART_GW", "0") != "1":
        print("gateway autostart disabled (set PANEL_AUTOSTART_GW=1 to enable)")
        return
    try:
        gw_proc.start()
        print("gateway started on startup")
    except Exception as e:
        print("gateway autostart failed:", str(e)[:120])


if __name__ == "__main__":
    cfg = load_cfg()
    host = os.environ.get("PANEL_HOST", "127.0.0.1")
    port = int(os.environ.get("PANEL_PORT", "8090"))
    print("panel on http://%s:%d" % (host, port))
    uvicorn.run(app, host=host, port=port, log_level="warning")
