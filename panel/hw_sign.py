# -*- coding: utf-8 -*-
"""华为云 SDK-HMAC-SHA256 请求签名（CodeArts snap-access 那套）
验证收割的 AK/SK/STS 凭据可直接调用上游。
"""
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def _encode_uri(path: str) -> str:
    # canonicalURI：路径先解码再按 JS encodeURIComponent 集合重编码，'/'
    out = []
    for ch in urllib.parse.unquote(path):
        if ch == "/":
            out.append("/")
        elif ch.isalnum() or ch in "-_.!~*'()":
            out.append(ch)
        else:
            out.extend("%%%02X" % b for b in ch.encode())
    return "".join(out)


def _encode_query(url_query: str) -> str:
    if not url_query:
        return ""
    pairs = []
    for kv in url_query.split("&"):
        if not kv:
            continue
        k, _, v = kv.partition("=")
        def dec(s):
            try:
                return urllib.parse.unquote_plus(s)
            except Exception:
                return None
        dk, dv = dec(k), dec(v)
        if dk is None or dv is None:
            continue  # Go 语义：坏对整对丢弃
        def enc(s):
            out = []
            for ch in s:
                if ch.isalnum() or ch in "-_.!~*'()":
                    out.append(ch)
                else:
                    out.extend("%%%02X" % b for b in ch.encode())
            return "".join(out)
        pairs.append((enc(dk), enc(dv)))
    pairs.sort()
    return "&".join("%s=%s" % p for p in pairs)


def sign_request(method, url, headers, body, ak, sk, security_token=""):
    u = urllib.parse.urlsplit(url)
    t = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = u.path or "/"
    canonical_uri = _encode_uri(path)
    if not canonical_uri.endswith("/"):
        canonical_uri += "/"   # 强制补尾斜杠
    canonical_query = _encode_query(u.query)
    body_hash = hashlib.sha256(body or b"").hexdigest()
    hdrs = dict(headers)
    hdrs["X-Sdk-Date"] = t
    if security_token:
        hdrs["X-Security-Token"] = security_token
    hdrs["X-Sdk-Content-Sha256"] = body_hash
    host = u.netloc
    hdrs.setdefault("Host", host)
    signed = []
    canon_lines = []
    for k in sorted(hdrs.keys()):
        lk = k.lower()
        canon_lines.append("%s:%s" % (lk, hdrs[k].strip()))
        signed.append(lk)
    canonical_headers = "\n".join(canon_lines) + "\n"
    canonical_request = "\n".join([
        method.upper(), canonical_uri, canonical_query,
        canonical_headers, ";".join(signed), body_hash])
    sts = "SDK-HMAC-SHA256\n%s\n%s" % (
        t, hashlib.sha256(canonical_request.encode()).hexdigest())
    sig = hmac.new(sk.encode(), sts.encode(), hashlib.sha256).hexdigest()
    hdrs["Authorization"] = ("SDK-HMAC-SHA256 Access=%s, SignedHeaders=%s, Signature=%s"
                             % (ak, ";".join(signed), sig))
    return hdrs


def main():
    phone = sys.argv[1] if len(sys.argv) > 1 else "17170245093"
    acc = json.load(open(os.path.join(HERE, "..", "accounts", "%s.json" % phone), encoding="utf-8"))
    c = acc["codearts_credential"]
    url = "https://snap-access.cn-north-4.myhuaweicloud.com/v1/model/builtin"
    hdrs = sign_request("GET", url, {"Accept": "application/json", "Agent-Type": "PromptCenter"}, b"",
                        c["access_key_id"], c["secret_access_key"], c["security_token"])
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
            models = []
            if isinstance(data, dict):
                models = [m.get("model_id") or m.get("id") or m.get("name")
                          for m in (data.get("models") or data.get("result") or data.get("data") or [])]
            print("HTTP %d | 模型数: %s" % (r.status, len(models)))
            print("样例:", models[:12])
    except urllib.error.HTTPError as e:
        print("HTTP", e.code, e.read()[:300])


if __name__ == "__main__":
    main()
