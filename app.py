# ================================================================
#  🔐 DoubleCounter-style Verify Website  (Flask + Upstash Redis)
#  Runs on Railway. Talks to the bot (on Wispbyte) through Upstash
#  Redis over plain HTTP — no shared files, no open ports needed.
#
#  Flow:
#   1) Bot stores a one-time token in Redis -> user opens /verify/<token>
#   2) We read the user's REAL IP (their browser connected to us), hash it,
#      and run IPQualityScore VPN/proxy/Tor detection.
#   3) We compare the IP hash against everyone already verified (stored in
#      Redis) -> same IP as a DIFFERENT discord user = "duplicate" flag.
#   4) We push the result to a Redis list the bot reads every few seconds.
#
#  A VPN/duplicate hit is a FLAG for humans, never an auto-ban. Shared IPs
#  (family, dorms, phone carriers) are common — a mod decides.
# ================================================================
import os, json, hashlib, time
from urllib.parse import quote
import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)

# ---- config (set these as environment variables on Railway) ----
IPQS_KEY    = os.getenv("IPQS_KEY", "")                # (legacy, unused now)
PROXYCHECK_KEY = os.getenv("PROXYCHECK_KEY", "")       # proxycheck.io API key (free 1000/day)
IP_SALT     = os.getenv("IP_SALT", "change-me")        # makes stored IP hashes unreversible
REDIS_URL   = os.getenv("UPSTASH_REDIS_REST_URL", "")  # from Upstash dashboard
REDIS_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")

# ---------------- Upstash Redis over HTTP ----------------
def _redis(*command):
    """Run one Redis command via Upstash REST API. Returns the 'result' field."""
    if not REDIS_URL or not REDIS_TOKEN:
        raise RuntimeError("Upstash Redis env vars not set")
    url = REDIS_URL.rstrip("/")   # tolerate a trailing slash just in case
    tok = REDIS_TOKEN.strip().strip('"').strip("'")   # tolerate stray quotes/spaces
    try:
        r = requests.post(url,
                          headers={"Authorization": f"Bearer {tok}"},
                          json=list(command), timeout=10)
    except Exception as ex:
        print(f"REDIS CONNECT FAIL: {ex}  (url={url[:40]}...)", flush=True)
        raise
    if r.status_code != 200:
        # print the real reason to Railway logs so we can see it
        print(f"REDIS HTTP {r.status_code}: {r.text[:200]}  "
              f"(url_ok={url.endswith('.upstash.io')}, token_len={len(tok)})", flush=True)
    r.raise_for_status()
    return r.json().get("result")

# ---------------- helpers ----------------
def hash_ip(ip):
    return hashlib.sha256((IP_SALT + "|" + ip).encode()).hexdigest()

def _is_internal_ip(p):
    """Internal/proxy ranges that are NOT a real visitor IP (incl. Cloudflare edge)."""
    p = (p or "").strip()
    if not p:
        return True
    prefixes = (
        "10.", "192.168.", "127.", "169.254.", "100.64.",
        "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.",
        "35.", "34.",                       # GCP / Render internal
        "::1", "fd",
        # Cloudflare IPv4 edge ranges (partial, the common ones)
        "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
        "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
        "104.28.", "172.64.", "172.65.", "172.66.", "172.67.", "172.68.",
        "172.69.", "172.70.", "172.71.", "173.245.", "108.162.", "141.101.",
        "162.158.", "162.159.", "188.114.", "190.93.", "197.234.", "198.41.",
        "131.0.72.",
    )
    return p.startswith(prefixes)

def client_ip():
    """Real public client IP.

    Render routes through Cloudflare, so the true visitor IP arrives in
    Cf-Connecting-Ip. If that header is missing (e.g. a preload request that
    doesn't carry it), we refuse to use a proxy/edge IP (Cloudflare/GCP/Render)
    and return None, so the user's REAL click reprocesses with their true IP.
    """
    xff   = request.headers.get("X-Forwarded-For", "")
    xreal = request.headers.get("X-Real-IP", "")
    cfip  = request.headers.get("Cf-Connecting-Ip", "")
    print(f"IP-DEBUG xff={xff!r} xreal={xreal!r} cf={cfip!r} remote={request.remote_addr!r}", flush=True)

    # 1) Cloudflare's own header is the single most reliable source of the real IP
    if cfip.strip() and not _is_internal_ip(cfip):
        return cfip.strip()
    # 2) otherwise, first NON-proxy entry in X-Forwarded-For
    if xff.strip():
        for part in xff.split(","):
            part = part.strip()
            if part and not _is_internal_ip(part):
                return part
    # 3) X-Real-IP if it's a real address
    if xreal.strip() and not _is_internal_ip(xreal):
        return xreal.strip()
    return None

def check_ipqs(ip):
    """VPN/proxy/Tor detection via proxycheck.io. Free tier: 1,000/day.
    Set PROXYCHECK_KEY env var. Fails OPEN (treats as clean) on error/no key.
    Function name kept as check_ipqs so the rest of the code is unchanged.
    """
    if not PROXYCHECK_KEY:
        print("PROXYCHECK: no key set -> skipping VPN check", flush=True)
        return {"vpn": False, "proxy": False, "tor": False, "fraud_score": None, "ok": True}
    try:
        # vpn=1 enables VPN detection, risk=1 adds a risk score (0-100)
        url = f"https://proxycheck.io/v2/{quote(ip)}?key={quote(PROXYCHECK_KEY)}&vpn=1&risk=1"
        resp = requests.get(url, timeout=15)
        print(f"PROXYCHECK http_status={resp.status_code} for {ip}", flush=True)
        data = resp.json()
        node = data.get(ip, {}) if isinstance(data, dict) else {}
        status = data.get("status")
        # proxycheck returns proxy: "yes"/"no"; type can be "VPN","TOR","PUB",...
        is_proxy = str(node.get("proxy", "no")).lower() == "yes"
        ptype = str(node.get("type", "")).upper()
        is_vpn = is_proxy and ptype in ("VPN", "COMPROMISED", "COMPROMISED SERVER")
        is_tor = ptype == "TOR"
        risk = node.get("risk")
        print(f"PROXYCHECK raw for {ip}: status={status} proxy={node.get('proxy')} "
              f"type={node.get('type')} risk={risk}", flush=True)
        return {
            "vpn": bool(is_vpn),
            "proxy": bool(is_proxy),   # any proxy (incl VPN) counts as proxy
            "tor": bool(is_tor),
            "fraud_score": risk if isinstance(risk, (int, float)) else None,
            "ok": status == "ok",
        }
    except Exception as ex:
        print(f"PROXYCHECK ERROR for {ip}: {type(ex).__name__}: {ex}", flush=True)
        return {"vpn": False, "proxy": False, "tor": False, "fraud_score": None, "ok": False}

# ---------------- the verify page ----------------
PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verify</title>
<style>
 body{background:#1e1f22;color:#f2f3f5;font-family:system-ui,Segoe UI,Roboto,sans-serif;
      display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
 .card{background:#2b2d31;padding:40px 44px;border-radius:16px;max-width:420px;text-align:center;
       box-shadow:0 12px 40px rgba(0,0,0,.4)}
 h1{margin:0 0 8px;font-size:22px}
 p{color:#b5bac1;line-height:1.5}
 .ok{color:#23a55a;font-size:44px}.flag{color:#f0b232;font-size:44px}.err{color:#f23f43;font-size:44px}
</style></head><body>
 <div class="card"><div class="{{cls}}">{{icon}}</div><h1>{{title}}</h1><p>{{msg}}</p></div>
</body></html>"""

@app.route("/verify/<token>")
def verify(token):
    print(f"=== VERIFY ROUTE HIT v5 === token={token!r}", flush=True)
    # First, check if this token was ALREADY processed (e.g. link preloaded by
    # Discord/browser). If so, show the correct outcome instead of "expired".
    try:
        done = _redis("GET", f"done:{token}")
    except Exception:
        done = None
    if done:
        if done == "flagged":
            return render_template_string(PAGE, cls="flag", icon="🟡",
                title="Verification received — pending review",
                msg="Your connection was flagged (VPN/proxy or shared network). A moderator will "
                    "review it shortly. If it's a false positive, you'll get your role.")
        return render_template_string(PAGE, cls="ok", icon="✅",
            title="Verified!", msg="Head back to Discord — your role has been granted. 🎉")

    try:
        raw = _redis("GET", f"pending:{token}")
        print(f"VERIFY lookup: key=pending:{token!r} -> found={raw is not None} "
              f"type={type(raw).__name__} value={str(raw)[:60]!r}", flush=True)
    except Exception as ex:
        print(f"VERIFY GET failed: {ex}", flush=True)
        return render_template_string(PAGE, cls="err", icon="✖",
            title="Service error", msg="Verification backend is unavailable. Try again shortly."), 500
    if not raw:
        return render_template_string(PAGE, cls="err", icon="✖",
            title="Invalid or expired link", msg="Press Verify again in Discord for a fresh link."), 404
    entry = json.loads(raw)

    # if a near-simultaneous request already processed this token, show success
    try:
        if _redis("GET", f"consumed:{token}"):
            d = _redis("GET", f"done:{token}")
            if d == "flagged":
                return render_template_string(PAGE, cls="flag", icon="🟡",
                    title="Verification received — pending review",
                    msg="Your connection was flagged (VPN/proxy or shared network). A moderator will "
                        "review it shortly. If it's a false positive, you'll get your role.")
            return render_template_string(PAGE, cls="ok", icon="✅",
                title="Verified!", msg="Head back to Discord — your role has been granted. 🎉")
    except Exception:
        pass

    ip  = client_ip()
    if ip:
        iph = hash_ip(ip)
        ipqs = check_ipqs(ip)
        # duplicate-IP check is PER-SERVER: only matches other users who verified
        # in the SAME guild. Different servers have independent IP tracking.
        gid = str(entry["guild_id"])
        me  = str(entry["discord_id"])
        stored = _redis("GET", f"iplink:{gid}:{iph}")
        stored = str(stored).strip().strip('"') if stored is not None else None
        # only a DIFFERENT user on the same IP counts as a duplicate
        if stored and stored != me:
            duplicate_of = stored
        else:
            duplicate_of = None
        # (re)store MY id for this IP+guild so future OTHER users are caught
        _redis("SET", f"iplink:{gid}:{iph}", me)
        # if a mod previously approved this user in this server, never re-flag them
        if duplicate_of:
            try:
                if _redis("GET", f"cleared:{gid}:{me}"):
                    duplicate_of = None
            except Exception:
                pass
    else:
        iph = None
        ipqs = {"vpn": False, "proxy": False, "tor": False, "fraud_score": None}
        duplicate_of = None
    fs = ipqs.get("fraud_score")
    high_fraud = isinstance(fs, (int, float)) and fs >= 85
    print(f"VERIFY ip={ip!r} dup_of={duplicate_of!r} vpn={ipqs['vpn']} proxy={ipqs['proxy']} "
          f"tor={ipqs['tor']} fraud={fs} high_fraud={high_fraud}", flush=True)

    flagged = bool(ipqs["vpn"] or ipqs["proxy"] or ipqs["tor"] or duplicate_of or high_fraud)

    # If we could NOT determine a real client IP, this is almost certainly a
    # header-less preload/bot request (not the actual user). Do NOT finalize:
    # show a neutral page and leave the token pending so the user's real click
    # processes with their true IP.
    if ip is None:
        print("VERIFY skipped: no real client IP (preload/internal request)", flush=True)
        return render_template_string(PAGE, cls="ok", icon="⏳",
            title="Almost there…",
            msg="Loading your verification — if this page doesn't update, tap the link once more.")

    result = {
        "discord_id": entry["discord_id"], "guild_id": entry["guild_id"],
        "ip_debug": ip,   # real IP for console debugging
        "xff_debug": request.headers.get("X-Forwarded-For", ""),  # raw header for debugging
        "ip_hash": iph, "vpn": ipqs["vpn"], "proxy": ipqs["proxy"], "tor": ipqs["tor"],
        "fraud_score": ipqs["fraud_score"], "duplicate_of": duplicate_of,
        "flagged": flagged, "ts": int(time.time()),
    }
    _redis("RPUSH", "verify_results", json.dumps(result))
    # remember the outcome so a preloaded/second/near-simultaneous view shows the
    # right message instead of "expired". Keep the pending token too (don't delete)
    # but shorten its life; the 'consumed' flag stops double-processing.
    _redis("SET", f"done:{token}", "flagged" if flagged else "ok", "EX", "600")
    _redis("SET", f"consumed:{token}", "1", "EX", "600")
    _redis("EXPIRE", f"pending:{token}", "600")

    if flagged:
        return render_template_string(PAGE, cls="flag", icon="🟡",
            title="Verification received — pending review",
            msg="Your connection was flagged (VPN/proxy or shared network). A moderator will "
                "review it shortly. If it's a false positive, you'll get your role.")
    return render_template_string(PAGE, cls="ok", icon="✅",
        title="Verified!", msg="Head back to Discord — your role has been granted. 🎉")

@app.route("/myip")
def myip():
    xff   = request.headers.get("X-Forwarded-For", "")
    xreal = request.headers.get("X-Real-IP", "")
    cfip  = request.headers.get("Cf-Connecting-Ip", "")
    picked = client_ip()
    return (f"<pre>picked_ip = {picked}\n\n"
            f"X-Forwarded-For = {xff}\n"
            f"X-Real-IP = {xreal}\n"
            f"CF-Connecting-IP = {cfip}\n"
            f"remote_addr = {request.remote_addr}\n</pre>"), 200

@app.route("/")
def home():
    return "Verify service is running. build=v16-proxycheck", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
