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
IPQS_KEY    = os.getenv("IPQS_KEY", "")                # IPQualityScore Default API Key
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

def client_ip():
    """Real public client IP behind Render's load balancer.

    On Render, the real client is the LEFTMOST entry of X-Forwarded-For
    (Render's LB appends its own hops to the right). Cloudflare header wins
    if present. This also works on most standard proxied hosts.
    """
    xff   = request.headers.get("X-Forwarded-For", "")
    xreal = request.headers.get("X-Real-IP", "")
    cfip  = request.headers.get("Cf-Connecting-Ip", "")
    print(f"IP-DEBUG xff={xff!r} xreal={xreal!r} cf={cfip!r} remote={request.remote_addr!r}", flush=True)

    if cfip.strip():
        return cfip.strip()
    if xff.strip():
        first = xff.split(",")[0].strip()
        if first:
            return first
    if xreal.strip():
        return xreal.strip()
    return None

def check_ipqs(ip):
    """{vpn, proxy, tor, fraud_score, ok}. Fails OPEN (treats as clean) if no key/error."""
    if not IPQS_KEY:
        return {"vpn": False, "proxy": False, "tor": False, "fraud_score": None, "ok": True}
    try:
        url = f"https://ipqualityscore.com/api/json/ip/{quote(IPQS_KEY)}/{quote(ip)}?strictness=1"
        r = requests.get(url, timeout=10).json()
        return {
            "vpn": bool(r.get("vpn")),
            "proxy": bool(r.get("proxy")),
            "tor": bool(r.get("tor")),
            "fraud_score": r.get("fraud_score"),
            "ok": bool(r.get("success", False)),
        }
    except Exception:
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
        # duplicate-IP: is this EXACT IP already linked to a DIFFERENT discord user?
        duplicate_of = _redis("GET", f"iplink:{iph}")
        if duplicate_of == entry["discord_id"]:
            duplicate_of = None  # same person re-verifying is fine
        # store the link IMMEDIATELY (not via the bot poller) so the very next
        # person on this IP is detected without a timing gap
        _redis("SET", f"iplink:{iph}", entry["discord_id"])
    else:
        iph = None
        ipqs = {"vpn": False, "proxy": False, "tor": False, "fraud_score": None}
        duplicate_of = None
    print(f"VERIFY ip={ip!r} dup_of={duplicate_of!r} vpn={ipqs['vpn']} proxy={ipqs['proxy']} tor={ipqs['tor']}", flush=True)

    flagged = bool(ipqs["vpn"] or ipqs["proxy"] or ipqs["tor"] or duplicate_of)

    result = {
        "discord_id": entry["discord_id"], "guild_id": entry["guild_id"],
        "ip_debug": ip,   # real IP for console debugging
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
    return "Verify service is running. build=v9", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
