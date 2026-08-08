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
    r = requests.post(REDIS_URL,
                      headers={"Authorization": f"Bearer {REDIS_TOKEN}"},
                      json=list(command), timeout=10)
    r.raise_for_status()
    return r.json().get("result")

# ---------------- helpers ----------------
def hash_ip(ip):
    return hashlib.sha256((IP_SALT + "|" + ip).encode()).hexdigest()

def client_ip():
    """Real client IP. Railway sits behind a proxy, so trust the first X-Forwarded-For hop."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

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
    try:
        raw = _redis("GET", f"pending:{token}")
    except Exception:
        return render_template_string(PAGE, cls="err", icon="✖",
            title="Service error", msg="Verification backend is unavailable. Try again shortly."), 500
    if not raw:
        return render_template_string(PAGE, cls="err", icon="✖",
            title="Invalid or expired link", msg="Press Verify again in Discord for a fresh link."), 404
    entry = json.loads(raw)

    ip  = client_ip()
    iph = hash_ip(ip)
    ipqs = check_ipqs(ip)

    # duplicate-IP: is this hash already linked to a DIFFERENT discord user?
    duplicate_of = _redis("GET", f"iplink:{iph}")
    if duplicate_of == entry["discord_id"]:
        duplicate_of = None  # same person re-verifying is fine

    flagged = bool(ipqs["vpn"] or ipqs["proxy"] or ipqs["tor"] or duplicate_of)

    result = {
        "discord_id": entry["discord_id"], "guild_id": entry["guild_id"],
        "ip_hash": iph, "vpn": ipqs["vpn"], "proxy": ipqs["proxy"], "tor": ipqs["tor"],
        "fraud_score": ipqs["fraud_score"], "duplicate_of": duplicate_of,
        "flagged": flagged, "ts": int(time.time()),
    }
    _redis("RPUSH", "verify_results", json.dumps(result))
    _redis("DEL", f"pending:{token}")   # one-time use

    if flagged:
        return render_template_string(PAGE, cls="flag", icon="🟡",
            title="Verification received — pending review",
            msg="Your connection was flagged (VPN/proxy or shared network). A moderator will "
                "review it shortly. If it's a false positive, you'll get your role.")
    return render_template_string(PAGE, cls="ok", icon="✅",
        title="Verified!", msg="Head back to Discord — your role has been granted. 🎉")

@app.route("/")
def home():
    return "Verify service is running.", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
