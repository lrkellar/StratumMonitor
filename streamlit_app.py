"""
Stratum Closet Monitor — Streamlit app
======================================
Sign in, see the 3D site with live YoLink readings. Nothing to install on anyone's computer.

Secrets (Streamlit Cloud: App settings > Secrets; locally: .streamlit/secrets.toml):

    admins = ["admin"]     # which names are admins (must be above the [sections])

    [yolink]
    uaid = "ua_..."
    secret = "sec_..."

    [passwords]            # one line per person: name = "password hash" (or a plain password)
    admin = "scrypt$..."
    stratum = "scrypt$..."

Every signed-in person sees the same monitor. Admins also get an Accounts panel that lists the
sign-ins and turns a new password into a hashed line to paste into the secrets.
With no [yolink] section the app runs in demo mode with fake sensors.
"""
import base64
import datetime as dt
import hashlib
import hmac
import json
import math
import random
import re
import secrets as pysecrets
import time
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
import streamlit as st
import streamlit.components.v1 as components

TOKEN_URL = "https://api.yosmart.com/open/yolink/token"
API_URL = "https://api.yosmart.com/open/yolink/v2/api"
KINDS = {"THSensor": "th", "LeakSensor": "leak"}
REFRESH_SECONDS = 300          # how often the page re-reads YoLink
STALE_HOURS = 24               # warn when a sensor has not reported for this long
YOLINK_CALLS_PER_5_MIN = 100   # YoLink's limit as reported by integrators; one call per sensor per read
PAGE = Path(__file__).with_name("monitor.html")
DIAG_FILE = Path(__file__).with_name("yolink_diagnostics.json")
TZ = ZoneInfo("America/New_York")
HIDDEN_KEYS = {"deviceid", "deviceudid", "token", "parentdeviceid", "servicezone", "homeid", "msgid"}
_VER = tuple(int(x) for x in re.findall(r"\d+", st.__version__)[:2])
WIDE = {"width": "stretch"} if _VER >= (1, 50) else {"use_container_width": True}

st.set_page_config(page_title="Stratum Closet Monitor", page_icon="💧", layout="wide")
st.markdown("<style>.block-container{padding:1rem 1rem 0 1rem;max-width:100%} header{visibility:hidden}</style>", unsafe_allow_html=True)


# ----------------------------------------------------------------------------- sign-in
def hash_password(password: str) -> str:
    salt = pysecrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(key).decode()


def password_ok(password: str, stored) -> bool:
    stored = str(stored)
    if stored.startswith("scrypt$"):
        try:
            _, salt, key = stored.split("$")
            salt, key = base64.b64decode(salt), base64.b64decode(key)
            return hmac.compare_digest(hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=len(key)), key)
        except Exception:
            return False
    return hmac.compare_digest(password.encode(), stored.encode())     # plain password in the secrets


def accounts() -> dict:
    """name -> {"stored": hash or password, "admin": bool}, from the app's secrets."""
    admins = st.secrets.get("admins", [])
    admins = {str(a).strip().lower() for a in ([admins] if isinstance(admins, str) else admins)}
    return {str(n).strip().lower(): {"stored": v, "admin": str(n).strip().lower() in admins}
            for n, v in dict(st.secrets.get("passwords", {})).items()}


def signed_in():
    """Returns (name, is_admin) for the signed-in person, or None after drawing the sign-in form."""
    users = accounts()
    name = st.session_state.get("user")
    if name in users:
        return name, users[name]["admin"]
    st.session_state.pop("user", None)          # removed from the secrets since signing in
    st.title("Stratum Closet Monitor")
    if not users:
        st.error("No sign-ins are configured. Add a [passwords] section to the app's secrets.")
        return None
    with st.form("login"):
        name = st.text_input("Name").strip().lower()
        pw = st.text_input("Password", type="password")
        if st.form_submit_button("Sign in"):
            if name in users and password_ok(pw, users[name]["stored"]):
                st.session_state["user"] = name
                st.rerun()
            time.sleep(1)                       # slow down guessing
            st.error("Name or password is incorrect.")
    return None


# ----------------------------------------------------------------------------- yolink
def closet_from_name(name):
    m = re.search(r"(3\d{3})[-_ ]?(\d{1,2})\b", name or "")
    return f"{m.group(1)}-{int(m.group(2)):02d}" if m else None


def report_time(value):
    """YoLink's reportAt (ISO text, or epoch seconds / milliseconds) -> epoch seconds, or None."""
    try:
        if isinstance(value, (int, float)):
            return value / 1000 if value > 1e11 else float(value)
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def scrub(x):
    """Copy of a YoLink response with ids and tokens removed, safe to show and save."""
    if isinstance(x, dict):
        return {k: scrub(v) for k, v in x.items() if k.lower() not in HIDDEN_KEYS and "token" not in k.lower()}
    return [scrub(v) for v in x] if isinstance(x, list) else x


@st.cache_resource
def token_box():
    return {"token": None, "expires": 0}


def get_token(uaid, secret):
    box = token_box()
    if box["token"] and time.time() < box["expires"]:
        return box["token"]
    r = requests.post(TOKEN_URL, data={"grant_type": "client_credentials", "client_id": uaid, "client_secret": secret}, timeout=20)
    try:
        j = r.json()
    except ValueError:
        j = {}
    if r.status_code >= 400 or "access_token" not in j:
        raise RuntimeError(f"YoLink sign-in failed ({r.status_code}). Check the UAID and Secret Key in the app's secrets.")
    box["token"], box["expires"] = j["access_token"], time.time() + int(j.get("expires_in", 7200)) - 300
    return box["token"]


def api(access_token, method, **body):
    body.update(method=method, time=int(time.time() * 1000))
    r = requests.post(API_URL, json=body, headers={"Authorization": f"Bearer {access_token}"}, timeout=20)
    if r.status_code == 401:
        token_box()["token"] = None                # expired or revoked: sign in again on the next read
    r.raise_for_status()
    j = r.json()
    if j.get("code") != "000000":
        raise RuntimeError(f"{method}: {j.get('code')} {j.get('desc')}")
    return j.get("data", {}) or {}


@st.cache_data(ttl=REFRESH_SECONDS - 10, show_spinner="Reading sensors from YoLink…")
def read_yolink(uaid, secret):
    """One pass over the account: every leak and humidity sensor's current state. Shared by all viewers."""
    token = get_token(uaid, secret)
    closets, devices, problems = {}, [], []
    everything = api(token, "Home.getDeviceList").get("devices", [])
    raw = {"read_at": dt.datetime.now(TZ).isoformat(timespec="seconds"), "device_list": scrub(everything), "states": {}}
    targets = [d for d in everything if d.get("type") in KINDS]
    if len(targets) + 1 > YOLINK_CALLS_PER_5_MIN:
        problems.append(f"{len(targets)} sensors is more than YoLink allows one program to read in 5 minutes "
                        f"({YOLINK_CALLS_PER_5_MIN} calls); some readings below will fail until the app reads in batches.")
    for n, d in enumerate(targets):
        if n:
            time.sleep(0.4)                        # stay under YoLink's rate limit
        kind, closet = KINDS[d["type"]], closet_from_name(d.get("name"))
        row = {"name": d.get("name"), "kind": kind, "closet": closet, "model": d.get("modelName"), "online": None, "reported": None}
        devices.append(row)
        try:
            data = api(token, f"{d['type']}.getState", targetDevice=d["deviceId"], token=d["token"])
        except Exception as e:                     # one bad sensor must not blank the page
            problems.append(f"{d.get('name')}: {e}")
            raw["states"][str(d.get("name"))] = {"error": str(e)}
            continue
        raw["states"][str(d.get("name"))] = scrub(data)
        state = data.get("state", {})
        if not isinstance(state, dict):
            state = {"state": state}
        row["online"], row["reported"], row["battery"] = data.get("online"), report_time(data.get("reportAt")), state.get("battery")
        if kind == "th":
            if isinstance(state.get("humidity"), (int, float)):
                row["rh"] = state["humidity"]
            if isinstance(state.get("temperature"), (int, float)):
                row["temp"] = round(state["temperature"] * 9 / 5 + 32, 1)      # YoLink reports Celsius
        elif isinstance(state.get("state"), str):
            row["wet"] = state["state"].lower() not in ("normal", "dry")
        if not closet:
            continue
        c = closets.setdefault(closet, {})
        c.update({k: row[k] for k in ("rh", "temp", "wet") if k in row})
        if row["battery"] is not None:
            c["batt_" + kind] = row["battery"]
        c["ts"] = int(max(c.get("ts", 0), row["reported"] or time.time()))
    try:                                           # for troubleshooting a new account; ids and tokens are removed
        DIAG_FILE.write_text(json.dumps(raw, indent=1, default=str), encoding="utf-8")
    except OSError:
        pass
    return {"closets": closets, "devices": devices, "problems": problems, "read_at": time.time(), "raw": raw}


def read_demo():
    h = time.time() / 20
    closets, devices = {}, []
    for i, cid in enumerate(["3130-01", "3130-02", "3110-01"]):
        rh = round(55 - 11 * math.sin(h / 24 * 2 * math.pi) + i * 2 + random.uniform(-1, 1), 1)
        wet = i == 1 and int(time.time() / 60) % 4 == 0
        closets[cid] = {"rh": rh, "temp": round(52 + 9 * math.sin(h / 24 * 2 * math.pi), 1), "wet": wet, "batt_th": 4, "batt_leak": 4, "ts": int(time.time())}
        nm = cid.replace("-", " ")
        devices += [{"name": f"{nm} Thermometer Hygrometer", "kind": "th", "closet": cid, "online": True, "rh": rh, "temp": closets[cid]["temp"], "battery": 4, "reported": time.time()},
                    {"name": f"{nm} Leak Sensor", "kind": "leak", "closet": cid, "online": True, "wet": wet, "battery": 4, "reported": time.time()}]
    return {"closets": closets, "devices": devices, "problems": [], "read_at": time.time(), "raw": None}


@st.cache_resource
def history():
    """Humidity readings kept while the app is awake, for the sparkline. The long-term record is the YoLink app."""
    return {}


# ----------------------------------------------------------------------------- page
def clock(ts, with_date=False):
    if not ts:
        return None
    return dt.datetime.fromtimestamp(ts, TZ).strftime("%b %d %I:%M %p" if with_date else "%I:%M:%S %p").replace(" 0", " ").lstrip("0")


def render_monitor(data, demo):
    hist = history()
    for cid, c in data["closets"].items():
        if c.get("rh") is not None:
            h = hist.setdefault(cid, [])
            if not h or h[-1][0] != data["read_at"]:
                h.append((data["read_at"], c["rh"]))
                del h[:-288]
    payload = {
        "closets": {cid: {**c, "hist": [v for _, v in hist.get(cid, [])]} for cid, c in data["closets"].items()},
        "devices": [{"name": d["name"], "kind": d["kind"], "closet": d["closet"]} for d in data["devices"]],
        "status": f"{'demo' if demo else 'live'} · {len(data['closets'])} closets reporting · read {clock(data['read_at'])} · refreshes every {REFRESH_SECONDS // 60} min",
    }
    inject = "<script>window.__STRATUM_DATA = " + json.dumps(payload).replace("</", "<\\/") + ";</script>"
    html = PAGE.read_text(encoding="utf-8").replace("</head>", inject + "</head>", 1)
    if hasattr(st, "iframe"):
        st.iframe(html, height=780)
    else:                                   # older Streamlit
        components.html(html, height=780, scrolling=False)


def render_warnings(data):
    """Everything that needs a person's attention, shown to every signed-in person."""
    for d in data["devices"]:
        if d.get("wet"):
            st.error(f"💧 WATER DETECTED — closet {d['closet'] or '?'} ({d['name']})")
    notes = []
    for d in data["devices"]:
        if d.get("online") is False:
            notes.append(f"{d['name']}: offline")
        elif d.get("reported") and time.time() - d["reported"] > STALE_HOURS * 3600:
            notes.append(f"{d['name']}: no report since {clock(d['reported'], True)}")
        if isinstance(d.get("battery"), (int, float)) and d["battery"] <= 1:
            notes.append(f"{d['name']}: battery low")
        if not d.get("closet"):
            notes.append(f"{d['name']}: no building and unit in its name, so it is not on the 3D view (rename it like \"3130 01 Leak Sensor\")")
    for n in notes + list(data["problems"]):
        st.warning(n)


def render_table(data):
    with st.expander(f"Sensors ({len(data['devices'])})", expanded=True):
        st.dataframe(
            [{"Closet": d["closet"] or "(no closet in name)", "Sensor": d["name"], "Humidity %": d.get("rh"), "Temp °F": d.get("temp"),
              "Leak": None if d.get("wet") is None else ("WET" if d["wet"] else "dry"), "Battery": d.get("battery"),
              "Online": d.get("online"), "Last report": clock(d.get("reported"), True)}
             for d in sorted(data["devices"], key=lambda d: (d["closet"] or "zzz", d["kind"]))],
            hide_index=True, **WIDE)


def render_admin(me, data_raw):
    users = accounts()
    with st.expander("Accounts (admins only)"):
        st.dataframe([{"Name": n, "Role": "admin" if u["admin"] else "viewer",
                       "Password stored as": "hash" if str(u["stored"]).startswith("scrypt$") else "PLAIN TEXT — replace with a hash"}
                      for n, u in sorted(users.items())], hide_index=True, **WIDE)
        st.caption("Accounts live in the app's secrets (Streamlit Cloud: your app > ⋮ > Settings > Secrets; on a PC: .streamlit/secrets.toml). "
                   "This form does not change anything by itself: it turns a password into a hashed line for you to paste there.")
        with st.form("make_account", clear_on_submit=True):
            a, b, c = st.columns([2, 2, 1])
            name = a.text_input("Name").strip().lower()
            pw = b.text_input("Password", type="password")
            role = c.selectbox("Role", ["Same as now", "Viewer", "Admin"], help="Same as now: keeps an existing person's role; a new person is a viewer.")
            go = st.form_submit_button("Make secrets line")
        if go:
            if not re.fullmatch(r"[a-z0-9_-]{2,32}", name):
                st.error("Use 2 to 32 letters, digits, - or _ for the name.")
            elif len(pw) < 8:
                st.error("Use at least 8 characters for the password.")
            else:
                st.write(f"**{'Replace the' if name in users else 'Add this'} line under `[passwords]`**, then Save. The app restarts by itself and the change applies within a minute.")
                st.code(f'{name} = "{hash_password(pw)}"', language="toml")
                current = {n for n, u in users.items() if u["admin"]}
                wanted = current | {name} if role == "Admin" else current - {name} if role == "Viewer" else current
                if wanted != current:
                    st.write("**And change the `admins` line at the top to:**")
                    st.code("admins = " + json.dumps(sorted(wanted)), language="toml")
        st.caption("To remove a person, delete their line under [passwords] (and their name from admins). They are signed out the next time their page refreshes.")
    if data_raw:
        with st.expander("YoLink diagnostics (admins only)"):
            st.caption("What YoLink returned on the last read, with ids and tokens removed. Also saved as yolink_diagnostics.json next to the app.")
            st.json(data_raw, expanded=False)


def main():
    who = signed_in()
    if not who:
        return
    me, is_admin = who
    yl = st.secrets.get("yolink", {})
    demo = not (yl.get("uaid") and yl.get("secret"))

    @st.fragment(run_every=REFRESH_SECONDS)
    def live():
        try:
            data = read_demo() if demo else read_yolink(yl["uaid"], yl["secret"])
        except Exception as e:
            st.error(f"Could not read YoLink: {e}")
            data = None
        if demo:
            st.info("Demo mode: fake sensors. Add your YoLink credential to the app's secrets to see real ones.")
        if data:
            render_monitor(data, demo)
        left, right = st.columns([5, 1])
        with right:
            if st.button("Refresh now", **WIDE):
                read_yolink.clear()
                st.rerun(scope="fragment")
            if st.button("Sign out", **WIDE):
                st.session_state.pop("user", None)
                st.rerun()
            st.caption(f"Signed in as {me}" + (" (admin)" if is_admin else ""))
        if data:
            with left:
                render_warnings(data)
                render_table(data)
            st.session_state["raw"] = data.get("raw")

    live()
    if is_admin:
        render_admin(me, st.session_state.get("raw"))


main()
