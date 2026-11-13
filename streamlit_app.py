"""
Stratum Closet Monitor — Streamlit app
======================================
Sign in, see the 3D site with live YoLink readings. Nothing to install on anyone's computer.

Secrets (Streamlit Cloud: App settings > Secrets; locally: .streamlit/secrets.toml):

    [yolink]
    uaid = "ua_..."
    secret = "sec_..."

    [passwords]            # one line per person: name = "password"
    lance = "choose-a-password"

With no [yolink] section the app runs in demo mode with fake sensors.
"""
import datetime as dt
import hmac
import json
import math
import random
import re
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
PAGE = Path(__file__).with_name("monitor.html")

st.set_page_config(page_title="Stratum Closet Monitor", page_icon="💧", layout="wide")
st.markdown("<style>.block-container{padding:1rem 1rem 0 1rem;max-width:100%} header{visibility:hidden}</style>", unsafe_allow_html=True)


# ----------------------------------------------------------------------------- sign-in
def signed_in() -> bool:
    if st.session_state.get("user"):
        return True
    users = dict(st.secrets.get("passwords", {}))
    st.title("Stratum Closet Monitor")
    if not users:
        st.error("No sign-ins are configured. Add a [passwords] section to the app's secrets.")
        return False
    with st.form("login"):
        name = st.text_input("Name").strip().lower()
        pw = st.text_input("Password", type="password")
        if st.form_submit_button("Sign in"):
            expected = users.get(name)
            if expected is not None and hmac.compare_digest(str(pw), str(expected)):
                st.session_state["user"] = name
                st.rerun()
            time.sleep(1)                       # slow down guessing
            st.error("Name or password is incorrect.")
    return False


# ----------------------------------------------------------------------------- yolink
def closet_from_name(name):
    m = re.search(r"(3\d{3})[-_ ]?(\d{1,2})\b", name or "")
    return f"{m.group(1)}-{int(m.group(2)):02d}" if m else None


@st.cache_resource
def token_box():
    return {"token": None, "expires": 0}


def get_token(uaid, secret):
    box = token_box()
    if box["token"] and time.time() < box["expires"]:
        return box["token"]
    r = requests.post(TOKEN_URL, data={"grant_type": "client_credentials", "client_id": uaid, "client_secret": secret}, timeout=20)
    j = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    if r.status_code >= 400 or "access_token" not in j:
        raise RuntimeError(f"YoLink sign-in failed ({r.status_code}). Check the UAID and Secret Key in the app's secrets.")
    box["token"], box["expires"] = j["access_token"], time.time() + int(j.get("expires_in", 7200)) - 300
    return box["token"]


def api(access_token, method, **body):
    body.update(method=method, time=int(time.time() * 1000))
    r = requests.post(API_URL, json=body, headers={"Authorization": f"Bearer {access_token}"}, timeout=20)
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
    targets = [d for d in api(token, "Home.getDeviceList").get("devices", []) if d.get("type") in KINDS]
    for n, d in enumerate(targets):
        kind, closet = KINDS[d["type"]], closet_from_name(d.get("name"))
        row = {"name": d.get("name"), "kind": kind, "closet": closet, "online": None, "reported": None}
        devices.append(row)
        try:
            data = api(token, f"{d['type']}.getState", targetDevice=d["deviceId"], token=d["token"])
        except Exception as e:                     # one bad sensor must not blank the page
            problems.append(f"{d.get('name')}: {e}")
            continue
        state = data.get("state", {})
        if not isinstance(state, dict):
            state = {"state": state}
        row["online"], row["reported"] = data.get("online"), data.get("reportAt")
        if not closet:
            continue
        c = closets.setdefault(closet, {})
        if kind == "th":
            if state.get("humidity") is not None:
                c["rh"] = state["humidity"]
            if state.get("temperature") is not None:
                c["temp"] = round(state["temperature"] * 9 / 5 + 32, 1)
        elif isinstance(state.get("state"), str):
            c["wet"] = state["state"].lower() not in ("normal", "dry")
        if state.get("battery") is not None:
            c["batt_" + kind] = state["battery"]
        c["ts"] = int(time.time())
        row.update({k: c.get(k) for k in (("rh", "temp") if kind == "th" else ("wet",))}, battery=state.get("battery"))
        if n < len(targets) - 1:
            time.sleep(0.4)                        # stay under YoLink's rate limit
    return {"closets": closets, "devices": devices, "problems": problems, "read_at": time.time()}


def read_demo():
    h = time.time() / 20
    closets, devices = {}, []
    for i, cid in enumerate(["3130-01", "3130-02", "3110-01"]):
        rh = round(55 - 11 * math.sin(h / 24 * 2 * math.pi) + i * 2 + random.uniform(-1, 1), 1)
        wet = i == 1 and int(time.time() / 60) % 4 == 0
        closets[cid] = {"rh": rh, "temp": round(52 + 9 * math.sin(h / 24 * 2 * math.pi), 1), "wet": wet, "batt_th": 4, "batt_leak": 4, "ts": int(time.time())}
        nm = cid.replace("-", " ")
        devices += [{"name": f"{nm} Thermometer Hygrometer", "kind": "th", "closet": cid, "online": True, "rh": rh, "temp": closets[cid]["temp"], "battery": 4},
                    {"name": f"{nm} Leak Sensor", "kind": "leak", "closet": cid, "online": True, "wet": wet, "battery": 4}]
    return {"closets": closets, "devices": devices, "problems": [], "read_at": time.time()}


@st.cache_resource
def history():
    """Humidity readings kept while the app is awake, for the sparkline. The long-term record is the YoLink app."""
    return {}


# ----------------------------------------------------------------------------- page
def render_monitor(data, demo):
    hist = history()
    for cid, c in data["closets"].items():
        if c.get("rh") is not None:
            h = hist.setdefault(cid, [])
            if not h or h[-1][0] != data["read_at"]:
                h.append((data["read_at"], c["rh"]))
                del h[:-288]
    when = dt.datetime.fromtimestamp(data["read_at"], ZoneInfo("America/New_York")).strftime("%I:%M:%S %p").lstrip("0")
    payload = {
        "closets": {cid: {**c, "hist": [v for _, v in hist.get(cid, [])]} for cid, c in data["closets"].items()},
        "devices": [{"name": d["name"], "kind": d["kind"], "closet": d["closet"]} for d in data["devices"]],
        "status": f"{'demo' if demo else 'live'} · {len(data['closets'])} closets reporting · read {when} · refreshes every {REFRESH_SECONDS // 60} min",
    }
    inject = "<script>window.__STRATUM_DATA = " + json.dumps(payload).replace("</", "<\\/") + ";</script>"
    html = PAGE.read_text(encoding="utf-8").replace("</head>", inject + "</head>", 1)
    if hasattr(st, "iframe"):
        st.iframe(html, height=780)
    else:                                   # older Streamlit
        components.html(html, height=780, scrolling=False)


def main():
    if not signed_in():
        return
    yl = st.secrets.get("yolink", {})
    demo = not (yl.get("uaid") and yl.get("secret"))

    @st.fragment(run_every=REFRESH_SECONDS)
    def live():
        try:
            data = read_demo() if demo else read_yolink(yl["uaid"], yl["secret"])
        except Exception as e:
            st.error(f"Could not read YoLink: {e}")
            return
        if demo:
            st.info("Demo mode: fake sensors. Add your YoLink credential to the app's secrets to see real ones.")
        render_monitor(data, demo)
        left, right = st.columns([5, 1])
        with right:
            if st.button("Refresh now", width="stretch"):
                read_yolink.clear()
                st.rerun(scope="fragment")
            if st.button("Sign out", width="stretch"):
                st.session_state.pop("user", None)
                st.rerun()
        with left, st.expander(f"Sensors ({len(data['devices'])})", expanded=False):
            st.dataframe(
                [{"Closet": d["closet"] or "(no closet in name)", "Sensor": d["name"], "Humidity %": d.get("rh"), "Temp °F": d.get("temp"),
                  "Leak": None if d.get("wet") is None else ("WET" if d["wet"] else "dry"), "Battery": d.get("battery"),
                  "Online": d.get("online"), "Last report": d.get("reported")}
                 for d in sorted(data["devices"], key=lambda d: (d["closet"] or "zzz", d["kind"]))],
                width="stretch", hide_index=True)
            for p in data["problems"]:
                st.warning(p)

    live()


main()
