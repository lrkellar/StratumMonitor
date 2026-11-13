# Stratum Closet Monitor (Streamlit)

3D view of the Stratum site with live YoLink leak and humidity readings. People open a link and sign in; nothing is installed on their computers.

## Put it online (Streamlit Community Cloud, free)
1. Create a **private** GitHub repository and upload everything in this folder (keep the folder layout).
2. Go to share.streamlit.io, sign in with GitHub, click **Create app**, pick the repository, and set the main file to `streamlit_app.py`.
3. Open **Advanced settings** and paste the contents of `.streamlit/secrets.toml.example` into **Secrets**, filled in with your YoLink UAID and Secret Key and a password for `admin` and `stratum`.
4. Deploy. An app deployed from a private repository starts out visible only to you: open the app's **Share** button and make it public so coworkers reach the sign-in page without a Streamlit invitation. The repository stays private.
5. Send coworkers the app link and their name and password.

## Accounts
Everyone who signs in sees the same monitor. Names listed in `admins` also get an **Accounts** panel: it lists the sign-ins and turns a name and password into a hashed line. Paste that line under `[passwords]` in the app's Secrets and Save; the app restarts itself. To remove a person, delete their line. The app never stores or changes passwords on its own.

## How it behaves
- Reads YoLink in the background 8 times a day (every 3 hours from midnight, plus once when the app starts), one call per sensor, at most 50 calls every 10 minutes. A full pass over 360 sensors takes about 70 minutes. The page updates after each batch. "Refresh now" starts a reading early, at the same pace. To change the numbers add `[schedule]` with `readings_per_day`, `batch_calls` or `batch_minutes` to the secrets.
- The monitor is not the leak alarm: a leak can be up to 3 hours old before it shows here. Keep YoLink's own phone alerts on for that.
- Readings only happen while the app is awake. A free app sleeps when nobody has opened it for a while and reads again as soon as someone wakes it.
- Sensors are matched to closets by name: `3130 01 Leak Sensor`, `3130 01 Thermometer Hygrometer`.
- With no `[yolink]` secrets it runs in demo mode with fake sensors.
- The sparkline history lasts only while the app is awake; the long-term record is the YoLink app. Use the monitor's Library button to replay YoLink exports.
- A free app goes to sleep when nobody has used it for a while; the first visit afterwards takes about a minute to wake.

## Run on your own PC instead
Double-click `Run locally.bat` (the first run opens the secrets file for you to fill in), or:

    pip install -r requirements.txt
    streamlit run streamlit_app.py

Each read also writes `yolink_diagnostics.json` (what YoLink returned, ids and tokens removed) for troubleshooting.
