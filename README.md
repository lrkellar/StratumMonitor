# Stratum Closet Monitor (Streamlit)

3D view of the Stratum site with live YoLink leak and humidity readings. People open a link and sign in; nothing is installed on their computers.

## Put it online (Streamlit Community Cloud, free)
1. Create a **private** GitHub repository and upload everything in this folder (keep the folder layout).
2. Go to share.streamlit.io, sign in with GitHub, click **Create app**, pick the repository, and set the main file to `streamlit_app.py`.
3. Open **Advanced settings** and paste the contents of `.streamlit/secrets.toml.example` into **Secrets**, filled in with your YoLink UAID and Secret Key and a name and password for each person.
4. Deploy. Send coworkers the app link and their name and password.

To add or remove a person later: App settings > Secrets, edit the `[passwords]` list, Save.

## How it behaves
- Reads every sensor from YoLink every 5 minutes (one read is shared by everyone viewing). "Refresh now" forces a read.
- Sensors are matched to closets by name: `3130 01 Leak Sensor`, `3130 01 Thermometer Hygrometer`.
- With no `[yolink]` secrets it runs in demo mode with fake sensors.
- The sparkline history lasts only while the app is awake; the long-term record is the YoLink app. Use the monitor's Library button to replay YoLink exports.
- A free app goes to sleep when nobody has used it for a while; the first visit afterwards takes about a minute to wake.

## Run on your own PC instead
    pip install -r requirements.txt
    streamlit run streamlit_app.py
