from flask import Flask, request
import subprocess
import datetime
import logging
import sys
import json

LISTEN_PORT = 5000
GORGONA_BIN = "gorgona"          # If the path to the binary isn't in your PATH, specify the full path, for example, /usr/local/bin/gorgona 
PUBLIC_KEY = "RWTPQzuhzBw=.pub"  # Gorgona channel public key: `sudo gorgona genkeys` 
EXPIRATION_DAYS = 10             # How many days should a message be stored in Mesh? 

app = Flask(__name__)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_utc_now():
    return datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

def get_utc_expiry():
    expiry = datetime.datetime.utcnow() + datetime.timedelta(days=EXPIRATION_DAYS)
    return expiry.strftime('%Y-%m-%d %H:%M:%S')

@app.route('/notify', methods=['POST'])
def notify():
    raw_data = request.data.decode('utf-8')
    # logging.info(f"Raw data received: {raw_data}")

    try:
        # strict=False is still required, since Proxmox sends “broken” JSON with line breaks 
        data = json.loads(raw_data, strict=False)
    except Exception as e:
        logging.error(f"JSON Decode Error: {str(e)}")
        return "Invalid JSON format", 400

    subject = data.get("subject", "")
    text = data.get("message", "")

    # IMPORTANT: Do not delete \n; simply remove any extra spaces at the beginning and end. 
    # We preserve the Proxmox log structure 
    if subject:
        full_message = f"#{subject}\n{text}".strip()
    else:
        full_message = text.strip()
    
    start_time = get_utc_now()
    end_time = get_utc_expiry()

    logging.info(f"Sending notification to Gorgona (Length: {len(full_message)} chars)")

    cmd = [GORGONA_BIN, "send", start_time, end_time, full_message, PUBLIC_KEY]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logging.info(f"Gorgona Success")
        return "OK", 200
    except subprocess.CalledProcessError as e:
        logging.error(f"Gorgona Error: {e.stderr}")
        return "Gorgona Command Failed", 500
    except Exception as e:
        logging.error(f"Bridge Error: {str(e)}")
        return "Internal Error", 500

if __name__ == '__main__':
    logging.info(f"Bridge started on port {LISTEN_PORT} with key {PUBLIC_KEY}")
    app.run(host='0.0.0.0', port=LISTEN_PORT)
