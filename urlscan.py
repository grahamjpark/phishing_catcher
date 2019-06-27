import requests
import yaml
import json
import time

with open('external.yaml', 'r') as f:
    external = yaml.safe_load(f)
    urlscan_config = external["urlscan"]
    
urlscan_url = "https://urlscan.io/api/v1/scan/"

def scan_url(bad_url):
    try:
        print("Scanning url")
        payload = {
            "url": bad_url,
            "public": urlscan_config["public_scans"]
        }

        headers = {
            'Content-Type': "application/json",
            'API-Key': urlscan_config["api_key"]
        }

        response = requests.request("POST", urlscan_url, data=json.dumps(payload), headers=headers)
        
        if response.status_code == 429:
            print("WARNING: Hitting urlscan too quick, sleeping then will try again.")
            time.sleep(2)
            return scan_url(bad_url)
        elif response.status_code != 200:
            print("ERROR: URLScan returned a non-200 response code: {}".format(response.status_code))
            print("Full response: {}".format(response.text))
            return None

        return response.json()

    except Exception as e:
        print("ERROR: Hitting URLScan resulted in the following exception: {}".format(repr(e)))