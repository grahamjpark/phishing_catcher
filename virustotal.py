import requests
import yaml
import json
import time

with open('external.yaml', 'r') as f:
    external = yaml.safe_load(f)
    virustotal_config = external["virustotal"]

virustotal_url = 'https://www.virustotal.com/vtapi/v2/url/scan'

def scan_url(bad_url):
    try:
        print("Scanning url via VirusTotal")
        payload = {
            "url": bad_url,
            "apikey": virustotal_config["api_key"]
        }
        response = requests.post(virustotal_url, data=payload)
        
        if response.status_code == 204:
            print("WARNING: Exceeded VirusTotal limit, continuing on without it.")
            return None
        elif response.status_code != 200:
            print("ERROR: VirusTotal returned a non-200 response code: {}".format(response.status_code))
            print("Full response: {}".format(response.text))
            return None

        return response.json()

    except Exception as e:
        print("ERROR: Hitting VirusTotal resulted in the following exception: {}".format(repr(e)))