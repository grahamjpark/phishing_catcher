import requests
import yaml
import json
from urlscan import scan_url

with open('external.yaml', 'r') as f:
    external = yaml.safe_load(f)
    airtable_config = external["airtable"]
    
airtable_url = "https://api.airtable.com/v0/" + airtable_config.get("base_id") + "/Hits"

already_logged = []

def _is_postable(bad_url, score, indicators):
    if score < airtable_config.get("min_score"):
        return False
    elif bad_url in already_logged:
        print("Domain already logged")
        return False
    else:
        return True
    # Check whitelist (remove www if present)
    # Add custom checks (like for particular indicators)

def _trim_url(bad_url):
    if bad_url.startswith("*."):
        return bad_url[2:]
    if bad_url.startswith("www."):
        return bad_url[4:]
    else:
        return bad_url


def update_logged_list():
    try:
        print("Updating list of already logged domains")
        querystring = {"fields[]":"URL"}
        headers = {
            'Content-Type': "application/json",
            'Authorization': "Bearer " + airtable_config.get("api_key"),
        }
        response = requests.request("GET", airtable_url, headers=headers, params=querystring)

        if response.status_code != 200:
            print("ERROR: Airtable returned a non-200 response code: {}".format(response.status_code))
            print("Full response: {}".format(response.text))
            return

        for record in response.json().get("records", []):
            already_logged.append(record.get("fields", {}).get("URL"))

    except Exception as e:
        print("ERROR: Pulling from airtable resulted in the following exception: {}".format(repr(e)))

def post_to_airtable(bad_url, score, priority, indicators=[]):
    # TODO: Group keywords by category to detect type of phish
    # TODO: Dynamically use indicators as a select multiple (requires creating new options)
    # TODO: Make this a class, pull down existing URLs and update indicators on initialization
    # TODO: Virus total
    try:
        trimmed_url = _trim_url(bad_url)
        
        if not _is_postable(trimmed_url, score, indicators):
            return

        print("Posting to airtable")
        payload = {
            "fields": {
                "URL": trimmed_url,
                "Score": score,
                "Priority": priority
            }
        }

        if external.get("use_urlscan"):
            urlscan_response = scan_url(trimmed_url)
            if urlscan_response and urlscan_response.get("result"):
                payload["fields"].update({
                    "URLScan": urlscan_response.get("result")
                })

        headers = {
            'Content-Type': "application/json",
            'Authorization': "Bearer " + airtable_config.get("api_key"),
        }
        response = requests.request("POST", airtable_url, data=json.dumps(payload), headers=headers)

        if response.status_code != 200:
            print("ERROR: Airtable returned a non-200 response code: {}".format(response.status_code))
            print("Full response: {}".format(response.text))
        else:
            already_logged.append(trimmed_url)

    except Exception as e:
        print("ERROR: Posting to airtable resulted in the following exception: {}".format(repr(e)))
