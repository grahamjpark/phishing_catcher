import requests
import yaml
import json

with open('external.yaml', 'r') as f:
    external = yaml.safe_load(f)
    airtable_config = external["airtable"]

    
    
airtable_url = "https://api.airtable.com/v0/" + airtable_config.get("base_id") + "/Hits"

def post_to_airtable(bad_url, score, priority):
    # TODO: Create list of already posted URLs to whitelist and clean up similar urls
    # TODO: Group keywords by category to detect type of phish
    # TODO: Handle error
    # TODO: URLscan
    # TODO: Virus total
    if score < airtable_config.get("min_score"):
        return

    payload = {
        "fields": {
            "URL": bad_url,
            "Score": score,
            "Priority": priority
        }
    }

    headers = {
        'Content-Type': "application/json",
        'Authorization': "Bearer " + airtable_config.get("api_key"),
        'Accept': "*/*",
        'Cache-Control': "no-cache",
        'Host': "api.airtable.com",
        'accept-encoding': "gzip, deflate",
        'content-length': "105",
        'Connection': "keep-alive",
        'cache-control': "no-cache"
    }

    response = requests.request("POST", airtable_url, data=json.dumps(payload), headers=headers)

    # print(response.text)