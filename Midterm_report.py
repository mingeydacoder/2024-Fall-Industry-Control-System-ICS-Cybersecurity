import requests
import json

#Analysis ip address

def ip_analysis(ip):

    url = f"https://api.ipdata.co/v1/{ip}/?api-key=aee95e0c17dbefff9e464363289684bbbda13e53b4cd037f38f83701"
    headers = {"accept": "application/json"}
    response = requests.get(url, headers=headers)
    data = response.json()
    ip_addr = data.get("ip")
    city = data.get("city")
    domain = data.get("asn").get("domain")
    threat = data.get("threat")

    return(ip_addr,city,domain,threat)


def get_analysis_id(url):
    url = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": "discozdata.org." }
    headers = {
        "accept": "application/json",
        "x-apikey": "ed09fa58b67b6de49518ffe6cfbc14cf0c93aa590f0d67020eadaed1f587907c",
        "content-type": "application/x-www-form-urlencoded"
    }

    response = requests.post(url, data=payload, headers=headers)
    if response.status_code == 200:
        response_data = response.json()
        id_part = response_data.get("data", {}).get("id", "ID not found")
        return(id_part)
    else:
        print(f"Request failed with status code: {response.status_code}")
    
def get_analysis_report(id):
    url = f"https://www.virustotal.com/api/v3/analyses/{id}"

    headers = {
        "accept": "application/json",
        "x-apikey": "ed09fa58b67b6de49518ffe6cfbc14cf0c93aa590f0d67020eadaed1f587907c"
    }

    response2 = requests.get(url, headers=headers)

    return(response2.text)


print(ip_analysis("144.178.56.0"))