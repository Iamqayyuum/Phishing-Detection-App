import requests

# Paste your exact FYP2 API Key inside the quotes below
API_KEY = "AIzaSyA6QMFPz8Umhqm0C2Cfml4TrO3xePoulbY"
URL_TO_TEST = "http://google.com"

endpoint = f"https://webrisk.googleapis.com/v1/uris:search?key={API_KEY}"
params = {
    "uri": URL_TO_TEST,
    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]
}

print("Pinging Google Web Risk...")
response = requests.get(endpoint, params=params)

print(f"Status Code: {response.status_code}")
print("--- EXACT GOOGLE RESPONSE ---")
print(response.text)