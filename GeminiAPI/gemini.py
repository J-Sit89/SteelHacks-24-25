import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("API_KEY")
url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={API_KEY}"

headers = {
    'Content-Type': 'application/json'
}

data = {
    "contents": [
        {
            "parts": [
                {"text": "Give me a one line joke"}
            ]
        }
    ]
}

response = requests.post(url, headers=headers, data=json.dumps(data))

if response.status_code == 200:
    response_json = response.json()
    answer = response_json['candidates'][0]['content']['parts'][0]['text']
    print(answer)
else:
    print(f"Error: {response.status_code} - {response.text}")
