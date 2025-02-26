#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_oauth2_vulnerabilities(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for OAuth2 abuse
        test_cases = [
            {
                'name': 'CSRF token bypass',
                'params': {
                    'response_type': 'code',
                    'client_id': 'valid_client',
                    'redirect_uri': 'http://attacker.com/callback',
                    'scope': 'read write',
                    'state': ''  # Missing CSRF token
                }
            },
            {
                'name': 'Redirect URI manipulation',
                'params': {
                    'response_type': 'code',
                    'client_id': 'valid_client',
                    'redirect_uri': 'https://legitimate-site.com.attacker.com',
                    'scope': 'read write',
                    'state': 'random_state'
                }
            },
            {
                'name': 'Scope escalation',
                'params': {
                    'response_type': 'code',
                    'client_id': 'valid_client',
                    'redirect_uri': 'http://legitimate-site.com/callback',
                    'scope': 'admin system_access all_permissions',
                    'state': 'random_state'
                }
            },
            {
                'name': 'Implicit flow abuse',
                'params': {
                    'response_type': 'token',
                    'client_id': 'valid_client',
                    'redirect_uri': 'http://legitimate-site.com/callback',
                    'scope': 'read write',
                    'state': 'random_state'
                }
            }
        ]
        
        auth_endpoint = detect_oauth_endpoint(initial_response)
        if not auth_endpoint:
            auth_endpoint = test_url
        
        for test in test_cases:
            try:
                response = requests.get(
                    auth_endpoint,
                    params=test['params'],
                    allow_redirects=False,
                    timeout=5
                )
                
                if is_oauth_vulnerable(response, test):
                    findings.append({
                        "type": "OAuth2 Abuse",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": auth_endpoint,
                            "params": test['params'],
                            "status_code": response.status_code,
                            "location": response.headers.get('Location', ''),
                            "response": response.text[:200]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in OAuth2 check: {str(e)}")
    
    return findings

def detect_oauth_endpoint(response: requests.Response) -> Optional[str]:
    # Check response headers for OAuth endpoints
    auth_endpoints = [
        'authorization_endpoint',
        'oauth_authorization_endpoint',
        'oauth2_authorization_endpoint'
    ]
    
    for header in response.headers:
        if header.lower() in auth_endpoints:
            return response.headers[header]
    
    # Check response body for OAuth endpoints
    try:
        body = response.json()
        for endpoint in auth_endpoints:
            if endpoint in body:
                return body[endpoint]
    except:
        pass
    
    # Check HTML content for OAuth-related links
    try:
        content = response.text.lower()
        indicators = [
            'oauth', 'authorize', 'authentication', 'auth/authorize',
            'oauth2/authorize', 'oauth/auth'
        ]
        
        for indicator in indicators:
            if indicator in content:
                # Basic pattern matching for URLs
                start = content.find('http', content.find(indicator))
                if start != -1:
                    end = content.find('"', start)
                    if end != -1:
                        return content[start:end]
    except:
        pass
    
    return None

def is_oauth_vulnerable(response: requests.Response, test: Dict) -> bool:
    # Check redirect response
    if response.status_code in [301, 302, 303, 307, 308]:
        location = response.headers.get('Location', '')
        
        # CSRF token bypass check
        if test['name'] == 'CSRF token bypass':
            if location and 'code=' in location and 'state=' not in location:
                return True
        
        # Redirect URI manipulation check
        if test['name'] == 'Redirect URI manipulation':
            parsed = urlparse(location)
            if parsed.netloc.endswith('attacker.com'):
                return True
        
        # Scope escalation check
        if test['name'] == 'Scope escalation':
            params = parse_qs(urlparse(location).query)
            sensitive_scopes = ['admin', 'system_access', 'all_permissions']
            if 'scope' in params and any(scope in params['scope'][0] for scope in sensitive_scopes):
                return True
        
        # Implicit flow abuse check
        if test['name'] == 'Implicit flow abuse':
            if 'access_token=' in location or 'token=' in location:
                return True
    
    # Check for error messages indicating OAuth issues
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        response_json = {}
    
    response_text = json.dumps(response_json).lower()
    error_indicators = [
        'invalid_request',
        'unauthorized_client',
        'access_denied',
        'invalid_scope',
        'server_error'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_oauth2_vulnerabilities(
            "http://localhost:5000",
            "/oauth/authorize",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())