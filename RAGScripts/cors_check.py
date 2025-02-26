#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_cors_vulnerabilities(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for CORS abuse
        test_cases = [
            {
                'name': 'Null origin',
                'origin': 'null',
                'headers': {
                    'Origin': 'null',
                    'Access-Control-Request-Method': 'GET'
                }
            },
            {
                'name': 'Wildcard subdomain',
                'origin': f'https://evil.{target_url.split("//")[1]}',
                'headers': {
                    'Origin': f'https://evil.{target_url.split("//")[1]}',
                    'Access-Control-Request-Method': 'GET'
                }
            },
            {
                'name': 'Reflected origin',
                'origin': 'https://attacker.com',
                'headers': {
                    'Origin': 'https://attacker.com',
                    'Access-Control-Request-Method': 'POST'
                }
            },
            {
                'name': 'Pre-flight manipulation',
                'origin': 'https://malicious.com',
                'headers': {
                    'Origin': 'https://malicious.com',
                    'Access-Control-Request-Method': 'PUT',
                    'Access-Control-Request-Headers': 'X-Custom-Header'
                }
            }
        ]
        
        for test in test_cases:
            try:
                # Pre-flight OPTIONS request
                options_response = requests.options(
                    test_url,
                    headers=test['headers'],
                    timeout=5
                )
                
                # Actual request with CORS headers
                response = requests.request(
                    method,
                    test_url,
                    headers={'Origin': test['origin']},
                    timeout=5
                )
                
                if is_cors_vulnerable(response, options_response, test):
                    findings.append({
                        "type": "CORS Abuse",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "origin": test['origin'],
                            "options_headers": dict(options_response.headers),
                            "response_headers": dict(response.headers),
                            "status_code": response.status_code
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in CORS check: {str(e)}")
    
    return findings

def is_cors_vulnerable(response: requests.Response, options_response: requests.Response, test: Dict) -> bool:
    # Extract CORS headers
    acao = response.headers.get('Access-Control-Allow-Origin', '')
    acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()
    acam = options_response.headers.get('Access-Control-Allow-Methods', '')
    acah = options_response.headers.get('Access-Control-Allow-Headers', '')
    
    # Check for null origin vulnerability
    if test['name'] == 'Null origin':
        if acao == 'null' and acac == 'true':
            return True
    
    # Check for wildcard subdomain vulnerability
    if test['name'] == 'Wildcard subdomain':
        if test['origin'] in acao or '*' in acao:
            return True
    
    # Check for reflected origin vulnerability
    if test['name'] == 'Reflected origin':
        if acao == test['origin'] and acac == 'true':
            return True
    
    # Check for pre-flight manipulation vulnerability
    if test['name'] == 'Pre-flight manipulation':
        if ('PUT' in acam or '*' in acam) and ('x-custom-header' in acah.lower() or '*' in acah):
            return True
    
    # General CORS misconfigurations
    if '*' in acao and acac == 'true':
        return True
    
    if response.status_code == 200:
        # Check for sensitive data in response with permissive CORS
        sensitive_data = [
            'password',
            'token',
            'key',
            'secret',
            'credential',
            'auth'
        ]
        
        try:
            response_text = response.text.lower()
            if any(data in response_text for data in sensitive_data):
                if acao == test['origin'] or '*' in acao:
                    return True
        except:
            pass
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_cors_vulnerabilities(
            "http://localhost:5000",
            "/api/data",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())