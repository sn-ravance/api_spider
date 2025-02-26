#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class CSRFScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, token: Optional[str] = None) -> List[Dict]:
        logger = setup_scanner_logger("csrf_check")
        vulnerabilities = []
        
        test_scenarios = [
            {
                'name': 'Missing CSRF token',
                'headers': {'Origin': 'http://evil.com'}
            },
            {
                'name': 'Invalid CSRF token',
                'headers': {
                    'Origin': 'http://evil.com',
                    'X-CSRF-Token': 'invalid_token'
                }
            },
            {
                'name': 'Modified Origin',
                'headers': {
                    'Origin': 'http://evil.com',
                    'Referer': 'http://evil.com/fake'
                }
            }
        ]
        
        for scenario in test_scenarios:
            try:
                headers = {
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {token}' if token else '',
                    **scenario['headers']
                }
                
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    json={'test': 'data'},
                    timeout=5
                )
                
                if response.status_code in [200, 201, 202]:
                    vuln = {
                        'type': 'CSRF_VULNERABILITY',
                        'severity': 'HIGH',
                        'detail': f'Potential CSRF vulnerability - {scenario["name"]}',
                        'evidence': {
                            'url': url,
                            'method': method,
                            'scenario': scenario['name'],
                            'headers_sent': headers,
                            'status_code': response.status_code,
                            'response': response.text[:500]
                        }
                    }
                    vulnerabilities.append(vuln)
                    
            except requests.RequestException as e:
                logger.error(f"Error in {scenario['name']}: {str(e)}")
                
        return vulnerabilities

scan = CSRFScanner.scan

def check_csrf_vulnerabilities(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for CSRF abuse
        test_cases = [
            {
                'name': 'Missing CSRF token',
                'modification': lambda h, d: ({}, {})
            },
            {
                'name': 'Empty CSRF token',
                'modification': lambda h, d: ({'X-CSRF-Token': ''}, {'csrf_token': ''})
            },
            {
                'name': 'Invalid CSRF token',
                'modification': lambda h, d: (
                    {'X-CSRF-Token': 'invalid_token'},
                    {'csrf_token': 'invalid_token'}
                )
            },
            {
                'name': 'Predictable CSRF token',
                'modification': lambda h, d: (
                    {'X-CSRF-Token': generate_predictable_token()},
                    {'csrf_token': generate_predictable_token()}
                )
            }
        ]
        
        original_headers = extract_csrf_headers(initial_response)
        original_data = extract_csrf_data(initial_response)
        
        for test in test_cases:
            try:
                modified_headers, modified_data = test['modification'](original_headers, original_data)
                headers = {**original_headers, **modified_headers}
                data = {**original_data, **modified_data}
                
                response = requests.request(
                    method,
                    test_url,
                    headers=headers,
                    data=data,
                    allow_redirects=False,
                    timeout=5
                )
                
                if is_csrf_vulnerable(response, test):
                    findings.append({
                        "type": "CSRF Abuse",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "method": method,
                            "original_headers": original_headers,
                            "modified_headers": modified_headers,
                            "original_data": original_data,
                            "modified_data": modified_data,
                            "status_code": response.status_code,
                            "response": response.text[:200]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in CSRF check: {str(e)}")
    
    return findings

def extract_csrf_headers(response: requests.Response) -> Dict:
    headers = {}
    csrf_header_patterns = [
        r'X-CSRF-Token',
        r'X-CSRFToken',
        r'_csrf',
        r'csrf-token',
        r'xsrf-token'
    ]
    
    for header in response.headers:
        if any(re.search(pattern, header, re.IGNORECASE) for pattern in csrf_header_patterns):
            headers[header] = response.headers[header]
    
    return headers

def extract_csrf_data(response: requests.Response) -> Dict:
    data = {}
    try:
        content = response.text
        csrf_patterns = [
            r'<input[^>]+name=["\']csrf[^"\']*["\'][^>]*value=["\'](.*?)["\']',
            r'<input[^>]+value=["\'](.*?)["\'][^>]*name=["\']csrf[^"\']*["\']',
            r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\'](.*?)["\']',
            r'csrf_token["\']:\s*["\']([^"\']+)'
        ]
        
        for pattern in csrf_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                data['csrf_token'] = match.group(1)
                break
    except:
        pass
    
    return data

def generate_predictable_token() -> str:
    from datetime import datetime
    timestamp = datetime.now().strftime('%Y%m%d')
    return f'csrf_token_{timestamp}'

def is_csrf_vulnerable(response: requests.Response, test: Dict) -> bool:
    # Check if the request was successful despite CSRF protection
    if response.status_code < 400:
        # Success indicators in response
        success_indicators = [
            'success',
            'created',
            'updated',
            'deleted',
            'modified'
        ]
        
        try:
            response_json = response.json()
            response_text = json.dumps(response_json).lower()
        except json.JSONDecodeError:
            response_text = response.text.lower()
        
        if any(indicator in response_text for indicator in success_indicators):
            return True
        
        # Check for specific test cases
        if test['name'] == 'Missing CSRF token':
            return True
        
        if test['name'] == 'Empty CSRF token':
            if not response_text.strip():
                return True
        
        if test['name'] == 'Invalid CSRF token':
            if 'invalid' not in response_text and 'error' not in response_text:
                return True
        
        if test['name'] == 'Predictable CSRF token':
            if 'token' not in response_text.lower():
                return True
    
    # Check for missing security headers
    security_headers = [
        'X-Frame-Options',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-XSS-Protection'
    ]
    
    if not any(header in response.headers for header in security_headers):
        return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_csrf_vulnerabilities(
            "http://localhost:5000",
            "/api/update",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())