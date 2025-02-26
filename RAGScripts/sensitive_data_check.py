#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import re
from RAGScripts.utils.logger import setup_scanner_logger

async def check_sensitive_data(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test for sensitive data exposure
        response = requests.request(
            method,
            test_url,
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        
        # Check response headers
        header_findings = check_headers(response)
        findings.extend(header_findings)
        
        # Check response body
        body_findings = check_response_body(response)
        findings.extend(body_findings)
        
        # Check for debug information
        debug_findings = check_debug_info(response)
        findings.extend(debug_findings)
        
    except Exception as e:
        print(f"Error in sensitive data check: {str(e)}")
    
    return findings

def check_headers(response: requests.Response) -> List[Dict]:
    findings = []
    sensitive_headers = {
        'Server': 'Server version disclosure',
        'X-Powered-By': 'Technology stack disclosure',
        'X-AspNet-Version': '.NET version disclosure',
        'X-AspNetMvc-Version': 'MVC version disclosure',
        'X-Runtime': 'Ruby version disclosure',
        'X-Version': 'Application version disclosure'
    }
    
    for header, desc in sensitive_headers.items():
        if header in response.headers:
            findings.append({
                "type": "Sensitive Header Exposure",
                "detail": desc,
                "evidence": {
                    "header": header,
                    "value": response.headers[header]
                }
            })
    
    return findings

def check_response_body(response: requests.Response) -> List[Dict]:
    findings = []
    
    # Patterns for sensitive data
    patterns = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        'api_key': r'(?i)(api[_-]?key|access[_-]?token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})["\'?]',
        'password': r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?[^"\'\s]+["\'?]',
        'private_key': r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
        'social_security': r'\b\d{3}[-]?\d{2}[-]?\d{4}\b',
        'aws_key': r'(?i)aws[_-]?(secret|key|token)',
        'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
    }
    
    try:
        response_text = response.text
        for data_type, pattern in patterns.items():
            matches = re.finditer(pattern, response_text)
            for match in matches:
                findings.append({
                    "type": "Sensitive Data Exposure",
                    "detail": f"Found potential {data_type} in response",
                    "evidence": {
                        "data_type": data_type,
                        "context": response_text[max(0, match.start()-20):min(len(response_text), match.end()+20)]
                    }
                })
    except:
        pass
    
    return findings

def check_debug_info(response: requests.Response) -> List[Dict]:
    findings = []
    
    debug_indicators = [
        ('stack trace', r'(?i)(stack trace|stacktrace)'),
        ('file path', r'(?i)[A-Z]:\\[A-Za-z0-9\\-_]+\.(php|js|py|rb|java|cs)'),
        ('debug info', r'(?i)(debug|warning|error|exception)'),
        ('internal IP', r'\b(?:127\.0\.0\.1|192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\b'),
        ('database error', r'(?i)(sql syntax|mysql error|postgresql error|ora-\d{5}|database error)')
    ]
    
    try:
        response_text = response.text.lower()
        for indicator_name, pattern in debug_indicators:
            if re.search(pattern, response_text):
                findings.append({
                    "type": "Debug Information Exposure",
                    "detail": f"Found {indicator_name} in response",
                    "evidence": {
                        "indicator": indicator_name,
                        "sample": response_text[:200]
                    }
                })
    except:
        pass
    
    return findings

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_sensitive_data(
            "http://localhost:5000",
            "/api/users",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())