#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import re
from RAGScripts.utils.logger import setup_scanner_logger

async def check_postmessage(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for postMessage vulnerabilities
        test_cases = [
            {
                'name': 'Missing origin check',
                'payload': '<script>window.postMessage("test", "*")</script>'
            },
            {
                'name': 'Weak origin validation',
                'payload': '<script>window.postMessage("test", "https://evil.com")</script>'
            },
            {
                'name': 'Data injection',
                'payload': '<script>window.postMessage(JSON.stringify({malicious: "data"}), "*")</script>'
            },
            {
                'name': 'Event listener pollution',
                'payload': '<script>window.addEventListener("message", function(e) { alert(1) });</script>'
            }
        ]
        
        for test in test_cases:
            try:
                # Test in different contexts
                headers = {'Content-Type': 'text/html'}
                params = {'callback': test['payload']}
                
                response = requests.request(
                    method,
                    test_url,
                    headers=headers,
                    params=params,
                    timeout=5
                )
                
                if is_postmessage_vulnerable(response, test):
                    findings.append({
                        "type": "Insecure postMessage",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "payload": test['payload'],
                            "status_code": response.status_code,
                            "response": response.text[:200]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in postMessage check: {str(e)}")
    
    return findings

def is_postmessage_vulnerable(response: requests.Response, test: Dict) -> bool:
    # Check for postMessage vulnerability indicators
    response_text = response.text.lower()
    
    # Check for unsafe postMessage usage
    if 'postmessage' in response_text:
        # Check for missing origin validation
        if test['name'] == 'Missing origin check':
            if 'postmessage(' in response_text and '"*"' in response_text:
                return True
        
        # Check for weak origin validation
        if test['name'] == 'Weak origin validation':
            origin_checks = re.findall(r'e\.origin\s*===?\s*[\'"]([^\'"]+)[\'"]', response_text)
            if origin_checks and any(not o.startswith('https://') for o in origin_checks):
                return True
        
        # Check for unsafe data handling
        if test['name'] == 'Data injection':
            if 'json.parse' in response_text and 'postmessage' in response_text:
                return True
        
        # Check for event listener issues
        if test['name'] == 'Event listener pollution':
            if 'addeventlistener("message"' in response_text and not 'e.origin' in response_text:
                return True
    
    # Check for reflected payloads
    if test['payload'].lower() in response_text:
        return True
    
    # Check for error messages indicating postMessage handling
    error_indicators = [
        'message event',
        'cross-origin',
        'origin not allowed',
        'invalid origin',
        'postmessage error'
    ]
    
    if any(indicator in response_text for indicator in error_indicators):
        if response.status_code < 400:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_postmessage(
            "http://localhost:5000",
            "/api/test",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())