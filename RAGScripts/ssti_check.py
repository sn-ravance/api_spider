#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse
import json
import re

async def check_ssti_vulnerabilities(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for SSTI
        test_cases = [
            {
                'name': 'Template Engine Detection',
                'payloads': [
                    '{{1+1}}',                     # Jinja2, Twig
                    '${1+1}',                      # Spring, FreeMarker
                    '<%= 1+1 %>',                  # ERB, EJS
                    '#{ 1+1 }',                    # Ruby Expression
                    '[%= 1+1 %]'                   # Mojolicious
                ]
            },
            {
                'name': 'Object Traversal',
                'payloads': [
                    '{{self}}',                    # Flask/Jinja2 self object
                    '{{namespace}}',               # Generic namespace access
                    '{{environment}}',             # Template environment
                    '{{template}}',                # Template object
                    '{{request}}'                  # Request object
                ]
            },
            {
                'name': 'Filter Bypass',
                'payloads': [
                    '{{"".\_\_class\_\_}}',       # Python class access
                    '{{request|attr("application")}}',  # Jinja2 filter
                    '${object.getClass()}',        # Java reflection
                    '{{variable.toString()}}',     # Object method call
                    '{{4*4}}[[5*5]]'              # Mixed syntax
                ]
            },
            {
                'name': 'Context Analysis',
                'payloads': [
                    '<%= debug() %>',              # Debug information
                    '{{settings}}',                # Application settings
                    '{{config}}',                  # Configuration access
                    '{{url_for.__globals__}}',     # Global namespace
                    '{{get_flashed_messages.__globals__}}' # Flask globals
                ]
            }
        ]
        
        # Extract parameters from initial response
        params = extract_parameters(initial_response)
        
        for param_name, param_value in params.items():
            for test in test_cases:
                for payload in test['payloads']:
                    try:
                        modified_params = params.copy()
                        modified_params[param_name] = payload
                        
                        response = requests.request(
                            method,
                            test_url,
                            params=modified_params if method == 'GET' else None,
                            data=modified_params if method != 'GET' else None,
                            headers={'Content-Type': 'application/x-www-form-urlencoded'},
                            timeout=5
                        )
                        
                        if is_ssti_vulnerable(response, test, payload):
                            findings.append({
                                "type": "SSTI",
                                "detail": f"Potential {test['name']} vulnerability",
                                "evidence": {
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "status_code": response.status_code,
                                    "response": response.text[:200]
                                }
                            })
                            
                    except requests.exceptions.RequestException:
                        continue
                    
    except Exception as e:
        print(f"Error in SSTI check: {str(e)}")
    
    return findings

def extract_parameters(response: requests.Response) -> Dict:
    params = {}
    
    # Extract URL parameters
    if response.request.url:
        parsed_url = urlparse(response.request.url)
        params.update(parse_qs(parsed_url.query))
    
    # Extract form parameters
    try:
        content = response.text
        input_pattern = r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>'
        for match in re.finditer(input_pattern, content):
            params[match.group(1)] = ''
    except:
        pass
    
    return params

def is_ssti_vulnerable(response: requests.Response, test: Dict, payload: str) -> bool:
    try:
        response_text = response.text.lower()
        
        # Check for template engine detection
        if test['name'] == 'Template Engine Detection':
            if '2' in response_text:  # Result of 1+1
                return True
        
        # Check for object traversal
        if test['name'] == 'Object Traversal':
            object_patterns = [
                '<flask.',
                '<jinja2.',
                '<werkzeug.',
                'at 0x',  # Memory address indicator
                '__main__'
            ]
            if any(pattern in response_text for pattern in object_patterns):
                return True
        
        # Check for filter bypass success
        if test['name'] == 'Filter Bypass':
            bypass_indicators = [
                'class',
                'module',
                'function',
                'method',
                'java.lang'
            ]
            if any(indicator in response_text for indicator in bypass_indicators):
                return True
        
        # Check for context information leak
        if test['name'] == 'Context Analysis':
            context_patterns = [
                'secret',
                'key',
                'password',
                'token',
                'config',
                'settings',
                'debug'
            ]
            if any(pattern in response_text for pattern in context_patterns):
                return True
        
        # Check for template errors that might indicate SSTI
        error_patterns = [
            'template syntax error',
            'parsing error',
            'evaluation failed',
            'template not found',
            'undefined variable',
            'unknown filter'
        ]
        
        if any(pattern in response_text for pattern in error_patterns):
            if response.status_code != 500:  # Expect 500 for proper error handling
                return True
        
    except:
        pass
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_ssti_vulnerabilities(
            "http://localhost:5000",
            "/template?name=test",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())