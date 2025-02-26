#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse
import json
import re
import base64
import pickle
from RAGScripts.utils.logger import setup_scanner_logger

async def check_deserialization_vulnerabilities(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for insecure deserialization
        test_cases = [
            {
                'name': 'Python Pickle',
                'payloads': [
                    base64.b64encode(pickle.dumps({'data': 'test'})).decode(),
                    base64.b64encode(pickle.dumps(['test', 'data'])).decode(),
                    base64.b64encode(pickle.dumps(('test', 'data'))).decode(),
                    base64.b64encode(pickle.dumps(set(['test']))).decode(),
                    base64.b64encode(pickle.dumps(b'test')).decode()
                ]
            },
            {
                'name': 'Java Serialization',
                'payloads': [
                    'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQZ',
                    'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwAB',
                    'rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0D',
                    'rO0ABXNyABpqYXZhLnV0aWwuTGlua2VkSGFzaE1hcDiM',
                    'rO0ABXNyABBqYXZhLnV0aWwuVmVjdG9y'
                ]
            },
            {
                'name': 'PHP Serialization',
                'payloads': [
                    'O:8:"stdClass":0:{}',
                    'a:2:{i:0;s:4:"test";i:1;s:4:"data"}',
                    'O:4:"Test":1:{s:4:"data";s:4:"test"}',
                    's:4:"test";',
                    'i:1234;'
                ]
            },
            {
                'name': 'YAML Deserialization',
                'payloads': [
                    '!!python/object:__main__.Test {}',
                    '!!python/object/apply:os.system ["id"]',
                    '!!python/object/new:type {}',
                    '!!python/name:subprocess.Popen []',
                    '!!python/object/apply:subprocess.check_output []'
                ]
            }
        ]
        
        # Extract parameters from initial response
        params = extract_parameters(initial_response)
        content_type = initial_response.headers.get('Content-Type', '')
        
        for param_name, param_value in params.items():
            for test in test_cases:
                for payload in test['payloads']:
                    try:
                        modified_params = params.copy()
                        modified_params[param_name] = payload
                        
                        headers = {'Content-Type': content_type} if content_type else {}
                        
                        response = requests.request(
                            method,
                            test_url,
                            params=modified_params if method == 'GET' else None,
                            data=modified_params if method != 'GET' else None,
                            headers=headers,
                            timeout=5
                        )
                        
                        if is_deserialization_vulnerable(response, test, payload):
                            findings.append({
                                "type": "Insecure Deserialization",
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
        print(f"Error in deserialization check: {str(e)}")
    
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

def is_deserialization_vulnerable(response: requests.Response, test: Dict, payload: str) -> bool:
    try:
        response_text = response.text.lower()
        
        # Check for Python pickle-related issues
        if test['name'] == 'Python Pickle':
            error_patterns = [
                'pickle.',
                'unpickle',
                'objectloader',
                '__reduce__',
                '__getstate__'
            ]
            if any(pattern in response_text for pattern in error_patterns):
                return True
        
        # Check for Java deserialization issues
        if test['name'] == 'Java Serialization':
            error_patterns = [
                'java.io.',
                'objectinputstream',
                'readobject',
                'serializable',
                'classloader'
            ]
            if any(pattern in response_text for pattern in error_patterns):
                return True
        
        # Check for PHP deserialization issues
        if test['name'] == 'PHP Serialization':
            error_patterns = [
                'unserialize',
                '__wakeup',
                '__destruct',
                'php_serialize',
                'object injection'
            ]
            if any(pattern in response_text for pattern in error_patterns):
                return True
        
        # Check for YAML deserialization issues
        if test['name'] == 'YAML Deserialization':
            error_patterns = [
                'yaml.',
                'unsafe_load',
                'constructor',
                'pyyaml',
                'load_all'
            ]
            if any(pattern in response_text for pattern in error_patterns):
                return True
        
        # Check for general deserialization errors
        error_patterns = [
            'type error',
            'class not found',
            'cannot instantiate',
            'deserialization',
            'object creation failed'
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
        result = await check_deserialization_vulnerabilities(
            "http://localhost:5000",
            "/api/data",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())