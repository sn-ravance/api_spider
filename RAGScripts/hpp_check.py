#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse
import json
from RAGScripts.utils.logger import setup_scanner_logger

async def check_hpp(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        parsed_url = urlparse(test_url)
        query_params = parse_qs(parsed_url.query)
        
        # Test scenarios for HTTP Parameter Pollution
        test_cases = [
            {
                'params': {'param': ['value1', 'value2']},
                'desc': 'Multiple parameter values'
            },
            {
                'params': {'param[]': ['value1', 'value2']},
                'desc': 'Array parameter notation'
            },
            {
                'params': {'param[0]': 'value1', 'param[1]': 'value2'},
                'desc': 'Indexed parameter notation'
            },
            {
                'params': {'param.0': 'value1', 'param.1': 'value2'},
                'desc': 'Dot notation parameters'
            }
        ]
        
        # Test query parameters
        for param_name in query_params.keys():
            for test in test_cases:
                modified_params = query_params.copy()
                test_param = {f"{param_name}{k[5:] if k.startswith('param') else ''}": v 
                            for k, v in test['params'].items()}
                modified_params.update(test_param)
                
                try:
                    response = requests.request(
                        method,
                        test_url,
                        params=modified_params,
                        headers={'Content-Type': 'application/json'},
                        timeout=5
                    )
                    
                    if is_hpp_vulnerable(response, initial_response):
                        findings.append({
                            "type": "HTTP Parameter Pollution",
                            "detail": f"{test['desc']} in parameter {param_name}",
                            "evidence": {
                                "url": test_url,
                                "parameters": modified_params,
                                "status_code": response.status_code,
                                "response": response.text[:200]
                            }
                        })
                except requests.exceptions.RequestException:
                    continue
        
        # Test request body for POST/PUT methods
        if method in ['POST', 'PUT']:
            for test in test_cases:
                try:
                    response = requests.request(
                        method,
                        test_url,
                        json=test['params'],
                        headers={'Content-Type': 'application/json'},
                        timeout=5
                    )
                    
                    if is_hpp_vulnerable(response, initial_response):
                        findings.append({
                            "type": "HTTP Parameter Pollution",
                            "detail": f"{test['desc']} in request body",
                            "evidence": {
                                "url": test_url,
                                "payload": test['params'],
                                "status_code": response.status_code,
                                "response": response.text[:200]
                            }
                        })
                except requests.exceptions.RequestException:
                    continue
                
    except Exception as e:
        print(f"Error in HPP check: {str(e)}")
    
    return findings

def is_hpp_vulnerable(response: requests.Response, initial_response: requests.Response) -> bool:
    # Check for HPP indicators
    if response.status_code != initial_response.status_code:
        return True
        
    try:
        # Compare response content
        initial_data = initial_response.json()
        response_data = response.json()
        
        # Check for array responses or modified data structures
        if isinstance(response_data, list) and not isinstance(initial_data, list):
            return True
            
        # Check for unexpected data merging
        if isinstance(response_data, dict) and isinstance(initial_data, dict):
            if len(response_data) != len(initial_data):
                return True
                
        # Check for parameter value concatenation
        if any(isinstance(v, str) and ',' in v for v in response_data.values()):
            return True
            
    except:
        pass
        
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_hpp(
            "http://localhost:5000",
            "/api/test?param=value",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())