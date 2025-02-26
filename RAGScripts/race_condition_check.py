#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import asyncio
import aiohttp
import time
from RAGScripts.utils.logger import setup_scanner_logger

async def check_race_condition(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for race conditions
        test_cases = [
            {
                'name': 'Concurrent requests',
                'requests': 10,
                'delay': 0,
                'payload': {'action': 'update', 'value': 1}
            },
            {
                'name': 'Rapid sequential requests',
                'requests': 5,
                'delay': 0.1,
                'payload': {'action': 'create', 'data': 'test'}
            },
            {
                'name': 'Interleaved requests',
                'requests': 8,
                'delay': 0.05,
                'payload': {'action': 'delete', 'id': 123}
            }
        ]
        
        for test in test_cases:
            responses = await send_concurrent_requests(
                test_url,
                method,
                test['requests'],
                test['delay'],
                test['payload']
            )
            
            if is_race_condition_vulnerable(responses):
                findings.append({
                    "type": "Race Condition",
                    "detail": f"Potential {test['name']} vulnerability",
                    "evidence": {
                        "url": test_url,
                        "concurrent_requests": test['requests'],
                        "response_variations": [
                            {
                                "status_code": r.status,
                                "response": r.text[:200]
                            } for r in responses if hasattr(r, 'text')
                        ]
                    }
                })
                
    except Exception as e:
        print(f"Error in race condition check: {str(e)}")
    
    return findings

async def send_concurrent_requests(url: str, method: str, count: int, delay: float, payload: Dict) -> List[aiohttp.ClientResponse]:
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i in range(count):
            if i > 0 and delay > 0:
                await asyncio.sleep(delay)
            
            tasks.append(
                session.request(
                    method,
                    url,
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                )
            )
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in responses if not isinstance(r, Exception)]

def is_race_condition_vulnerable(responses: List[aiohttp.ClientResponse]) -> bool:
    if not responses:
        return False
    
    # Check for inconsistent status codes
    status_codes = [r.status for r in responses]
    if len(set(status_codes)) > 1:
        return True
    
    # Check for inconsistent response content
    try:
        contents = []
        for r in responses:
            if hasattr(r, 'text'):
                contents.append(r.text)
        
        if len(set(contents)) > 1:
            return True
        
        # Check for error messages indicating race conditions
        error_indicators = [
            'concurrent',
            'simultaneous',
            'deadlock',
            'lock timeout',
            'transaction conflict'
        ]
        
        for content in contents:
            if any(indicator in content.lower() for indicator in error_indicators):
                return True
                
    except:
        pass
    
    return False

if __name__ == "__main__":
    # For standalone testing
    async def test():
        result = await check_race_condition(
            "http://localhost:5000",
            "/api/resource",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())