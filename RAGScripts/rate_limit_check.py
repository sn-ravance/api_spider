#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
import aiohttp
from RAGScripts.utils.logger import setup_scanner_logger

async def check_rate_limiting(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        initial_headers = dict(initial_response.headers)
        
        async with aiohttp.ClientSession() as session:
            # Test basic rate limiting
            basic_results = await test_basic_rate_limiting(session, test_url, method, initial_headers)
            findings.extend(basic_results)
            
            # Test burst requests
            burst_results = await test_burst_requests(session, test_url, method, initial_headers)
            findings.extend(burst_results)
            
            # Test rate limit bypass
            bypass_results = await test_rate_limit_bypass(session, test_url, method, initial_headers)
            findings.extend(bypass_results)
            
            # Test distributed rate limiting
            distributed_results = await test_distributed_requests(session, test_url, method, initial_headers)
            findings.extend(distributed_results)
    
    except Exception as e:
        print(f"Error in rate limiting check: {str(e)}")
    
    return findings

async def test_basic_rate_limiting(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    request_count = 50
    
    try:
        start_time = time.time()
        responses = []
        
        for _ in range(request_count):
            async with session.request(method, url, headers=headers, timeout=5) as response:
                responses.append({
                    'status': response.status,
                    'headers': dict(response.headers)
                })
                await asyncio.sleep(0.1)  # Small delay between requests
        
        total_time = time.time() - start_time
        
        if await analyze_rate_limit_responses(responses, total_time, request_count):
            findings.append({
                "type": "API4:2023",
                "name": "Lack of Rate Limiting",
                "detail": "No effective rate limiting detected",
                "evidence": {
                    "url": url,
                    "requests_sent": request_count,
                    "time_period": round(total_time, 2),
                    "success_rate": sum(1 for r in responses if r['status'] == 200) / len(responses)
                },
                "severity": "HIGH"
            })
    except:
        pass
    
    return findings

async def test_burst_requests(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    burst_size = 20
    
    try:
        tasks = []
        for _ in range(burst_size):
            tasks.append(session.request(method, url, headers=headers, timeout=5))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        valid_responses = [r for r in responses if isinstance(r, aiohttp.ClientResponse)]
        
        if len(valid_responses) > burst_size * 0.8:  # If more than 80% successful
            findings.append({
                "type": "API4:2023",
                "name": "Insufficient Burst Protection",
                "detail": "Server allows high-volume burst requests",
                "evidence": {
                    "url": url,
                    "burst_size": burst_size,
                    "successful_requests": len(valid_responses)
                },
                "severity": "MEDIUM"
            })
    except:
        pass
    
    return findings

async def test_rate_limit_bypass(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    bypass_headers = [
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Real-IP': '127.0.0.1'},
        {'Client-IP': '127.0.0.1'},
        {'X-Originating-IP': '127.0.0.1'},
        {'CF-Connecting-IP': '127.0.0.1'}
    ]
    
    try:
        for test_header in bypass_headers:
            test_headers = headers.copy()
            test_headers.update(test_header)
            
            responses = []
            for _ in range(10):
                async with session.request(method, url, headers=test_headers, timeout=5) as response:
                    responses.append(response.status)
                    await asyncio.sleep(0.1)
            
            if all(status == 200 for status in responses):
                findings.append({
                    "type": "API4:2023",
                    "name": "Rate Limit Bypass",
                    "detail": "Rate limiting bypass possible using modified headers",
                    "evidence": {
                        "url": url,
                        "bypass_header": test_header,
                        "success_rate": "100%"
                    },
                    "severity": "HIGH"
                })
    except:
        pass
    
    return findings

async def test_distributed_requests(session: aiohttp.ClientSession, url: str, method: str, headers: Dict) -> List[Dict]:
    findings = []
    test_ips = [
        '1.1.1.1',
        '2.2.2.2',
        '3.3.3.3',
        '4.4.4.4',
        '5.5.5.5'
    ]
    
    try:
        success_count = 0
        for ip in test_ips:
            test_headers = headers.copy()
            test_headers['X-Forwarded-For'] = ip
            
            async with session.request(method, url, headers=test_headers, timeout=5) as response:
                if response.status == 200:
                    success_count += 1
        
        if success_count == len(test_ips):
            findings.append({
                "type": "API4:2023",
                "name": "Distributed Rate Limit Bypass",
                "detail": "Rate limiting appears to be IP-based and can be bypassed",
                "evidence": {
                    "url": url,
                    "test_ips": test_ips,
                    "success_rate": "100%"
                },
                "severity": "CRITICAL"
            })
    except:
        pass
    
    return findings

async def analyze_rate_limit_responses(responses: List[Dict], total_time: float, request_count: int) -> bool:
    try:
        success_count = sum(1 for r in responses if r['status'] == 200)
        rate_limit_headers = [
            'x-ratelimit-limit',
            'x-ratelimit-remaining',
            'x-ratelimit-reset',
            'retry-after'
        ]
        
        # Check if rate limit headers are present
        has_rate_limit_headers = any(
            any(h.lower() in r['headers'] for h in rate_limit_headers)
            for r in responses
        )
        
        # If high success rate and no rate limit headers, likely vulnerable
        return success_count > request_count * 0.8 and not has_rate_limit_headers
    except:
        return False

if __name__ == "__main__":
    async def test():
        result = await check_rate_limiting(
            "http://localhost:5000",
            "/api/data",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())