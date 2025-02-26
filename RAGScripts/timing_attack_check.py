#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin
import json
import time
import statistics

async def check_timing_attack(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for timing attacks
        test_cases = [
            {
                'name': 'Parameter length variation',
                'params': [
                    {'param': 'a' * i} for i in [10, 100, 1000, 10000]
                ]
            },
            {
                'name': 'SQL injection timing',
                'params': [
                    {'param': 'normal'},
                    {'param': "' AND SLEEP(1)--"},
                    {'param': "' OR BENCHMARK(1000000,MD5('test'))--"}
                ]
            },
            {
                'name': 'Authentication bypass timing',
                'params': [
                    {'username': 'admin', 'password': 'a' * i} for i in [1, 10, 20, 30]
                ]
            }
        ]
        
        baseline_times = get_baseline_times(test_url, method)
        
        for test in test_cases:
            timing_data = []
            
            for params in test['params']:
                try:
                    start_time = time.time()
                    response = requests.request(
                        method,
                        test_url,
                        params=params if method == 'GET' else None,
                        json=params if method in ['POST', 'PUT'] else None,
                        headers={'Content-Type': 'application/json'},
                        timeout=10
                    )
                    response_time = time.time() - start_time
                    
                    timing_data.append((response_time, response, params))
                    
                except requests.exceptions.RequestException:
                    continue
            
            if is_timing_vulnerable(timing_data, baseline_times):
                findings.append({
                    "type": "Timing Attack",
                    "detail": f"Potential {test['name']} vulnerability",
                    "evidence": {
                        "url": test_url,
                        "timing_variations": [
                            {
                                "params": params,
                                "response_time": round(t, 3),
                                "status_code": r.status_code
                            } for t, r, params in timing_data
                        ],
                        "baseline_time": round(statistics.mean(baseline_times), 3)
                    }
                })
                
    except Exception as e:
        print(f"Error in timing attack check: {str(e)}")
    
    return findings

def get_baseline_times(url: str, method: str, samples: int = 10) -> List[float]:
    times = []
    for _ in range(samples):
        try:
            start_time = time.time()
            requests.request(method, url, timeout=5)
            times.append(time.time() - start_time)
            time.sleep(0.1)  # Prevent rate limiting
        except:
            continue
    return times if times else [0.1]  # Default baseline if all requests fail

def is_timing_vulnerable(timing_data: List[Tuple[float, requests.Response, Dict]], baseline_times: List[float]) -> bool:
    if not timing_data:
        return False
    
    baseline_mean = statistics.mean(baseline_times)
    baseline_stdev = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0.1
    
    times = [t for t, _, _ in timing_data]
    
    # Check for significant timing variations
    if len(times) > 1:
        # Calculate timing statistics
        mean_time = statistics.mean(times)
        max_time = max(times)
        
        # Check for outliers (more than 3 standard deviations from baseline)
        if max_time > baseline_mean + (3 * baseline_stdev):
            return True
        
        # Check for consistent timing differences
        if mean_time > baseline_mean * 2:
            return True
        
        # Check for progressive timing increases
        if len(times) > 2 and all(times[i] < times[i+1] for i in range(len(times)-1)):
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_timing_attack(
            "http://localhost:5000",
            "/api/login",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())