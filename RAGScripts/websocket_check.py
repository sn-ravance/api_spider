#!/usr/bin/env python3
import requests
import websockets
import asyncio
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
import json

async def check_websocket(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        # Convert HTTP URL to WebSocket URL
        parsed_url = urlparse(target_url)
        ws_scheme = 'wss' if parsed_url.scheme == 'https' else 'ws'
        ws_url = f"{ws_scheme}://{parsed_url.netloc}{path}"
        
        # Test cases for WebSocket vulnerabilities
        test_cases = [
            {
                'name': 'Missing origin validation',
                'headers': {'Origin': 'https://evil.com'}
            },
            {
                'name': 'Protocol downgrade',
                'headers': {'Sec-WebSocket-Protocol': 'v1.0'}
            },
            {
                'name': 'Frame injection',
                'payload': '<img src=x onerror=alert(1)>'
            },
            {
                'name': 'Connection flooding',
                'connections': 5
            },
            {
                'name': 'Authentication bypass',
                'headers': {'Authorization': 'Bearer invalid_token'}
            },
            {
                'name': 'Message size overflow',
                'payload': 'A' * 65536
            },
            {
                'name': 'Protocol manipulation',
                'headers': {'Sec-WebSocket-Version': '7'}
            },
            {
                'name': 'Cross-site WebSocket hijacking',
                'headers': {'Cookie': 'session=test'}
            },
            {
                'name': 'Payload injection',
                'payload': '{"__proto__": {"admin": true}}'
            },
            {
                'name': 'Command injection',
                'payload': '{"cmd": "ping -c 1 evil.com"}'
            },
            {
                'name': 'SQL injection via WebSocket',
                'payload': '{"query": "1 OR 1=1"}'
            },
            {
                'name': 'Denial of Service',
                'payload': '{"data": ' + '"X"*1000000' + '}'
            },
            {
                'name': 'Event handler injection',
                'payload': '{"handler": "onload=alert(1)"}'
            },
            {
                'name': 'Malformed UTF-8',
                'payload': '\uD800\uDFFF'
            }
        ]

        for test in test_cases:
            try:
                if test['name'] == 'Connection flooding':
                    # Test multiple concurrent connections
                    connections = []
                    for _ in range(test['connections']):
                        ws = await websockets.connect(ws_url)
                        connections.append(ws)
                    
                    if len(connections) == test['connections']:
                        findings.append({
                            "type": "WebSocket Vulnerability",
                            "detail": "Multiple concurrent connections accepted",
                            "evidence": {
                                "url": ws_url,
                                "connection_count": len(connections)
                            }
                        })
                    
                    for ws in connections:
                        await ws.close()
                else:
                    # Test individual cases
                    async with websockets.connect(ws_url, extra_headers=test.get('headers', {})) as ws:
                        if test.get('payload'):
                            await ws.send(test['payload'])
                            response = await ws.recv()
                        else:
                            response = await ws.recv()
                        
                        if await is_websocket_vulnerable(ws, response, test):
                            findings.append({
                                "type": "WebSocket Vulnerability",
                                "detail": f"Potential {test['name']} vulnerability",
                                "evidence": {
                                    "url": ws_url,
                                    "headers": test.get('headers', {}),
                                    "payload": test.get('payload', ''),
                                    "response": response[:200]
                                }
                            })
                    
            except Exception as e:
                continue
                
    except Exception as e:
        print(f"Error in WebSocket check: {str(e)}")
    
    return findings

async def is_websocket_vulnerable(ws: websockets.WebSocketClientProtocol, response: str, test: Dict) -> bool:
    # Check for WebSocket vulnerability indicators
    
    # Check for missing origin validation
    if test['name'] == 'Missing origin validation':
        if ws.origin and ws.origin != ws.host:
            return True
    
    # Check for protocol downgrade
    if test['name'] == 'Protocol downgrade':
        if ws.subprotocol and ws.subprotocol == 'v1.0':
            return True
    
    # Check for frame injection
    if test['name'] == 'Frame injection' or test['name'] == 'Event handler injection':
        if test['payload'] in response or 'alert' in response.lower():
            return True
    
    # Check for command injection
    if test['name'] == 'Command injection':
        cmd_indicators = ['ping', 'exec', 'system', 'shell', 'command']
        if any(indicator in response.lower() for indicator in cmd_indicators):
            return True
    
    # Check for SQL injection
    if test['name'] == 'SQL injection via WebSocket':
        sql_indicators = ['sql', 'database', 'query', 'syntax', 'mysql', 'postgresql']
        if any(indicator in response.lower() for indicator in sql_indicators):
            return True
    
    # Check for DoS indicators
    if test['name'] == 'Denial of Service' or test['name'] == 'Message size overflow':
        if 'timeout' in response.lower() or 'size exceeded' in response.lower():
            return True
    
    # Check for payload injection
    if test['name'] == 'Payload injection':
        if '"admin":true' in response.lower() or '__proto__' in response:
            return True
    
    # Check for malformed data handling
    if test['name'] == 'Malformed UTF-8':
        if 'invalid' in response.lower() or 'malformed' in response.lower():
            return True
    
    # Check for general error messages
    error_indicators = [
        'websocket error',
        'connection failed',
        'invalid frame',
        'protocol error',
        'security violation',
        'unauthorized',
        'forbidden',
        'exception'
    ]
    
    if any(indicator in response.lower() for indicator in error_indicators):
        return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    async def test():
        result = await check_websocket(
            "http://localhost:5000",
            "/ws",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())