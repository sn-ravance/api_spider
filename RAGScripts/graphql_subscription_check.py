#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import websockets
import asyncio
from RAGScripts.utils.logger import setup_scanner_logger

async def check_graphql_subscriptions(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        ws_url = test_url.replace('http', 'ws')
        
        # Test cases for GraphQL subscription abuse
        test_cases = [
            {
                'name': 'Subscription flooding',
                'subscription': '''
                    subscription {
                        userUpdates {
                            id
                            status
                            lastAction
                        }
                    }
                ''',
                'connections': 50  # Number of simultaneous connections to attempt
            },
            {
                'name': 'Long-lived subscription',
                'subscription': '''
                    subscription {
                        systemEvents {
                            type
                            severity
                            details
                        }
                    }
                ''',
                'duration': 30  # Duration in seconds to maintain connection
            },
            {
                'name': 'Privileged subscription',
                'subscription': '''
                    subscription {
                        adminNotifications {
                            message
                            level
                            timestamp
                        }
                        securityAlerts {
                            type
                            source
                            data
                        }
                    }
                '''
            },
            {
                'name': 'Nested subscription',
                'subscription': '''
                    subscription {
                        dataStream {
                            sensitive {
                                internal
                                restricted
                            }
                            updates {
                                configChanges
                                secretRotations
                            }
                        }
                    }
                '''
            }
        ]
        
        for test in test_cases:
            try:
                if test['name'] == 'Subscription flooding':
                    findings.extend(await test_subscription_flooding(ws_url, test))
                elif test['name'] == 'Long-lived subscription':
                    findings.extend(await test_long_lived_subscription(ws_url, test))
                else:
                    findings.extend(await test_single_subscription(ws_url, test))
                    
            except Exception as e:
                print(f"Error in subscription test {test['name']}: {str(e)}")
                continue
                
    except Exception as e:
        print(f"Error in GraphQL subscription check: {str(e)}")
    
    return findings

async def test_subscription_flooding(ws_url: str, test: Dict) -> List[Dict]:
    findings = []
    connections = []
    
    try:
        for _ in range(test['connections']):
            ws = await websockets.connect(ws_url)
            await ws.send(json.dumps({
                'type': 'start',
                'payload': {
                    'query': test['subscription']
                }
            }))
            connections.append(ws)
        
        # Wait briefly to check if connections are maintained
        await asyncio.sleep(2)
        
        active_connections = sum(1 for ws in connections if not ws.closed)
        if active_connections > 10:  # Arbitrary threshold
            findings.append({
                "type": "GraphQL Subscription Abuse",
                "detail": "Potential subscription flooding vulnerability",
                "evidence": {
                    "url": ws_url,
                    "subscription": test['subscription'],
                    "active_connections": active_connections
                }
            })
            
    finally:
        for ws in connections:
            if not ws.closed:
                await ws.close()
    
    return findings

async def test_long_lived_subscription(ws_url: str, test: Dict) -> List[Dict]:
    findings = []
    
    try:
        ws = await websockets.connect(ws_url)
        await ws.send(json.dumps({
            'type': 'start',
            'payload': {
                'query': test['subscription']
            }
        }))
        
        start_time = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - start_time < test['duration']:
            try:
                message = await asyncio.wait_for(ws.recv(), timeout=1.0)
                if is_subscription_vulnerable(message, test):
                    findings.append({
                        "type": "GraphQL Subscription Abuse",
                        "detail": "Potential long-lived subscription vulnerability",
                        "evidence": {
                            "url": ws_url,
                            "subscription": test['subscription'],
                            "duration": test['duration'],
                            "message": message[:200]
                        }
                    })
                    break
            except asyncio.TimeoutError:
                continue
                
    finally:
        if not ws.closed:
            await ws.close()
    
    return findings

async def test_single_subscription(ws_url: str, test: Dict) -> List[Dict]:
    findings = []
    
    try:
        ws = await websockets.connect(ws_url)
        await ws.send(json.dumps({
            'type': 'start',
            'payload': {
                'query': test['subscription']
            }
        }))
        
        try:
            message = await asyncio.wait_for(ws.recv(), timeout=5.0)
            if is_subscription_vulnerable(message, test):
                findings.append({
                    "type": "GraphQL Subscription Abuse",
                    "detail": f"Potential {test['name']} vulnerability",
                    "evidence": {
                        "url": ws_url,
                        "subscription": test['subscription'],
                        "message": message[:200]
                    }
                })
        except asyncio.TimeoutError:
            pass
            
    finally:
        if not ws.closed:
            await ws.close()
    
    return findings

def is_subscription_vulnerable(message: str, test: Dict) -> bool:
    try:
        message_json = json.loads(message)
    except json.JSONDecodeError:
        return False
    
    message_text = json.dumps(message_json).lower()
    
    # Check for privileged data
    if test['name'] == 'Privileged subscription':
        sensitive_fields = ['adminnotifications', 'securityalerts', 'level', 'source']
        if any(field in message_text for field in sensitive_fields):
            return True
    
    # Check for nested sensitive data
    if test['name'] == 'Nested subscription':
        sensitive_data = ['internal', 'restricted', 'configchanges', 'secretrotations']
        if any(data in message_text for data in sensitive_data):
            return True
    
    # Check for error messages indicating subscription issues
    error_indicators = [
        'unauthorized',
        'forbidden',
        'permission denied',
        'invalid subscription',
        'subscription error'
    ]
    
    if any(indicator in message_text for indicator in error_indicators):
        return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_graphql_subscriptions(
            "http://localhost:5000",
            "/graphql",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())