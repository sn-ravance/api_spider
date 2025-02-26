#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import socket
import ssl
from RAGScripts.utils.logger import setup_scanner_logger

async def check_http_version(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        parsed_url = urlparse(test_url)
        
        # Test cases for HTTP version manipulation
        test_cases = [
            {
                'name': 'HTTP/0.9 request',
                'version': b'HTTP/0.9',
                'desc': 'Legacy HTTP version'
            },
            {
                'name': 'HTTP/1.0 request',
                'version': b'HTTP/1.0',
                'desc': 'Older HTTP version'
            },
            {
                'name': 'Invalid HTTP version',
                'version': b'HTTP/9.9',
                'desc': 'Non-standard version'
            },
            {
                'name': 'Malformed version',
                'version': b'HTTP/1.1',
                'desc': 'Protocol typo'
            }
        ]
        
        base_response = send_raw_request(parsed_url.netloc, parsed_url.path, b'HTTP/1.1')
        
        for test in test_cases:
            try:
                response = send_raw_request(
                    parsed_url.netloc,
                    parsed_url.path,
                    test['version']
                )
                
                if is_version_vulnerable(response, base_response, test):
                    findings.append({
                        "type": "HTTP Version Manipulation",
                        "detail": f"Potential vulnerability with {test['name']}",
                        "evidence": {
                            "url": test_url,
                            "http_version": test['version'].decode(),
                            "response_code": get_status_code(response),
                            "response": response[:200].decode(errors='ignore')
                        }
                    })
                    
            except Exception as e:
                continue
                
    except Exception as e:
        print(f"Error in HTTP version check: {str(e)}")
    
    return findings

def send_raw_request(host: str, path: str, version: bytes) -> bytes:
    if ':' in host:
        host, port = host.split(':')
        port = int(port)
    else:
        port = 443 if path.startswith('https') else 80
    
    with socket.create_connection((host, port)) as sock:
        if port == 443:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        
        request = (
            f"{method} {path} ".encode() + version + b"\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        
        sock.send(request)
        response = b""
        
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
            
        return response

def get_status_code(response: bytes) -> int:
    try:
        status_line = response.split(b'\r\n')[0].decode()
        return int(status_line.split()[1])
    except:
        return 0

def is_version_vulnerable(response: bytes, base_response: bytes, test: Dict) -> bool:
    # Check for version manipulation indicators
    
    # Different status code might indicate version handling issues
    if get_status_code(response) != get_status_code(base_response):
        return True
    
    # Check for error messages in response
    error_indicators = [
        b'invalid protocol',
        b'unsupported version',
        b'bad request',
        b'version not supported',
        b'protocol error'
    ]
    
    if any(indicator in response.lower() for indicator in error_indicators):
        return True
    
    # Check for unusual server behavior
    try:
        response_text = response.decode(errors='ignore').lower()
        
        # Check for version-specific headers
        if test['version'] == b'HTTP/0.9' and b'\r\n\r\n' in response:
            return True
        
        # Check for server software disclosure
        if b'server:' in response.lower():
            base_server = None
            response_server = None
            
            for line in base_response.split(b'\r\n'):
                if line.lower().startswith(b'server:'):
                    base_server = line
            
            for line in response.split(b'\r\n'):
                if line.lower().startswith(b'server:'):
                    response_server = line
            
            if base_server != response_server:
                return True
    except:
        pass
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    from urllib.parse import urlparse
    
    async def test():
        result = await check_http_version(
            "http://localhost:5000",
            "/api/test",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())