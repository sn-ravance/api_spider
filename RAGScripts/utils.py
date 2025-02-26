from typing import Dict, List, Optional
import requests
from requests.models import Response

def make_request(url: str, method: str, headers: Dict = None, 
                params: Dict = None, data: Dict = None) -> Response:
    """Make HTTP request with error handling"""
    try:
        return requests.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json=data,
            timeout=10,
            verify=False  # For testing only
        )
    except Exception as e:
        print(f"Request error: {e}")
        return None

def is_vulnerable_response(response: Response, 
                         patterns: List[str] = None) -> bool:
    """Check if response indicates vulnerability"""
    if not response:
        return False
        
    # Check status code
    if response.status_code in [500, 200]:
        # Check response content for error patterns
        if patterns:
            return any(pattern.lower() in response.text.lower() 
                      for pattern in patterns)
        return True
    return False