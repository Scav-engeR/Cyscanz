#!/usr/bin/env python3
"""
API Security Scanner - Analyzes endpoints for common API vulnerabilities
By: Scav-engeR
"""
import asyncio
import json
import random
import re
import sys
from typing import Dict, List, Set, Tuple, Optional
import httpx
import argparse
from urllib.parse import urlparse, urljoin, parse_qs
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
from rich import box

console = Console()

# Common API paths to check for existence
API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", 
    "/rest", "/graphql", "/query", "/service",
    "/wp-json", "/api/swagger", "/swagger-ui",
    "/api-docs", "/openapi.json", "/swagger.json",
    "/graphiql", "/playground", "/.well-known"
]

# HTTP methods to test against endpoints
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# Common API parameter injection payloads
PAYLOADS = {
    "sql_injection": ["'", "1' OR '1'='1", "1; DROP TABLE users"],
    "nosql_injection": ['{"$gt": ""}', '{"$regex": ".*"}', '{"$where": "this"}'],
    "command_injection": ["; ls -la", "& dir", "| cat /etc/passwd"],
    "idors": ["../../../etc/passwd", "/admin/users", "../../config.json"],
    "rate_limit": ["REPEAT_REQUEST"],
    "mass_assignment": ["is_admin=true", "role=admin", "permissions=all"],
    "bola": ["user_id=1", "account_id=admin", "tenant=system"]
}

# Headers for fingerprinting
API_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-API-Key": "test",
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.Et9HFtf9R3GEMA0IICOfFMVXY7kkTX1wr4qCyhIf58U"
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
]

class APIScanner:
    def __init__(self, timeout: int = 10, concurrency: int = 10):
        self.timeout = timeout
        self.concurrency = concurrency
        self.discovered_endpoints = set()
        self.confirmed_api_hosts = set()
        self.vulnerabilities = []
    
    def get_headers(self) -> Dict[str, str]:
        """Generate request headers with randomized User-Agent"""
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            **API_HEADERS
        }
        return headers
    
    async def scan_url(self, target_url: str) -> Dict:
        """Initial scanning of a URL to determine if it hosts APIs"""
        result = {
            "url": target_url,
            "is_api": False,
            "api_type": None,
            "endpoints": [],
            "server": None,
            "technologies": []
        }
        
        try:
            # Normalize URL
            if not target_url.startswith(('http://', 'https://')):
                target_url = f'https://{target_url}'
                
            parsed_url = urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Probe for API presence
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                headers = self.get_headers()
                
                # First check the base URL
                try:
                    response = await client.get(base_url, headers=headers)
                    result["server"] = response.headers.get("Server", "Unknown")
                    
                    # Check for API-related headers
                    for header in response.headers:
                        if any(api_hint in header.lower() for api_hint in ["api", "oauth", "jwt", "token", "content-type"]):
                            result["is_api"] = True
                            result["technologies"].append(f"Header: {header}")
                    
                    # Check if response is JSON
                    content_type = response.headers.get("Content-Type", "")
                    if "application/json" in content_type or response.text.strip().startswith(("{", "[")):
                        result["is_api"] = True
                        result["api_type"] = "REST"
                except Exception:
                    pass
                
                # Probe common API paths
                for api_path in API_PATHS:
                    try:
                        test_url = urljoin(base_url, api_path)
                        response = await client.get(test_url, headers=headers)
                        
                        # If status code is 2XX or 401 (Unauthorized), likely an API endpoint
                        is_potential_api = (200 <= response.status_code < 300 or response.status_code == 401)
                        
                        # Check content type
                        content_type = response.headers.get("Content-Type", "")
                        is_json = "application/json" in content_type or response.text.strip().startswith(("{", "["))
                        is_xml = "application/xml" in content_type or "<xml" in response.text
                        
                        if is_potential_api and (is_json or is_xml):
                            result["is_api"] = True
                            result["endpoints"].append({
                                "path": api_path,
                                "status": response.status_code,
                                "content_type": content_type
                            })
                            
                            # Determine API type
                            if "graphql" in api_path.lower():
                                result["api_type"] = "GraphQL"
                            elif "rest" in api_path.lower() or is_json:
                                result["api_type"] = "REST"
                            elif is_xml:
                                result["api_type"] = "SOAP/XML"
                            
                            self.discovered_endpoints.add(test_url)
                            
                            # For GraphQL, test introspection
                            if "graphql" in api_path.lower():
                                await self.test_graphql_introspection(client, test_url)
                                
                    except Exception:
                        continue
            
            if result["is_api"]:
                self.confirmed_api_hosts.add(base_url)
                
            return result
            
        except Exception as e:
            console.print(f"[red]Error scanning {target_url}: {str(e)}")
            return result
    
    async def test_graphql_introspection(self, client, graphql_url):
        """Test for GraphQL introspection vulnerabilities"""
        introspection_query = """
        {
          __schema {
            queryType {
              name
            }
            types {
              name
              kind
              fields {
                name
              }
            }
          }
        }
        """
        
        try:
            response = await client.post(
                graphql_url, 
                json={"query": introspection_query},
                headers=self.get_headers(),
                timeout=self.timeout
            )
            
            if response.status_code == 200 and "__schema" in response.text:
                self.vulnerabilities.append({
                    "url": graphql_url,
                    "vulnerability": "GraphQL Introspection Enabled",
                    "severity": "Medium",
                    "description": "GraphQL introspection is enabled, exposing schema information",
                    "evidence": response.text[:100] + "..." if len(response.text) > 100 else response.text
                })
        except Exception:
            pass

    async def analyze_api_endpoint(self, endpoint_url):
        """Analyze a specific API endpoint for vulnerabilities"""
        results = []
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                headers = self.get_headers()
                
                # 1. Test HTTP method enumeration
                for method in HTTP_METHODS:
                    try:
                        if method == "GET":
                            response = await client.get(endpoint_url, headers=headers)
                        elif method == "POST":
                            response = await client.post(endpoint_url, headers=headers, json={})
                        elif method == "PUT":
                            response = await client.put(endpoint_url, headers=headers, json={})
                        elif method == "DELETE":
                            response = await client.delete(endpoint_url, headers=headers)
                        elif method == "PATCH":
                            response = await client.patch(endpoint_url, headers=headers, json={})
                        elif method == "OPTIONS":
                            response = await client.options(endpoint_url, headers=headers)
                        elif method == "HEAD":
                            response = await client.head(endpoint_url, headers=headers)
                        
                        # If not 404 or 405, the method might be supported
                        if response.status_code not in [404, 405]:
                            # Check if we get any sensitive data in the response
                            sensitive_patterns = [
                                r'password', r'token', r'secret', r'key', r'credentials',
                                r'admin', r'config', r'jwt', r'auth', r'private'
                            ]
                            
                            response_text = response.text.lower()
                            matches = []
                            for pattern in sensitive_patterns:
                                if re.search(pattern, response_text):
                                    matches.append(pattern)
                            
                            if matches:
                                self.vulnerabilities.append({
                                    "url": endpoint_url,
                                    "method": method,
                                    "vulnerability": "Sensitive Data Exposure",
                                    "severity": "High",
                                    "description": f"Method {method} reveals sensitive data: {', '.join(matches)}",
                                    "evidence": response.text[:100] + "..." if len(response.text) > 100 else response.text
                                })
                    except Exception:
                        continue
                
                # 2. Test for injection vulnerabilities using payloads
                parsed_url = urlparse(endpoint_url)
                path_parts = parsed_url.path.split('/')
                
                # Create variations of the URL path for testing
                test_paths = []
                for i in range(1, len(path_parts)):
                    if path_parts[i]:
                        # Replace IDs with payloads
                        if path_parts[i].isdigit() or (len(path_parts[i]) >= 20 and all(c in '0123456789abcdefABCDEF-' for c in path_parts[i])):
                            for vuln_type, payloads in PAYLOADS.items():
                                for payload in payloads:
                                    if vuln_type != "rate_limit":  # Skip rate limit test here
                                        new_parts = path_parts.copy()
                                        new_parts[i] = payload
                                        test_path = '/'.join(new_parts)
                                        test_url = parsed_url._replace(path=test_path).geturl()
                                        test_paths.append((test_url, vuln_type, payload))
                
                # Test each path variation
                for test_url, vuln_type, payload in test_paths:
                    try:
                        response = await client.get(test_url, headers=headers)
                        
                        # Look for error indicators
                        error_patterns = {
                            "sql_injection": [
                                "sql syntax", "mysql error", "ora-", "postgresql", 
                                "sqlite", "syntax error"
                            ],
                            "nosql_injection": [
                                "mongodb", "mongoose", "bson", "syntax error"
                            ],
                            "command_injection": [
                                "root:", "uid=", "gid=", "bin/bash", "Directory of",
                                "Volume Serial Number", "Last login"
                            ],
                            "idors": [
                                "root:", "userid", "password", "config", "not authorized",
                                "permission denied", "access denied"
                            ],
                            "mass_assignment": [
                                "cannot set", "property not allowed", "attribute protected"
                            ],
                            "bola": [
                                "not authorized", "permission denied", "forbidden", 
                                "access denied"
                            ]
                        }
                        
                        for pattern in error_patterns.get(vuln_type, []):
                            if pattern.lower() in response.text.lower():
                                self.vulnerabilities.append({
                                    "url": test_url,
                                    "vulnerability": f"Potential {vuln_type.replace('_', ' ').title()}",
                                    "severity": "High",
                                    "description": f"Endpoint may be vulnerable to {vuln_type.replace('_', ' ')}",
                                    "payload": payload,
                                    "evidence": response.text[:100] + "..." if len(response.text) > 100 else response.text
                                })
                                break
                    except Exception:
                        continue
                
                # 3. Test for rate limiting issues
                rate_limit_url = endpoint_url
                if not any(param in rate_limit_url for param in ["key", "token", "auth"]):
                    rate_limit_responses = []
                    for _ in range(10):  # Send 10 rapid requests
                        try:
                            response = await client.get(rate_limit_url, headers=headers)
                            rate_limit_responses.append(response.status_code)
                        except Exception:
                            break
                    
                    # Check if we got consistent 200 OK responses with no rate limiting
                    if len(rate_limit_responses) == 10 and all(code == 200 for code in rate_limit_responses):
                        self.vulnerabilities.append({
                            "url": rate_limit_url,
                            "vulnerability": "Missing Rate Limiting",
                            "severity": "Medium",
                            "description": "No rate limiting detected after 10 rapid requests",
                            "evidence": f"Received {rate_limit_responses.count(200)} OK responses in rapid succession"
                        })
                
                # 4. Check for missing authentication
                sensitive_endpoints = [
                    "/users", "/admin", "/accounts", "/settings", "/config",
                    "/profiles", "/dashboard", "/payments", "/billing"
                ]
                
                for sensitive in sensitive_endpoints:
                    if sensitive in endpoint_url.lower():
                        try:
                            # Try without auth headers
                            no_auth_headers = self.get_headers()
                            if "Authorization" in no_auth_headers:
                                del no_auth_headers["Authorization"]
                            if "X-API-Key" in no_auth_headers:
                                del no_auth_headers["X-API-Key"]
                            
                            response = await client.get(endpoint_url, headers=no_auth_headers)
                            
                            # If status code is 200, might be missing authentication
                            if response.status_code == 200 and (
                                response.text.strip().startswith(("{", "[")) or 
                                "application/json" in response.headers.get("Content-Type", "")
                            ):
                                self.vulnerabilities.append({
                                    "url": endpoint_url,
                                    "vulnerability": "Missing Authentication",
                                    "severity": "Critical",
                                    "description": f"Sensitive endpoint {sensitive} accessible without authentication",
                                    "evidence": response.text[:100] + "..." if len(response.text) > 100 else response.text
                                })
                                break
                        except Exception:
                            continue
                            
                # 5. Check for JWT vulnerabilities if endpoint accepts JWT
                jwt_header = "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJoYWNrZXIiLCJpYXQiOjE2NzY2NzQwNjEsImV4cCI6MTcwODIxMDA2MSwiYXVkIjoid3d3LnZpY3RpbS5jb20iLCJzdWIiOiJoYWNrZXJAd3d3LmhhY2tlci5jb20iLCJyb2xlIjoiYWRtaW4ifQ."
                try:
                    jwt_test_headers = self.get_headers()
                    jwt_test_headers["Authorization"] = jwt_header
                    
                    response = await client.get(endpoint_url, headers=jwt_test_headers)
                    
                    # Check if we got a non-error response
                    if response.status_code < 400:
                        self.vulnerabilities.append({
                            "url": endpoint_url,
                            "vulnerability": "JWT Algorithm None Vulnerability",
                            "severity": "Critical",
                            "description": "Endpoint accepts unsigned JWT with algorithm 'none'",
                            "evidence": f"Response code: {response.status_code}"
                        })
                except Exception:
                    pass
        
        except Exception as e:
            console.print(f"[red]Error analyzing endpoint {endpoint_url}: {str(e)}")
        
        return results
    
    async def scan_targets(self, targets: List[str]) -> List[Dict]:
        """Scan a list of target URLs"""
        results = []
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning targets for API endpoints...", total=len(targets))
            
            # First, scan all targets to determine which are API hosts
            batch_size = min(self.concurrency, len(targets))
            for i in range(0, len(targets), batch_size):
                batch = targets[i:i+batch_size]
                batch_tasks = [self.scan_url(target) for target in batch]
                batch_results = await asyncio.gather(*batch_tasks)
                results.extend(batch_results)
                progress.update(task, advance=len(batch))
        
        api_endpoints_to_analyze = []
        for result in results:
            if result["is_api"]:
                # Add discovered endpoints
                for endpoint in result["endpoints"]:
                    path = endpoint["path"]
                    base_url = urlparse(result["url"]).netloc
                    if not result["url"].startswith(('http://', 'https://')):
                        full_url = f"https://{base_url}{path}"
                    else:
                        protocol = urlparse(result["url"]).scheme
                        full_url = f"{protocol}://{base_url}{path}"
                    
                    api_endpoints_to_analyze.append(full_url)
        
        # Now analyze each API endpoint in detail
        console.print(f"[green]Found {len(api_endpoints_to_analyze)} API endpoints to analyze in detail")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Analyzing API endpoints for vulnerabilities...", total=len(api_endpoints_to_analyze))
            
            batch_size = min(self.concurrency, len(api_endpoints_to_analyze))
            for i in range(0, len(api_endpoints_to_analyze), batch_size):
                batch = api_endpoints_to_analyze[i:i+batch_size]
                batch_tasks = [self.analyze_api_endpoint(endpoint) for endpoint in batch]
                await asyncio.gather(*batch_tasks)
                progress.update(task, advance=len(batch))
        
        return results
    
    def print_results(self, scan_results):
        """Print a summary of the scan results"""
        console.print(Panel.fit("[bold cyan]API Security Scan Results", border_style="cyan"))
        
        # Print API endpoints found
        console.print(f"\n[bold green]Found {len(self.confirmed_api_hosts)} targets with API endpoints")
        
        if self.confirmed_api_hosts:
            api_table = Table(title="Discovered API Hosts", box=box.ROUNDED)
            api_table.add_column("Host", style="cyan")
            api_table.add_column("API Type", style="green")
            api_table.add_column("Endpoints", style="yellow")
            
            for result in scan_results:
                if result["is_api"]:
                    api_table.add_row(
                        result["url"],
                        result["api_type"] or "Unknown",
                        str(len(result["endpoints"]))
                    )
            
            console.print(api_table)
        
        # Print vulnerabilities found
        console.print(f"\n[bold red]Found {len(self.vulnerabilities)} API vulnerabilities")
        
        if self.vulnerabilities:
            vuln_table = Table(title="API Vulnerabilities", box=box.ROUNDED)
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
            "api_hosts": list(self.confirmed_api_hosts),
            "api_endpoints": list(self.discovered_endpoints),
            "vulnerabilities": self.vulnerabilities
        }
        
        try:
            with open(filepath, 'w') as f:
                json.dump(output, f, indent=2)
            console.print(f"[green]Results saved to {filepath}")
        except Exception as e:
            console.print(f"[red]Error saving results: {e}")


async def main():
    parser = argparse.ArgumentParser(description="API Security Scanner")
    parser.add_argument("--input", "-i", help="Input file with URLs to scan (one per line)")
    parser.add_argument("--url", "-u", help="Single URL to scan")
    parser.add_argument("--output", "-o", default="api_scan_results.json", help="Output file for scan results")
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
    
    console.print(Panel.fit(f"[bold cyan]API Security Scanner\n[green]Targets: {len(targets)}\n[neon_pink]By: Scav-engeR | Monsoon Squad", border_style="cyan"))
    
    scanner = APIScanner(timeout=args.timeout, concurrency=args.concurrency)
    results = await scanner.scan_targets(targets)
    scanner.print_results(results)
    scanner.save_results(args.output)


if __name__ == "__main__":
    # Only missing import for datetime at the top
    from datetime import datetime
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("[red]Scan terminated by user")
    except Exception as e:
        console.print(f"[red]Critical error: {e}")
