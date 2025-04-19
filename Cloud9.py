#!/usr/bin/env python3
"""
Cloud Misconfiguration Scanner
Detects exposed cloud credentials, open storage buckets, and metadata service vulnerabilities
By: Scav-engeR
"""
import asyncio
import json
import re
import random
import socket
import ssl
from typing import Dict, List, Set, Tuple, Optional
import httpx
import argparse
from urllib.parse import urlparse, urljoin
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
from rich import box
from datetime import datetime
import ipaddress

console = Console()

# Cloud provider detection patterns
CLOUD_PATTERNS = {
    "aws": {
        "domains": ["amazonaws.com", "aws.amazon.com", "cloudfront.net", "s3.amazonaws.com"],
        "headers": ["x-amz-", "aws-", "amz-"],
        "metadata_endpoints": ["http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/user-data/"],
        "bucket_url_patterns": [
            r"https?://[a-zA-Z0-9.\-]+\.s3\.amazonaws\.com",
            r"https?://s3\.amazonaws\.com/[a-zA-Z0-9.\-]+",
            r"https?://[a-zA-Z0-9.\-]+\.s3\.[a-zA-Z0-9\-]+\.amazonaws\.com"
        ]
    },
    "azure": {
        "domains": ["azure.com", "azurewebsites.net", "cloudapp.net", "core.windows.net"],
        "headers": ["x-ms-", "azure-"],
        "metadata_endpoints": ["http://169.254.169.254/metadata/instance"],
        "storage_url_patterns": [
            r"https?://[a-zA-Z0-9]+\.blob\.core\.windows\.net",
            r"https?://[a-zA-Z0-9]+\.file\.core\.windows\.net",
            r"https?://[a-zA-Z0-9]+\.queue\.core\.windows\.net",
            r"https?://[a-zA-Z0-9]+\.table\.core\.windows\.net"
        ]
    },
    "gcp": {
        "domains": ["googleapis.com", "googleusercontent.com", "appspot.com", "cloud.google.com"],
        "headers": ["x-goog-", "goog-"],
        "metadata_endpoints": ["http://metadata.google.internal/computeMetadata/v1/"],
        "storage_url_patterns": [
            r"https?://storage\.googleapis\.com/[a-zA-Z0-9.\-]+",
            r"https?://[a-zA-Z0-9.\-]+\.storage\.googleapis\.com"
        ]
    },
    "digitalocean": {
        "domains": ["digitalocean.com", "digitaloceanspaces.com"],
        "headers": ["x-do-"],
        "metadata_endpoints": ["http://169.254.169.254/metadata/v1/"],
        "spaces_url_patterns": [
            r"https?://[a-zA-Z0-9.\-]+\.digitaloceanspaces\.com"
        ]
    }
}

# Credential patterns to search for
CREDENTIAL_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"[0-9a-zA-Z/+]{40}",
    "azure_connection_string": r"DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9+/=]+;EndpointSuffix=core\.windows\.net",
    "azure_sas_token": r"sv=\d{4}-\d{2}-\d{2}&s[a-z]=([a-z]|%[0-9A-F]{2})+&s[a-z]=([a-z]|%[0-9A-F]{2})+",
    "gcp_api_key": r"AIza[0-9A-Za-z\\-_]{35}",
    "gcp_service_account": r"[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com"
}

# SSRF payloads for accessing cloud metadata
SSRF_PAYLOADS = {
    "aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2019-06-01",
        "http://169.254.169.254/metadata/instance/compute?api-version=2019-06-01"
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    ],
    "digitalocean": [
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1/id"
    ]
}

# URL parameters commonly vulnerable to SSRF
SSRF_PARAMETERS = [
    "url", "uri", "link", "src", "source", "dest", "destination", 
    "redirect", "redirect_to", "redirect_uri", "return", "return_to",
    "callback", "callback_url", "next", "next_url", "target", "view",
    "file", "reference", "fetch", "load", "resource", "navigate", "path"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
]

class CloudScanner:
    def __init__(self, timeout: int = 10, concurrency: int = 10, verify_ssl: bool = True):
        self.timeout = timeout
        self.concurrency = concurrency
        self.verify_ssl = verify_ssl
        self.discovered_buckets = set()
        self.discovered_credentials = []
        self.vulnerabilities = []
        self.cloud_resources = {}
    
    def get_headers(self) -> Dict[str, str]:
        """Generate request headers with randomized User-Agent"""
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close"
        }
        return headers
    
    def extract_domain(self, url: str) -> str:
        """Extract the domain from a URL"""
        parsed_url = urlparse(url)
        return parsed_url.netloc
    
    def detect_cloud_provider(self, url: str, headers: Dict[str, str], body: str) -> List[str]:
        """Detect cloud providers based on URL, headers and response body"""
        providers = set()
        domain = self.extract_domain(url)
        
        for provider, patterns in CLOUD_PATTERNS.items():
            # Check domain
            if any(cloud_domain in domain.lower() for cloud_domain in patterns["domains"]):
                providers.add(provider)
            
            # Check headers
            for header in headers:
                if any(cloud_header in header.lower() for cloud_header in patterns["headers"]):
                    providers.add(provider)
            
            # Check for storage URLs in body
            if "bucket_url_patterns" in patterns:
                for pattern in patterns["bucket_url_patterns"]:
                    if re.search(pattern, body, re.IGNORECASE):
                        providers.add(provider)
                        
            if "storage_url_patterns" in patterns:
                for pattern in patterns["storage_url_patterns"]:
                    if re.search(pattern, body, re.IGNORECASE):
                        providers.add(provider)
                        
            if "spaces_url_patterns" in patterns:
                for pattern in patterns["spaces_url_patterns"]:
                    if re.search(pattern, body, re.IGNORECASE):
                        providers.add(provider)
        
        return list(providers)
    
    def extract_credentials(self, text: str) -> List[Dict]:
        """Extract cloud credentials from text"""
        credentials = []
        
        for cred_type, pattern in CREDENTIAL_PATTERNS.items():
            matches = re.findall(pattern, text)
            for match in matches:
                credential = {
                    "type": cred_type,
                    "value": match,
                    "masked_value": self.mask_credential(match)
                }
                credentials.append(credential)
        
        return credentials
    
    def mask_credential(self, credential: str) -> str:
        """Mask a credential for safe display"""
        if len(credential) <= 8:
            return credential[:2] + "*" * (len(credential) - 4) + credential[-2:]
        return credential[:4] + "*" * (len(credential) - 8) + credential[-4:]
    
    def extract_storage_urls(self, text: str) -> List[str]:
        """Extract cloud storage URLs from text"""
        storage_urls = []
        
        for provider, patterns in CLOUD_PATTERNS.items():
            for pattern_key in ["bucket_url_patterns", "storage_url_patterns", "spaces_url_patterns"]:
                if pattern_key in patterns:
                    for pattern in patterns[pattern_key]:
                        matches = re.findall(pattern, text)
                        storage_urls.extend(matches)
        
        return list(set(storage_urls))  # Remove duplicates
    
    async def scan_url(self, target_url: str) -> Dict:
        """Scan a URL for cloud misconfigurations"""
        result = {
            "url": target_url,
            "cloud_providers": [],
            "credentials_found": [],
            "storage_urls": [],
            "ssrf_vulnerable_params": []
        }
        
        try:
            # Normalize URL
            if not target_url.startswith(('http://', 'https://')):
                target_url = f'https://{target_url}'
                
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=self.verify_ssl) as client:
                # Scan the main page
                headers = self.get_headers()
                response = await client.get(target_url, headers=headers)
                
                # Detect cloud providers
                result["cloud_providers"] = self.detect_cloud_provider(
                    target_url, 
                    response.headers, 
                    response.text
                )
                
                # Extract credentials from response
                credentials = self.extract_credentials(response.text)
                if credentials:
                    result["credentials_found"] = credentials
                    self.discovered_credentials.extend(credentials)
                    
                    for cred in credentials:
                        self.vulnerabilities.append({
                            "url": target_url,
                            "vulnerability": f"Exposed {cred['type']}",
                            "severity": "Critical",
                            "description": f"Found exposed cloud credential in page content",
                            "evidence": cred["masked_value"]
                        })
                
                # Extract storage URLs
                storage_urls = self.extract_storage_urls(response.text)
                if storage_urls:
                    result["storage_urls"] = storage_urls
                    for url in storage_urls:
                        if url not in self.discovered_buckets:
                            self.discovered_buckets.add(url)
                            
                            # Now test if the bucket is publicly accessible
                            await self.test_bucket_access(url)
                
                # Look for JS files that might contain credentials
                js_urls = re.findall(r'<script[^>]+src="([^"]+)"', response.text)
                for js_url in js_urls:
                    # Resolve relative URLs
                    if not js_url.startswith(('http://', 'https://')):
                        js_url = urljoin(target_url, js_url)
                    
                    try:
                        js_response = await client.get(js_url, headers=headers)
                        js_credentials = self.extract_credentials(js_response.text)
                        if js_credentials:
                            for cred in js_credentials:
                                if cred not in result["credentials_found"]:
                                    result["credentials_found"].append(cred)
                                    self.discovered_credentials.append(cred)
                                    
                                    self.vulnerabilities.append({
                                        "url": js_url,
                                        "vulnerability": f"Exposed {cred['type']} in JavaScript",
                                        "severity": "Critical",
                                        "description": f"Found exposed cloud credential in JavaScript file",
                                        "evidence": cred["masked_value"]
                                    })
                    except Exception:
                        pass
                
                # Test for SSRF vulnerabilities that could access cloud metadata
                await self.test_ssrf_vulnerabilities(target_url, client, result)
            
            return result
            
        except Exception as e:
            console.print(f"[red]Error scanning {target_url}: {str(e)}")
            return result
    
    async def test_bucket_access(self, bucket_url: str) -> None:
        """Test if a cloud storage bucket is publicly accessible"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
                response = await client.get(bucket_url, headers=self.get_headers())
                
                # Check if bucket is accessible (status code 200)
                if response.status_code == 200:
                    # Check response to determine if it's an open bucket
                    if "ListBucketResult" in response.text or "Contents" in response.text:
                        # Look for specific signs of valid bucket content
                        self.vulnerabilities.append({
                            "url": bucket_url,
                            "vulnerability": "Publicly Accessible Storage Bucket",
                            "severity": "Critical",
                            "description": "Storage bucket is publicly accessible and lists contents",
                            "evidence": f"Status code: {response.status_code}, Contains bucket listing"
                        })
                    else:
                        # Might be accessible but not listing contents
                        self.vulnerabilities.append({
                            "url": bucket_url,
                            "vulnerability": "Publicly Accessible Storage Bucket",
                            "severity": "High",
                            "description": "Storage bucket is publicly accessible",
                            "evidence": f"Status code: {response.status_code}"
                        })
        except Exception:
            # Failed to access the bucket, which is actually good for security
            pass
    
    async def test_ssrf_vulnerabilities(self, target_url: str, client: httpx.AsyncClient, result: Dict) -> None:
        """Test for SSRF vulnerabilities that could access cloud metadata"""
        # Find URL parameters by analyzing the URL
        parsed_url = urlparse(target_url)
        target_domain = parsed_url.netloc
        
        # Look for GET parameters that might be vulnerable to SSRF
        from urllib.parse import parse_qs
        query_params = parse_qs(parsed_url.query)
        
        for param_name in query_params:
            if param_name.lower() in SSRF_PARAMETERS:
                # Try SSRF payloads for each cloud provider
                for provider, payloads in SSRF_PAYLOADS.items():
                    for payload in payloads:
                        test_url = target_url.replace(f"{param_name}={query_params[param_name][0]}", f"{param_name}={payload}")
                        
                        try:
                            # Use a shorter timeout for SSRF tests
                            ssrf_response = await client.get(test_url, headers=self.get_headers(), timeout=5.0)
                            
                            # Check if the response contains metadata indicators
                            metadata_indicators = ["ami-id", "instance-id", "security-credentials", 
                                                  "host-name", "public-keys", "iam", "metadata",
                                                  "computeMetadata", "serviceAccounts", "token"]
                            
                            if any(indicator in ssrf_response.text for indicator in metadata_indicators):
                                result["ssrf_vulnerable_params"].append({
                                    "param": param_name,
                                    "payload": payload,
                                    "provider": provider
                                })
                                
                                self.vulnerabilities.append({
                                    "url": test_url,
                                    "vulnerability": "SSRF to Cloud Metadata Service",
                                    "severity": "Critical",
                                    "description": f"Parameter '{param_name}' is vulnerable to SSRF that can access {provider} metadata service",
                                    "evidence": f"Response contains metadata indicators"
                                })
                                
                                # Once we find one vulnerability, move to the next parameter
                                break
                        except Exception:
                            continue
        
        # Also look for SSRF in POST parameters by finding forms
        form_matches = re.findall(r'<form[^>]*action="([^"]*)"[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)
        for form_action, form_content in form_matches:
            # Resolve form action URL
            form_url = urljoin(target_url, form_action) if form_action else target_url
            
            # Extract form fields
            input_matches = re.findall(r'<input[^>]*name="([^"]*)"[^>]*>', form_content, re.IGNORECASE)
            
            # Check if any input field might be vulnerable to SSRF
            for input_name in input_matches:
                if input_name.lower() in SSRF_PARAMETERS:
                    # For each potentially vulnerable parameter, try SSRF payloads
                    for provider, payloads in SSRF_PAYLOADS.items():
                        for payload in payloads:
                            form_data = {input_name: payload}
                            
                            try:
                                ssrf_response = await client.post(form_url, data=form_data, headers=self.get_headers(), timeout=5.0)
                                
                                # Check if the response contains metadata indicators
                                metadata_indicators = ["ami-id", "instance-id", "security-credentials", 
                                                      "host-name", "public-keys", "iam", "metadata",
                                                      "computeMetadata", "serviceAccounts", "token"]
                                
                                if any(indicator in ssrf_response.text for indicator in metadata_indicators):
                                    result["ssrf_vulnerable_params"].append({
                                        "param": input_name,
                                        "payload": payload,
                                        "provider": provider,
                                        "method": "POST"
                                    })
                                    
                                    self.vulnerabilities.append({
                                        "url": form_url,
                                        "vulnerability": "SSRF to Cloud Metadata Service (POST)",
                                        "severity": "Critical",
                                        "description": f"Form parameter '{input_name}' is vulnerable to SSRF that can access {provider} metadata service",
                                        "evidence": f"Response contains metadata indicators"
                                    })
                                    
                                    # Once we find one vulnerability, move to the next parameter
                                    break
                            except Exception:
                                continue
    
    async def scan_targets(self, targets: List[str]) -> List[Dict]:
        """Scan a list of target URLs for cloud misconfigurations"""
        results = []
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning targets for cloud misconfigurations...", total=len(targets))
            
            batch_size = min(self.concurrency, len(targets))
            for i in range(0, len(targets), batch_size):
                batch = targets[i:i+batch_size]
                batch_tasks = [self.scan_url(target) for target in batch]
                batch_results = await asyncio.gather(*batch_tasks)
                results.extend(batch_results)
                progress.update(task, advance=len(batch))
        
        # Group results by cloud provider
        for result in results:
            for provider in result["cloud_providers"]:
                if provider not in self.cloud_resources:
                    self.cloud_resources[provider] = []
                self.cloud_resources[provider].append(result["url"])
        
        return results
    
    def print_results(self, scan_results):
        """Print a summary of the scan results"""
        console.print(Panel.fit("[bold cyan]Cloud Misconfiguration Scan Results", border_style="cyan"))
        
        # Print cloud resources by provider
        console.print(f"\n[bold green]Cloud Resources by Provider")
        
        if self.cloud_resources:
            for provider, urls in self.cloud_resources.items():
                console.print(f"[green]{provider.upper()}: {len(urls)} resources")
                
                provider_table = Table(title=f"{provider.upper()} Resources", box=box.ROUNDED)
                provider_table.add_column("URL", style="cyan")
                
                for url in urls[:10]:  # Limit to 10 for display
                    provider_table.add_row(url)
                
                if len(urls) > 10:
                    provider_table.add_row(f"... and {len(urls) - 10} more")
                
                console.print(provider_table)
        else:
            console.print("[yellow]No cloud resources identified")
        
        # Print discovered storage buckets
        console.print(f"\n[bold green]Found {len(self.discovered_buckets)} storage buckets")
        
        if self.discovered_buckets:
            buckets_table = Table(title="Cloud Storage Buckets", box=box.ROUNDED)
            buckets_table.add_column("URL", style="cyan")
            
            for bucket in self.discovered_buckets:
                buckets_table.add_row(bucket)
            
            console.print(buckets_table)
        
        # Print discovered credentials
        console.print(f"\n[bold red]Found {len(self.discovered_credentials)} exposed credentials")
        
        if self.discovered_credentials:
            creds_table = Table(title="Exposed Cloud Credentials", box=box.ROUNDED)
            creds_table.add_column("Type", style="red")
            creds_table.add_column("Masked Value", style="yellow")
            
            for cred in self.discovered_credentials:
                creds_table.add_row(
                    cred["type"],
                    cred["masked_value"]
                )
            
            console.print(creds_table)
        
        # Print vulnerabilities
        console.print(f"\n[bold red]Found {len(self.vulnerabilities)} cloud misconfigurations")
        
        if self.vulnerabilities:
            vuln_table = Table(title="Cloud Misconfigurations", box=box.ROUNDED)
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
            "cloud_resources": self.cloud_resources,
            "storage_buckets": list(self.discovered_buckets),
            "credentials": [
                {
                    "type": cred["type"],
                    "masked_value": cred["masked_value"]
                } for cred in self.discovered_credentials
            ],
            "vulnerabilities": self.vulnerabilities
        }
        
        try:
            with open(filepath, 'w') as f:
                json.dump(output, f, indent=2)
            console.print(f"[green]Results saved to {filepath}")
        except Exception as e:
            console.print(f"[red]Error saving results: {e}")


async def main():
    parser = argparse.ArgumentParser(description="Cloud Misconfiguration Scanner")
    parser.add_argument("--input", "-i", help="Input file with URLs to scan (one per line)")
    parser.add_argument("--url", "-u", help="Single URL to scan")
    parser.add_argument("--output", "-o", default="cloud_scan_results.json", help="Output file for scan results")
    parser.add_argument("--timeout", "-t", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--concurrency", "-c", type=int, default=5, help="Number of concurrent requests")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification")
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
    
    console.print(Panel.fit(f"[bold cyan]Cloud Misconfiguration Scanner\n[green]Targets: {len(targets)}\n[neon_pink]By: Scav-engeR | Monsoon Squad", border_style="cyan"))
    
    scanner = CloudScanner(
        timeout=args.timeout, 
        concurrency=args.concurrency,
        verify_ssl=not args.no_verify_ssl
    )
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
