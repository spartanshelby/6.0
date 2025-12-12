#!/usr/bin/env python3
"""
Complete JavaScript Monitoring System
Gathers JS files from target URLs and monitors for new JS launches
"""

import os
import sys
import json
import time
import re
import logging
import hashlib
import threading
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
import subprocess
import warnings

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException, NoSuchElementException
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
import urllib3

# Suppress warnings
warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging with colors
class ColorFormatter(logging.Formatter):
    """Custom formatter with colors"""
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    green = "\x1b[32;20m"
    blue = "\x1b[34;20m"
    cyan = "\x1b[36;20m"
    reset = "\x1b[0m"
    
    COLORS = {
        logging.DEBUG: grey,
        logging.INFO: cyan,
        logging.WARNING: yellow,
        logging.ERROR: red,
        logging.CRITICAL: bold_red
    }
    
    def format(self, record):
        color = self.COLORS.get(record.levelno, self.grey)
        message = super().format(record)
        return f"{color}{message}{self.reset}"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('js_monitoring.log'),
        logging.StreamHandler()
    ]
)

# Apply color formatter to console handler
for handler in logging.getLogger().handlers:
    if isinstance(handler, logging.StreamHandler):
        handler.setFormatter(ColorFormatter('%(asctime)s - %(levelname)s - %(message)s'))

logger = logging.getLogger(__name__)

# Global flag for graceful shutdown
shutdown_flag = False

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    global shutdown_flag
    logger.info("Shutdown signal received")
    shutdown_flag = True

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def print_banner(text: str, color: str = "\033[94m"):
    """Print a banner message"""
    width = 80
    print(f"\n{color}{'='*width}")
    print(f"{text.center(width)}")
    print(f"{'='*width}\033[0m\n")

def print_warning(text: str):
    """Print a warning in large font"""
    width = 80
    border = "!" * width
    print(f"\n\033[91m{border}")
    print(f"{'WARNING'.center(width)}")
    print(f"{border}")
    print(f"{text.center(width)}")
    print(f"{border}\033[0m\n")

class JSMonitoringSystem:
    def __init__(self, geckodriver_path: str = None, headless: bool = True, max_concurrent: int = 2):
        """
        Initialize the JS Monitoring System
        
        Args:
            geckodriver_path: Path to geckodriver executable
            headless: Run browser in headless mode
            max_concurrent: Maximum concurrent requests
        """
        self.geckodriver_path = geckodriver_path
        self.headless = headless
        self.max_concurrent = max_concurrent
        self.drivers = {}  # Store WebDriver instances per thread
        self.session = self._create_session()
        self.grep_patterns = self._load_grep_patterns()
        self.output_base = Path("monitor_output")
        
        # Cookie cache: domain -> cookies
        self.cookie_cache = {}
        
        # Initialize directories
        self._init_directories()
    
    def _init_directories(self):
        """Initialize output directories"""
        dirs = [
            self.output_base / "js_files",
            self.output_base / "newjsurls",
            self.output_base / "reports",
            self.output_base / "downloaded_js"
        ]
        
        for dir_path in dirs:
            dir_path.mkdir(parents=True, exist_ok=True)
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry strategy"""
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        })
        return session
    
    def _load_grep_patterns(self) -> List[str]:
        """Load grep patterns from patterns file"""
        patterns_file = Path("grep_patterns.txt")
        patterns = []
        
        if patterns_file.exists():
            with open(patterns_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        patterns.append(line)
            logger.info(f"Loaded {len(patterns)} grep patterns")
        else:
            # Default patterns
            patterns = [
                r'ads?\.',
                r'analytics',
                r'tracking',
                r'cdn\.',
                r'\.cdn\.',
                r'googletagmanager\.com',
                r'googlesyndication\.com',
                r'google-analytics\.com',
                r'facebook\.net',
                r'connect\.facebook\.net',
                r'twitter\.com/widgets\.js',
                r'platform\.twitter\.com',
                r'disqus\.com/embed\.js',
                r'\.cloudfront\.net',
                r'\.akamaihd\.net',
                r'\.amazonaws\.com',
                r'\.jquery\.com',
                r'\.bootstrapcdn\.com',
                r'\.cloudflare\.com',
                r'\.fontawesome\.com',
                r'\.googleapis\.com',
                r'\.gstatic\.com',
                r'\.doubleclick\.net',
                r'\.scorecardresearch\.com',
                r'\.hotjar\.com',
                r'\.optimizely\.com',
                r'\.mixpanel\.com',
                r'\.segment\.com',
                r'\.newrelic\.com',
                r'\.appdynamics\.com',
                r'\.pingdom\.net',
                r'\.datadoghq\.com',
                r'\.raygun\.io',
                r'\.sentry\.io',
                r'\.logrocket\.com',
                r'\.fullstory\.com',
                r'\.mouseflow\.com',
                r'\.crazyegg\.com',
                r'\.inspectlet\.com',
                r'\.clicktale\.net',
                r'\.min\.js$',
                r'\.bundle\.js$',
                r'\.chunk\.js$',
                r'\.runtime\.js$',
                r'\.vendor\.js$',
                r'\.polyfill\.js$',
            ]
            # Save default patterns
            with open(patterns_file, 'w', encoding='utf-8') as f:
                f.write("# JavaScript URL Exclusion Patterns\n")
                f.write("# Add patterns to exclude specific JavaScript files\n\n")
                for pattern in patterns:
                    f.write(f"{pattern}\n")
            logger.info(f"Created default grep_patterns.txt with {len(patterns)} patterns")
            
        return patterns
    
    def _load_all_cookies(self, cookies_folder: str = None) -> Dict[str, List[Dict]]:
        """
        Load all cookies from cookie folder.
        Reads all JSON files and maps domains to cookies.
        Supports subdomain matching.
        """
        if not cookies_folder:
            return {}
        
        cookie_dir = Path(cookies_folder)
        if not cookie_dir.exists() or not cookie_dir.is_dir():
            logger.warning(f"Cookie folder not found: {cookies_folder}")
            return {}
        
        all_cookies = {}
        
        # Read all JSON files in cookie folder
        for cookie_file in cookie_dir.glob("*.json"):
            try:
                with open(cookie_file, 'r', encoding='utf-8') as f:
                    cookies = json.load(f)
                
                if not isinstance(cookies, list):
                    logger.warning(f"Invalid cookie format in {cookie_file.name}: expected list")
                    continue
                
                # Extract domains from cookies
                domains_in_file = set()
                for cookie in cookies:
                    if isinstance(cookie, dict) and 'domain' in cookie:
                        domain = cookie['domain']
                        # Remove leading dot if present
                        if domain.startswith('.'):
                            domain = domain[1:]
                        domains_in_file.add(domain)
                
                # Store cookies for each domain found in the file
                for domain in domains_in_file:
                    if domain not in all_cookies:
                        all_cookies[domain] = []
                    # Add all cookies from this file for the domain
                    for cookie in cookies:
                        if isinstance(cookie, dict):
                            # Ensure the cookie has a domain field
                            cookie_copy = cookie.copy()
                            if 'domain' in cookie_copy and cookie_copy['domain'].startswith('.'):
                                cookie_copy['domain'] = cookie_copy['domain'][1:]
                            all_cookies[domain].append(cookie_copy)
                    
                logger.info(f"Loaded cookies from {cookie_file.name} for domains: {', '.join(domains_in_file)}")
                
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in {cookie_file.name}: {e}")
            except Exception as e:
                logger.error(f"Error reading {cookie_file.name}: {e}")
        
        # Log summary
        if all_cookies:
            logger.info(f"Loaded cookies for {len(all_cookies)} domains")
            for domain, cookies in all_cookies.items():
                logger.debug(f"  {domain}: {len(cookies)} cookies")
        else:
            logger.warning("No cookies loaded from cookie folder")
        
        return all_cookies
    
    def _find_cookies_for_domain(self, target_domain: str, all_cookies: Dict[str, List[Dict]]) -> List[Dict]:
        """
        Find cookies for a target domain, including subdomain matches.
        Returns cookies for exact match or parent domain.
        """
        if not all_cookies:
            return []
        
        # Try exact match first
        if target_domain in all_cookies:
            logger.info(f"Found exact cookie match for domain: {target_domain}")
            return all_cookies[target_domain]
        
        # Try parent domain (e.g., for sub.example.com, try example.com)
        domain_parts = target_domain.split('.')
        for i in range(1, len(domain_parts) - 1):
            parent_domain = '.'.join(domain_parts[i:])
            if parent_domain in all_cookies:
                logger.info(f"Found cookie for parent domain {parent_domain} for target {target_domain}")
                return all_cookies[parent_domain]
        
        # Try wildcard match (check if any cookie domain is a parent of target)
        for cookie_domain, cookies in all_cookies.items():
            if target_domain.endswith('.' + cookie_domain) or target_domain == cookie_domain:
                logger.info(f"Found cookie domain {cookie_domain} matching target {target_domain}")
                return cookies
        
        return []
    
    def _should_exclude_js(self, js_url: str) -> bool:
        """Check if JS URL should be excluded based on grep patterns"""
        for pattern in self.grep_patterns:
            try:
                if re.search(pattern, js_url, re.IGNORECASE):
                    logger.debug(f"Excluding {js_url} due to pattern: {pattern}")
                    return True
            except re.error as e:
                logger.warning(f"Invalid regex pattern: {pattern} - {e}")
                continue
        return False
    
    def _get_driver(self, thread_id: int):
        """Get or create a WebDriver instance for a thread"""
        if thread_id not in self.drivers:
            try:
                options = Options()
                
                if self.headless:
                    options.add_argument("--headless")
                
                # Additional options for better performance and compatibility
                options.set_preference("dom.webdriver.enabled", False)
                options.set_preference('useAutomationExtension', False)
                options.set_preference("javascript.enabled", True)
                options.set_preference("permissions.default.image", 2)
                options.set_preference("permissions.default.stylesheet", 2)
                
                # Disable cache
                options.set_preference("browser.cache.disk.enable", False)
                options.set_preference("browser.cache.memory.enable", False)
                options.set_preference("browser.cache.offline.enable", False)
                options.set_preference("network.http.use-cache", False)
                
                # Disable safe browsing and other checks
                options.set_preference("browser.safebrowsing.enabled", False)
                options.set_preference("browser.safebrowsing.malware.enabled", False)
                options.set_preference("browser.safebrowsing.phishing.enabled", False)
                options.set_preference("browser.helperApps.alwaysAsk.force", False)
                options.set_preference("browser.download.manager.showWhenStarting", False)
                options.set_preference("browser.download.manager.useWindow", False)
                options.set_preference("browser.download.manager.focusWhenStarting", False)
                options.set_preference("browser.download.manager.alertOnEXEOpen", False)
                options.set_preference("browser.download.manager.showAlertOnComplete", False)
                options.set_preference("browser.download.manager.closeWhenDone", True)
                
                # Set Firefox binary path if needed
                firefox_binary = None
                try:
                    firefox_paths = [
                        '/usr/bin/firefox-esr',
                        '/usr/bin/firefox',
                        '/usr/local/bin/firefox',
                        '/opt/homebrew/bin/firefox'
                    ]
                    
                    for path in firefox_paths:
                        if Path(path).exists():
                            firefox_binary = FirefoxBinary(path)
                            logger.debug(f"Using Firefox binary: {path}")
                            break
                except:
                    pass
                
                service = None
                if self.geckodriver_path:
                    service = Service(executable_path=self.geckodriver_path)
                
                # Create driver
                if firefox_binary and service:
                    driver = webdriver.Firefox(
                        options=options,
                        service=service,
                        firefox_binary=firefox_binary
                    )
                elif service:
                    driver = webdriver.Firefox(options=options, service=service)
                else:
                    driver = webdriver.Firefox(options=options)
                
                # Set timeouts
                driver.set_page_load_timeout(45)
                driver.set_script_timeout(30)
                driver.implicitly_wait(10)
                
                self.drivers[thread_id] = driver
                logger.info(f"Created WebDriver for thread {thread_id}")
                
            except Exception as e:
                logger.error(f"Failed to create WebDriver for thread {thread_id}: {e}")
                raise
        
        return self.drivers[thread_id]
    
    def _close_all_drivers(self):
        """Close all WebDriver instances"""
        for thread_id, driver in self.drivers.items():
            try:
                driver.quit()
                logger.info(f"Closed WebDriver for thread {thread_id}")
            except Exception as e:
                logger.debug(f"Error closing WebDriver for thread {thread_id}: {e}")
        self.drivers.clear()
    
    def _inject_cookies(self, driver, url: str, cookies: List[Dict]):
        """Inject cookies into WebDriver - MUST BE ON CORRECT DOMAIN FIRST"""
        if not cookies:
            return
        
        injected_count = 0
        failed_count = 0
        
        # First, navigate to the domain to set cookies
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        try:
            # Navigate to the base domain first
            driver.get(base_url)
            time.sleep(1)  # Wait for page to load
            
            # Clear existing cookies to avoid conflicts
            driver.delete_all_cookies()
            
            # Now inject new cookies
            for cookie in cookies:
                try:
                    # Prepare cookie dict
                    cookie_dict = {
                        'name': str(cookie.get('name', '')),
                        'value': str(cookie.get('value', '')),
                    }
                    
                    # Add optional fields if they exist
                    if 'domain' in cookie and cookie['domain']:
                        domain = cookie['domain']
                        # Ensure domain doesn't start with dot for Selenium
                        if domain.startswith('.'):
                            domain = domain[1:]
                        cookie_dict['domain'] = domain
                    
                    if 'path' in cookie:
                        cookie_dict['path'] = cookie['path']
                    
                    if 'secure' in cookie:
                        cookie_dict['secure'] = bool(cookie['secure'])
                    
                    if 'httpOnly' in cookie:
                        cookie_dict['httpOnly'] = bool(cookie['httpOnly'])
                    
                    # Try to add the cookie
                    driver.add_cookie(cookie_dict)
                    injected_count += 1
                    logger.debug(f"Injected cookie: {cookie.get('name', 'unknown')}")
                    
                except Exception as e:
                    failed_count += 1
                    logger.debug(f"Failed to inject cookie {cookie.get('name', 'unknown')}: {e}")
            
            if injected_count > 0:
                logger.info(f"✅ Successfully injected {injected_count} cookies for {parsed_url.netloc}")
                if failed_count > 0:
                    logger.warning(f"Failed to inject {failed_count} cookies")
                
                # Refresh page to apply cookies
                driver.refresh()
                time.sleep(2)
            else:
                logger.warning(f"⚠️ No cookies were successfully injected for {parsed_url.netloc}")
                
        except Exception as e:
            logger.error(f"❌ Error during cookie injection for {url}: {e}")
    
    def _wait_for_page_load(self, driver, timeout: int = 25):
        """Wait for page to fully load with multiple checks"""
        try:
            start_time = time.time()
            
            # Wait for document ready state
            try:
                WebDriverWait(driver, timeout).until(
                    lambda d: d.execute_script('return document.readyState') == 'complete'
                )
            except TimeoutException:
                logger.debug("Document ready state timeout, continuing anyway")
            
            # Wait a bit for initial load
            time.sleep(2)
            
            # Scroll multiple times to trigger lazy loading
            scroll_scripts = [
                "window.scrollTo(0, document.body.scrollHeight * 0.25);",
                "window.scrollTo(0, document.body.scrollHeight * 0.5);",
                "window.scrollTo(0, document.body.scrollHeight * 0.75);",
                "window.scrollTo(0, document.body.scrollHeight);"
            ]
            
            for script in scroll_scripts:
                try:
                    driver.execute_script(script)
                    time.sleep(1)
                except:
                    pass
            
            # Scroll back to top
            driver.execute_script("window.scrollTo(0, 0);")
            time.sleep(1)
            
            # Additional wait for dynamic content
            try:
                WebDriverWait(driver, 5).until(
                    EC.presence_of_element_located((By.TAG_NAME, "script"))
                )
            except:
                pass
            
            elapsed = time.time() - start_time
            logger.debug(f"Page load completed in {elapsed:.2f} seconds")
            
            return True
            
        except Exception as e:
            logger.warning(f"Error during page load wait: {e}")
            return True
    
    def _get_js_urls_from_page(self, driver, url: str, domain: str, use_cookies: bool = False) -> Set[str]:
        """Extract JavaScript URLs from a web page"""
        js_urls = set()
        
        try:
            logger.info(f"Navigating to {url}")
            
            # Navigate to the URL
            driver.get(url)
            
            # Wait for page to fully load
            if not self._wait_for_page_load(driver, 25):
                logger.warning(f"Page may not have fully loaded: {url}")
            
            # Give extra time for JavaScript execution
            time.sleep(3)
            
            # Method 1: Find all script tags
            try:
                script_tags = driver.find_elements(By.TAG_NAME, "script")
                logger.debug(f"Found {len(script_tags)} script tags")
                
                for script in script_tags:
                    try:
                        src = script.get_attribute("src")
                        if src:
                            # Convert relative URLs to absolute
                            if src.startswith('//'):
                                src = f"https:{src}"
                            elif src.startswith('/'):
                                src = f"https://{domain}{src}"
                            elif not src.startswith(('http://', 'https://')):
                                base_url = f"https://{domain}"
                                if url.endswith('/'):
                                    src = urljoin(url, src)
                                else:
                                    src = urljoin(base_url + '/', src)
                            
                            # Clean up URL
                            src = src.split('#')[0]
                            
                            # Only include .js files
                            if src.endswith('.js') or '.js?' in src or 'javascript' in src.lower():
                                if not self._should_exclude_js(src):
                                    js_urls.add(src)
                    except:
                        continue
            except Exception as e:
                logger.debug(f"Error getting script tags: {e}")
            
            # Method 2: Execute JavaScript to find all script sources
            try:
                script_sources = driver.execute_script("""
                    var scripts = document.querySelectorAll('script[src]');
                    var sources = [];
                    for (var i = 0; i < scripts.length; i++) {
                        if (scripts[i].src) {
                            sources.push(scripts[i].src);
                        }
                    }
                    var observerScripts = Array.from(document.querySelectorAll('script')).map(s => s.src).filter(Boolean);
                    sources = sources.concat(observerScripts);
                    return Array.from(new Set(sources));
                """)
                
                for src in script_sources:
                    if src:
                        if src.startswith('//'):
                            src = f"https:{src}"
                        elif src.startswith('/'):
                            src = f"https://{domain}{src}"
                        elif not src.startswith(('http://', 'https://')):
                            src = urljoin(f"https://{domain}/", src)
                        
                        if not self._should_exclude_js(src):
                            js_urls.add(src)
            except Exception as e:
                logger.debug(f"Error executing JS to find scripts: {e}")
            
            # Method 3: Check network requests via performance API
            try:
                performance_entries = driver.execute_script("""
                    try {
                        var entries = performance.getEntriesByType('resource');
                        var jsEntries = entries.filter(function(entry) {
                            return entry.name && (entry.name.includes('.js') || 
                                                  entry.name.includes('.js?') || 
                                                  entry.initiatorType === 'script');
                        });
                        return jsEntries.map(function(entry) { return entry.name; });
                    } catch(e) {
                        return [];
                    }
                """)
                
                for entry in performance_entries:
                    if entry and not self._should_exclude_js(entry):
                        js_urls.add(entry)
            except Exception as e:
                logger.debug(f"Error checking performance entries: {e}")
            
            logger.info(f"Found {len(js_urls)} unique JS URLs on {url}")
            
            # Log some example URLs
            if js_urls:
                sample = list(js_urls)[:3]
                for url_example in sample:
                    logger.debug(f"  Example: {url_example}")
            
        except TimeoutException:
            logger.warning(f"Timeout while loading {url}")
        except Exception as e:
            logger.error(f"Error processing {url}: {e}")
        
        return js_urls
    
    def _download_js_file(self, js_url: str, output_path: Path) -> bool:
        """Download a JavaScript file"""
        try:
            js_url = js_url.strip()
            if not js_url.startswith(('http://', 'https://')):
                logger.warning(f"Invalid URL: {js_url}")
                return False
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0',
                'Accept': 'text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01',
                'Accept-Language': 'en-US,en;q=0.5',
                'Referer': 'https://www.google.com/',
                'Connection': 'keep-alive',
            }
            
            response = self.session.get(js_url, headers=headers, timeout=15, stream=True, verify=False)
            response.raise_for_status()
            
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            
            if output_path.stat().st_size == 0:
                logger.warning(f"Empty file downloaded from {js_url}")
                output_path.unlink()
                return False
            
            logger.debug(f"Downloaded JS: {js_url} to {output_path}")
            return True
            
        except requests.exceptions.SSLError:
            try:
                response = self.session.get(js_url, timeout=15, stream=True, verify=False)
                response.raise_for_status()
                
                with open(output_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                
                if output_path.stat().st_size > 0:
                    logger.debug(f"Downloaded JS (no SSL): {js_url}")
                    return True
            except Exception as e:
                logger.error(f"Failed to download {js_url} (no SSL): {e}")
                return False
        except Exception as e:
            logger.error(f"Failed to download {js_url}: {e}")
            return False
    
    def _get_clean_filename(self, js_url: str) -> str:
        """Create a clean filename from JS URL"""
        parsed = urlparse(js_url)
        path = parsed.path
        
        if not path:
            domain = parsed.netloc.replace('.', '_')
            return f"{domain}.js"
        
        filename = os.path.basename(path)
        
        if not filename or '.' not in filename:
            path_parts = [p for p in path.split('/') if p]
            if path_parts:
                filename = f"{'_'.join(path_parts[-2:])}.js"
            else:
                filename = f"script_{parsed.netloc.replace('.', '_')}.js"
        
        if '?' in filename:
            filename = filename.split('?')[0]
        
        if not filename.endswith('.js'):
            filename += '.js'
        
        filename = re.sub(r'[<>:"|?*]', '_', filename)
        
        if len(filename) > 100:
            name, ext = os.path.splitext(filename)
            name = name[:95]
            filename = name + ext
        
        return filename
    
    def _get_previous_js_urls(self, domain: str) -> Set[str]:
        """Get all previous JS URLs for a domain"""
        domain_dir = self.output_base / "js_files" / domain
        previous_urls = set()
        
        if not domain_dir.exists():
            return previous_urls
        
        for urls_file in domain_dir.glob("jsurls_*.txt"):
            try:
                with open(urls_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        url = line.strip()
                        if url and not url.startswith('#'):
                            previous_urls.add(url)
            except:
                continue
        
        return previous_urls
    
    def _save_current_js_urls(self, domain: str, js_urls: Set[str]) -> Path:
        """Save current JS URLs to file"""
        domain_dir = self.output_base / "js_files" / domain
        domain_dir.mkdir(parents=True, exist_ok=True)
        
        # Get sequence number (alternating with timestamp)
        existing_files = list(domain_dir.glob("jsurls_*.txt"))
        
        # Try to parse sequence numbers from existing files
        seq_numbers = []
        for f in existing_files:
            match = re.search(r'jsurls_(\d+)\.txt$', f.name)
            if match:
                try:
                    seq_numbers.append(int(match.group(1)))
                except:
                    pass
        
        if seq_numbers:
            seq_num = max(seq_numbers) + 1
        else:
            seq_num = 1
        
        # Save with sequence number only (no timestamp)
        urls_file = domain_dir / f"jsurls_{seq_num}.txt"
        
        with open(urls_file, 'w', encoding='utf-8') as f:
            f.write(f"# JS URLs for {domain}\n")
            f.write(f"# Collected: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total URLs: {len(js_urls)}\n")
            f.write(f"# Sequence: {seq_num}\n")
            f.write("#" * 80 + "\n\n")
            for url in sorted(js_urls):
                f.write(f"{url}\n")
        
        logger.info(f"Saved {len(js_urls)} JS URLs to {urls_file}")
        return urls_file
    
    def _save_new_js_urls(self, domain: str, new_urls: Set[str]) -> Optional[Path]:
        """Save new JS URLs to newjsurls folder"""
        if not new_urls:
            return None
        
        newjsurls_dir = self.output_base / "newjsurls"
        newjsurls_dir.mkdir(parents=True, exist_ok=True)
        
        # Get sequence number
        existing_files = list(newjsurls_dir.glob("new_js_urls_*.txt"))
        
        # Try to parse sequence numbers
        seq_numbers = []
        for f in existing_files:
            match = re.search(r'new_js_urls_(\d+)\.txt$', f.name)
            if match:
                try:
                    seq_numbers.append(int(match.group(1)))
                except:
                    pass
        
        if seq_numbers:
            seq_num = max(seq_numbers) + 1
        else:
            seq_num = 1
        
        # Save with sequence number only
        new_urls_file = newjsurls_dir / f"new_js_urls_{seq_num}.txt"
        
        with open(new_urls_file, 'w', encoding='utf-8') as f:
            f.write(f"# NEW JS URLs DETECTED\n")
            f.write(f"# Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Domain: {domain}\n")
            f.write(f"# Total New URLs: {len(new_urls)}\n")
            f.write(f"# Sequence: {seq_num}\n")
            f.write("#" * 80 + "\n\n")
            for url in sorted(new_urls):
                f.write(f"{url}\n")
        
        logger.info(f"🎯 Saved {len(new_urls)} NEW JS URLs to {new_urls_file}")
        return new_urls_file
    
    def _download_new_js_files(self, domain: str, new_urls: Set[str]):
        """Download new JS files"""
        download_dir = self.output_base / "downloaded_js" / domain
        download_dir.mkdir(parents=True, exist_ok=True)
        
        downloaded_files = []
        
        for js_url in new_urls:
            try:
                filename = self._get_clean_filename(js_url)
                output_path = download_dir / filename
                
                counter = 1
                while output_path.exists():
                    name, ext = os.path.splitext(filename)
                    filename = f"{name}_{counter}{ext}"
                    output_path = download_dir / filename
                    counter += 1
                
                logger.info(f"Downloading new JS: {js_url}")
                if self._download_js_file(js_url, output_path):
                    downloaded_files.append({
                        'url': js_url,
                        'filename': filename,
                        'path': str(output_path),
                        'size': output_path.stat().st_size,
                        'timestamp': datetime.now().isoformat()
                    })
                    logger.info(f"✅ Downloaded: {filename} ({output_path.stat().st_size} bytes)")
                    
            except Exception as e:
                logger.error(f"❌ Error downloading {js_url}: {e}")
        
        return downloaded_files
    
    def process_target(self, target_url: str, thread_id: int, all_cookies: Dict[str, List[Dict]]) -> Dict:
        """Process a single target URL"""
        if shutdown_flag:
            return {'url': target_url, 'status': 'cancelled', 'reason': 'shutdown'}
        
        result = {
            'url': target_url,
            'domain': '',
            'cookies_found': False,
            'cookies_injected': 0,
            'js_urls_found': 0,
            'new_js_urls': 0,
            'downloaded': 0,
            'status': 'unknown',
            'error': None,
            'new_urls_list': []
        }
        
        try:
            # Parse URL
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc
            result['domain'] = domain
            
            logger.info(f"🚀 Processing: {target_url}")
            
            # Find cookies for this domain
            domain_cookies = self._find_cookies_for_domain(domain, all_cookies)
            
            if domain_cookies:
                result['cookies_found'] = True
                result['cookies_injected'] = len(domain_cookies)
                logger.info(f"🍪 Found {len(domain_cookies)} cookies for {domain}")
            else:
                result['cookies_found'] = False
                print_warning(f"NO COOKIES AVAILABLE FOR: {domain}")
                logger.warning(f"No cookies found for {domain}, proceeding without cookies")
            
            # Get WebDriver for this thread
            driver = self._get_driver(thread_id)
            
            # Inject cookies if available
            if domain_cookies:
                logger.info(f"📋 Injecting cookies for {domain}")
                self._inject_cookies(driver, target_url, domain_cookies)
            
            # Get JS URLs from page
            logger.info(f"🔍 Extracting JS URLs from {target_url}")
            js_urls = self._get_js_urls_from_page(driver, target_url, domain, bool(domain_cookies))
            result['js_urls_found'] = len(js_urls)
            
            if not js_urls:
                result['status'] = 'no_js_found'
                logger.warning(f"⚠️ No JS URLs found for {target_url}")
                return result
            
            # Get previous URLs
            previous_urls = self._get_previous_js_urls(domain)
            logger.info(f"📊 Previous scan had {len(previous_urls)} JS URLs")
            
            # Find new URLs (only newly launched JS, not updates)
            new_urls = js_urls - previous_urls
            result['new_js_urls'] = len(new_urls)
            result['new_urls_list'] = list(new_urls)
            
            # Save current URLs (using sequence number only)
            current_file = self._save_current_js_urls(domain, js_urls)
            
            if new_urls:
                # Save new URLs (using sequence number only)
                new_urls_file = self._save_new_js_urls(domain, new_urls)
                
                # Download new JS files
                logger.info(f"⬇️ Downloading {len(new_urls)} new JS files")
                downloaded = self._download_new_js_files(domain, new_urls)
                result['downloaded'] = len(downloaded)
                
                result['status'] = 'new_js_found'
                logger.info(f"🎉 Found {len(new_urls)} NEW JS URLs for {domain}")
            else:
                result['status'] = 'no_new_js'
                logger.info(f"✅ No new JS URLs found for {domain} (already had {len(previous_urls)} URLs)")
            
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            logger.error(f"❌ Error processing {target_url}: {e}")
        
        return result
    
    def gather_js(self, targets_file: str, cookies_folder: str = None):
        """Gather JavaScript from all targets with concurrent processing"""
        print_banner("JavaScript Monitoring System - Starting JS Gathering", "\033[94m")
        
        # Read targets
        try:
            with open(targets_file, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            logger.error(f"❌ Targets file not found: {targets_file}")
            return
        
        if not targets:
            logger.error("❌ No targets found in file")
            return
        
        # Load all cookies
        all_cookies = {}
        if cookies_folder:
            print_banner(f"Loading cookies from: {cookies_folder}", "\033[93m")
            all_cookies = self._load_all_cookies(cookies_folder)
            
            if all_cookies:
                print_banner("COOKIES LOADED SUCCESSFULLY", "\033[92m")
                print("Loaded cookies for domains:")
                for domain, cookies in all_cookies.items():
                    print(f"  🍪 {domain}: {len(cookies)} cookies")
                print()
            else:
                print_warning("NO COOKIES FOUND IN FOLDER")
                print(f"Checked folder: {cookies_folder}")
                print("Make sure cookie files are in JSON format with correct structure.")
                print("Proceeding without cookies...\n")
        
        logger.info(f"🚀 Starting JS gathering for {len(targets)} targets with {self.max_concurrent} concurrent workers")
        if all_cookies:
            logger.info(f"🍪 Loaded cookies for {len(all_cookies)} domains")
        
        results = []
        start_time = time.time()
        
        try:
            # Process targets concurrently
            with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
                # Submit all tasks
                future_to_target = {}
                for i, target_url in enumerate(targets):
                    if shutdown_flag:
                        logger.info("🛑 Shutdown requested, stopping new tasks")
                        break
                    
                    thread_id = i % self.max_concurrent
                    future = executor.submit(self.process_target, target_url, thread_id, all_cookies)
                    future_to_target[future] = target_url
                    logger.debug(f"📝 Submitted task for {target_url} (thread {thread_id})")
                
                # Collect results
                for future in as_completed(future_to_target):
                    if shutdown_flag:
                        # Cancel remaining futures
                        for f in future_to_target:
                            if not f.done():
                                f.cancel()
                        break
                    
                    target_url = future_to_target[future]
                    try:
                        result = future.result(timeout=90)
                        results.append(result)
                        
                        status_icons = {
                            'new_js_found': '🎉',
                            'no_new_js': '✅',
                            'no_js_found': '⚠️',
                            'error': '❌',
                            'cancelled': '🛑'
                        }
                        
                        icon = status_icons.get(result['status'], '🔹')
                        cookie_icon = '🍪' if result.get('cookies_found') else '🚫'
                        
                        logger.info(f"{icon}{cookie_icon} {target_url} - {result['status']} (JS: {result.get('js_urls_found', 0)}, New: {result.get('new_js_urls', 0)})")
                        
                    except TimeoutException:
                        logger.error(f"⏰ Timeout processing {target_url}")
                        results.append({
                            'url': target_url,
                            'status': 'timeout',
                            'error': 'Processing timeout'
                        })
                    except Exception as e:
                        logger.error(f"❌ Task failed for {target_url}: {e}")
                        results.append({
                            'url': target_url,
                            'status': 'failed',
                            'error': str(e)
                        })
        
        finally:
            # Close all drivers
            self._close_all_drivers()
        
        # Generate report
        self._generate_gathering_report(results, start_time, all_cookies)
    
    def _generate_gathering_report(self, results: List[Dict], start_time: float, all_cookies: Dict):
        """Generate gathering report"""
        if not results:
            logger.warning("⚠️ No results to report")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_base / "reports" / f"gathering_report_{timestamp}.json"
        summary_file = self.output_base / "reports" / f"gathering_summary_{timestamp}.txt"
        
        # Calculate statistics
        total_targets = len(results)
        successful = sum(1 for r in results if r['status'] in ['new_js_found', 'no_new_js', 'no_js_found'])
        errors = sum(1 for r in results if r['status'] in ['error', 'failed', 'timeout'])
        new_js_found = sum(1 for r in results if r['status'] == 'new_js_found')
        total_js_urls = sum(r.get('js_urls_found', 0) for r in results)
        total_new_urls = sum(r.get('new_js_urls', 0) for r in results)
        total_downloaded = sum(r.get('downloaded', 0) for r in results)
        with_cookies = sum(1 for r in results if r.get('cookies_found', False))
        without_cookies = total_targets - with_cookies
        
        elapsed_time = time.time() - start_time
        
        # JSON Report
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'elapsed_seconds': round(elapsed_time, 2),
            'cookie_summary': {
                'domains_with_cookies': len(all_cookies),
                'targets_with_cookies': with_cookies,
                'targets_without_cookies': without_cookies
            },
            'summary': {
                'total_targets': total_targets,
                'successful': successful,
                'errors': errors,
                'new_js_found': new_js_found,
                'total_js_urls': total_js_urls,
                'total_new_urls': total_new_urls,
                'total_downloaded': total_downloaded
            },
            'results': results
        }
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        # Text Summary
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"JavaScript Gathering Summary\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {elapsed_time:.2f} seconds\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"📊 Summary:\n")
            f.write(f"  Total Targets Processed: {total_targets}\n")
            f.write(f"  ✅ Successful: {successful}\n")
            f.write(f"  ❌ Errors: {errors}\n")
            f.write(f"  🎉 Targets with New JS: {new_js_found}\n")
            f.write(f"  🔗 Total JS URLs Found: {total_js_urls}\n")
            f.write(f"  🆕 Total New JS URLs: {total_new_urls}\n")
            f.write(f"  ⬇️ Files Downloaded: {total_downloaded}\n")
            f.write(f"  🍪 Targets with Cookies: {with_cookies}\n")
            f.write(f"  🚫 Targets without Cookies: {without_cookies}\n\n")
            
            # Cookie information
            if all_cookies:
                f.write(f"🍪 Cookie Information:\n")
                f.write(f"  Domains with cookies: {len(all_cookies)}\n")
                for domain, cookies in all_cookies.items():
                    f.write(f"    {domain}: {len(cookies)} cookies\n")
                f.write("\n")
            
            f.write("📝 Detailed Results:\n")
            f.write("-" * 80 + "\n")
            
            for result in results:
                status_icon = {
                    'new_js_found': '🎉',
                    'no_new_js': '✅',
                    'no_js_found': '⚠️',
                    'error': '❌',
                    'failed': '❌',
                    'timeout': '⏰',
                    'cancelled': '🛑'
                }.get(result['status'], '🔹')
                
                cookie_icon = '🍪' if result.get('cookies_found') else '🚫'
                
                f.write(f"\n{status_icon}{cookie_icon} URL: {result['url']}\n")
                f.write(f"  Status: {result['status']}\n")
                f.write(f"  Domain: {result.get('domain', 'N/A')}\n")
                f.write(f"  Cookies: {'Yes' if result.get('cookies_found') else 'No'} ({result.get('cookies_injected', 0)} injected)\n")
                f.write(f"  JS URLs Found: {result.get('js_urls_found', 0)}\n")
                f.write(f"  New JS URLs: {result.get('new_js_urls', 0)}\n")
                f.write(f"  Downloaded: {result.get('downloaded', 0)}\n")
                if result.get('error'):
                    f.write(f"  Error: {result['error']}\n")
                
                # List new URLs
                if result.get('new_urls_list'):
                    f.write(f"  New URLs:\n")
                    for url in result['new_urls_list'][:3]:
                        f.write(f"    - {url}\n")
                    if len(result['new_urls_list']) > 3:
                        f.write(f"    ... and {len(result['new_urls_list']) - 3} more\n")
        
        # Print summary to console
        print_banner("GATHERING COMPLETE", "\033[92m")
        
        print(f"📊 Targets: {total_targets} | ✅ Successful: {successful} | ❌ Errors: {errors}")
        print(f"⏱️  Duration: {elapsed_time:.2f} seconds")
        print(f"🔗 Total JS URLs Found: {total_js_urls}")
        print(f"🆕 New JS URLs Detected: {total_new_urls}")
        print(f"⬇️ Files Downloaded: {total_downloaded}")
        print(f"🍪 Targets with Cookies: {with_cookies} | 🚫 Without: {without_cookies}")
        
        if new_js_found > 0:
            print(f"\n🎉 Found new JS on {new_js_found} targets!")
            print(f"📁 New URLs: {self.output_base / 'newjsurls'}")
            print(f"📥 Downloads: {self.output_base / 'downloaded_js'}")
        
        # List domains without cookies
        domains_without_cookies = []
        for result in results:
            if not result.get('cookies_found'):
                domains_without_cookies.append(result.get('domain', result['url']))
        
        if domains_without_cookies:
            print(f"\n⚠️  Domains without cookies:")
            for domain in domains_without_cookies[:5]:  # Show first 5
                print(f"   {domain}")
            if len(domains_without_cookies) > 5:
                print(f"   ... and {len(domains_without_cookies) - 5} more")
        
        print(f"\n📋 Reports saved to:")
        print(f"  📄 Detailed: {report_file}")
        print(f"  📝 Summary: {summary_file}")
        
        print_banner("END OF REPORT", "\033[94m")
        
        # Also log the summary
        logger.info(f"📊 Gathering complete: {total_targets} targets, {total_new_urls} new URLs")
    
    def monitor(self):
        """Monitor for changes across all domains"""
        print_banner("JavaScript Monitoring System - Starting Monitoring", "\033[94m")
        
        logger.info("🔍 Starting JS monitoring...")
        
        all_domains = []
        for domain_dir in (self.output_base / "js_files").iterdir():
            if domain_dir.is_dir():
                all_domains.append(domain_dir.name)
        
        if not all_domains:
            logger.warning("⚠️ No domains found to monitor")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        monitor_file = self.output_base / "reports" / f"monitor_report_{timestamp}.json"
        
        monitor_data = {
            'timestamp': datetime.now().isoformat(),
            'total_domains': len(all_domains),
            'domains': {}
        }
        
        for domain in all_domains:
            domain_data = self._analyze_domain(domain)
            monitor_data['domains'][domain] = domain_data
        
        # Save monitor report
        with open(monitor_file, 'w', encoding='utf-8') as f:
            json.dump(monitor_data, f, indent=2, default=str)
        
        # Generate summary
        self._generate_monitor_summary(monitor_data, monitor_file)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="🚀 JavaScript Monitoring System - Detect new JavaScript launches",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python js_monitoring_system.py gather -t targets.txt
  python js_monitoring_system.py gather -t targets.txt --concurrent 3 --no-headless
  python js_monitoring_system.py gather -t targets.txt -c cookies/
  python js_monitoring_system.py monitor

Cookie Folder Structure:
  cookies/
  ├── example.com.json    # Cookies for example.com and *.example.com
  ├── google.com.json     # Cookies for google.com and *.google.com
  └── anyname.json        # Filename doesn't matter, domain is extracted from cookie data

Cookie JSON Format:
  [
    {
      "name": "session_id",
      "value": "abc123",
      "domain": ".example.com",  # Leading dot for subdomains
      "path": "/",
      "secure": true,
      "httpOnly": true
    }
  ]
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run', required=True)
    
    # Gather command
    gather_parser = subparsers.add_parser('gather', help='Gather JavaScript from targets')
    gather_parser.add_argument("-t", "--targets", required=True, help="Path to targets file (one URL per line)")
    gather_parser.add_argument("-c", "--cookies", help="Path to cookies folder (domain.json files)")
    gather_parser.add_argument("--geckodriver", help="Path to geckodriver executable")
    gather_parser.add_argument("--no-headless", action="store_true", help="Run browser in visible mode")
    gather_parser.add_argument("--concurrent", type=int, default=2, help="Max concurrent requests (default: 2)")
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Monitor JS changes across domains')
    
    args = parser.parse_args()
    
    if args.command == 'gather':
        print_banner("JavaScript Monitoring System - GATHER MODE", "\033[94m")
        monitor = JSMonitoringSystem(
            geckodriver_path=args.geckodriver,
            headless=not args.no_headless,
            max_concurrent=args.concurrent
        )
        monitor.gather_js(args.targets, args.cookies)
    
    elif args.command == 'monitor':
        print_banner("JavaScript Monitoring System - MONITOR MODE", "\033[94m")
        monitor = JSMonitoringSystem()
        monitor.monitor()


if __name__ == "__main__":
    main()
