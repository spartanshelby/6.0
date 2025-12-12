#!/usr/bin/env python3
"""
Cookie Extractor - Extract cookies from browser and save to cookie folder
"""

import os
import json
import sqlite3
import shutil
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import browser_cookie3

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cookie_extractor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CookieExtractor:
    def __init__(self, output_folder: str = "cookies"):
        """
        Initialize cookie extractor
        
        Args:
            output_folder: Folder to save extracted cookies
        """
        self.output_folder = Path(output_folder)
        self.output_folder.mkdir(parents=True, exist_ok=True)
    
    def extract_from_browser(self, browser: str = "firefox") -> Dict[str, List[Dict]]:
        """
        Extract cookies from browser
        
        Args:
            browser: Browser to extract from ('firefox', 'chrome', 'edge', 'brave')
        
        Returns:
            Dictionary of domain -> cookies list
        """
        cookies_by_domain = {}
        
        try:
            if browser.lower() == "firefox":
                cj = browser_cookie3.firefox()
            elif browser.lower() == "chrome":
                cj = browser_cookie3.chrome()
            elif browser.lower() == "edge":
                cj = browser_cookie3.edge()
            elif browser.lower() == "brave":
                cj = browser_cookie3.brave()
            else:
                logger.error(f"Unsupported browser: {browser}")
                return {}
            
            # Group cookies by domain
            for cookie in cj:
                domain = cookie.domain
                if domain.startswith('.'):
                    domain = domain[1:]  # Remove leading dot
                
                if domain not in cookies_by_domain:
                    cookies_by_domain[domain] = []
                
                cookie_dict = {
                    'name': cookie.name,
                    'value': cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'expires': cookie.expires,
                    'secure': cookie.secure,
                    'httpOnly': getattr(cookie, 'httpOnly', False),
                    'sameSite': getattr(cookie, 'sameSite', None)
                }
                
                cookies_by_domain[domain].append(cookie_dict)
            
            logger.info(f"Extracted {len(cj)} cookies from {browser}")
            
        except Exception as e:
            logger.error(f"Error extracting cookies from {browser}: {e}")
            return {}
        
        return cookies_by_domain
    
    def extract_for_domain(self, domain: str, browser: str = "firefox") -> List[Dict]:
        """
        Extract cookies for specific domain
        
        Args:
            domain: Domain to extract cookies for
            browser: Browser to extract from
        
        Returns:
            List of cookies for the domain
        """
        all_cookies = self.extract_from_browser(browser)
        
        # Get cookies for exact domain
        domain_cookies = all_cookies.get(domain, [])
        
        # Also get cookies for parent domains (e.g., .example.com for sub.example.com)
        for cookie_domain, cookies in all_cookies.items():
            if cookie_domain.startswith('.') and domain.endswith(cookie_domain[1:]):
                domain_cookies.extend(cookies)
            elif cookie_domain == f".{domain}":
                domain_cookies.extend(cookies)
        
        # Remove duplicates
        unique_cookies = []
        seen = set()
        for cookie in domain_cookies:
            key = (cookie['name'], cookie['domain'], cookie['path'])
            if key not in seen:
                seen.add(key)
                unique_cookies.append(cookie)
        
        logger.info(f"Found {len(unique_cookies)} cookies for domain {domain}")
        return unique_cookies
    
    def save_cookies(self, domain: str, cookies: List[Dict], filename: str = None):
        """
        Save cookies to file
        
        Args:
            domain: Domain name
            cookies: List of cookie dictionaries
            filename: Optional custom filename
        """
        if not cookies:
            logger.warning(f"No cookies to save for {domain}")
            return
        
        if filename is None:
            filename = f"{domain}.json"
        
        filepath = self.output_folder / filename
        
        # Clean up cookie data
        cleaned_cookies = []
        for cookie in cookies:
            cleaned_cookie = {
                'name': cookie.get('name', ''),
                'value': cookie.get('value', ''),
                'domain': cookie.get('domain', ''),
                'path': cookie.get('path', '/'),
                'secure': cookie.get('secure', True),
                'httpOnly': cookie.get('httpOnly', False)
            }
            
            # Add expires if present
            if cookie.get('expires'):
                cleaned_cookie['expires'] = cookie['expires']
            
            # Add sameSite if present
            if cookie.get('sameSite'):
                cleaned_cookie['sameSite'] = cookie['sameSite']
            
            cleaned_cookies.append(cleaned_cookie)
        
        # Save to file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(cleaned_cookies, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Saved {len(cleaned_cookies)} cookies to {filepath}")
        return filepath
    
    def extract_and_save_all(self, browser: str = "firefox"):
        """
        Extract all cookies from browser and save by domain
        """
        cookies_by_domain = self.extract_from_browser(browser)
        
        saved_count = 0
        for domain, cookies in cookies_by_domain.items():
            if cookies:  # Only save if there are cookies
                self.save_cookies(domain, cookies)
                saved_count += 1
        
        logger.info(f"Saved cookies for {saved_count} domains")
    
    def extract_and_save_domain(self, domain: str, browser: str = "firefox", filename: str = None):
        """
        Extract cookies for specific domain and save
        
        Args:
            domain: Domain to extract cookies for
            browser: Browser to extract from
            filename: Optional custom filename
        """
        cookies = self.extract_for_domain(domain, browser)
        if cookies:
            return self.save_cookies(domain, cookies, filename)
        else:
            logger.warning(f"No cookies found for {domain}")
            return None
    
    def merge_cookies(self, domain: str, new_cookies: List[Dict], merge_method: str = "replace"):
        """
        Merge new cookies with existing cookies for a domain
        
        Args:
            domain: Domain name
            new_cookies: New cookies to add
            merge_method: 'replace', 'update', or 'add'
        """
        existing_file = self.output_folder / f"{domain}.json"
        existing_cookies = []
        
        # Load existing cookies if file exists
        if existing_file.exists():
            try:
                with open(existing_file, 'r', encoding='utf-8') as f:
                    existing_cookies = json.load(f)
            except:
                existing_cookies = []
        
        if merge_method == "replace":
            final_cookies = new_cookies
        elif merge_method == "update":
            # Update existing cookies with new values
            cookie_dict = {c['name']: c for c in existing_cookies}
            for new_cookie in new_cookies:
                cookie_dict[new_cookie['name']] = new_cookie
            final_cookies = list(cookie_dict.values())
        else:  # add
            final_cookies = existing_cookies + new_cookies
        
        # Save merged cookies
        return self.save_cookies(domain, final_cookies)
    
    def list_domains(self):
        """List all domains with saved cookies"""
        cookie_files = list(self.output_folder.glob("*.json"))
        
        if not cookie_files:
            logger.info("No cookie files found")
            return []
        
        domains = []
        for file in cookie_files:
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    cookies = json.load(f)
                    if cookies:
                        # Get domains from cookies
                        file_domains = set()
                        for cookie in cookies:
                            domain = cookie.get('domain', '')
                            if domain.startswith('.'):
                                domain = domain[1:]
                            if domain:
                                file_domains.add(domain)
                        
                        domains.append({
                            'file': file.name,
                            'domains': list(file_domains),
                            'cookie_count': len(cookies)
                        })
            except:
                continue
        
        return domains
    
    def view_cookies(self, domain: str = None):
        """View cookies for a domain or all domains"""
        if domain:
            filepath = self.output_folder / f"{domain}.json"
            if filepath.exists():
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        cookies = json.load(f)
                        print(f"\n📋 Cookies for {domain}:")
                        print(f"{'='*60}")
                        for i, cookie in enumerate(cookies, 1):
                            print(f"{i}. {cookie['name']}: {cookie['value'][:30]}...")
                            print(f"   Domain: {cookie.get('domain', 'N/A')}")
                            print(f"   Path: {cookie.get('path', '/')}")
                            print(f"   Secure: {cookie.get('secure', False)}")
                            print(f"   HttpOnly: {cookie.get('httpOnly', False)}")
                            print()
                except Exception as e:
                    logger.error(f"Error reading cookie file: {e}")
            else:
                logger.warning(f"No cookie file found for {domain}")
        else:
            domains = self.list_domains()
            print(f"\n📁 Cookie files in {self.output_folder}:")
            print(f"{'='*60}")
            for item in domains:
                print(f"📄 {item['file']}:")
                print(f"   Domains: {', '.join(item['domains'])}")
                print(f"   Cookies: {item['cookie_count']}")
                print()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Cookie Extractor - Extract and manage browser cookies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract all cookies from Firefox
  python cookie_extractor.py extract-all --browser firefox
  
  # Extract cookies for specific domain
  python cookie_extractor.py extract-domain -d example.com
  
  # View all saved cookies
  python cookie_extractor.py list
  
  # View cookies for specific domain
  python cookie_extractor.py view -d example.com
  
  # Manual cookie creation
  python cookie_extractor.py manual -d example.com -n session_id -v abc123
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run', required=True)
    
    # Extract all cookies
    extract_all_parser = subparsers.add_parser('extract-all', help='Extract all cookies from browser')
    extract_all_parser.add_argument('--browser', default='firefox', 
                                   choices=['firefox', 'chrome', 'edge', 'brave'],
                                   help='Browser to extract from (default: firefox)')
    extract_all_parser.add_argument('--output', default='cookies', 
                                   help='Output folder (default: cookies)')
    
    # Extract domain cookies
    extract_domain_parser = subparsers.add_parser('extract-domain', help='Extract cookies for specific domain')
    extract_domain_parser.add_argument('-d', '--domain', required=True, help='Domain to extract cookies for')
    extract_domain_parser.add_argument('--browser', default='firefox',
                                      choices=['firefox', 'chrome', 'edge', 'brave'],
                                      help='Browser to extract from (default: firefox)')
    extract_domain_parser.add_argument('--output', default='cookies',
                                      help='Output folder (default: cookies)')
    extract_domain_parser.add_argument('--filename', help='Custom filename (default: domain.json)')
    
    # List domains
    list_parser = subparsers.add_parser('list', help='List all saved cookies')
    list_parser.add_argument('--output', default='cookies',
                            help='Cookie folder (default: cookies)')
    
    # View cookies
    view_parser = subparsers.add_parser('view', help='View cookies for domain')
    view_parser.add_argument('-d', '--domain', help='Domain to view (optional, shows all if not specified)')
    view_parser.add_argument('--output', default='cookies',
                            help='Cookie folder (default: cookies)')
    
    # Manual cookie creation
    manual_parser = subparsers.add_parser('manual', help='Create cookie manually')
    manual_parser.add_argument('-d', '--domain', required=True, help='Domain for cookie')
    manual_parser.add_argument('-n', '--name', required=True, help='Cookie name')
    manual_parser.add_argument('-v', '--value', required=True, help='Cookie value')
    manual_parser.add_argument('--path', default='/', help='Cookie path (default: /)')
    manual_parser.add_argument('--secure', action='store_true', help='Secure cookie')
    manual_parser.add_argument('--http-only', action='store_true', help='HTTP Only cookie')
    manual_parser.add_argument('--output', default='cookies',
                              help='Output folder (default: cookies)')
    manual_parser.add_argument('--filename', help='Custom filename (default: domain.json)')
    
    args = parser.parse_args()
    
    extractor = CookieExtractor(args.output if hasattr(args, 'output') else 'cookies')
    
    if args.command == 'extract-all':
        print(f"\n🔍 Extracting all cookies from {args.browser}...")
        extractor.extract_and_save_all(args.browser)
        
    elif args.command == 'extract-domain':
        print(f"\n🔍 Extracting cookies for {args.domain} from {args.browser}...")
        extractor.extract_and_save_domain(args.domain, args.browser, args.filename)
        
    elif args.command == 'list':
        print(f"\n📁 Listing all cookies in {extractor.output_folder}:")
        domains = extractor.list_domains()
        if domains:
            for item in domains:
                print(f"\n📄 {item['file']}:")
                print(f"   Domains: {', '.join(item['domains'])}")
                print(f"   Cookies: {item['cookie_count']}")
        else:
            print("No cookie files found.")
        
    elif args.command == 'view':
        if args.domain:
            extractor.view_cookies(args.domain)
        else:
            extractor.view_cookies()
    
    elif args.command == 'manual':
        print(f"\n📝 Creating manual cookie for {args.domain}...")
        cookie = {
            'name': args.name,
            'value': args.value,
            'domain': f".{args.domain}",  # Add leading dot for subdomain support
            'path': args.path,
            'secure': args.secure,
            'httpOnly': args.http_only
        }
        
        # Load existing cookies if file exists
        filename = args.filename or f"{args.domain}.json"
        filepath = extractor.output_folder / filename
        
        existing_cookies = []
        if filepath.exists():
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    existing_cookies = json.load(f)
            except:
                existing_cookies = []
        
        # Add new cookie
        existing_cookies.append(cookie)
        
        # Save
        extractor.save_cookies(args.domain, existing_cookies, filename)
        print(f"✅ Cookie saved to {filepath}")

if __name__ == "__main__":
    main()
