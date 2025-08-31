#!/usr/bin/env python3

# ReconHound - Advanced tool for Directory & File Enumeration,subdomian enumeration,fuzzing, vhost discovery
# Author: Sreeraj (https://github.com/s-r-e-e-r-a-j)

import argparse
import requests
import concurrent.futures
import random
import sys
import time
import json
import signal
from urllib.parse import urlparse
import dns.resolver

class ReconHound:
    def __init__(self):
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/91.0.864.59",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
        ]
        self.found_paths = []
        self.found_subdomains = []
        self.found_vhosts = []
        self.is_running = True
        self.start_time = time.time()
        self.current_mode = None
        self.target = None
        self.wordlist = None
        self.threads = 10
        self.extensions = None
        self.param = None
        self.output_file = None
        self.wildcard_ips = None
        self.vhost_wildcard_size = None  # for vhost wildcard detection
        signal.signal(signal.SIGINT, self.signal_handler)

    def detect_subdomain_wildcard(self, domain):
        # Generate a random subdomain
        test_sub = f"{random.randint(100000,999999)}.{domain}"
        try:
             answers = dns.resolver.resolve(test_sub, 'A')
             if answers:
                 wildcard_ips = [r.to_text() for r in answers]
                 print(f"[!] Wildcard DNS detected on {domain} -> IPs: {wildcard_ips}")
                 return wildcard_ips
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
               return None

    def detect_vhost_wildcard(self, ip, base_domain):
         test_host = f"{random.randint(100000,999999)}.{base_domain}"
         url = f"http://{ip}/"
         headers = {'User-Agent': self.random_user_agent(), 'Host': test_host}
         try:
             response = requests.get(url, headers=headers, allow_redirects=False, timeout=5)
             print(f"[!] Wildcard VHOST detected for {base_domain}, default size: {len(response.content)}")
             return len(response.content)
         except requests.RequestException:
                return None
        
    
    def print_banner(self):
        print("===============================================================")
        print(f" ReconHound on {self.current_mode} mode")
        print("===============================================================")
        print(f"[+] Target:         {self.target}")
        print(f"[+] Wordlist:       {self.wordlist}")
        print(f"[+] Threads:        {self.threads}")
        if self.current_mode == 'dir' and self.extensions:
            print(f"[+] Extensions:     {self.extensions}")
        elif self.current_mode == 'fuzz':
            print(f"[+] Parameter:      {self.param}")
        elif self.current_mode == 'fuzzany':
            print(f"[+] Fuzzing all 'FUZZ' tokens in URL")
        elif self.current_mode == 'vhost':
            print(f"[+] Base Domain:    {self.base_domain}")
            print(f"[+] IP Address:    {self.ip_address}")
        print(f"[+] Status codes:   200,204,301,302,307,401,403")
        print("===============================================================")
        print("Developed By Sreeraj | GitHub: https://github.com/s-r-e-e-r-a-j")
        print("===============================================================\n")

    def random_user_agent(self):
        return random.choice(self.user_agents)

    def signal_handler(self, sig, frame):
        self.is_running = False
        print("\n[!] Received interrupt signal. Shutting down...")
        self.save_partial_results()
        sys.exit(0)

    def save_partial_results(self):
        if self.output_file:
            try:
                with open(self.output_file, 'w') as f:
                    if self.current_mode in ['dir', 'fuzz', 'fuzzany']:
                        json.dump({'paths': self.found_paths}, f, indent=2)
                    elif self.current_mode == 'sub':
                        json.dump({'subdomains': self.found_subdomains}, f, indent=2)
                    elif self.current_mode == 'vhost':
                        json.dump({'vhosts': self.found_vhosts}, f, indent=2)
                print(f"[+] Partial results saved to {self.output_file}")
            except IOError as e:
                print(f"[-] Error saving partial results: {str(e)}")

    def check_url(self, url, word, extensions=None):
        if not self.is_running:
            return
        try:
            headers = {'User-Agent': self.random_user_agent()}

            # Always check base word
            test_url = f"{url.rstrip('/')}/{word}"
            self.make_request(test_url, headers)

            # Then check each word+extension if provided
            if extensions:
                for ext in extensions:
                    test_url_ext = f"{url.rstrip('/')}/{word}{ext}"
                    self.make_request(test_url_ext, headers)
        except requests.RequestException:
            pass

    def make_request(self, test_url, headers):
        try:
            response = requests.get(test_url, headers=headers, allow_redirects=False, timeout=5)
            if response.status_code in [200, 204, 301, 302, 307, 401, 403]:
                self.found_paths.append({
                    'url': test_url,
                    'status': response.status_code,
                    'size': len(response.content)
                })
                print(f"[+] Found: {test_url} (Status: {response.status_code})")
        except requests.RequestException:
            pass

    def check_subdomain(self, domain, subdomain):
        if not self.is_running:
            return
        try:
            full_domain = f"{subdomain}.{domain}"
            answers = dns.resolver.resolve(full_domain, 'A')
            ips = [r.to_text() for r in answers]
            if hasattr(self, 'wildcard_ips') and self.wildcard_ips and all(ip in self.wildcard_ips for ip in ips):
                return
            if answers:
                self.found_subdomains.append(full_domain)
                print(f"[+] Found: {full_domain}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
        except Exception as e:
            print(f"[-] Error resolving {subdomain}.{domain}: {str(e)}")

    def fuzz_parameter(self, url, param, value):
        if not self.is_running:
            return
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            query = parsed.query.replace('FUZZ', value)
            full_url = f"{base_url}?{query}"
            headers = {'User-Agent': self.random_user_agent()}
            response = requests.get(full_url, headers=headers, allow_redirects=False, timeout=5)
            if response.status_code in [200, 204, 301, 302, 307, 401, 403]:
                self.found_paths.append({
                    'url': full_url,
                    'status': response.status_code,
                    'size': len(response.content)
                })
                print(f"[+] Found: {full_url} (Status: {response.status_code})")
        except requests.RequestException:
            pass

    def fuzz_anywhere_worker(self, url, word):
        if not self.is_running:
            return
        try:
            test_url = url.replace("FUZZ", word)
            headers = {'User-Agent': self.random_user_agent()}
            response = requests.get(test_url, headers=headers, allow_redirects=False, timeout=5)
            if response.status_code in [200, 204, 301, 302, 307, 401, 403]:
                self.found_paths.append({
                    'url': test_url,
                    'status': response.status_code,
                    'size': len(response.content)
                })
                print(f"[+] Found: {test_url} (Status: {response.status_code})")
        except requests.RequestException:
            pass

    def check_vhost(self, ip, base_domain, word):
        if not self.is_running:
            return
        try:
            test_host = f"{word}.{base_domain}"
            url = f"http://{ip}/"
            headers = {
                'User-Agent': self.random_user_agent(),
                'Host': test_host
            }
            response = requests.get(url, headers=headers, allow_redirects=False, timeout=5)
            if response.status_code in [200, 204, 301, 302, 307, 401, 403]:
                self.found_vhosts.append({
                    'vhost': test_host,
                    'status': response.status_code,
                    'size': len(response.content)
                })
                print(f"[+] Found: {test_host} (Status: {response.status_code})")
        except requests.RequestException:
            pass

    def run_directory_buster(self, url, wordlist, extensions=None, threads=10):
        self.current_mode = 'dir'
        self.target = url
        self.wordlist = wordlist
        self.threads = threads
        if extensions:
           self.extensions = [ext if ext.startswith('.') else '.' + ext for ext in extensions.split(',')]
        else:
             self.extensions = None

        self.print_banner()
        try:
            with open(wordlist, 'r', encoding='utf-8') as f:
                  words = [line.strip() for line in f if line.strip()]
        except UnicodeDecodeError:
               # fallback to latin-1 encoding if UTF-8 fails
               try:
                   with open(wordlist, 'r', encoding='latin-1') as f:
                         words = [line.strip() for line in f if line.strip()]
               except Exception as e:
                      print(f"[-] Error reading wordlist with latin-1: {e}")
                      return
        except FileNotFoundError:
               print(f"[-] Error: Wordlist file '{wordlist}' not found")
               return

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            for word in words:
                executor.submit(self.check_url, url, word, self.extensions)

    def run_subdomain_buster(self, domain, wordlist, threads=10):
        self.current_mode = 'sub'
        self.target = domain
        self.wordlist = wordlist
        self.threads = threads
        self.wildcard_ips = self.detect_subdomain_wildcard(domain)
        self.print_banner()
        try:
            with open(wordlist, 'r', encoding='utf-8') as f:
                 subdomains = [line.strip() for line in f if line.strip()]
        except UnicodeDecodeError:
             # Fallback to latin-1 encoding if UTF-8 fails
              try:
                  with open(wordlist, 'r', encoding='latin-1') as f:
                       subdomains = [line.strip() for line in f if line.strip()]
              except Exception as e:
                     print(f"[-] Error reading wordlist with latin-1: {e}")
                     return
        except FileNotFoundError:
              print(f"[-] Error: Wordlist file '{wordlist}' not found")
              return

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            for subdomain in subdomains:
                executor.submit(self.check_subdomain, domain, subdomain)

    def run_fuzzer(self, url, param, wordlist, threads=10):
        self.current_mode = 'fuzz'
        self.target = url
        self.wordlist = wordlist
        self.threads = threads
        self.param = param
        self.print_banner()
        try:
            with open(wordlist, 'r', encoding='utf-8') as f:
                 values = [line.strip() for line in f if line.strip()]
        except UnicodeDecodeError:
               # Fallback to latin-1 encoding if UTF-8 fails
               try:
                   with open(wordlist, 'r', encoding='latin-1') as f:
                        values = [line.strip() for line in f if line.strip()]
               except Exception as e:
                      print(f"[-] Error reading wordlist with latin-1: {e}")
                      return
        except FileNotFoundError:
               print(f"[-] Error: Wordlist file '{wordlist}' not found")
               return
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            for value in values:
                executor.submit(self.fuzz_parameter, url, param, value)

    def run_fuzzer_anywhere(self, url, wordlist, threads=10):
        self.current_mode = 'fuzzany'
        self.target = url
        self.wordlist = wordlist
        self.threads = threads
        self.print_banner()
        try:
            with open(wordlist, 'r', encoding='utf-8') as f:
                 values = [line.strip() for line in f if line.strip()]
        except UnicodeDecodeError:
               # Fallback to latin-1 encoding if UTF-8 fails
               try:
                   with open(wordlist, 'r', encoding='latin-1') as f:
                        values = [line.strip() for line in f if line.strip()]
               except Exception as e:
                      print(f"[-] Error reading wordlist with latin-1: {e}")
                      return
        except FileNotFoundError:
               print(f"[-] Error: Wordlist file '{wordlist}' not found")
               return

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            for value in values:
                executor.submit(self.fuzz_anywhere_worker, url, value)

    def run_vhost_buster(self, ip, base_domain, wordlist, threads=10):
        self.current_mode = 'vhost'
        self.target = f"{base_domain} @ {ip}"
        self.wordlist = wordlist
        self.threads = threads
        self.vhost_wildcard_size = self.detect_vhost_wildcard(ip, base_domain)
        self.base_domain = base_domain
        self.ip_address = ip
        self.print_banner()
        try:
            with open(wordlist, 'r', encoding='utf-8') as f:
                 words = [line.strip() for line in f if line.strip()]
        except UnicodeDecodeError:
               # Fallback to latin-1 encoding if UTF-8 fails
               try:
                   with open(wordlist, 'r', encoding='latin-1') as f:
                        words = [line.strip() for line in f if line.strip()]
               except Exception as e:
                      print(f"[-] Error reading wordlist with latin-1: {e}")
                      return
        except FileNotFoundError:
               print(f"[-] Error: Wordlist file '{wordlist}' not found")
               return
   
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            for word in words:
                executor.submit(self.check_vhost, ip, base_domain, word)

    def save_results(self, output_file):
        self.output_file = output_file
        try:
            with open(output_file, 'w') as f:
                if self.current_mode in ['dir', 'fuzz', 'fuzzany']:
                    json.dump({'paths': self.found_paths}, f, indent=2)
                elif self.current_mode == 'sub':
                    json.dump({'subdomains': self.found_subdomains}, f, indent=2)
                elif self.current_mode == 'vhost':
                    json.dump({'vhosts': self.found_vhosts}, f, indent=2)
            print(f"[+] Results saved to {output_file}")
        except IOError as e:
            print(f"[-] Error saving results: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="ReconHound - Advanced Web Reconnaissance Tool")
    subparsers = parser.add_subparsers(dest='mode', required=True, help="Select a mode of operation")

    dir_parser = subparsers.add_parser('dir', help='Directory busting mode')
    dir_parser.add_argument('-u', '--url', required=True, help="Target URL to scan for directories")
    dir_parser.add_argument('-w', '--wordlist', required=True, help="Path to the wordlist file")
    dir_parser.add_argument('-e', '--extensions', help="Comma-seperated list of file extensions to try (e.g., .php,.db,.txt,.js)")
    dir_parser.add_argument('-t', '--threads', type=int, default=10, help="Number of threads to use (default: 10)")
    dir_parser.add_argument('-o', '--output', help="Path to save results as a JSON file (e.g.,/home/kali/Desktop/output.json)")

    sub_parser = subparsers.add_parser('sub', help='Subdomain enumeration mode')
    sub_parser.add_argument('-d', '--domain', required=True, help="Target domain to enumerate subdomains")
    sub_parser.add_argument('-w', '--wordlist', required=True, help="Path to the wordlist file")
    sub_parser.add_argument('-t', '--threads', type=int, default=10, help="Number of threads to use (default: 10)")
    sub_parser.add_argument('-o', '--output', help="Path to save results as a JSON file (e.g.,/home/kali/Desktop/output.json)")

    fuzz_parser = subparsers.add_parser('fuzz', help='Parameter fuzzing mode')
    fuzz_parser.add_argument('-u', '--url', required=True, help="Target URL with the query parameter to fuzz (e,g., https://example.com/page.php?id=1)")
    fuzz_parser.add_argument('-p', '--param', required=True, help="Parameter name to fuzz (e.g., id)")
    fuzz_parser.add_argument('-w', '--wordlist', required=True, help="Path to the wordlist file")
    fuzz_parser.add_argument('-t', '--threads', type=int, default=10, help="Number of threads to use (default: 10)")
    fuzz_parser.add_argument('-o', '--output', help="Path to save results as a JSON file (e.g.,/home/kali/Desktop/output.json)")

    fuzzany_parser = subparsers.add_parser('fuzzany', help="Fuzz all 'FUZZ' placeholders anywhere in the URL")
    fuzzany_parser.add_argument('-u', '--url', required=True, help="URL with one or more 'FUZZ' placeholders")
    fuzzany_parser.add_argument('-w', '--wordlist', required=True, help="Path to the wordlist file")
    fuzzany_parser.add_argument('-t', '--threads', type=int, default=10, help="Number of threads to use (default: 10)")
    fuzzany_parser.add_argument('-o', '--output', help="Path to save results as a JSON file (e.g.,/home/kali/Desktop/output.json)")

    vhost_parser = subparsers.add_parser('vhost', help='Virtual host brute-forcing mode')
    vhost_parser.add_argument('-i', '--ip', required=True, help="IP address of the target server")
    vhost_parser.add_argument('-d', '--domain', required=True, help="Original base domain")
    vhost_parser.add_argument('-w', '--wordlist', required=True, help="Wordlist file with virtual host words")
    vhost_parser.add_argument('-t', '--threads', type=int, default=10, help="Number of threads to use (default: 10)")
    vhost_parser.add_argument('-o', '--output', help="Path to save results as a JSON file (e.g.,/home/kali/Desktop/output.json)")

    args = parser.parse_args()
    hound = ReconHound()

    try:
        if args.mode == 'dir':
            hound.output_file=args.output
            hound.run_directory_buster(args.url, args.wordlist, args.extensions, args.threads)
        elif args.mode == 'sub':
            hound.output_file=args.output
            hound.run_subdomain_buster(args.domain, args.wordlist, args.threads)
        elif args.mode == 'fuzz':
            hound.output_file=args.output
            hound.run_fuzzer(args.url, args.param, args.wordlist, args.threads)
        elif args.mode == 'fuzzany':
            hound.output_file=args.output
            hound.run_fuzzer_anywhere(args.url, args.wordlist, args.threads)
        elif args.mode == 'vhost':
            hound.output_file=args.output
            hound.run_vhost_buster(args.ip, args.domain, args.wordlist, args.threads)

        if args.output:
            hound.save_results(args.output)

        print("\n[+] Scan completed!")
        print(f"[+] Total paths found: {len(hound.found_paths)}")
        print(f"[+] Total subdomains found: {len(hound.found_subdomains)}")
        print(f"[+] Total virtual hosts found: {len(hound.found_vhosts)}")
        print(f"[+] Duration: {time.time() - hound.start_time:.2f} seconds")

    except KeyboardInterrupt:
        hound.signal_handler(None, None)

if __name__ == '__main__':
    main()
