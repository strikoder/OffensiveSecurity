# source: https://gist.github.com/SecFathy/2f04e3207d9790e9209ef2eab5a8459f
# Identify and confirm reflected XSS vulnerabilities using parameter discovery + AI-based validation (via Gemini API).

import warnings
from urllib3.exceptions import NotOpenSSLWarning
warnings.filterwarnings("ignore", category=NotOpenSSLWarning)

import subprocess
import requests
import urllib.parse
import json
import os
from datetime import datetime

# Gemini Configuration
GEMINI_API_KEY = "Add-Your-Gemini-API-Key-Here"
GEMINI_MODEL = "gemini-2.0-flash"
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
HEADERS = {"Content-Type": "application/json"}

# ANSI color codes
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"
RED = "\033[91m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"

# Banner

def print_banner():
    banner = f"""
{BOLD}{CYAN}
==========================================
   Automated Reflected XSS Scanner v1.0
   Author: SecFathy
==========================================
{RESET}
"""
    print(banner)

def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Step 1: Run fallparams to extract parameters
def run_fallparams(url):
    print(f"{BLUE}[{now()}] Running fallparams...{RESET}")
    try:
        subprocess.run(["fallparams", "-u", url], check=True)
        if not os.path.exists("parameters.txt"):
            print(f"{RED}[-] fallparams did not create parameters.txt{RESET}")
            return []
        with open("parameters.txt", "r") as f:
            params = [line.strip() for line in f.readlines() if line.strip()]
        print(f"{GREEN}[+] Found {len(params)} parameters.{RESET}")
        return params
    except subprocess.CalledProcessError as e:
        print(f"{RED}[-] fallparams error: {e}{RESET}")
        return []

# Step 2: Load XSS payloads
def load_payloads():
    try:
        with open("payloads.txt", "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{RED}[-] payloads.txt not found.{RESET}")
        return []

# Step 3: Send HTTP request with injected payload
def test_param(url, param, payload):
    parsed_url = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed_url.query)
    query[param] = payload
    new_query = urllib.parse.urlencode(query, doseq=True)
    final_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
    try:
        response = requests.get(final_url, timeout=10)
        return response.text, final_url
    except Exception as e:
        return f"Request Error: {e}", final_url

# Step 4: Send response to Gemini API
def analyze_with_gemini(http_response, payload, tested_url):
    prompt = f"""
You are a security expert helping analyze potential reflected XSS vulnerabilities.

Below is the HTTP response returned after injecting this payload:
PAYLOAD: {payload}
URL: {tested_url}

--- START OF HTTP RESPONSE ---
{http_response[:6000]}
--- END OF RESPONSE ---

Your task:
1. Detect if the payload is reflected.
2. Determine if it results in XSS.
3. Explain where it appears (HTML body, tag attribute, JS context, etc).
4. Reply with:
   - "Confirmed Reflected XSS: [reason]"
   - "Reflected But Not XSS: [explanation]"
   - "Not Reflected: [why]"
"""

    data = {
        "contents": [{"parts": [{"text": prompt}]}]
    }
    try:
        response = requests.post(GEMINI_API_URL, headers=HEADERS, json=data)
        result = response.json()
        return result["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        return f"Error from Gemini: {e} | Raw Response: {response.text}"

# Step 5: Main logic
def main():
    print_banner()
    url = input(f"{BOLD}Enter target URL (e.g., http://testphp.vulnweb.com/search.php): {RESET}").strip()

    parameters = run_fallparams(url)
    if not parameters:
        return

    payloads = load_payloads()
    if not payloads:
        return

    results = []

    for param in parameters:
        print(f"\n{BOLD}{'='*40}{RESET}")
        print(f"{BOLD}[{now()}] Testing parameter: {param}{RESET}")
        print(f"{BOLD}{'='*40}{RESET}")
        for payload in payloads:
            html, tested_url = test_param(url, param, payload)
            print(f"{CYAN}[*] Payload: {payload}{RESET}")
            result = analyze_with_gemini(html, payload, tested_url)
            if result.strip() == "Error from Gemini: 'candidates' | Raw Response":
                result = "Gemini Error"
            print(f"{GREEN}[Gemini]: {result}{RESET}")
            if result.strip().startswith("Confirmed Reflected XSS"):
                print(f"{MAGENTA}[Status] Confirmed Reflected Cross Site Scripting{RESET}")
            results.append({
                "parameter": param,
                "payload": payload,
                "result": result,
                "tested_url": tested_url
            })
            if "Confirmed" in result:
                print(f"{BOLD}{YELLOW}[POC] {tested_url} | Payload: {payload}{RESET}")
                break  # stop testing once one payload confirms

    with open("xss_results.json", "w") as f:
        json.dump(results, f, indent=2)

    # Summary Section
    confirmed = [r for r in results if r['result'].startswith('Confirmed Reflected XSS')]
    print(f"\n{BOLD}{'='*40}{RESET}")
    if confirmed:
        print(f"\n{MAGENTA}[Summary] Confirmed Reflected XSS Findings:{RESET}")
        for r in confirmed:
            print(f" - Param: {r['parameter']} | Payload: {r['payload']} | URL: {r['tested_url']}")
    else:
        print(f"{BLUE}[Summary] No confirmed reflected XSS found.{RESET}")
    print(f"{BOLD}{'='*40}{RESET}")
    print(f"\n{CYAN}Thank you for using the Automated Reflected XSS Scanner!{RESET}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        ans = input(f"\n{YELLOW}KeyboardInterrupt detected. Do you want to exit? (Y/n): {RESET}").strip().lower()
        if ans in ('', 'y', 'yes'):
            print(f"{CYAN}Exiting. Thank you for using the Automated Reflected XSS Scanner!{RESET}")
            exit(0)
        else:
            print(f"{GREEN}Resuming...{RESET}")
            main()
