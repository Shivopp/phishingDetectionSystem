#!/usr/bin/env python3
import requests
import json
from colorama import init, Fore, Style

init(autoreset=True)

API_URL = "http://localhost:5000"

def print_header(text):
    print(f"\n{Fore.BLUE}{'='*50}")
    print(f"{text}")
    print(f"{'='*50}{Style.RESET_ALL}")

def print_result(result):
    print(json.dumps(result, indent=2))
    if 'verdict' in result:
        verdict = result['verdict']
        if verdict == 'safe':
            print(f"{Fore.GREEN}✓ Verdict: SAFE{Style.RESET_ALL}")
        elif verdict == 'suspicious':
            print(f"{Fore.YELLOW}⚠ Verdict: SUSPICIOUS{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ Verdict: MALICIOUS{Style.RESET_ALL}")

# Test 1: Health Check
print_header("Test 1: Health Check")
response = requests.get(f"{API_URL}/api/health")
print_result(response.json())

# Test 2: Safe URL
print_header("Test 2: Safe URL (google.com)")
response = requests.post(
    f"{API_URL}/api/analyze/url",
    json={"url": "https://google.com"}
)
print_result(response.json())

# Test 3: Suspicious URL
print_header("Test 3: Suspicious URL (IP address)")
response = requests.post(
    f"{API_URL}/api/analyze/url",
    json={"url": "http://192.168.1.1/admin/login.php"}
)
print_result(response.json())

# Test 4: Malicious URL
print_header("Test 4: Malicious URL")
response = requests.post(
    f"{API_URL}/api/analyze/url",
    json={"url": "http://paypal-security-verification-urgent.ru/login.html"}
)
print_result(response.json())

# Test 5: Safe Email
print_header("Test 5: Safe Email")
response = requests.post(
    f"{API_URL}/api/analyze/email",
    json={
        "content": "Hello, just a friendly reminder about tomorrow's meeting.",
        "sender": "team@company.com"
    }
)
print_result(response.json())

# Test 6: Phishing Email
print_header("Test 6: Phishing Email")
response = requests.post(
    f"{API_URL}/api/analyze/email",
    json={
        "content": "URGENT! Your account will be suspended. Click here NOW: http://verify-account.ru",
        "sender": "noreply@suspicious.com"
    }
)
print_result(response.json())

# Test 7: Statistics
print_header("Test 7: System Statistics")
response = requests.get(f"{API_URL}/api/stats")
print_result(response.json())

print(f"\n{Fore.GREEN}{'='*50}")
print("All tests completed successfully!")
print(f"{'='*50}{Style.RESET_ALL}")