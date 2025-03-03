import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import threading

# Configuration
GITHUB_MAX_WORKERS = 5   # Limit concurrent GitHub API calls (unauthenticated)
REPO_MAX_WORKERS = 5    # Lower concurrency for repo checks to avoid overloading target endpoint
GITHUB_SEARCH_TIMEOUT = 10   # Timeout for GitHub search requests
CHECK_TIMEOUT = 20           # Increased timeout for repo checks
MAX_RETRIES = 3              # Maximum number of retries for repo checks

INITIAL_DELAY = 2            # Initial delay (in seconds) for exponential backoff in repo checks

# Define search terms
search_terms = [
    # Token Stealers
    "discord token stealer",
    "discord token grabber",
    "discord token sniper",
    "discord token checker",
    "discord token generator",
    "discord token cracker",
    "discord token exploit",
    "discord token dumper",
    "discord token logger",

    # RATs (Remote Access Trojans)
    "discord rat",
    "discord remote access tool",
    "discord rat builder",
    "discord rat panel",
    "discord trojan",
    "discord malware",

    # Spamming & Raiding
    "discord spam bot",
    "discord raid bot",
    "discord mass dm bot",
    "discord flood bot",
    "discord group spammer",
    "discord mention spammer",
    "discord webhook spammer",
    "discord nuke bot",
    "discord nuker script",
    "discord server nuker",

    # Webhooks & Exploits
    "discord webhook stealer",
    "discord webhook grabber",
    "discord webhook spam",
    "discord webhook bot",
    "discord webhook exploit",
    "discord webhook remover",

    # Phishing & Scam Bots
    "discord phishing bot",
    "discord scam bot",
    "discord fake nitro bot",
    "discord nitro scam",
    "discord nitro phishing",
    "discord phishing panel",
    "discord fake login page",

    # Credential Stuffing & Brute Force
    "discord credential stuffing",
    "discord brute force tool",
    "discord account cracker",
    "discord password cracker",
    "discord login cracker",
    "discord brute force attack",

    # Account Generators & Checkers
    "discord account generator",
    "discord free account generator",
    "discord alt generator",
    "discord account checker",
    "discord token checker",

    # Botnets & Malware
    "discord botnet",
    "discord ddos bot",
    "discord ddos panel",
    "discord malware bot",
    "discord spyware",

    # Spreading Malware via Discord
    "discord file spreader",
    "discord virus spreader",
    "discord payload dropper",
    "discord self-spreading malware",
    "discord worm",

    # Hacking Tools & Exploits
    "discord exploit tool",
    "discord api abuse",
    "discord webhook abuse",
    "discord bot token grabber",
    "discord webhook spam tool",

    # Cloning & Spoofing
    "discord fake bot",
    "discord fake verification bot",
    "discord fake verification",
    "discord impersonator bot",

    # Miscellaneous Attacks
    "discord ip logger",
    "discord ip grabber",
    "discord ddos tool",
    "discord fake moderation bot",
    "discord admin bypass tool",
]



# Shuffle the search terms to avoid bias on every run
search_terms = sorted(search_terms, key=lambda x: hash(x))

# Global counters
total_found = 0
total_checked = 0

# Create a shared session for connection reuse.
session = requests.Session()

# Semaphore for GitHub searches (to control concurrency for GitHub API calls)
github_semaphore = threading.Semaphore(GITHUB_MAX_WORKERS)


def wait_for_rate_limit():
    """
    Check the GitHub rate limit and sleep if necessary.
    For unauthenticated requests the search endpoint is limited.
    """
    rate_limit_url = "https://api.github.com/rate_limit"
    try:
        response = session.get(rate_limit_url, timeout=GITHUB_SEARCH_TIMEOUT)
        response.raise_for_status()
        rate_limit = response.json()
        # We're checking the search resource limits.
        remaining = rate_limit['resources']['search']['remaining']
        reset_time = rate_limit['resources']['search']['reset']
        if remaining == 0:
            sleep_time = reset_time - time.time() + 5  # extra buffer
            print(f"GitHub search rate limit exceeded. Sleeping for {sleep_time:.0f} seconds.")
            time.sleep(sleep_time)
    except Exception as e:
        print(f"Error checking GitHub rate limit: {e}")


def fetch_github_repos(search):
    """
    Fetch repositories for a given search term from GitHub.
    Uses a semaphore to limit concurrent API calls.
    """
    with github_semaphore:
        time.sleep(120)
        wait_for_rate_limit()
        github_url = f"https://api.github.com/search/repositories?q={search}+language:python&sort=updated&per_page=100"
        try:
            response = session.get(github_url, timeout=GITHUB_SEARCH_TIMEOUT)
            response.raise_for_status()
            items = response.json().get('items', [])
            print(f"Search term '{search}' returned {len(items)} repos")
            return [repo['full_name'] for repo in items]
        except requests.exceptions.RequestException as e:
            print(f"Failed to fetch repos for search term '{search}', error: {e}")
            return []


def check_repo(name, max_retries=MAX_RETRIES):
    """
    Check if a repository is suspicious using the custom endpoint.
    Uses retry logic with exponential backoff if transient errors occur.
    """
    url = f"https://dev.elliott.diy/?repo={name}"
    delay = INITIAL_DELAY
    r = None
    for attempt in range(max_retries):
        try:
            r = session.get(url, timeout=CHECK_TIMEOUT)
            r.raise_for_status()
            # If the endpoint returns valid JSON with a 'suspicious' flag, return that.
            if r.status_code == 413:
                print(f"Repository {name} is too large to check.")
                return name, None
            if r.json().get('suspicious'):
                return name, True
            else:
                return name, False
        except requests.exceptions.RequestException as e:
            if r is not None and r.status_code == 413:
                return name, None
            print(f"Attempt {attempt + 1} failed to check {name}, error: {e}")
            time.sleep(delay)
            delay *= 2  # exponential backoff
    # After all retries, return failure
    return name, None


def main():
    global total_checked, total_found
    with ThreadPoolExecutor(max_workers=100) as search_executor, \
         ThreadPoolExecutor(max_workers=REPO_MAX_WORKERS) as repo_executor:
        github_futures = {search_executor.submit(fetch_github_repos, term): term for term in search_terms}
        for future in as_completed(github_futures):
            search_term = github_futures[future]
            try:
                repo_names = future.result()
                if not repo_names:
                    continue
                repo_futures = {repo_executor.submit(check_repo, name): name for name in repo_names}
                for repo_future in as_completed(repo_futures):
                    name, is_suspicious = repo_future.result()
                    if is_suspicious is not None:
                        total_checked += 1
                        if is_suspicious:
                            total_found += 1
                            print(f"Suspicious repository found: {name}")
                    else:
                        print(f"Failed to check repository {name}")
            except Exception as e:
                print(f"Error processing search term '{search_term}': {e}")

    print(f"\nTotal suspicious repositories found: {total_found}")
    print(f"Total repositories checked: {total_checked}")
    if total_checked:
        suspicious_percentage = (total_found / total_checked) * 100
        print(f"Suspicious percentage: {suspicious_percentage:.2f}%")
    else:
        print("No repositories were checked.")


if __name__ == '__main__':
    main()
