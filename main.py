import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import threading

# Configuration
GITHUB_MAX_WORKERS = 5
REPO_MAX_WORKERS = 5
GITHUB_SEARCH_TIMEOUT = 10
CHECK_TIMEOUT = 20
MAX_RETRIES = 3              #

INITIAL_DELAY = 2

# Define search terms
search_terms = [
    "discord token stealer",
    "discord token grabber",
    "discord token sniper",
    "discord token checker",
    "discord token generator",
    "discord token cracker",
    "discord token exploit",
    "discord token dumper",
    "discord token logger",
    "discord rat",
    "discord remote access tool",
    "discord rat builder",
    "discord rat panel",
    "discord trojan",
    "discord malware",
    "discord spam bot",
    "discord raid bot",
    "discord mass dm bot",
    "discord flood bot",
    "discord group spammer",
    "discord mention spammer",
    "discord webhook spammer",
    "discord nuke bot",
    "discord nuker script",
    "discord webhook stealer",
    "discord webhook grabber",
    "discord webhook spam",
    "discord webhook bot",
    "discord webhook exploit",
    "discord webhook remover",
    "discord phishing bot",
    "discord scam bot",
    "discord fake nitro bot",
    "discord nitro scam",
    "discord nitro phishing",
    "discord phishing panel",
    "discord fake login page",
    "discord credential stuffing",
    "discord brute force tool",
    "discord account cracker",
    "discord password cracker",
    "discord login cracker",
    "discord brute force attack",
    "discord account generator",
    "discord free account generator",
    "discord alt generator",
    "discord account checker",
    "discord token checker",
    "discord botnet",
    "discord ddos bot",
    "discord ddos panel",
    "discord malware bot",
    "discord spyware",
    "discord file spreader",
    "discord virus spreader",
    "discord payload dropper",
    "discord self-spreading malware",
    "discord worm",
    "discord exploit tool",
    "discord api abuse",
    "discord webhook abuse",
    "discord bot token grabber",
    "discord webhook spam tool",
    "discord fake bot",
    "discord fake verification bot",
    "discord fake verification",
    "discord impersonator bot",
    "discord ip logger",
    "discord ip grabber",
    "discord ddos tool",
    "discord fake moderation bot",
    "discord admin bypass tool",
]



search_terms = sorted(search_terms, key=lambda x: hash(x))

total_found = 0
total_checked = 0

session = requests.Session()

github_semaphore = threading.Semaphore(GITHUB_MAX_WORKERS)


def wait_for_rate_limit():
    rate_limit_url = "https://api.github.com/rate_limit"
    try:
        response = session.get(rate_limit_url, timeout=GITHUB_SEARCH_TIMEOUT)
        response.raise_for_status()
        rate_limit = response.json()
        remaining = rate_limit['resources']['search']['remaining']
        reset_time = rate_limit['resources']['search']['reset']
        if remaining == 0:
            sleep_time = reset_time - time.time() + 5  # extra buffer hopefully maybe please god work
            print(f"GitHub search rate limit exceeded. Sleeping for {sleep_time:.0f} seconds.")
            time.sleep(sleep_time)
    except Exception as e:
        print(f"Error checking GitHub rate limit: {e}")


def fetch_github_repos(search):
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
    url = f"https://dev.elliott.diy/?repo={name}"
    delay = INITIAL_DELAY
    r = None
    for attempt in range(max_retries):
        try:
            r = session.get(url, timeout=CHECK_TIMEOUT)
            r.raise_for_status()
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
            delay *= 2

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
