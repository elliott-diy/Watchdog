# GitHub Malware Scanner

## Overview
This script automates the process of scanning GitHub repositories for suspicious terms and checks them against my malware scanner API. The goal is to collect and analyze samples to improve malware detection capabilities.
## Features
- **Automated GitHub Repository Search:** Fetches repositories based on predefined search terms.
- **Parallel Processing:** Uses multi-threading to scan repositories efficiently.
- **Malware Detection:** Checks repositories against dev.elliott.diy API for suspicious activity.
- **Rate Limit Handling:** Ensures compliance with GitHub API rate limits.

## Prerequisites
- Python 3.7+
- `requests` library
- Internet connection


## Usage
Run the script using:
```sh
python main.py
```

### Configuration
Modify the following parameters in the script as needed:
- **`GITHUB_MAX_WORKERS`**: Controls concurrent GitHub search requests.
- **`REPO_MAX_WORKERS`**: Limits concurrent repository checks.
- **`GITHUB_SEARCH_TIMEOUT`**: Timeout for GitHub requests.
- **`CHECK_TIMEOUT`**: Timeout for repository analysis.
- **`MAX_RETRIES`**: Number of retries per request.

### Example Output
```sh
Search term 'discord token stealer' returned 5 repos
Suspicious repository found: user/repo-name
Total suspicious repositories found: 3
Total repositories checked: 10
Suspicious percentage: 30.00%
```

## API Endpoint
The scanner sends requests to:
```
https://dev.elliott.diy/?repo=<repository_name>
```
- **Response Format:** JSON with a `suspicious` flag indicating malware presence.
- **Payload Extraction** JSON with a line number and payload found.
- **HTTP Status Code 413:** Repository is too large to check.

## Limitations
- False positives/negatives may occur.
- GitHub rate limits can slow scanning.
- Payloads are too big.Heavy obfuscation can cause this to happen. 
- Does not analyze private repositories.

## License
This project is licensed under the MIT License.

