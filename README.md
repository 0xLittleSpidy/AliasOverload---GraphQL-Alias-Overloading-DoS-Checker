# AliasOverload - GraphQL Alias Overloading DoS Checker

AliasOverload is a Python-based tool designed to detect potential Denial-of-Service (DoS) vulnerabilities in GraphQL servers caused by **alias overloading**. This tool sends crafted GraphQL queries with varying numbers of aliases to measure the server's response time and identify if the server is vulnerable to alias-based DoS attacks.

---

## Table of Contents
1. [About the Vulnerability](#about-the-vulnerability)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Example Output](#example-output)
6. [Contributing](#contributing)
7. [License](#license)

---

## About the Vulnerability

### Description
GraphQL servers permit duplicate or repetitive fields in queries, enabling end users to force the server to process the same field multiple times. This behavior can be exploited to overload the server with computationally expensive queries, leading to a denial-of-service (DoS) condition.

### Impact
- **Increased Response Time**: As the number of identical fields in a query increases, the server's response time may grow significantly.
- **Resource Exhaustion**: The server may become overwhelmed by processing repetitive fields, making it unable to handle legitimate requests.
- **DoS Exploitation**: An attacker can craft malicious queries with a high number of aliases to keep the server busy, effectively causing a denial-of-service.

### Root Cause
The vulnerability arises due to **insecure configuration** of the GraphQL server, which fails to enforce limits on the number of aliases or repetitive fields in a single request.

### Recommendation
To mitigate this vulnerability:
1. **Limit Aliases**: Implement restrictions on the number of aliases allowed in a single request.
2. **Query Cost Analysis**: Use query cost analysis to reject overly complex or expensive queries.
3. **Rate Limiting**: Enforce rate limits to prevent abuse of the GraphQL API.

---

## Features
- **Alias Overloading Detection**: Tests for potential DoS vulnerabilities by sending queries with varying numbers of aliases.
- **Customizable Alias Counts**: Allows you to specify two alias counts (`--alias1` and `--alias2`) for testing.
- **Sequential Execution**: Sends requests one at a time to ensure accurate timing.
- **Human-Readable Output**: Displays start time, end time, and response time in a user-friendly format.
- **DoS Analysis**: Flags potential DoS vulnerabilities if the response time increases with higher alias counts.
- **Custom Headers**: Supports adding custom headers (e.g., for authentication).
- **Output to File**: Saves results to a file for further analysis.

---

## Installation

### Prerequisites
- Python 3.7 or higher
- `aiohttp` library
- `tqdm` library (for progress bar)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/AliasOverload.git
   cd AliasOverload
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

### Basic Usage
```bash
python alias_overload.py -u https://example.com/graphql --alias1 100 --alias2 200
```

### Advanced Options
| Flag                  | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| `-u`, `--url`         | Single URL to test.                                                         |
| `-uf`, `--url-file`   | File containing multiple URLs to test.                                      |
| `--alias1`            | First alias count (e.g., 100).                                              |
| `--alias2`            | Second alias count (e.g., 200).                                             |
| `-o`, `--output`      | Output file to store results.                                               |
| `-t`, `--disable-tls` | Disable TLS verification.                                                   |
| `-de`, `--debug`      | Enable debug mode to show detailed logs.                                    |
| `-p`, `--proxy`       | Proxy server to use for requests.                                           |
| `-ua`, `--user-agent` | Custom User-Agent string to use for requests.                               |
| `-H`, `--header`      | Add custom headers (e.g., `-H "Authorization: Bearer token"`).              |

### Example Commands
1. Test a single URL with custom alias counts:
   ```bash
   python alias_overload.py -u https://example.com/graphql --alias1 100 --alias2 200
   ```

2. Test multiple URLs from a file:
   ```bash
   python alias_overload.py -uf urls.txt --alias1 100 --alias2 200
   ```

3. Save results to a file:
   ```bash
   python alias_overload.py -u https://example.com/graphql --alias1 100 --alias2 200 -o results.txt
   ```

4. Add custom headers (e.g., for authentication):
   ```bash
   python alias_overload.py -u https://example.com/graphql --alias1 100 --alias2 200 -H "Authorization: Bearer token"
   ```

---

## Example Output

### Console Output
```
Status, URL, Aliases, Start Time, End Time, Response Time
200, https://example.com/graphql, 100, 2025-03-22 16:18:46.078157, 2025-03-22 16:18:47.211936, 1.13s
200, https://example.com/graphql, 200, 2025-03-22 16:18:47.211936, 2025-03-22 16:18:48.691936, 1.48s

Total Request Time: 2.61s

Analysis:
https://example.com/graphql: Potential DoS vulnerability detected (higher alias count has higher response time).
```

### File Output (`results.txt`)
```
Status, URL, Aliases, Start Time, End Time, Response Time
200, https://example.com/graphql, 100, 2025-03-22 16:18:46.078157, 2025-03-22 16:18:47.211936, 1.13s
200, https://example.com/graphql, 200, 2025-03-22 16:18:47.211936, 2025-03-22 16:18:48.691936, 1.48s

Total Request Time: 2.61s

Analysis:
https://example.com/graphql: Potential DoS vulnerability detected (higher alias count has higher response time).
```

---

## Contributing
Contributions are welcome! If you'd like to contribute to this project, please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes.
4. Submit a pull request.

---

## License
This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments
- Inspired by real-world GraphQL vulnerabilities and the need for robust security testing tools.
- Thanks to the open-source community for providing the libraries and tools that made this project possible.

---
