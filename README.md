# SQLi Scanner

## Overview

This is a personal project created to scan web applications for potential SQL Injection (SQLi) vulnerabilities. The tool is designed to detect different types of SQLi, including Boolean-based, Time-based, and Error-based injections.

**Important:** This project is intended for educational purposes only. It should not be used to attack systems or cause harm to any infrastructure. Please ensure you have proper authorization before using this tool on any web application.

## Features

- **Random User-Agent**: The tool can send requests with random User-Agents to avoid detection.
- **Basic and Extended Checks**: The tool performs both basic and advanced SQLi checks to identify potential vulnerabilities.
- **Boolean-based SQLi Detection**: Detects vulnerabilities by sending payloads that trigger different responses based on the evaluation of Boolean conditions.
- **Time-based SQLi Detection**: Measures the response time of a server after injecting time-delay payloads.
- **Error-based SQLi Detection**: Identifies SQLi vulnerabilities by looking for error patterns in the response.

## Installation

To install and use this SQLi Scanner on your local machine, follow these steps:

### 1. Clone the Repository

First, clone the repository to your local machine using the following command:

```bash
git clone https://github.com/dgnnj/sqli-scanner.git
```

### 2. Navigate to the Project Directory

Move into the project directory:

```bash
cd sqli-scanner
```

### 3. Install Go (if not already installed)

Ensure that Go is installed on your system. You can download and install Go from the official website: https://golang.org/dl/

To verify the installation, run:

```bash
go version
```

### 4. Run the Project

You can now run the SQLi Scanner by using the following command:

```bash
go run main.go --url=<URL> --param=<param> [options]
```

Replace <URL> with the target URL and <param> with the parameter name to be tested.

## Usage

To run the tool, use the following command:

```bash
go run main.go --url=<URL> --param=<param> [options]
```

## Options

--**url**: The target URL to scan for SQLi vulnerabilities.
--**param**: The parameter name to test.
--**user-agent**: The User-Agent to use in requests. Use random for a random User-Agent.
--**delay**: Waiting time in seconds for Time-based SQLi tests.
--**techniques**: SQLi techniques to test: B=Boolean, T=Time, E=Error.
--**report**: File to save the vulnerability report (default: report.txt).

## Examples

Test a URL with all techniques using a random User-Agent:

```bash
go run main.go --url=http://example.com --param=id --user-agent=random
```

Test a URL with Boolean-based, Time-based, and Error-based injections:

```bash
go run main.go --url=http://example.com --param=id --techniques=BTE
```

### Output

The tool generates a report file containing all the vulnerabilities found during the scan. If no vulnerabilities are found, the report will state that no vulnerabilities were detected.

### License

This project is licensed under the MIT License. See the LICENSE file for more details.

### Disclaimer

This is a personal project. The author takes no responsibility for any misuse of this tool. All data handled by this tool remains under the user's control and responsibility.