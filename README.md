# Domain Probe 🚀🔍

![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![License](https://img.shields.io/badge/License-GPLv3-blue.svg)

A powerful domain probing tool that gathers extensive information and site structure details. This script performs comprehensive checks and analyses to provide in-depth insights about any given domain's infrastructure, security posture, and technology stack.

## 🚀 Features

- 🌐 WHOIS information retrieval
- 🏷️ DNS record analysis
- 🔍 Subdomain discovery
- 🖥️ IP and reverse DNS lookup
- 🛡️ Web Application Firewall (WAF) detection
- 🔐 SSL certificate information
- 🕸️ Website technology stack detection
- 🔎 Sensitive file and directory checks
- 📡 API endpoint discovery
- 🛡️ Security header analysis
- 🍪 Cookie security assessment
- 🔒 DNSSEC, SPF, and DMARC record checks
- 🌐 Integration with Shodan for additional network insights

## 📋 Prerequisites

- Python
- pip (Python package manager)

## 🛠️ Installation

1. Clone this repository:
   ```
   git clone https://github.com/RocketGod-git/domain-probe.git
   cd domain-probe
   ```

## 🖥️ Usage

Run the script from the command line:

```
python domain-probe.py
```

The script will prompt you for the domain name to analyze. Alternatively, you can provide the domain name as a command-line argument:

```
python domain-probe.py example.com
```

The tool will guide you through the process, including prompting for a Shodan API key if needed.

## 📊 Output

The script provides a detailed report of its findings, organized into the following categories:

- Subdomains
- DNS Records
- SSL Certificate Information
- Interesting URLs
- Security Headers
- Sensitive Headers
- Cookies
- Framework Detection
- Other relevant information

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! 

## 📜 License

This project is licensed under the GPL-3.0 license - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and research purposes only. Always ensure you have permission to perform scans or information gathering on any domain or network that you do not own or have explicit permission to test.

## 🙏 Acknowledgements

- [Shodan](https://www.shodan.io/) for providing additional network insights
- All the open-source libraries used in this project

---

![RocketGod](https://github.com/RocketGod-git/HackRF-Treasure-Chest/assets/57732082/38158b0d-7a3d-4ae1-918c-3b72b316bbc5)
