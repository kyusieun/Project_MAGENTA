# SYOVD Tool

This tool is designed to detect vulnerable drivers on a Windows system. It performs the following tasks:
1. Queries and hashes local system drivers.
2. Retrieves and parses updated vulnerable driver lists from the web.
3. Matches local drivers against known vulnerable drivers using both name and hash.
4. Displays the results and saves them to CSV files.
5. Analyzes matched drivers further and saves the analysis to additional CSV files.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Files](#files)
- [Functions](#functions)
- [Contributing](#contributing)
- [License](#license)

## Prerequisites

This tool requires the following:
- Python 3.x
- Windows operating system

## Installation

First, clone this repository to your local machine:

```sh
git clone https://github.com/https://github.com/kyusieun/Project_MAGENTA.git
cd SYOVD
```

Next, install the required Python packages using pip:
```sh
pip install requests beautifulsoup4 pefile pandas
```
Usage

To run the tool, execute the following command:
```sh
python3 syovd.py
```

Files

-	syovd.py: Main script containing all functions and the main execution flow.

## Contributing

### Important Notice

This tool is intended solely for educational purposes and should be used only in a lawful manner. Unauthorized or malicious use of this tool is strictly prohibited. Ensure that you have the appropriate permissions and legal rights to analyze the system you are testing.

### Disclaimer

This project is provided for educational purposes only. The authors do not condone the use of this tool for any illegal or unethical activities. Use this tool at your own risk. The authors are not responsible for any damage or legal consequences resulting from the use of this tool.

### Guidelines for Contributing

If you would like to contribute to the project, please follow these guidelines:

1. **Educational Use Only**: Contributions should be aimed at improving the educational value of the project. Ensure that any additions or modifications serve to enhance the learning experience.
2. **Legal Compliance**: Ensure that your contributions do not violate any laws or regulations. This includes, but is not limited to, respecting intellectual property rights and user privacy.
3. **Ethical Use**: Use this tool responsibly and ethically. Do not use it to target systems without explicit permission from the owner.
4. **Security Best Practices**: Adhere to security best practices in your contributions. This tool deals with sensitive operations, and it is crucial to ensure that no additional vulnerabilities are introduced.

By contributing to this project, you agree to adhere to these guidelines and to use the tool in a responsible and ethical manner.