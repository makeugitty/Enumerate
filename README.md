# WebAppScan Enumeration Guide Generator

This project provides a script to generate an enumeration guide for network vulnerabilities identified during a network scan. The script leverages OpenAI's GPT-3.5-turbo model to provide detailed enumeration steps for each identified service and attempts to find relevant exploits on Exploit-DB.

### Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Directory Structure](#directory-structure)
- [Customization](#customization)
- [License](#license)

## Features
- Automatically generates detailed enumeration steps for identified network services.
- Searches Exploit-DB for relevant exploits based on the service and version.
- Outputs the enumeration guide in a Markdown file for easy reading and sharing.

## Prerequisites
- Python 3.6+
- An OpenAI API key (sign up at [OpenAI](https://www.openai.com/) to get one).
- `pip` package manager.

## Installation

1. **Clone the Repository**

    ```sh
    git clone https://github.com/yourusername/WebAppScan.git
    cd WebAppScan
    ```

2. **Install Required Packages**

    ```sh
    pip install -r requirements.txt
    ```

    Ensure that your `requirements.txt` includes the following:
    ```txt
    openai
    jinja2
    requests
    beautifulsoup4
    ```

3. **Set Up OpenAI API Key**

    Replace the placeholder API key in the script with your actual API key:
    ```python
    API_KEY = 'your-openai-api-key'
    ```

## Usage

1. **Prepare the Vulnerabilities JSON File**

    Ensure you have a JSON file named `vulnerabilities.json` containing the scan results. The file should be in the following format:
    ```json
    [
        {
            "ip": "192.168.1.1",
            "mac": "00:11:22:33:44:55",
            "scan_result": {
                "scan": {
                    "192.168.1.1": {
                        "tcp": {
                            "22": {
                                "state": "open",
                                "name": "ssh",
                                "product": "OpenSSH",
                                "version": "7.6p1",
                                "script": {
                                    "CVE-2020-1234": "Description of CVE-2020-1234"
                                }
                            }
                        }
                    }
                }
            }
        }
    ]
    ```

2. **Run the Script**

    ```sh
    python enumerate.py
    ```

3. **Output**

    The script will generate an `enumeration_guide.md` file in the specified output directory (`YOURPATH/WebAppScan/`).

## Directory Structure

WebAppScan/
│

├── vulnerabilities.json # JSON file with scan results

├── enumerate.py # Main script to generate enumeration guide

├── enumeration_guide.md # Output file (generated)

├── requirements.txt # List of dependencies

└── README.md # This README file




## Customization

- **Modify OpenAI Prompt**: Customize the prompt in the `generate_enumeration_steps` function to change the type of information generated.
- **Add More Sources**: Extend the `search_exploits` function to query other sources for exploits, such as GitHub.
- **Adjust Output Format**: Modify the Jinja2 template to change the format of the output Markdown file.


For any issues or contributions, feel free to open an issue or submit a pull request on the GitHub repository. Happy scanning and stay secure!

