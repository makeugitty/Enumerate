WebAppScan Enumeration Guide Generator
This project provides a script to generate an enumeration guide for network vulnerabilities identified during a network scan. The script leverages OpenAI's GPT-3.5-turbo model to provide detailed enumeration steps for each identified service and attempts to find relevant exploits on Exploit-DB.

Table of Contents
Features
Prerequisites
Installation
Usage
Directory Structure
Customization
License
Features
Automatically generates detailed enumeration steps for identified network services.
Searches Exploit-DB for relevant exploits based on the service and version.
Outputs the enumeration guide in a Markdown file for easy reading and sharing.
Prerequisites
Python 3.6+
An OpenAI API key (sign up at OpenAI to get one).
pip package manager.
Installation
Clone the Repository

sh
Copy code
git clone https://github.com/yourusername/WebAppScan.git
cd WebAppScan
Install Required Packages

sh
Copy code
pip install -r requirements.txt
Ensure that your requirements.txt includes the following:

txt
Copy code
openai
jinja2
requests
beautifulsoup4
Set Up OpenAI API Key

Replace the placeholder API key in the script with your actual API key:

python
Copy code
API_KEY = 'your-openai-api-key'
Usage
Prepare the Vulnerabilities JSON File

Ensure you have a JSON file named vulnerabilities.json containing the scan results. The file should be in the following format:

json
Copy code
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
Run the Script

sh
Copy code
python enumerate.py
Output

The script will generate an enumeration_guide.md file in the specified output directory (/Users/jonfab/Desktop/WebAppScan/).

Directory Structure
python
Copy code
WebAppScan/
│
├── vulnerabilities.json      # JSON file with scan results
├── enumerate.py              # Main script to generate enumeration guide
├── enumeration_guide.md      # Output file (generated)
├── requirements.txt          # List of dependencies
└── README.md                 # This README file
Customization
Modify OpenAI Prompt: Customize the prompt in the generate_enumeration_steps function to change the type of information generated.
Add More Sources: Extend the search_exploits function to query other sources for exploits, such as GitHub.
Adjust Output Format: Modify the Jinja2 template to change the format of the output Markdown file.
