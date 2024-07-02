import json
import openai
from jinja2 import Template

# Replace with your actual API key
API_KEY = 'YOUR_API_KEY'
openai.api_key = API_KEY

# Function to call the AI API to generate enumeration steps
def generate_enumeration_steps(port, service, version):
    prompt = f"""
   Given a specific network service, your task is to analyze its security posture comprehensively. Follow the structured approach below to ensure a thorough evaluation:

1. **Service Identification**
   - **Service Name**: {service}
   - **Port Number**: {port}
   - **Version**: {version}

2. **Initial Analysis**
   - Describe the initial steps to gather more information about the specified service. What tools and commands would you use to perform a detailed service enumeration?

3. **Tools and Commands**
   - List the tools and commands required for an in-depth analysis of the service running on the specified port. Include syntax examples for clarity.

4. **Analyzing Results**
   - Explain what to look for in the output of the tools and commands used. Highlight indicators of potential vulnerabilities or misconfigurations.

5. **Vulnerability Identification**
   - Based on the service version and initial analysis, identify known vulnerabilities associated with this service. Reference specific CVEs (Common Vulnerabilities and Exposures) if applicable.

6. **Exploitation Guide**
   - Provide a step-by-step guide for exploiting identified vulnerabilities. Include:
     - Required tools and their installation commands.
     - Specific commands to exploit the vulnerability, including any necessary payloads.
     - Tips on ensuring successful exploitation.

7. **Mitigation Measures**
   - Suggest mitigation measures or best practices to protect against identified vulnerabilities.

Please ensure that your analysis is conducted ethically and within legal boundaries. Unauthorized testing on systems without explicit permission is illegal and unethical.
    """
    
    try:
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=300,
            temperature=0.7
        )
        steps = response.choices[0].message.content.strip()
    except Exception as e:
        steps = f"Error generating enumeration steps: {e}"
    
    return steps

# Function to generate the enumeration guide
def generate_enumeration_guide(vulnerabilities):
    template = Template("""
    Enumeration Guide for Vulnerabilities
    =====================================

    {% for host in vulnerabilities %}
    ### IP: {{ host['ip'] }}
    **MAC Address:** {{ host['mac'] }}

    {% for port, details in host['tcp'].items() %}
    #### Port {{ port }} ({{ details.get('name', 'N/A') }})
    **State:** {{ details.get('state', 'N/A') }}
    **Product:** {{ details.get('product', 'N/A') }}
    **Version:** {{ details.get('version', 'N/A') }}
    **CVE Details:**
    {% for key, value in details.get('script', {}).items() %}
    {% if 'CVE' in key %}
    - {{ key }}: {{ value }}
    {% endif %}
    {% endfor %}
    **Enumeration Steps:**
    {{ generate_enumeration_steps(port, details.get('name', 'N/A'), details.get('version', 'N/A')) }}
    {% endfor %}

    {% endfor %}
    """)
    
    # Prepare data for the template
    data = []
    for host in vulnerabilities:
        try:
            ip = host['ip']
            mac = host['mac']
            scan_results = host['scan_result']['scan'][ip].get('tcp', {})
            if not scan_results:
                print(f"Skipping host {ip} due to missing key: 'tcp'")
                continue
            data.append({
                'ip': ip,
                'mac': mac,
                'tcp': scan_results
            })
        except KeyError as e:
            print(f"Skipping host {host.get('ip', 'unknown IP')} due to missing key: {e}")

    # Render the document with the template
    output = template.render(vulnerabilities=data, generate_enumeration_steps=generate_enumeration_steps)

    # Save to a file
    with open('/Users/jonfab/Desktop/WebAppScan/enumeration_guide.md', 'w') as file:
        file.write(output)

    print("Enumeration guide has been created as '/Users/jonfab/Desktop/WebAppScan/enumeration_guide.md'.")

# Main function
def main():
    # Load JSON file
    with open('vulnerabilities.json', 'r') as file:
        vulnerabilities = json.load(file)
    
    # Generate the enumeration guide
    generate_enumeration_guide(vulnerabilities)

if __name__ == "__main__":
    main()
