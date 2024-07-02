import json
import openai
from jinja2 import Template

# Replace with your actual API key
API_KEY = 'YOUR-API-KEY'
openai.api_key = API_KEY

# Function to call the AI API to generate enumeration steps
def generate_enumeration_steps(port, service, version):
    prompt = f"""
    Provide detailed steps to enumerate the {service} service running on port {port}, version {version}. Include initial steps, tools to use, commands to run, and what to look for in the results.
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
