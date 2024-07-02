import json
import requests

# Function to fetch CVE details from the NVD API
def fetch_cve_details(cve_id):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to fetch details for {cve_id}, status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"An error occurred while fetching CVE details: {e}")
        return None

# Function to extract CVEs from the nmap scan results
def extract_cves(scan_result):
    cves = []
    for host, details in scan_result.get('scan', {}).items():
        for protocol in ['tcp', 'udp']:
            if protocol in details:
                for port, port_details in details[protocol].items():
                    script_data = port_details.get('script', {})
                    for script_name, script_output in script_data.items():
                        if 'CVE' in script_output:
                            cves.extend([word for word in script_output.split() if word.startswith('CVE-')])
    return cves

# Function to enrich scan results with CVE details
def enrich_with_cve_details(scan_results):
    enriched_results = []
    for device in scan_results:
        print(f"Processing device: {device['ip']}")
        device_cves = extract_cves(device['scan_result'])
        print(f"Extracted CVEs: {device_cves}")
        cve_details = []
        for cve_id in device_cves:
            details = fetch_cve_details(cve_id)
            if details:
                try:
                    description = details['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
                    exploit = "Exploit details or mitigation steps"  # Placeholder, can be enhanced further
                    cve_details.append({
                        'id': cve_id,
                        'description': description,
                        'exploit': exploit
                    })
                    print(f"Fetched details for {cve_id}: {description}")
                except (IndexError, KeyError):
                    print(f"Details for {cve_id} not in expected format")
        device['cve_details'] = cve_details
        enriched_results.append(device)
    return enriched_results

def main():
    # Load the scan results from JSON file
    with open('network_scan_results.json', 'r') as f:
        scan_results = json.load(f)

    # Enrich scan results with CVE details
    enriched_results = enrich_with_cve_details(scan_results)

    # Save the enriched results to a new JSON file
    with open('enriched_network_scan_results.json', 'w') as f:
        json.dump(enriched_results, f, indent=4)

    print("Enriched scan results saved to enriched_network_scan_results.json")

if __name__ == "__main__":
    main()
