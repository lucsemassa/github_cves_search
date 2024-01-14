import requests
import json
import sys
import time
import argparse
from bs4 import BeautifulSoup



cves = []

def search_cve(link, startIndex="0"):
    link = link+"&startIndex="+startIndex
    
    global cves
    response = requests.get(link)
    if response.status_code == 200:
        # Parse the HTML content of the response
        soup = BeautifulSoup(response.text, 'html.parser')

        matching_records_count = int(soup.find('strong', {'data-testid': 'vuln-matching-records-count'}).text)
        displaying_count_through = int(soup.find('strong', {'data-testid': 'vuln-displaying-count-through'}).text)

        # Extract CVEs
        
        for result in soup.find_all(lambda tag: tag.name == 'a' and tag.get('data-testid', '').startswith('vuln-detail-link-')):
            cve = result.text.strip()
            if(not cve in cves):
                cves.append(cve)
    else:
        return None

    return [matching_records_count, displaying_count_through]

def search_github_cve(cve_search):
    # Set the GitHub API URL
    api_url = "https://api.github.com/search/repositories?q="+cve_search

    # Define headers (optional, you can include your token here)
    headers = {
        "Accept": "application/vnd.github.v3+json",
        # "Authorization": f"Bearer {GITHUB_API_TOKEN}",  # Uncomment and replace with your token
    }

    # Send the GET request to the GitHub API
    cve_response = requests.get(api_url, headers=headers)

    # Check if the request was successful (status code 200)
    if cve_response.status_code == 200:
        # Parse the JSON response
        data = json.loads(cve_response.text)
        
        # Extract the 'html_url' for each matching repository
        for item in data.get("items", []):
            html_url = item.get("html_url")
            if html_url:
                print(html_url)

        time.sleep(10)
    else:
        print("")
        


def main():
    global kernel_version, cves
    # Send an HTTP GET request to the URL
    # Define the URL with the kernel version (e.g., 5.15.70)
   
   
    parser = argparse.ArgumentParser(description="Github payload searcher by shinningstar")
    parser.add_argument('-c', '--cve', type=str, help='CVE string (Ex: CVE-2023-27163)')
    parser.add_argument('-l', '--linux', type=str, help='Linux kernel string (Ex: 5.15.70)')
    parser.add_argument('-w', '--windows', action='store_true', help='Windows related string (Ex: 10.0.0.1)')
    parser.add_argument('-p', '--product', type=str, help='Product to be scanned (Ex: Joomla)')
    parser.add_argument('-pv', '--productversion', type=str, help='Version of the product (Ex: 4.2.6)')

    args = parser.parse_args()
    
    if not any([args.cve, args.kernel, args.product, args.windows]):
        parser.print_help() 
        sys.exit(1)  

    if args.product and not args.productversion:
        print("You must enter the product version")
        sys.exit(1)  

    url = ""
    if args.kernel:
        url = f"https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&cpe_vendor=cpe%3A%2F%3Alinux&cpe_version=cpe%3A%2F%3Alinux%3Alinux_kernel%3A{args.kernel}&query=escalate&cpe_product=cpe%3A%2F%3Alinux%3Alinux_kernel&results_type=overview&form_type=Advanced&search_type=all"
    elif args.product:
        product = args.product.lower()
        product_version = args.productversion.lower().replace(" ", "")
        url = f"https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&&cpe_product=cpe:/::{product}:{product_version}"
    elif args.windows:
        windows_version = args.windows.lower().replace(" ", "")
        url = f"https://nvd.nist.gov/vuln/search/results?query=windows+{windows_version}&search_type=all&results_type=overview&form_type=Basic"

    if url:
        get_first_cve = search_cve(url)
        if args.product and (get_first_cve is None or get_first_cve == [0, 0]):
            time.sleep(5)
            url = f"https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&&cpe_product=cpe:/:{product}::{product_version}"
            get_first_cve = search_cve(url)

        if get_first_cve is None or get_first_cve == [0, 0]:
            print("No CVEs found!")
            exit()

        matching_records_count, displaying_count_through = get_first_cve

        remainder = 1 if (matching_records_count % displaying_count_through != 0 and matching_records_count > displaying_count_through) else 0 
        if remainder != 0:
            for i in range(1, int(matching_records_count / displaying_count_through) + remainder + 1):
                search_cve(url, str(i * 20))

        if cves:
            if args.kernel:
                print(f"CVEs related to Linux Kernel {args.kernel}")
            elif args.product:
                print(f"CVEs related to {args.product} version {args.productversion}")
            elif args.windows:
                print(f"CVEs related to Windows {args.windows}")
            for cve in cves:
                print(cve)
                search_github_cve(cve.replace(" ", ""))
        else:
            print("No CVEs found for the specified parameters.")

    elif args.cve:
        print(f"Public GitHub links related to CVE {args.cve}")
        search_github_cve(args.cve.replace(" ", ""))

main()
