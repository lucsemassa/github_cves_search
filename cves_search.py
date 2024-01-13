import requests
import json
import sys
import time
import argparse
from bs4 import BeautifulSoup

# List to store the CVEs that are found
cves = []

# Function to search CVEs from NVD based on a constructed URL and a start index for pagination
def search_cve(link, startIndex="0"):
    link = link + "&startIndex=" + startIndex
    
    global cves
    response = requests.get(link)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract total number of matching records and currently displayed records count
        matching_records_count = int(soup.find('strong', {'data-testid': 'vuln-matching-records-count'}).text)
        displaying_count_through = int(soup.find('strong', {'data-testid': 'vuln-displaying-count-through'}).text)

        # Extract CVEs from the response
        for result in soup.find_all(lambda tag: tag.name == 'a' and tag.get('data-testid', '').startswith('vuln-detail-link-')):
            cve = result.text.strip()
            if not cve in cves:
                cves.append(cve)
    else:
        return None

    return [matching_records_count, displaying_count_through]

# Function to search GitHub for repositories related to a specific CVE
def search_github_cve(cve_search):
    # Set the GitHub API URL for searching repositories related to the CVE
    api_url = "https://api.github.com/search/repositories?q=" + cve_search
    # Define headers for the API request
    headers = {
        "Accept": "application/vnd.github.v3+json",
        # "Authorization": f"Bearer {GITHUB_API_TOKEN}",  # Uncomment and include your GitHub token if needed
    }

    # GitHub API
    cve_response = requests.get(api_url, headers=headers)
    if cve_response.status_code == 200:
        # Parse the JSON response
        data = json.loads(cve_response.text)
        # Extract and print the 'html_url' for each matching repository
        for item in data.get("items", []):
            html_url = item.get("html_url")
            if html_url:
                print(html_url)

        # Pause to respect GitHub API rate limits
        time.sleep(10)
    else:
        print("Error in GitHub API request.")

# Function to handle the search and output process for CVEs
def process_search(url):
    get_first_cve = search_cve(url)
    if get_first_cve == None or get_first_cve == [0, 0]:
        print("No CVEs found!")
        exit()

    matching_records_count, displaying_count_through = get_first_cve

    # Calculate if additional pages of results are needed
    remainder = 1 if (matching_records_count % displaying_count_through != 0 and matching_records_count > displaying_count_through) else 0 

    # Process additional pages if necessary
    if remainder != 0:
        for i in range(1, int(matching_records_count / displaying_count_through) + remainder + 1):
            search_cve(url, str(i * 20))

    # Print CVEs and search related GitHub repos
    if cves:
        for cve in cves:
            print(cve)
            search_github_cve(cve.replace(" ", ""))

    else:
        print("No CVEs found for the specified criteria.")

def main():
    global cves
    parser = argparse.ArgumentParser(description="Github payload searcher by shinningstar")

    # Command-line arguments for CVE, Linux kernel, Windows kernel, product, and product version
    parser.add_argument('-c', '--cve', type=str, help='CVE string (Ex: CVE-2023-27163)')
    parser.add_argument('-l', '--linux', type=str, help='Linux kernel string (Ex: 5.15.70)')
    parser.add_argument('-w', '--windows', type=str, help='Windows kernel string (Ex: 10.0.19041)')
    parser.add_argument('-p', '--product', type=str, help='Product to be scanned (Ex: Joomla)')
    parser.add_argument('-pv', '--productversion', type=str, help='Version of the product (Ex: 4.2.6)')

    args = parser.parse_args()

    if not args.cve and not args.linux and not args.windows and not args.product:
        parser.print_help()
        sys.exit(1)

    if args.product and not args.productversion:
        print("You must enter the product version")
        sys.exit(1)


    if args.linux:
        linux_version = args.linux
        url = f"https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&cpe_vendor=cpe%3A%2F%3Alinux&cpe_version=cpe%3A%2F%3Alinux%3Alinux_kernel%3A{linux_version}&query=escalate&cpe_product=cpe%3A%2F%3Alinux%3Alinux_kernel&results_type=overview&form_type=Advanced&search_type=all"
        process_search(url)

    elif args.windows:
        windows_version = args.windows
        url = f"https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&cpe_vendor=cpe%3A%2F%3Amicrosoft&cpe_version=cpe%3A%2F%3Amicrosoft%3Awindows_kernel%3A{windows_version}&query=escalate&cpe_product=cpe%3A%2F%3Amicrosoft%3Awindows_kernel&results_type=overview&form_type=Advanced&search_type=all"
        process_search(url)

    elif args.cve:
        cve_search_str = args.cve
        print("Public GitHub links related to CVE", cve_search_str)
        search_github_cve(cve_search_str.replace(" ", ""))

    elif args.product:
        product = args.product.lower()
        product_version = args.productversion.lower().replace(" ", "")
        url = f"https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&&cpe_product=cpe:/::{product}:{product_version}"
        get_first_cve = search_cve(url)
        if get_first_cve == None or get_first_cve == [0, 0]:
            print("No CVEs found!")
        else:
            process_search(url)

    else:
        print("No valid input provided.")
        sys.exit(1)


    main()
