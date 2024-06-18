import pandas as pd
import requests
import re
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth
import time

# Configuration
EXCEL_FILE = 'clients_CVE.xlsx'
BASE_URL = 'https://www.opencve.io/api/cve'
USERNAME = 'usernamehere'
PASSWORD = 'passwordhere'
DAYS_LIMIT = 7  # Number of days to filter recent CVEs

# Function to check if the required columns exist in the DataFrame
def check_required_columns(df, required_columns):
    for column in required_columns:
        if column not in df.columns:
            raise KeyError(f"Column '{column}' is missing from the input Excel file.")

# Read the Excel file containing client information
clients_df = None
try:
    clients_df = pd.read_excel(EXCEL_FILE)
    required_columns = ['Client', 'Vendor', 'Product', 'Software or Specific Product Model/Version/Keywords']
    check_required_columns(clients_df, required_columns)
    print("Columns in the DataFrame after reading the Excel file:", clients_df.columns)
except FileNotFoundError:
    print(f"The file '{EXCEL_FILE}' was not found.")
    exit(1)
except KeyError as e:
    print(e)
    exit(1)

if clients_df is not None:
    # Ensure all entries in the 'Software or Specific Product Model/Version' column are strings and handle NaN values
    clients_df['Software or Specific Product Model/Version/Keywords'] = clients_df['Software or Specific Product Model/Version/Keywords'].fillna('').astype(str)

    # Treat empty 'Product' entries with a placeholder
    clients_df['Product'] = clients_df['Product'].replace('', 'Unknown Product')

    # Combine software lists for the same client and split them into individual software entries
    clients_df = clients_df.groupby(['Client', 'Vendor', 'Product'])['Software or Specific Product Model/Version/Keywords'].apply(lambda x: ','.join(x)).reset_index()
    clients_df['Software or Specific Product Model/Version/Keywords'] = clients_df['Software or Specific Product Model/Version/Keywords'].apply(lambda x: [s.strip() for s in x.split(',') if s.strip()])

    # Explode the software list into individual rows
    clients_df = clients_df.explode('Software or Specific Product Model/Version/Keywords').reset_index(drop=True)

    # Debugging print statements
    print("DataFrame after processing:")
    print(clients_df)

    # Function to fetch CVEs from OpenCVE API with filters
    def fetch_cves(page=1):
        params = {'page': page}
        response = requests.get(BASE_URL, params=params, auth=HTTPBasicAuth(USERNAME, PASSWORD))
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:
            print(f"Rate limit exceeded. Sleeping for 60 seconds.")
            time.sleep(60)
            return fetch_cves(page)
        else:
            print(f"Failed to fetch CVEs for page {page}: {response.status_code}")
        return []

    # Function to fetch details of a specific CVE from OpenCVE API
    def fetch_cve_details(cve_id):
        response = requests.get(f'{BASE_URL}/{cve_id}', auth=HTTPBasicAuth(USERNAME, PASSWORD))
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:
            print(f"Rate limit exceeded. Sleeping for 60 seconds.")
            time.sleep(60)
            return fetch_cve_details(cve_id)
        else:
            print(f"Failed to fetch details for CVE {cve_id}: {response.status_code}")
        return {}

    # Function to check if a CVE is relevant to a client row
    def is_relevant_to_row(cve, row):
        vendor = row['Vendor'].lower()
        product = row['Product'].lower() if pd.notna(row['Product']) else ''
        software = row['Software or Specific Product Model/Version/Keywords'].lower() if isinstance(row['Software or Specific Product Model/Version/Keywords'], str) else ''
        description = cve['summary'].lower()

        if vendor in description and (product in description or product == 'unknown product'):
            return True
        if product and product in description:
            return True
        if software and software in description:
            return True
        return False

    def extract_versions_from_summary(summary):
        version_pattern = r'\b\d+\.\d+(?:\.\d+)*(?:-[a-zA-Z0-9]+)?\b'
        return re.findall(version_pattern, summary)

    # Function to safely access nested data
    def get_nested(data, keys, default=None):
        for key in keys:
            try:
                data = data[key]
            except (TypeError, KeyError):
                return default
        return data

    # Function to process CVEs and generate reports
    def process_and_generate_reports():
        last_days_limit = datetime.utcnow() - timedelta(days=DAYS_LIMIT)
        all_relevant_cves = []
        seen_cve_ids = set()  # Set to keep track of seen CVE IDs

        # Fetch CVEs once for each page
        for page in range(1, 40):
            print(f"Fetching page {page}")
            cves = fetch_cves(page=page)
            if not cves:
                print(f"No CVEs found on page {page}")
                break

            for cve in cves:
                if cve['id'] in seen_cve_ids:
                    continue  # Skip if CVE has already been processed
                seen_cve_ids.add(cve['id'])

                created_date = datetime.strptime(cve['created_at'], '%Y-%m-%dT%H:%M:%SZ')
                if created_date < last_days_limit:
                    continue

                for index, row in clients_df.iterrows():
                    if is_relevant_to_row(cve, row):
                        print(f"Fetching details for CVE {cve['id']}")
                        cve_details = fetch_cve_details(cve['id'])
                        if cve_details:
                            cvss_v3 = get_nested(cve_details, ['cvss', 'v3'], None)
                            if cvss_v3 is not None and cvss_v3 >= 7:
                                references = [
                                    ref['url']
                                    for ref in get_nested(cve_details, ['raw_nvd_data', 'references'], [])
                                ]
                                affected_versions = []
                                for node in get_nested(cve_details, ['configurations', 'nodes'], []):
                                    for match in node.get('cpe_match', []):
                                        if match.get('vulnerable'):
                                            start_incl = match.get('versionStartIncluding', '')
                                            end_excl = match.get('versionEndExcluding', '')
                                            version_info = f"{start_incl} - {end_excl}".strip(' - ')
                                            if version_info:
                                                affected_versions.append(version_info)

                                # If no affected versions, extract from descriptions
                                if not affected_versions:
                                    filtered_descriptions = [desc['value'] for desc in cve_details['raw_nvd_data']['descriptions'] if desc['lang'] == 'en']
                                    joined_descriptions = ' '.join(filtered_descriptions)  # Join all descriptions into a single string
                                    affected_versions = extract_versions_from_summary(joined_descriptions)

                                cve_info = {
                                    'CVE ID': cve_details['id'],
                                    'Description': cve_details['summary'],
                                    'Published': cve_details['created_at'],
                                    'CVSSv3': cvss_v3,
                                    'Affected Versions': ', '.join(affected_versions) if affected_versions else 'N/A',
                                    'References': ', '.join(references) if references else 'N/A'
                                }
                                print(f"Adding CVE to relevant list: {cve_info}")
                                all_relevant_cves.append((row['Client'], cve_info))

        # Process and generate reports for each client
        for client in clients_df['Client'].unique():
            print(f"Processing client: {client}")
            relevant_cves = [cve_info for cl, cve_info in all_relevant_cves if cl == client]

            # Create a DataFrame for the relevant CVEs
            cves_df = pd.DataFrame(relevant_cves)

            # Read the client's existing Excel file, if it exists
            try:
                client_excel_df = pd.read_excel(f'{client}_vulnerabilities.xlsx')
            except FileNotFoundError:
                client_excel_df = pd.DataFrame()

            # Append the new CVEs to the existing DataFrame and drop duplicates based on the 'CVE ID' column
            if not cves_df.empty:
                combined_df = pd.concat([client_excel_df, cves_df], ignore_index=True).drop_duplicates(subset=['CVE ID'])
                combined_df.to_excel(f'{client}_vulnerabilities.xlsx', index=False)
                print(f'Report updated for {client}: {client}_vulnerabilities.xlsx')
            else:
                print(f'No relevant CVEs found for {client}')

        print('All reports generated.')

    # Run the process to generate reports
    process_and_generate_reports()
else:
    print("No valid client data to process.")
