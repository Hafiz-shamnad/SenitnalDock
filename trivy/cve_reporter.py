import requests

def get_mitigation(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cve/{cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('vectorString', 'No mitigation found')
    return "No mitigation found"
