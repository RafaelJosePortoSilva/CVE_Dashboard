import requests
import pandas as pd

def get_nvd_data(cve_id):
    """
    Fetches the NVD (National Vulnerability Database) data for a given CVE ID.

    Args:
        cve_id (str): The CVE ID to fetch data for.

    Returns:
        dict: A dictionary containing the NVD data.
    """
    response = requests.get(f'https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}')
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch data: {response.status_code}")

def process_nvd_data(data):
    """
    Processes the NVD data into a pandas DataFrame.

    Args:
        data (dict): A dictionary containing the NVD data.

    Returns:
        pd.DataFrame: A DataFrame containing the processed NVD data.
    """
    df = pd.DataFrame(data)
    df['published'] = pd.to_datetime(df['published'])
    return df

def save_data_to_dir(df, dir):
    """
    Saves the NVD data to a CSV file in the specified directory.

    Args:
        df (pd.DataFrame): The DataFrame containing the processed NVD data.
        dir (str): The directory to save the CSV file.
    """
    if dir == 'raw':
        dir = 'data/raw'
    if dir == 'processed':
        dir = 'data/processed'
    if dir == 'interim':
        dir = 'data/interim'
    df.to_csv(dir, index=False)
