import pandas as pd
from pathlib import Path
import logging
import re

BASE_DIR = Path(__file__).resolve().parent

INPUT_DIR = BASE_DIR / 'input'
OUTPUT_DIR = BASE_DIR / 'output'
LOG_DIR = BASE_DIR / 'logs'

def setup_logging():
    LOG_DIR.mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
        handlers=[
            logging.FileHandler(LOG_DIR / 'wiz_analysis.log', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )


def extract_resource_group(url):
    if pd.isna(url):
        return ''
    m = re.search(r'/resourcegroups/([^/]+)', str(url), re.IGNORECASE)
    return m.group(1) if m else ''


def extract_tenant(url):
    if pd.isna(url):
        return ''
    m = re.search(r'#@([^/]+)/', str(url))
    return m.group(1) if m else ''


def get_owner(component, path, remediation):
    text = f'{component} {path} {remediation}'.lower()

    if any(k in text for k in ['rapid7', 'crowdstrike', 'qualys', 'defender', 'wiz agent']):
        return 'Security Team'

    if any(k in text for k in ['mysql', 'postgres', 'postgresql', 'oracle', 'sql server', 'mongodb', 'redis', 'odbc']):
        return 'Data Team'

    if any(k in text for k in ['protobufjs', 'fast-xml-parser', 'golang.org', 'jackson', 'lodash', 'npm', 'maven', 'gradle', 'node_modules']):
        return 'Development Team'

    return 'Infrastructure Team'


def get_asset_type(row):
    text = ' '.join([
        str(row.get('AssetName', '')),
        str(row.get('CloudProviderURL', '')),
        str(row.get('LocationPath', '')),
        str(row.get('DetailedName', '')),
    ]).lower()

    if 'virtualmachines' in text or '/vm' in text:
        return 'Virtual Machine'
    if 'microsoft.web/sites/functions' in text:
        return 'Function App'
    if 'microsoft.web/sites' in text:
        return 'Web App'
    if 'kubernetes' in text and 'node' in text:
        return 'Kubernetes Node'
    if 'aks' in text:
        return 'AKS Cluster'
    if 'container' in text or 'image' in text:
        return 'Container'
    if any(x in text for x in ['sql', 'mysql', 'postgres', 'oracle', 'mongodb']):
        return 'Database'

    return 'Other'


def choose_csv():
    INPUT_DIR.mkdir(exist_ok=True)
    files = sorted(INPUT_DIR.glob('*.csv'))

    if not files:
        print('No CSV files found in input folder')
        return None

    for i, f in enumerate(files, 1):
        print(f'{i}. {f.name}')

    while True:
        try:
            return files[int(input('Select file number: ')) - 1]
        except Exception:
            print('Invalid selection')


def choose_scope():
    print('\n1. Critical only')
    print('2. Critical + High')
    print('3. All findings')

    while True:
        choice = input('Select severity scope: ').strip()

        if choice == '1':
            return ['CRITICAL']
        if choice == '2':
            return ['CRITICAL', 'HIGH']
        if choice == '3':
            return None

        print('Invalid selection')


def format_workbook(writer, sheets):
    for name, df in sheets.items():
        ws = writer.sheets[name]
        rows, cols = df.shape

        if cols:
            ws.autofilter(0, 0, rows, cols - 1)

        ws.freeze_panes(1, 0)

        for idx, col in enumerate(df.columns):
            width = max(len(str(col)), df[col].astype(str).str.len().max() if len(df) else 0)
            ws.set_column(idx, idx, min(width + 2, 80))


def main():
    setup_logging()
    logging.info('Starting Wiz analysis')

    file_path = choose_csv()
    if not file_path:
        return

    severity_scope = choose_scope()

    required_columns = [
        'CVSSSeverity','CloudProviderURL','AssetName','DetailedName','Name',
        'SubscriptionName','LocationPath','Remediation','Version',
        'FixedVersion','OperatingSystem','HasExploit','HasCisaKevExploit','Tags'
    ]

    try:
        df = pd.read_csv(file_path, low_memory=False)
    except Exception:
        logging.exception('Failed to read CSV')
        return

    missing = [c for c in required_columns if c not in df.columns]
    if missing:
        logging.error(f'Missing columns: {missing}')
        return

    if severity_scope:
        df = df[df['CVSSSeverity'].astype(str).str.upper().isin(severity_scope)].copy()

    # Remove host-set entries
    df = df[df['AssetName'].astype(str).str.lower() != 'host-set'].copy()

    if df.empty:
        logging.warning('No findings after filtering')
        return

    OUTPUT_DIR.mkdir(exist_ok=True)

    df['ResourceGroup'] = df['CloudProviderURL'].apply(extract_resource_group)
    df['Tenant'] = df['CloudProviderURL'].apply(extract_tenant)
    df['AssetType'] = df.apply(get_asset_type, axis=1)
    df['LikelyOwner'] = df.apply(lambda r: get_owner(r['DetailedName'], r['LocationPath'], r['Remediation']), axis=1)

    raw = pd.DataFrame({
        'Severity': df['CVSSSeverity'],
        'AssetType': df['AssetType'],
        'LikelyOwner': df['LikelyOwner'],
        'Component': df['DetailedName'],
        'Version': df['Version'],
        'FixedVersion': df['FixedVersion'],
        'Tenant': df['Tenant'],
        'Subscription': df['SubscriptionName'],
        'ResourceGroup': df['ResourceGroup'],
        'Resource': df['AssetName'],
        'CVE': df['Name'],
        'Path': df['LocationPath'],
        'Remediation': df['Remediation'],
        'HasExploit': df['HasExploit'],
        'HasCisaKevExploit': df['HasCisaKevExploit']
    })

    executive = pd.DataFrame({
        'Metric': ['Total Findings','Affected Resources','Unique CVEs'],
        'Value': [len(raw), raw['Resource'].nunique(), raw['CVE'].nunique()]
    })

    asset_dashboard = raw.groupby(['AssetType','Severity']).agg(
        Findings=('CVE','count'),
        Assets=('Resource','nunique')
    ).reset_index().sort_values('Findings', ascending=False)

    remediation_plan = raw.groupby(['LikelyOwner','Remediation']).agg(
        Findings=('CVE','count'),
        Assets=('Resource','nunique'),
        CVEs=('CVE','nunique'),
        AssetTypes=('AssetType','nunique')
    ).reset_index().sort_values('Findings', ascending=False)

    asset_plan = raw.groupby([
        'AssetType','Subscription','ResourceGroup','Resource'
    ]).agg(
        Findings=('CVE','count'),
        CVEs=('CVE','nunique'),
        Components=('Component','nunique')
    ).reset_index().sort_values('Findings', ascending=False)

    component_plan = raw.groupby([
        'LikelyOwner','Component','Version','FixedVersion'
    ]).agg(
        Findings=('CVE','count'),
        Assets=('Resource','nunique'),
        CVEs=('CVE','nunique')
    ).reset_index().sort_values('Findings', ascending=False)

    sheets = {
        '01_Executive_Dashboard': executive,
        '02_Asset_Type_Dashboard': asset_dashboard,
        '03_Remediation_Action_Plan': remediation_plan,
        '04_Asset_Action_Plan': asset_plan,
        '05_Component_Action_Plan': component_plan,
        '06_Raw_Findings': raw
    }

    output_file = OUTPUT_DIR / f'{file_path.stem}_Enhanced_Analysis.xlsx'

    with pd.ExcelWriter(output_file, engine='xlsxwriter', engine_kwargs={'options': {'strings_to_urls': False}}) as writer:
        for sheet, data in sheets.items():
            data.to_excel(writer, sheet_name=sheet, index=False)
        format_workbook(writer, sheets)

    logging.info(f'Workbook created: {output_file}')


if __name__ == '__main__':
    main()
