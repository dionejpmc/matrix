def parse_grype_results(json_path):
    """
    Extrai CVEs do output do Grype para ingestão[cite: 71, 72].
    """
    with open(json_path, 'r') as f:
        data = json.load(f)

    vulnerabilities = []
    for match in data.get('matches', []):
        vuln = match.get('vulnerability', {})
        artifact = match.get('artifact', {})
        
        vulnerabilities.append({
            'cve_id': vuln.get('id'),
            'severity': vuln.get('severity').upper(),
            'cvss_score': vuln.get('cvss', [{}])[0].get('metrics', {}).get('baseScore'),
            'component_name': artifact.get('name'),
            'component_version': artifact.get('version'),
            'description': vuln.get('description')
        })
    return vulnerabilities