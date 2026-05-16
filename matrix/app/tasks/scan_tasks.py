import subprocess
import os
import json
import logging
from celery import shared_task, chain
from django.conf import settings
from apps.sbom.models import SbomUpload, Component, Vulnerability
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)

# Configurações do Neo4j
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://matrix-graph:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "outra_senha_forte_aqui")

# Diretório de saída dos resultados do Grype dentro do volume compartilhado
VULNS_DIR = os.path.join(settings.MEDIA_ROOT, "vulns")


@shared_task(name="run_full_scan")
def run_full_scan(upload_id):
    chain(
        run_grype_scan.si(upload_id),
        run_ingestion.si(upload_id),
    ).delay()


@shared_task(name="run_vulnerability_scan")
def run_grype_scan(upload_id):
    upload = SbomUpload.objects.get(id=upload_id)

    # Path absoluto do SBOM: /data/uploads/sboms/YYYY/MM/DD/{uuid}.json
    sbom_path = os.path.join(settings.MEDIA_ROOT, upload.sbom_file.name)

    # Path de saída: /data/uploads/vulns/{upload_id}.vulns.json
    os.makedirs(VULNS_DIR, exist_ok=True)
    output_path = os.path.join(VULNS_DIR, f"{upload_id}.vulns.json")

    try:
        command = ["grype", f"sbom:{sbom_path}", "-o", "json"]
        logger.info(f"[run_grype_scan] Iniciando scan: {sbom_path}")
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        with open(output_path, "w") as f:
            f.write(result.stdout)

        logger.info(f"[run_grype_scan] Scan concluído para upload {upload_id}")
    except Exception as e:
        logger.error(f"[run_grype_scan] Erro no Grype: {str(e)}")
        raise e


@shared_task(name="run_ingestion")
def run_ingestion(upload_id):
    upload = SbomUpload.objects.get(id=upload_id)
    vuln_path = os.path.join(VULNS_DIR, f"{upload_id}.vulns.json")
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    try:
        if not os.path.exists(vuln_path):
            logger.error(f"[run_ingestion] Arquivo não encontrado: {vuln_path}")
            return

        with open(vuln_path, 'r') as f:
            data = json.load(f)

        with driver.session() as session:
            for match in data.get('matches', []):
                vuln_data = match.get('vulnerability', {})
                artifact = match.get('artifact', {})

                # --- ASSOCIAÇÃO NO POSTGRES ---
                comp = Component.objects.filter(
                    product=upload.product,
                    name=artifact.get('name'),
                    version=artifact.get('version'),
                ).first()

                if comp:
                    # Extrai cvss_score de cvss[0].metrics.baseScore
                    cvss_list = vuln_data.get('cvss', [])
                    cvss_score = None
                    if cvss_list:
                        cvss_score = cvss_list[0].get('metrics', {}).get('baseScore')

                    Vulnerability.objects.get_or_create(
                        component=comp,
                        cve_id=vuln_data.get('id'),
                        defaults={
                            'severity': vuln_data.get('severity', 'UNKNOWN').upper(),
                            'description': vuln_data.get('description', 'Sem descrição'),
                            'cvss_score': cvss_score,
                            'status': 'OPEN',
                        }
                    )

                    # --- ASSOCIAÇÃO NO NEO4J ---
                    session.run("""
                        MATCH (c:Component {name: $pkg_name, version: $pkg_version})
                        MERGE (v:CVE {cveId: $cve_id})
                        SET v.severity = $severity
                        MERGE (c)-[:HAS_VULNERABILITY]->(v)
                    """, {
                        "pkg_name": artifact.get('name'),
                        "pkg_version": artifact.get('version'),
                        "cve_id": vuln_data.get('id'),
                        "severity": vuln_data.get('severity', 'UNKNOWN').upper(),
                    })

        logger.info(f"[run_ingestion] Ingestão concluída para upload {upload_id}")
    except Exception as e:
        logger.error(f"[run_ingestion] Erro: {str(e)}")
        raise e
    finally:
        driver.close()