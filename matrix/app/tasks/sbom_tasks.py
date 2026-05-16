from celery import shared_task, chain
from django.db import transaction
from django.conf import settings
from apps.sbom.models import Component, SbomUpload, Vulnerability
from apps.organizations.models import Product
from neo4j import GraphDatabase
import json
import os
import logging
from urllib.parse import unquote

logger = logging.getLogger(__name__)

# Configurações do Neo4j
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://matrix-graph:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "outra_senha_forte_aqui")


def _parse_purl(purl):
    """
    Extrai name e version de um PURL CycloneDX.
    Ex: pkg:deb/debian/adduser@3.118?arch=all → ('adduser', '3.118')
    """
    try:
        base = purl.split('?')[0]
        pkg = base.split('/')[-1]
        if '@' in pkg:
            name, version = pkg.split('@', 1)
            version = unquote(version)
            return name, version
        return pkg, None
    except Exception:
        return None, None


@shared_task(bind=True, name="tasks.sbom_tasks.process_sbom_task")
def process_sbom_task(self, upload_id):
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    upload = None
    try:
        upload = SbomUpload.objects.get(id=upload_id)
        upload.status = 'PROCESSING'
        upload.save()

        # 1. Garante o Produto no Postgres e vincula ao upload
        product, _ = Product.objects.get_or_create(name=upload.product_name)
        upload.product = product
        upload.save()

        # 2. Resolve o path absoluto do arquivo via MEDIA_ROOT
        sbom_path = os.path.join(settings.MEDIA_ROOT, upload.sbom_file.name)

        with open(sbom_path, 'r') as f:
            sbom_data = json.load(f)

        components_list = sbom_data.get('components') or sbom_data.get('artifacts') or []
        dependencies_list = sbom_data.get('dependencies', [])

        with driver.session() as session:

            # ── ETAPA 1: Salva componentes no Postgres e Neo4j ──────────────
            for item in components_list:
                name = item.get('name')
                version = item.get('version')
                if not name or not version:
                    continue

                purl = item.get('purl') or f"pkg:generic/{name}@{version}"
                comp_type = item.get('type', 'unknown')

                # SALVAR NO POSTGRES
                with transaction.atomic():
                    Component.objects.get_or_create(
                        product=product,
                        name=name,
                        version=version,
                        defaults={"purl": purl, "type": comp_type}
                    )

                # SALVAR NO NEO4J — usa name+version como chave estável
                session.run("""
                    MERGE (p:Product {name: $prod_name})
                    SET p.db_id = toInteger($prod_id)
                    MERGE (c:Component {name: $name, version: $version})
                    SET c.purl = $purl
                    MERGE (p)-[:HAS_COMPONENT]->(c)
                """, {
                    "prod_name": product.name,
                    "prod_id": product.id,
                    "purl": purl,
                    "name": name,
                    "version": version,
                })

            # ── ETAPA 2: Salva dependências no Neo4j (DEPENDS_ON) ───────────
            dep_count = 0
            for dep_entry in dependencies_list:
                source_purl = dep_entry.get('ref')
                depends_on = dep_entry.get('dependsOn', [])

                if not source_purl or not depends_on:
                    continue

                src_name, src_version = _parse_purl(source_purl)
                if not src_name or not src_version:
                    continue

                for target_purl in depends_on:
                    tgt_name, tgt_version = _parse_purl(target_purl)
                    if not tgt_name or not tgt_version:
                        continue

                    # MERGE por name+version — mesma chave usada nos componentes
                    session.run("""
                        MERGE (src:Component {name: $src_name, version: $src_version})
                        MERGE (tgt:Component {name: $tgt_name, version: $tgt_version})
                        MERGE (src)-[:DEPENDS_ON]->(tgt)
                    """, {
                        "src_name": src_name,
                        "src_version": src_version,
                        "tgt_name": tgt_name,
                        "tgt_version": tgt_version,
                    })
                    dep_count += 1

            logger.info(f"[process_sbom_task] {dep_count} relações DEPENDS_ON criadas no Neo4j")

        upload.status = 'COMPLETED'
        upload.save()

        # 3. Dispara o scan de vulnerabilidades em sequência
        from tasks.scan_tasks import run_grype_scan, run_ingestion
        chain(
            run_grype_scan.si(upload_id),
            run_ingestion.si(upload_id),
        ).delay()

    except Exception as e:
        logger.error(f"ERRO NA TASK: {str(e)}")
        if upload:
            upload.status = 'FAILED'
            upload.error_message = str(e)
            upload.save()
        raise e
    finally:
        driver.close()