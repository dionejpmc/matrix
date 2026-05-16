import os
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
import traceback
from .models import SbomUpload
from apps.organizations.models import Product, UserBUMembership # Importe os models necessários
from tasks.sbom_tasks import process_sbom_task
from tasks.scan_tasks import *
from neo4j import GraphDatabase

UPLOAD_DIR = "/data/uploads"

@login_required
def upload_sbom_view(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método não permitido'}, status=405)

    # ... (Seu código de captura de chunks continua igual até a remontagem) ...
    chunk = request.FILES.get('file') or request.FILES.get('sbom_file')
    upload_id = request.POST.get('upload_id')
    chunk_index = int(request.POST.get('chunk_index', 0))
    total_chunks = int(request.POST.get('total_chunks', 1))
    filename = request.POST.get('filename', 'upload')
    upload_type = request.POST.get('type', 'sbom')
    product_name = request.POST.get('product_name', '')
    product_version = request.POST.get('product_version', '')

    # ... (Lógica de salvamento de chunks e diretórios temporários) ...
    tmp_dir = os.path.join(UPLOAD_DIR, upload_id)
    os.makedirs(tmp_dir, exist_ok=True)
    chunk_path = os.path.join(tmp_dir, f'chunk_{chunk_index:05d}')
    
    with open(chunk_path, 'wb') as f:
        for part in chunk.chunks():
            f.write(part)

    if chunk_index + 1 < total_chunks:
        return JsonResponse({'status': 'chunk_ok', 'chunk': chunk_index, 'total': total_chunks})

    # ── ÚLTIMO CHUNK: Lógica de Persistência com Relações ──────────────────
    final_filename = f'{upload_id}_{filename}'
    final_path = os.path.join(UPLOAD_DIR, final_filename)
    
    try:
        # Remontagem do arquivo
        with open(final_path, 'wb') as final_file:
            for i in range(total_chunks):
                part_path = os.path.join(tmp_dir, f'chunk_{i:05d}')
                with open(part_path, 'rb') as part:
                    final_file.write(part.read())
                os.remove(part_path)
        os.rmdir(tmp_dir)

        # ── PERSISTÊNCIA NO BANCO (Onde a mágica acontece) ──
        from django.core.files import File
        
        # 1. Identificar a BU do usuário logado (usando a tabela de membership)
        membership = UserBUMembership.objects.filter(user=request.user).first()
        user_bu = membership.business_unit if membership else None

        # 2. Criar ou atualizar o Produto com Versão, BU e Criador
        # O nome e a BU definem a unicidade aqui.
        product_obj, created = Product.objects.update_or_create(
            name=product_name,
            business_unit=user_bu,
            defaults={
                'version': product_version,
                'created_by': request.user,
            }
        )

        # 3. Criar o registro de Upload vinculado ao produto
        with open(final_path, 'rb') as f:
            upload_record = SbomUpload.objects.create(
                product_name=product_name, # Mantido para fins de log
                product=product_obj,     # Se você tiver a FK no SbomUpload, descomente aqui
                status='PENDING'
            )
            upload_record.sbom_file.save(filename, File(f), save=True)
        
        os.remove(final_path)
        process_sbom_task.delay(str(upload_record.id))

        return JsonResponse({
            'status': 'success',
            'message': f'Produto {product_obj.name} v{product_obj.version} processando!',
            'id': str(upload_record.id),
        }, status=201)

    except Exception as e:
        print(traceback.format_exc())
        if os.path.exists(final_path): os.remove(final_path)
        return JsonResponse({'error': f'Erro interno: {str(e)}'}, status=500)

def dashboard_view(request):
    # Pega apenas os produtos da BU do usuário logado
    user_bu = request.user.userbumembership_set.first().business_unit
    products = Product.objects.filter(business_unit=user_bu).order_by('-created_at')
    
    return render(request, 'dashboard.html', {'products': products})

@login_required
def api_cve_detail(request, cve_id):
    from apps.sbom.models import Vulnerability
    from neo4j import GraphDatabase

    vuln = Vulnerability.objects.filter(cve_id=cve_id).first()
    if not vuln:
        return JsonResponse({'error': 'não encontrado'}, status=404)

    # Busca impacto transitivo no Neo4j
    uri = "bolt://matrix-graph:7687"
    user = "neo4j"
    password = "outra_senha_forte_aqui"

    transitive = []
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session() as session:
            result = session.run("""
                MATCH (a:Component)-[:DEPENDS_ON*1..]->(b:Component)-[:HAS_VULNERABILITY]->(v:CVE {cveId: $cve_id})
                WITH DISTINCT a, b
                RETURN a.name as dependent, a.version as dep_version,
                    b.name as vulnerable, b.version as vuln_version
                ORDER BY dependent
            """, {"cve_id": cve_id})
            transitive = [dict(r) for r in result]
        driver.close()
    except Exception as e:
        print(f"Neo4j error: {e}")

    return JsonResponse({
        'cve_id': vuln.cve_id,
        'severity': vuln.severity,
        'description': vuln.description,
        'cvss_score': vuln.cvss_score,
        'status': vuln.status,
        'component': vuln.component.name,
        'component_version': vuln.component.version,
        'transitive_impact': transitive,
    })

@login_required
def api_product_graph(request, product_id):
    from neo4j import GraphDatabase
    from django.http import JsonResponse
    import traceback
    import uuid

    uri = "bolt://matrix-graph:7687"
    user = "neo4j"
    password = "outra_senha_forte_aqui"

    # Parâmetros de filtro vindos do frontend
    severity_filter = request.GET.getlist('severity')  # ex: ?severity=CRITICAL&severity=HIGH
    cve_filter = request.GET.get('cve', '').strip().upper()  # ex: ?cve=CVE-2022-1234
    show_all = request.GET.get('all', 'false') == 'true'  # ?all=true traz componentes sem vuln

    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        nodes = []
        edges = []
        seen_nodes = set()
        seen_edges = set()

        with driver.session() as session:

            # Monta cláusula WHERE dinâmica para CVE
            vuln_filter_clause = ""
            params = {"id": str(product_id)}

            if cve_filter:
                vuln_filter_clause = "AND v.cveId CONTAINS $cve"
                params["cve"] = cve_filter
            elif severity_filter:
                vuln_filter_clause = "AND v.severity IN $severities"
                params["severities"] = [s.upper() for s in severity_filter]

            if show_all:
                # Traz todos os componentes, com ou sem CVE
                query = f"""
                MATCH (p:Product)
                WHERE p.db_id = toInteger($id) OR p.name = $id
                OPTIONAL MATCH (p)-[:HAS_COMPONENT]->(c:Component)
                OPTIONAL MATCH (c)-[:HAS_VULNERABILITY]->(v:CVE)
                WHERE v IS NULL OR true {vuln_filter_clause}
                RETURN
                    elementId(p) as prod_id, p.name as prod_name,
                    elementId(c) as comp_id, c.name as comp_name, c.version as comp_version,
                    elementId(v) as vuln_id, v.cveId as vuln_cve, v.severity as vuln_severity
                """
            else:
                # Padrão: só componentes que têm pelo menos uma CVE (com filtro aplicado)
                query = f"""
                MATCH (p:Product)
                WHERE p.db_id = toInteger($id) OR p.name = $id
                MATCH (p)-[:HAS_COMPONENT]->(c:Component)-[:HAS_VULNERABILITY]->(v:CVE)
                WHERE true {vuln_filter_clause}
                RETURN
                    elementId(p) as prod_id, p.name as prod_name,
                    elementId(c) as comp_id, c.name as comp_name, c.version as comp_version,
                    elementId(v) as vuln_id, v.cveId as vuln_cve, v.severity as vuln_severity
                """

            records = list(session.run(query, **params))

        driver.close()

        if not records:
            return JsonResponse({"nodes": [], "edges": []})

        for record in records:
            prod_id = record["prod_id"]
            comp_id = record["comp_id"]
            vuln_id = record["vuln_id"]

            if prod_id and prod_id not in seen_nodes:
                nodes.append({"data": {"id": prod_id, "label": record["prod_name"] or "Produto", "type": "product"}})
                seen_nodes.add(prod_id)

            if comp_id and comp_id not in seen_nodes:
                label = record["comp_name"] or "Component"
                if record["comp_version"]:
                    label += f"\n{record['comp_version']}"
                nodes.append({"data": {"id": comp_id, "label": label, "type": "component"}})
                seen_nodes.add(comp_id)

            if prod_id and comp_id:
                edge_key = (prod_id, comp_id)
                if edge_key not in seen_edges:
                    edges.append({"data": {"id": str(uuid.uuid4()), "source": prod_id, "target": comp_id, "label": "HAS_COMPONENT"}})
                    seen_edges.add(edge_key)

            if vuln_id and vuln_id not in seen_nodes:
                nodes.append({"data": {"id": vuln_id, "label": record["vuln_cve"] or "CVE", "type": "cve", "severity": record["vuln_severity"] or "UNKNOWN"}})
                seen_nodes.add(vuln_id)

            if comp_id and vuln_id:
                edge_key = (comp_id, vuln_id)
                if edge_key not in seen_edges:
                    edges.append({"data": {"id": str(uuid.uuid4()), "source": comp_id, "target": vuln_id, "label": "HAS_VULNERABILITY"}})
                    seen_edges.add(edge_key)

        return JsonResponse({"nodes": nodes, "edges": edges})

    except Exception as e:
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)
    

@login_required
def api_components(request, product_id):
    components = Component.objects.filter(product_id=product_id).prefetch_related('vulnerabilities')
    
    result = []
    for comp in components:
        result.append({
            'id': comp.id,
            'name': comp.name,
            'version': comp.version,
            'type': comp.type,
            'purl': comp.purl,
            'license': comp.license,
            'vulnerabilities': [
                {
                    'cve_id': v.cve_id,
                    'severity': v.severity,
                    'description': v.description,
                    'cvss_score': v.cvss_score,
                    'status': v.status,
                }
                for v in comp.vulnerabilities.all()
            ],
            'vuln_count': comp.vulnerabilities.count(),
        })
    
    return JsonResponse({'components': result})


# views.py sbom
@login_required
def api_bu_stats(request):
    from apps.organizations.models import UserBUMembership
    from apps.sbom.models import Vulnerability

    membership = UserBUMembership.objects.filter(user=request.user).first()
    if not membership:
        return JsonResponse({'sboms': 0, 'total_vulns': 0, 'resolved_vulns': 0})

    user_bu = membership.business_unit

    sboms = SbomUpload.objects.filter(
        product__business_unit=user_bu,
        status='COMPLETED'
    ).count()

    vulns = Vulnerability.objects.filter(
        component__product__business_unit=user_bu
    )

    return JsonResponse({
        'sboms': sboms,
        'total_vulns': vulns.count(),
        'resolved_vulns': vulns.filter(status__in=['RESOLVED', 'ACCEPTED']).count(),
    })

@login_required
def api_component_products(request):
    from apps.sbom.models import Component
    name = request.GET.get('name', '')
    version = request.GET.get('version', '')
    count = Component.objects.filter(
        name=name,
        version=version
    ).values('product').distinct().count()
    return JsonResponse({'count': count})