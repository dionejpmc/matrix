import os
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
import traceback
from .models import SbomUpload
from tasks.sbom_tasks import process_sbom_task

UPLOAD_DIR = "/data/uploads"

@login_required
def upload_sbom_view(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método não permitido'}, status=405)

    print(f"DEBUG em view: FILES recebidos: {request.FILES.keys()}")
    
    print(f"DEBUG em view: POST recebido: {request.POST.dict()}")

    # ── Dados do chunk ────────────────────────────────────────────
    chunk        = request.FILES.get('file') or request.FILES.get('sbom_file')
    upload_id    = request.POST.get('upload_id')
    chunk_index  = int(request.POST.get('chunk_index', 0))
    total_chunks = int(request.POST.get('total_chunks', 1))
    filename     = request.POST.get('filename', 'upload')
    upload_type  = request.POST.get('type', 'sbom')
    product_name = request.POST.get('product_name', '')
    product_version = request.POST.get('product_version', '')

    print("FILES:", request.FILES)
    print("POST:", request.POST)
    if not chunk or not upload_id:
        return JsonResponse({'error': 'Dados incompletos no envio.'}, status=400)

    # ── Validação de extensão ─────────────────────────────────────
    fname = filename.lower()
    if upload_type == 'sbom' and not fname.endswith('.json'):
        return JsonResponse({'error': 'Formato inválido. Envie um arquivo .json'}, status=400)
    if upload_type == 'rootfs' and not (fname.endswith('.tar') or fname.endswith('.gz')):
        return JsonResponse({'error': 'Formato inválido. Envie .tar ou .tar.gz'}, status=400)

    # ── Salva o chunk em /tmp/matrix_uploads/<upload_id>/ ─────────
    tmp_dir = os.path.join(UPLOAD_DIR, upload_id)
    os.makedirs(tmp_dir, exist_ok=True)

    chunk_path = os.path.join(tmp_dir, f'chunk_{chunk_index:05d}')
    with open(chunk_path, 'wb') as f:
        for part in chunk.chunks():
            f.write(part)

    print(f"DEBUG: Chunk {chunk_index + 1}/{total_chunks} salvo em {chunk_path}")

    # ── Ainda não é o último chunk — apenas confirma recebimento ──
    if chunk_index + 1 < total_chunks:
        return JsonResponse({
            'status': 'chunk_ok',
            'chunk': chunk_index,
            'total': total_chunks,
        })

    # ── Último chunk: remonta o arquivo completo ──────────────────
    print(f"DEBUG: Último chunk recebido. Remontando arquivo...")

    final_filename = f'{upload_id}_{filename}'
    final_path = os.path.join(UPLOAD_DIR, final_filename)
    
    try:
        with open(final_path, 'wb') as final_file:
            for i in range(total_chunks):
                part_path = os.path.join(tmp_dir, f'chunk_{i:05d}')
                with open(part_path, 'rb') as part:
                    final_file.write(part.read())
                os.remove(part_path)
        os.rmdir(tmp_dir)
        print(f"DEBUG: Arquivo remontado em {final_path}")
    except Exception as e:
        return JsonResponse({'error': f'Erro ao remontar arquivo: {str(e)}'}, status=500)

    # ── Salva no banco e dispara o Celery ─────────────────────────
    try:
        # Abre o arquivo remontado e passa para o Django salvar via model
        with open(final_path, 'rb') as f:
            from django.core.files import File
            upload_record = SbomUpload.objects.create(
                product_name=product_name,
                status='PENDING'
            )
            upload_record.sbom_file.save(filename, File(f), save=True)

        # Remove o temporário após salvar no model
        os.remove(final_path)

        # Dispara o pipeline Celery
        process_sbom_task.delay(str(upload_record.id))

        print(f"DEBUG: Upload registrado ID={upload_record.id}, Celery disparado.")

        return JsonResponse({
            'status': 'success',
            'message': f'Arquivo {filename} recebido e processamento iniciado!',
            'id': str(upload_record.id),
        }, status=201)

    except Exception as e:
        # Limpa o arquivo remontado se falhar ao salvar
        print("ERRO REAL:")
        print(traceback.format_exc())
        if os.path.exists(final_path):
            os.remove(final_path)
        return JsonResponse({'error': f'Erro interno: {str(e)}'}, status=500)