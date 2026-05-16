# app/apps/rootfs/views.py
from django.http import JsonResponse
from .models import RootFS
from tasks.scan_tasks import run_full_scan # Sua task orquestradora

def upload_rootfs(request):
    if request.method == 'POST' and request.FILES.get('file'):
        file = request.FILES['file']
        product_id = request.POST.get('product_id') # Vindo da interface
        
        # 1. Cria o registro no banco (Gera o UUID interno automaticamente)
        obj = RootFS.objects.create(
            product_id=product_id,
            filename=file.name,
            file_path=file # O Django salva no volume /rootfs configurado
        )
        
        # 2. Dispara o Pipeline Assíncrono (P3)
        run_full_scan.delay(obj.id) 
        
        return JsonResponse({'status': 'success', 'rootfs_id': str(obj.id)})
    return JsonResponse({'status': 'error'}, status=400)