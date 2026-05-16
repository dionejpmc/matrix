import uuid
from django.db import models
from apps.organizations.models import Product

class RootFS(models.Model):
    # Status do pipeline conforme especificado na documentação [cite: 48]
    STATUS_CHOICES = [
        ('PENDING', 'Pendente'),
        ('GENERATING_SBOM', 'Gerando SBOM'),
        ('SCANNING_VULNS', 'Escaneando Vulnerabilidades'),
        ('INGESTING', 'Ingerindo Dados'),
        ('COMPLETED', 'Concluído'),
        ('ERROR', 'Erro'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='rootfs_files')
    filename = models.CharField(max_length=255)  # Nome original para exibição
    internal_name = models.UUIDField(default=uuid.uuid4) # Nome interno seguro [cite: 190]
    file_path = models.FilePathField(path='/rootfs')
    scan_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    sha256 = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.product.name} - {self.filename}"

class ScanLog(models.Model):
    rootfs = models.ForeignKey(RootFS, on_delete=models.CASCADE, related_name='logs')
    stage = models.CharField(max_length=50)
    message = models.TextField()
    level = models.CharField(max_length=10) # INFO, ERROR, WARNING [cite: 48]
    timestamp = models.DateTimeField(auto_now_add=True)