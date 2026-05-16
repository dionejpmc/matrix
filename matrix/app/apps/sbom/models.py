from django.db import models
from apps.organizations.models import Product
import uuid
import hashlib
from django.utils import timezone  # <--- Adicione esta linha

class Component(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='components')
    name = models.CharField(max_length=255)
    version = models.CharField(max_length=100)
    type = models.CharField(max_length=50, blank=True) 
    purl = models.CharField(max_length=500, blank=True, null=True)
    license = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.name}@{self.version}"
    
    
def upload_to_uuid(instance, filename):
    ext = filename.split('.')[-1]
    # Agora o timezone.now() vai funcionar
    now = timezone.now()
    date_path = now.strftime('%Y/%m/%d')
    return f'sboms/{date_path}/{instance.id}.{ext}'

class SbomUpload(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pendente'),
        ('PROCESSING', 'Processando'),
        ('COMPLETED', 'Concluído'),
        ('FAILED', 'Falha'),
    ]

    product_name = models.CharField(max_length=255)
    product = models.ForeignKey(
        'organizations.Product', 
        on_delete=models.CASCADE,
        related_name='uploads',
        null=True, 
        blank=True
    )
    # AJUSTE: default=uuid.uuid4 garante que o ID exista antes do arquivo ser salvo
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False) 
    sbom_file = models.FileField(upload_to=upload_to_uuid)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    hashcode = models.CharField(max_length=64, editable=False, unique=False, null=True, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    error_message = models.TextField(null=True, blank=True)

    def save(self, *args, **kwargs):
        # Gera o hash se o arquivo existir e o hash ainda não
        if self.sbom_file and not self.hashcode:
            self.hashcode = self.generate_hash()
        super().save(*args, **kwargs)

    def generate_hash(self):
        sha256_hash = hashlib.sha256()
        # Chunks evitam carregar arquivos gigantes na memória RAM
        for chunk in self.sbom_file.chunks():
            sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def __str__(self):
        return f"{self.product_name} - {self.uploaded_at}"

class Vulnerability(models.Model):
    component = models.ForeignKey(Component, on_delete=models.CASCADE, related_name='vulnerabilities')
    cve_id = models.CharField(max_length=50) 
    severity = models.CharField(max_length=20) 
    description = models.TextField(null=True, blank=True)
    cvss_score = models.FloatField(null=True, blank=True)
    status = models.CharField(max_length=50, default='OPEN') 

    def __str__(self):
        return f"{self.cve_id} - {self.component.name}"