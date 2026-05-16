from django.db import models
from apps.rootfs.models import RootFS

class Vulnerability(models.Model):
    # Severidades conforme padrão CVSS citado na sua doc
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Crítico'),
        ('HIGH', 'Alto'),
        ('MEDIUM', 'Médio'),
        ('LOW', 'Baixo'),
        ('UNKNOWN', 'Desconhecido'),
    ]

    rootfs = models.ForeignKey(RootFS, on_delete=models.CASCADE, related_name='vulnerabilities')
    cve_id = models.CharField(max_length=50) # Ex: CVE-2023-1234
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    cvss_score = models.FloatField(null=True, blank=True)
    package_name = models.CharField(max_length=255)
    package_version = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    
    # Controle de triagem (VEX/Contexto)
    is_false_positive = models.BooleanField(default=False)
    fix_status = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"{self.cve_id} - {self.package_name}"

    class Meta:
        verbose_name_plural = "Vulnerabilities"