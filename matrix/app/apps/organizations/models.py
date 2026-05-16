from django.db import models
from django.contrib.auth.models import User
from django.conf import settings

class Product(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    version = models.CharField(max_length=50, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    business_unit = models.ForeignKey(
        'BusinessUnit',  # O Django resolve isso sozinho sem precisar do import no topo
        on_delete=models.CASCADE,
        related_name='products',
        null=True
    )
    
    # Para o criador, use a configuração padrão do Django
    created_by = models.ForeignKey(
        'auth.User', # Ou settings.AUTH_USER_MODEL
        on_delete=models.SET_NULL,
        null=True
    )
    
    created_at = models.DateTimeField(auto_now_add=True)

class BusinessUnit(models.Model):
    name = models.CharField(max_length=100)
    # ... outros campos

    def __str__(self):
        return self.name # ISSO resolve o erro no /signup/

class UserBUMembership(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Administrador'),
        ('operator', 'Operador'),
        ('viewer', 'Visualizador'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    business_unit = models.ForeignKey(BusinessUnit, on_delete=models.CASCADE)
    role = models.CharField(
        max_length=20, 
        choices=ROLE_CHOICES, 
        default='viewer'
    )

    def __str__(self):
        # ISSO resolve o erro de visualização do objeto no banco
        return f"{self.user.username} - {self.business_unit.name} ({self.get_role_display()})"