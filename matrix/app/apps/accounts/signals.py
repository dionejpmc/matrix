from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from apps.organizations.models import UserBUMembership, BusinessUnit

@receiver(post_save, sender=User)
def create_user_rbac_profile(sender, instance, created, **kwargs):
    """
    Cria automaticamente a infraestrutura de acesso ao criar um usuário.
    Garante que a BU padrão exista para evitar erros de integridade.
    """
    if created:
        # 1. Garante que a BU 'WEG S.A' exista no sistema (Cria se o banco estiver zerado)
        bu, _ = BusinessUnit.objects.get_or_create(
            name="WEG S.A"
        )

        # 2. Define o papel (Role) baseado no tipo de usuário
        # Superusers ganham 'admin', usuários comuns 'viewer'
        user_role = 'admin' if instance.is_superuser else 'viewer'

        # 3. Cria o vínculo de membro na unidade de negócio
        UserBUMembership.objects.create(
            user=instance,
            business_unit=bu,
            role=user_role
        )
        
        print(f"RBAC: Perfil '{user_role}' criado para {instance.username} na unidade {bu.name}")