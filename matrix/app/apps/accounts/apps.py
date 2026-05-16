from django.apps import AppConfig

class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.accounts'  # Deve ser exatamente o caminho das pastas

    def ready(self):
        # Carrega os signals de RBAC para criar o perfil do operador automaticamente
        import apps.accounts.signals