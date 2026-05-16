from django.apps import AppConfig

class SbomConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.sbom'  # O nome completo do módulo
    label = 'sbom'      # O apelido que o Django usa para migrações