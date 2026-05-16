import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

app = Celery('matrix')

app.config_from_object('django.conf:settings', namespace='CELERY')

# Importa os módulos de tasks explicitamente
app.conf.include = [
    'tasks.sbom_tasks',
    'tasks.scan_tasks',
]


@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')