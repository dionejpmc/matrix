from django.urls import path
from apps.sbom.views import api_product_graph, api_components
from .views import upload_sbom_view
from .views import *

app_name = 'sbom'

urlpatterns = [
    path('upload/', upload_sbom_view, name='upload'),
    path('api/graph/<int:product_id>/', api_product_graph, name='product_graph_api'),
    path('api/components/<int:product_id>/', api_components, name='components_api'),
    path('api/cve/<str:cve_id>/', api_cve_detail, name='cve_detail'),
    path('api/bu-stats/', api_bu_stats, name='bu_stats'),
    path('api/component-products/', api_component_products, name='component_products'),
]

