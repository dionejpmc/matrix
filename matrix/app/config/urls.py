"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from usuarios import views as usuarios_views
from apps.sbom.views import upload_sbom_view
from apps.accounts.users import SignUpView
from django.contrib.auth import views as auth_views



urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Autenticação nativa do Django
    # app/core/urls.py (ou onde estiver o seu urls.py principal)
    path('accounts/login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    # Rota do Dashboard (Página inicial após o login)
    path('', usuarios_views.dashboard, name='dashboard'),
    path('upload/', upload_sbom_view, name='upload_sbom'),
    path('signup/', SignUpView.as_view(), name='signup'),
    path('logoff/', auth_views.LogoutView.as_view(), name='logoff'),
    path('sbom/', include('apps.sbom.urls')),
    path('hbom/', include('apps.hbom.urls')),
]
