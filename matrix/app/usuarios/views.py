# matrix/app/usuarios/views.py
from django.shortcuts import render
from django.contrib.auth.decorators import login_required

@login_required  # Garante que apenas usuários logados acessem (Boundary 1 da documentação)
def dashboard(request):
    # O Django buscará em matrix/app/templates/ + usuarios/dashboard.html
    return render(request, 'usuarios/dashboard.html')

# Create your views here.
