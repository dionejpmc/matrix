from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Product, UserBUMembership

@login_required
def product_list_view(request):
    # 1. Busca a qual BU o usuário logado pertence
    membership = UserBUMembership.objects.filter(user=request.user).first()
    
    if membership:
        # 2. Filtra os produtos APENAS daquela BU (Segurança de dados)
        products = Product.objects.filter(business_unit=membership.business_unit).order_by('-created_at')
        current_bu = membership.business_unit.name
    else:
        # Se o usuário não tiver BU, não mostramos nada ou mostramos erro
        products = Product.objects.none()
        current_bu = "Nenhuma Unidade Vinculada"

    # 3. Envia os dados para o template
    return render(request, 'organizations/dashboard.html', {
        'products': products,
        'current_bu': current_bu
    })