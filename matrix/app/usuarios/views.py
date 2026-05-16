# matrix/app/usuarios/views.py
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from apps.organizations.models import Product, UserBUMembership # Importamos os models de outro app

from django.db.models import Count # <--- Adicione este import


@login_required
def dashboard(request):
    membership = UserBUMembership.objects.filter(user=request.user).first()
    
    products = []
    current_bu = "Nenhuma Unidade Vinculada"

    if membership:
        products = Product.objects.filter(
            business_unit=membership.business_unit
        ).select_related(
            'business_unit', 'created_by'
        ).annotate(
            # Ajustado para 'components' conforme sugerido pelo erro do Django
            total_components=Count('components') 
        ).order_by('-created_at')
        
        current_bu = membership.business_unit.name

    context = {
        'products': products,
        'current_bu': current_bu,
    }

    return render(request, 'usuarios/dashboard.html', context)