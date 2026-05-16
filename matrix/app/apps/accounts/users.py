from django.urls import reverse_lazy
from django.views.generic import CreateView
from .forms import MatrixUserCreationForm

from django.contrib.auth import logout
from django.shortcuts import redirect

class SignUpView(CreateView):
    form_class = MatrixUserCreationForm
    success_url = reverse_lazy('login')
    template_name = 'registration/signup.html'



