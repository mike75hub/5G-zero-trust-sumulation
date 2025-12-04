from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

def redirect_to_dashboard(request):
    return redirect('zero_trust_demo:dashboard')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', redirect_to_dashboard),
    path('demo/', include('zero_trust_demo.urls')),
]