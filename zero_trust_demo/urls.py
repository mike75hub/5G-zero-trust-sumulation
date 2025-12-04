from django.urls import path
from . import views

app_name = 'zero_trust_demo'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('auth/', views.zero_trust_auth, name='zero_trust_auth'),
    path('manage/', views.device_management, name='device_management'),
    path('monitor/', views.security_monitor, name='security_monitor'),
    path('analytics/', views.device_analytics, name='device_analytics'),
    path('slicing/', views.network_slicing_demo, name='network_slicing'),
    path('slices/', views.slice_management, name='slice_management'),  # NEW
    path('api/authenticate/', views.api_authenticate, name='api_authenticate'),
]