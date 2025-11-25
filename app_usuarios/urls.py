# app_usuarios/urls.py

from django.urls import path
from . import views

urlpatterns = [
    path('invitar-admin/', views.enviar_invitacion, name='enviar_invitacion'),
    path('registro-admin/<uuid:token>/', views.registro_admin_evento, name='registro_admin_evento'),
    path('activar-admin/<int:user_id>/', views.activar_admin_evento, name='activar_admin_evento'),
]
