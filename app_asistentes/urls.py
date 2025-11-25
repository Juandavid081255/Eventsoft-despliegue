# app_asistentes/urls.py

from django.urls import path
from . import views

urlpatterns = [
    # CREACIÓN Y GESTIÓN DE ASISTENTES
    path('preins/asistente/<int:pk>', views.AsistenteCreateView.as_view(), name='crear_asistente'),
    
    # DASHBOARD
    path('', views.DashboardAsistenteView.as_view(), name='dashboard_asistente'),

    # CONFIGURACIÓN DE CUENTA
    path('cambiar_password/asistente/', views.CambioPasswordAsistenteView.as_view(), name='cambio_password_asistente'),
    path('editar_preinscripcion_asistente/<int:id>/', views.EditarPreinscripcionAsistenteView.as_view(), name='editar_preinscripcion_asistente'), 
    path('asistente/eliminar/<int:asistente_id>/', views.EliminarAsistenteView.as_view(), name='eliminar_asistente'),

    # EVENTOS (PRIVADO PARA ASISTENTES AUTENTICADOS)
    path('ver_detalle_evento/<int:pk>', views.EventoDetailAsistenteView.as_view(), name='ver_info_evento_asi'),
    path('ingreso_evento_asistente/<int:pk>/', views.IngresoEventoAsistenteView.as_view(), name='ingreso_evento_asi'),

    # GESTIÓN DE INSCRIPCIONES
    path('cancelar_inscripcion_asistente/<int:evento_id>/', views.AsistenteCancelacionView.as_view(), name='cancelar_inscripcion_asistente'),

    # MEMORIAS
    path('evento/<int:evento_id>/memorias/asistente/', views.MemoriasAsistenteView.as_view(), name='memorias_asistente'),

    path('evento/<int:evento_id>/notificar/', views.NotificarAsistentesView.as_view(), name='notificar_asistentes'),
]