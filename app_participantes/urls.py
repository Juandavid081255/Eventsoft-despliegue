from django.urls import path
from . import views



urlpatterns = [
    path('', views.DashboardParticipanteView.as_view(),name='dashboard_participante'),

    path('preins/participante/<int:pk>', views.ParticipanteCreateView.as_view(), name='crear_participante'),

    path('editar_preinscripcion/<int:id>/', views.EditarPreinscripcionView.as_view(),name='editar_preinscripcion'), 
    path('participante/eliminar/<int:participante_id>/', views.EliminarParticipanteView.as_view(), name='eliminar_participante'),
    path('cambiar_password/participante/', views.CambioPasswordParticipanteView.as_view(), name='cambio_password_participante'),

    path('ver_detalle_evento_par/<int:pk>', views.EventoDetailView.as_view(), name='ver_info_evento_par'),

    path('ingreso_evento_par/<int:pk>/', views.IngresoEventoParticipanteView.as_view(), name='ingreso_evento_par'),

    path('criterios_par/<int:evento_id>/', views.VerCriteriosParticipanteView.as_view(), name='ver_criterios_par'),

    path('ver_calificaciones/<int:evento_id>/', views.VerCalificacionView.as_view(), name='ver_calificaciones_par'),

    path('ver_detalle_calificacion/<int:evento_id>/',views.DetalleCalificacionView.as_view(),name='ver_detalle_calificacion_par'),

    path('evento/<int:evento_id>/memorias/participante/',views.MemoriasParticipanteView.as_view(),name='memorias_participante'),

    path('cancelar_inscripcion_participante/<int:evento_id>/',views.ParticipanteCancelacionView.as_view(),name='cancelar_inscripcion_participante'),


    path('ver_miembros/<int:evento_id>/', views.ListaMiembrosView.as_view(), name='ver_miembros_par'),
    path('ver_miembros/agregar_miembros/<int:evento_id>/', views.AgregarMiembrosView.as_view(), name='agregar_miembro_par'),


]
