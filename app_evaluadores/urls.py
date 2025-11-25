from django.urls import path
from . import views



urlpatterns = [
    path('', views.DashboardEvaluadorView.as_view(), name='dashboard_evaluador'),
    path('Preins/evaluador/<int:evento_id>', views.EvaluadorCreateView.as_view(), name='crear_evaluador'),
    path('ver_detalle_evento_eva/<int:pk>', views.EventoDetailView.as_view(), name='ver_info_evento_eva'),

    path('cambiar_password/evaluador/', views.CambioPasswordEvaluadorView.as_view(), name='cambio_password_evaluador'),

    path('crear_criterios_eva/<int:evento_id>/', views.CriterioEvaListView.as_view(), name='crear_criterios_eva'),
    path('ver_criterios_agregados_eva/<int:evento_id>/', views.CriterioAgregadosEvaListView.as_view(), name='ver_criterios_agregados_eva'),
    path('crear_criterio_eva/<int:evento_id>/', views.CrearCriterioEvaView.as_view(), name='crear_criterio_eva'),
    path('actualizar_criterio_eva/<int:criterio_id>/', views.ActualizarEvaCriterioView.as_view(), name='actualizar_criterio_eva'),
    path('eliminar_criterio_eva/<int:criterio_id>/', views.EliminarEvaCriterioView.as_view(), name='eliminar_criterio_eva'),

    path('criterios_eva/<int:evento_id>/', views.VerCriteriosEvaluadorView.as_view(), name='ver_criterios_eva'),


    path('calificar_participantes/<int:evento_id>/', views.CalificarParticipantesView.as_view(), name='calificar_participantes'),
    path('evaluador/calificar/<int:participante_id>/<int:evento_id>/', views.CalificandoParticipanteView.as_view(), name='calificando_participante'),

    path('ver_podio/<int:evento_id>/', views.VerPodioParticipantesView.as_view(), name='ver_calificaciones'),
    path('evento/<int:evento_id>/participante/<int:participante_id>/detalle/',views.DetalleCalificacionView.as_view(),name='ver_detalle_calificacion'),

    path('evaluador/eliminar/<int:evaluador_id>/', views.EliminarEvaluadorView.as_view(), name='eliminar_evaluador'),
    path('evaluador/editar/<int:evaluador_id>/', views.EditarEvaluadorView.as_view(), name='editar_evaluador'),

    path('evento/<int:evento_id>/participantes/', views.ListadoParticipantesPorEventoView.as_view(), name='listado_participantes'),

    path('evento/<int:pk>/info_tecnica_evento/', views.InformacionTecnicaEventoEvaluadorView.as_view(), name='ver_info_tecnica_evento'),

    path('ingreso_evento_eva/<int:pk>/', views.IngresoEventoEvaluadorView.as_view(), name='ingreso_evento_eva'),

        
    path('evento/<int:evento_id>/memorias/evaluador/',views.MemoriasEvaluadorView.as_view(),name='memorias_evaluador'),

    path('cancelar_inscripcion_evaluador/<int:evento_id>/',views.EvaluadorCancelacionView.as_view(),name='cancelar_inscripcion_evaluador'),
    path('evento/<int:evento_id>/aprobar/<int:evaluador_evento_id>/', views.aprobar_eva, name='aprobar_eva'),
    path('evento/<int:evento_id>/rechazar/<int:evaluador_evento_id>/', views.rechazar_eva, name='rechazar_eva'),
    path('evento/<int:evento_id>/solicitar_certificado/',
     views.SolicitarCertificadoEvaluadorView.as_view(),
     name='solicitar_certificado_evaluador'),



    
]