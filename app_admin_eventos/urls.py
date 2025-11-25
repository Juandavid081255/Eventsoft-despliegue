
from django.urls import path, include
from app_admin_eventos import views
from app_admin_eventos.views import CertificadosView, cargar_personas

urlpatterns = [
    path('', views.MenuPrincipalView.as_view(), name='dashboard_admin'),
    path('crear/', views.EventoCreateView.as_view(), name='crear_evento'),
    path('crear_categoria_area/', views.CreateCategoriaView.as_view(), name='crear_categoria_area'),
    path("lista_categorias/", views.ListaCategoriasView.as_view(), name="lista_categorias"),
    path("eliminar_categoria/<int:pk>/", views.eliminar_categoria, name="eliminar_categoria"),

    #Contraseña editar al iniciar la primera sesion
    path('cambiar_password/admin/', views.CambioPasswordAdminView.as_view(), name='cambio_password_admin'),


    path('evento/editar/<int:pk>/', views.EventoEditarView.as_view(), name='editar_evento'),
    path('ver_info_evento/<int:pk>/', views.EventoDetailView.as_view(), name='ver_info_evento_admin'),

    
    path('evento/<int:evento_id>/cancelacion/', views.PageCancelarEventoView.as_view(), name='cancelar_evento_page'),
    path('evento/<int:pk>/cancelar_conteo/', views.CancelarEventoView.as_view(), name='evento_estado_cancelado'),

    path('evento/<int:evento_id>/cambiar_preinscripcion_asistente/', views.CambiarPreinscripcionAsistenteView.as_view(), name='cambiar_preinscripcion_asistente'),
    path('evento/<int:evento_id>/cambiar_preinscripcion_participante/', views.CambiarPreinscripcionParticipanteView.as_view(), name='cambiar_preinscripcion_participante'),
    path('evento/<int:evento_id>/cambiar_preinscripcion_evaluador/', views.CambiarPreinscripcionEvaluadorView.as_view(), name='cambiar_preinscripcion_evaluador'),
    path('validaciones/<int:evento_id>/', views.ValidacionesView.as_view(), name='validaciones'),
    
    path('validacion_asi/<int:evento_id>/', views.ValidacionAsistentesView.as_view(), name='validacion_asi'),
    path('aprobar_asi/<int:evento_id>/<int:asistente_id>/', views.AprobarAsistenteView.as_view(), name='aprobar_asi'),
    path('rechazar_asi/<int:evento_id>/<int:asistente_id>/', views.RechazarAsistenteView.as_view(), name='rechazar_asi'),

    path('validacion_par/<int:evento_id>/', views.ValidacionParticipanteView.as_view(), name='validacion_par'),
    path('aprobar_par/<int:evento_id>/<int:participante_id>/', views.AprobarParticipanteView.as_view(), name='aprobar_par'),
    path('rechazar_par/<int:evento_id>/<int:participante_id>/', views.RechazarParticipanteView.as_view(), name='rechazar_par'),

    path('estadisticas/<int:evento_id>/', views.EstadisticasView.as_view(), name='estadisticas_evento'),


    path('ver_criterios/<int:evento_id>/', views.CriterioListView.as_view(), name='ver_criterios'),
    path('ver_criterios_agregados/<int:evento_id>/', views.CriterioAgregadosListView.as_view(), name='ver_criterios_agregados'),
    path('crear-criterio/<int:evento_id>/', views.CrearCriterioView.as_view(), name='crear_criterio'),
    path('actualizar-criterio/<int:criterio_id>/', views.ActualizarCriterioView.as_view(), name='actualizar_criterio'),
    path('eliminar-criterio/<int:criterio_id>/', views.EliminarCriterioView.as_view(), name='eliminar_criterio'),

    path('ver_podio_admin/<int:evento_id>/', views.VerPodioParticipantesAdminView.as_view(), name='ver_calificaciones_admin'),
    path('evento_admin/<int:evento_id>/participante/<int:participante_id>/detalle/',views.DetalleCalificacionAdminView.as_view(),name='ver_detalle_calificacion_admin'),

    path('evento/<int:evento_id>/validacion_eva/', views.ValidacionEvaluadorView.as_view(), name='validacion_eva'),
    path('evento/<int:evento_id>/aprobar_eva/<int:evaluador_id>/', views.AprobarEvaluadorView.as_view(), name='aprobar_eva'),
    path('evento/<int:evento_id>/rechazar_eva/<int:evaluador_id>/', views.RechazarEvaluadorView.as_view(), name='rechazar_eva'),

    path('administrador/editar/<int:administrador_id>/', views.EditarAdministradorView.as_view(), name='editar_administrador'),

    path('evento/<int:pk>/info_tecnica/', views.InformacionTecnicaEventoView.as_view(), name='ver_info_tecnica'),


    

    path('evento/<int:evento_id>/certificados/',CertificadosView.as_view(),name='certificados_admin'),

    # AJAX para cargar personas (sin @admin_required, usa login y session cookies)
    path('evento/cargar_personas/',cargar_personas,name='cargar_personas'),


    path('evento/<int:evento_id>/premiacion/',views.PremiacionView.as_view(),name='premiacion_admin'),

    path('evento/<int:evento_id>/memorias/admin/',views.MemoriasAdminView.as_view(),name='memorias_admin'),
    path('evento/<int:evento_id>/memoria/<int:memoria_id>/borrar/', views.BorrarMemoriaAdminView.as_view(), name='borrar_memoria_admin'),

    path("eventos/<int:evento_id>/previsualizar/<str:tipo>/<int:persona_id>/",views.previsualizar_certificado,name="previsualizar_certificado"),

    #Notificar sobre eventos relevantes del evento
    path("eventos/<int:evento_id>/notificar/",views.NotificarEventoView.as_view(),name="notificar_evento"),

    path("eventos/<int:evento_id>/notificar/asistentes/",views.EnviarNotificacionAsistentesView.as_view(),name="notificar_asi"),
    path("eventos/<int:evento_id>/notificar/evaluador/",views.EnviarNotificacionEvaluadoresView.as_view(),name="notificar_eva"),
    path("eventos/<int:evento_id>/notificar/exponentes/",views.EnviarNotificacionParticipantesView.as_view(),name="notificar_par"),
    path('<int:evento_id>/configurar/', 
     views.ConfigurarEventoView.as_view(), 
     name='configurar_evento'),

    





    
    




]


