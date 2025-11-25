"""
URL configuration for principal_eventos project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from . import views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('admin/', admin.site.urls),

    #VisitanteWeb URLs
    path('', views.MenuPrincipalVisitanteView.as_view(), name='pagina_principal'),
    path('ver_info/<int:pk>/', views.EventoDetailView.as_view(), name='ver_info_evento'),
    path('ver_info/eva/par<int:pk>/', views.EventoPreinscripcionesView.as_view(), name='preinscripcion_avanzada'),

    #AdminEventos URLs
    path('dashboardadmin/', include('app_admin_eventos.urls')),
    

    #Participantes URLs
    path('dashboardparticipante/', include('app_participantes.urls')),


    #Asistentes URLs
    path('dashboardasistente/', include('app_asistentes.urls')),


    #Evaluadores URLs
    path('dashboardevaluador/', include('app_evaluadores.urls')),

    #Roles Usuarios URLs
    path ('superuser/token.url=33546f5sg7D6#8f7@68F7F-68d68E6@84qW/', include('app_usuarios.urls')),



    path('login/', views.login_view, name='login_view'),
    path('logout/', views.logout_view, name='logout_view'),
    path('reset_password/', views.RestablecerContrasenaView.as_view(), name='restablecer_contrasena'),
    path('resetio_password/', views.RestablecioUnPasswordView.as_view(), name='reset_password'),
    path("reset/<uidb64>/<token>/", views.ResetPasswordConfirmView.as_view(), name="password_reset_confirm"),
    


    
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
