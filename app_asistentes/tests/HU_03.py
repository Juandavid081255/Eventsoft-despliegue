""" Como visitante web quiero Acceder a 
información detallada sobre los eventos de mi interés para 
Tener mayor claridad sobre mi posibilidad e interés de asistir"""

# app_admin_eventos/tests/HU_03.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from app_admin_eventos.models import Evento 
from app_usuarios.models import Usuario, AdministradorEvento 
from datetime import date, timedelta
import uuid


class VisitanteWebEventosTestCase(TestCase):
    """
    Casos de prueba para la funcionalidad de visualización de eventos por un Visitante Web.
    
    Un visitante web NO autenticado debe poder:
    - Ver solo eventos en estado "Publicado"
    - Acceder a detalles de eventos publicados
    - NO acceder a detalles de eventos Cancelados o Finalizados
    """
    
    @classmethod
    def setUpTestData(cls):
        """
        Configuración inicial compartida para todos los tests.
        Crea un admin y 3 eventos en diferentes estados.
        """
        
        # 1. Crear Administrador de Evento
        user_admin = Usuario.objects.create_user(
            username='admin_test_hu03',
            email='admin_hu03@eventsoft.com', 
            password='password123', 
            rol=Usuario.Roles.ADMIN_EVENTO, 
            cedula='111111111B'
        )
        
        admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=user_admin)
        
        # 2. Archivos dummy para los eventos
        imagen_dummy = SimpleUploadedFile(
            "logo.png", 
            b"file_content", 
            content_type="image/png"
        )
        programacion_dummy = SimpleUploadedFile(
            "prog.pdf", 
            b"file_content", 
            content_type="application/pdf"
        )
        
        fecha_actual = date.today()
        
        # 3. Crear Evento PUBLICADO (visible)
        cls.evento_publicado = Evento.objects.create(
            eve_nombre="Congreso de IA Publicado",
            eve_descripcion="Evento visible para el público en general.",
            eve_estado="Publicado",
            eve_administrador_fk=admin_evento,
            eve_ciudad="Bogota",
            eve_lugar="Centro de Convenciones",
            eve_fecha_inicio=fecha_actual + timedelta(days=30),
            eve_fecha_fin=fecha_actual + timedelta(days=32),
            eve_tienecosto='Sí',
            eve_capacidad=100,
            eve_imagen=imagen_dummy,
            eve_programacion=programacion_dummy,
            preinscripcion_habilitada_asistentes=True
        )
        
        # 4. Crear Evento CANCELADO (no visible)
        cls.evento_cancelado = Evento.objects.create(
            eve_nombre="Taller de Python Cancelado",
            eve_descripcion="Evento cancelado, no debe ser visible.",
            eve_estado="Cancelado",
            eve_administrador_fk=admin_evento,
            eve_ciudad="Medellin",
            eve_lugar="Universidad X",
            eve_fecha_inicio=fecha_actual,
            eve_fecha_fin=fecha_actual + timedelta(days=1),
            eve_tienecosto='No',
            eve_capacidad=50,
            eve_imagen=imagen_dummy,
            eve_programacion=programacion_dummy,
        )
        
        # 5. Crear Evento FINALIZADO (no visible)
        cls.evento_finalizado = Evento.objects.create(
            eve_nombre="Webinar de Django Finalizado",
            eve_descripcion="Evento finalizado, no debe ser visible.",
            eve_estado="Finalizado",
            eve_administrador_fk=admin_evento,
            eve_ciudad="Cali",
            eve_lugar="Online",
            eve_fecha_inicio=date(2020, 1, 1), 
            eve_fecha_fin=date(2020, 1, 1),
            eve_tienecosto='No',
            eve_capacidad=200,
            eve_imagen=imagen_dummy,
            eve_programacion=programacion_dummy,
        )
        
        cls.client = Client()

    # --- Casos de Prueba de Listado (Página Principal) ---
    
    def test_cp01_acceso_pagina_principal_visitante(self):
        """
        CP01: Verifica que un visitante web sin autenticación puede acceder 
        a la página principal (HTTP 200).
        """
        response = self.client.get(reverse('pagina_principal'))
        self.assertEqual(response.status_code, 200)
    
    def test_cp02_solo_muestra_eventos_publicados_en_listado(self):
        """
        CP02: Verifica que solo los eventos en estado 'Publicado' aparecen 
        en el listado de la página principal.
        
        Los eventos Cancelados y Finalizados NO deben aparecer.
        """
        response = self.client.get(reverse('pagina_principal'))
        
        # Obtener lista de eventos del contexto
        # Ajusta 'eventos' según el nombre de variable en tu template
        eventos_en_contexto = response.context.get('object_list') or response.context.get('eventos')
        
        self.assertIsNotNone(eventos_en_contexto, "No se encontró lista de eventos en el contexto")
        
        # Debe haber exactamente 1 evento (el publicado)
        self.assertEqual(len(eventos_en_contexto), 1)
        self.assertEqual(eventos_en_contexto[0].eve_nombre, self.evento_publicado.eve_nombre)
        self.assertEqual(eventos_en_contexto[0].eve_estado, "Publicado")

    # --- Casos de Prueba de Detalle de Evento ---
    
    def test_cp03_acceso_detalle_evento_publicado(self):
        """
        CP03/CP05: Verifica que un visitante puede acceder al detalle 
        de un evento publicado y ver su información correcta (HTTP 200).
        """
        # URL para ver detalle del evento publicado
        # Ajusta 'ver_info_evento' según tu URL name
        url = reverse('ver_info_evento', kwargs={'pk': self.evento_publicado.pk})
        response = self.client.get(url)
        
        # Debe retornar 200
        self.assertEqual(response.status_code, 200)
        
        # El contexto debe contener el objeto evento
        self.assertIn('object', response.context)
        self.assertEqual(response.context['object'].pk, self.evento_publicado.pk)
        
        # El nombre del evento debe aparecer en la respuesta
        self.assertContains(response, "Congreso de IA Publicado")
        
        # Información adicional del evento
        self.assertContains(response, "Bogota")
        self.assertContains(response, "Centro de Convenciones")

    def test_cp04_no_acceso_detalle_evento_cancelado(self):
        """
        CP04: Verifica que un visitante NO puede acceder al detalle 
        de un evento cancelado (HTTP 404).
        """
        url = reverse('ver_info_evento', kwargs={'pk': self.evento_cancelado.pk})
        response = self.client.get(url)
        
        # Debe retornar 404 (Not Found)
        self.assertEqual(response.status_code, 404)

    def test_cp05_no_acceso_detalle_evento_finalizado(self):
        """
        CP05: Verifica que un visitante NO puede acceder al detalle 
        de un evento finalizado (HTTP 404).
        """
        url = reverse('ver_info_evento', kwargs={'pk': self.evento_finalizado.pk})
        response = self.client.get(url)
        
        # Debe retornar 404 (Not Found)
        self.assertEqual(response.status_code, 404)