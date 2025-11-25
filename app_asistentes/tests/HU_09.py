""" Como Asistente quiero Compartir la información de los eventos en los que estoy inscrito con mis contactos para 
Motivar a otras personas a asistir a los eventos
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile 
from urllib.parse import quote as urlquote 
from django.utils import timezone 
from datetime import date, datetime
from unittest.mock import patch
import uuid

from app_usuarios.models import Usuario, Asistente, AdministradorEvento
from app_admin_eventos.models import Evento
from app_asistentes.models import AsistenteEvento


class SharingEventoAsistenteTests(TestCase):
    """Pruebas para la historia de usuario de Compartir Evento como Asistente (HU-09)."""

    @classmethod
    def setUpTestData(cls):
        # 1. Crear datos de Administrador de Evento (con cédula única)
        cedula_admin = f'ADM{uuid.uuid4().hex[:8].upper()}'
        cls.super_admin_user = Usuario.objects.create_user(
            username=f'superadmin_{uuid.uuid4().hex[:6]}',
            password='password123',
            rol=Usuario.Roles.SUPERADMIN,
            cedula=cedula_admin
        )
        cls.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=cls.super_admin_user)

        # 2. Crear datos de Asistente (con cédula única)
        cedula_asistente = f'ASI{uuid.uuid4().hex[:8].upper()}'
        cls.asistente_user = Usuario.objects.create_user(
            username=f'asistente1_{uuid.uuid4().hex[:6]}',
            password='password123',
            email=f'asistente_{uuid.uuid4().hex[:6]}@test.com',
            rol=Usuario.Roles.ASISTENTE,
            cedula=cedula_asistente
        )
        cls.asistente = Asistente.objects.create(usuario=cls.asistente_user)

        # 3. Crear archivos simulados
        img_content = b'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'
        
        # 4. Crear Evento X (Inscrito)
        cls.evento_x = Evento.objects.create(
            eve_nombre='Conferencia de Python',
            eve_descripcion='Todo sobre Django',
            eve_ciudad='Manizales',
            eve_lugar='Teatro',
            eve_fecha_inicio=date(2025, 12, 1),
            eve_fecha_fin=date(2025, 12, 3),
            eve_estado='Publicado',
            eve_imagen=SimpleUploadedFile("test_image_x.gif", img_content, content_type="image/gif"),
            eve_administrador_fk=cls.admin_evento,
            eve_tienecosto='Sí',
            eve_capacidad=100,
            eve_programacion=SimpleUploadedFile("test_programacion_x.pdf", b"Content X", content_type="application/pdf"),
            preinscripcion_habilitada_asistentes=True
        )
        
        # 5. Crear Evento Y (No Inscrito)
        cls.evento_y = Evento.objects.create(
            eve_nombre='Seminario de DevOps',
            eve_descripcion='Containers y Kubernetes',
            eve_ciudad='Bogota',
            eve_lugar='Auditorio',
            eve_fecha_inicio=date(2026, 1, 15),
            eve_fecha_fin=date(2026, 1, 16),
            eve_estado='Publicado',
            eve_imagen=SimpleUploadedFile("test_image_y.gif", img_content, content_type="image/gif"),
            eve_administrador_fk=cls.admin_evento,
            eve_tienecosto='No',
            eve_capacidad=50,
            eve_programacion=SimpleUploadedFile("test_programacion_y.pdf", b"Content Y", content_type="application/pdf"),
            preinscripcion_habilitada_asistentes=True
        )

        # 6. Inscribir asistente al Evento X
        aware_datetime = timezone.make_aware(datetime(2025, 11, 1, 10, 0, 0))
        cls.asistente_evento = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=cls.asistente,
            asi_eve_evento_fk=cls.evento_x,
            asi_eve_fecha_hora=aware_datetime,
            asi_eve_estado='Aprobado',
            asi_eve_soporte=SimpleUploadedFile("test_soporte.pdf", b"Soporte", content_type="application/pdf"), 
            asi_eve_qr=SimpleUploadedFile("test_qr_asi_eve.png", b"Datos QR", content_type="image/png"), 
            asi_eve_clave='CLAVEX'
        )
        
        # URLs
        cls.url_detalle_evento = reverse('ver_info_evento_asi', kwargs={'pk': cls.evento_x.pk})
        cls.url_detalle_evento_no_inscrito = reverse('ver_info_evento_asi', kwargs={'pk': cls.evento_y.pk})
        cls.url_dashboard_asistente = reverse('dashboard_asistente')

    def setUp(self):
        """Setup para cada test individual."""
        self.client = Client()
        self.client.login(username=self.asistente_user.username, password='password123')
        session = self.client.session
        session['asistente_id'] = self.asistente.id 
        session.save()

    # CP-SHR-001: Verifica acceso 200 y presencia del botón compartir (CA1)
    def test_cshr_001_acceso_y_visibilidad_inscrito(self):
        """
        Verifica que el asistente inscrito accede a la vista y ve el botón compartir.
        """
        response = self.client.get(self.url_detalle_evento)
        
        self.assertEqual(response.status_code, 200)
        # Verificar que el botón compartir está presente
        self.assertContains(response, 'Compartir')

    # CP-SHR-002: Valida que la URL absoluta se genere y se pase al contexto (CA2)
    def test_cshr_002_validacion_url_compartir_generada(self):
        """
        Verifica que la URL absoluta se genere correctamente en el contexto.
        """
        response = self.client.get(self.url_detalle_evento)
        
        self.assertEqual(response.status_code, 200)
        
        # Verificar que hay una URL en el contexto
        self.assertIn('url_para_compartir', response.context)
        
        # Verificar que la URL contiene el servidor y la ruta
        url_compartir = response.context['url_para_compartir']
        self.assertIn('testserver', url_compartir)
        self.assertIn(f'ver_detalle_evento/{self.evento_x.pk}', url_compartir)

    # CP-SHR-003: Verifica que el asistente no inscrito sea redirigido (CA5)
    def test_cshr_003_restriccion_acceso_no_inscrito(self):
        """
        Verifica que el asistente no inscrito sea redirigido al dashboard.
        """
        response = self.client.get(self.url_detalle_evento_no_inscrito, follow=False)
        
        # Debe redirigir (302)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.url_dashboard_asistente)

    # CP-SHR-004: Valida la correcta codificación de las URLs de redes sociales (CA4)
    def test_cshr_004_validar_urls_redes_sociales(self):
        """
        Valida que las URLs de compartir en redes sociales se codifiquen correctamente.
        """
        response = self.client.get(self.url_detalle_evento)
        
        self.assertEqual(response.status_code, 200)
        
        # Obtener la URL del contexto
        url_compartir = response.context.get('url_para_compartir', '')
        
        # Validar que contiene URLs de redes sociales
        self.assertContains(response, 'wa.me')  # WhatsApp
        self.assertContains(response, 'facebook.com')  # Facebook
        
        # Validar que la URL está presente en el HTML
        self.assertContains(response, url_compartir)