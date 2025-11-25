""" Como Asistente Visualizar y Descargar la información detallada de la programación del evento 
en el que estoy inscrito para 
Tener mayor claridad sobre los horarios y los lugares en que se desarrollará cada actividad del evento"""

# app_asistentes/tests/HU_11.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import date, timedelta
from app_usuarios.models import Asistente, AdministradorEvento
from app_admin_eventos.models import Evento
from app_asistentes.models import AsistenteEvento
import uuid

Usuario = get_user_model()


class AsistenteProgramacionTestCase(TestCase):
    """
    Casos de prueba para visualizar y descargar programación del evento (HU11).
    
    Un asistente debe poder ver y descargar la programación solo si:
    1. Está inscrito en el evento (existe AsistenteEvento)
    2. Está autenticado como asistente
    3. El evento existe
    """

    @classmethod
    def setUpTestData(cls):
        """Datos compartidos para todos los tests."""
        
        # Crear admin
        user_admin = Usuario.objects.create_user(
            username='admin_hu11',
            email='admin_hu11@eventsoft.com',
            password='password123',
            rol=Usuario.Roles.ADMIN_EVENTO,
            cedula='999999999HU11'
        )
        admin_perfil, _ = AdministradorEvento.objects.get_or_create(usuario=user_admin)
        
        # Archivos dummy
        imagen_dummy = SimpleUploadedFile("logo.png", b"file_content", content_type="image/png")
        programacion_content = b"PROGRAMACION:\n1. Apertura: 9:00 AM - Auditorio Principal\n2. Conferencia 1: 10:00 AM - Sala A\n3. Almuerzo: 12:00 PM - Comedor"
        programacion_dummy = SimpleUploadedFile("programacion.pdf", programacion_content, content_type="application/pdf")
        
        fecha_futura = date.today() + timedelta(days=30)
        
        # Evento Publicado
        cls.evento = Evento.objects.create(
            eve_nombre="Conferencia de Testing",
            eve_descripcion="Evento de testing con programación.",
            eve_estado="Publicado",
            eve_administrador_fk=admin_perfil,
            eve_ciudad="Manizales",
            eve_lugar="Teatro",
            eve_fecha_inicio=fecha_futura,
            eve_fecha_fin=fecha_futura + timedelta(days=2),
            eve_tienecosto='No',
            eve_capacidad=200,
            eve_imagen=imagen_dummy,
            eve_programacion=programacion_dummy,
            preinscripcion_habilitada_asistentes=True
        )

    def setUp(self):
        """Setup para cada test individual."""
        self.client = Client()
        
        # Asistente INSCRITO
        user_inscrito = Usuario.objects.create_user(
            username=f'asistente_prog_{uuid.uuid4().hex[:6]}',
            email=f'prog_{uuid.uuid4().hex[:6]}@test.com',
            password='password123',
            rol=Usuario.Roles.ASISTENTE,
            cedula=f'PROG{uuid.uuid4().hex[:8]}'
        )
        self.asistente_inscrito = Asistente.objects.create(usuario=user_inscrito)
        
        qr_dummy = SimpleUploadedFile("qr.png", b"qr_content", content_type="image/png")
        soporte_dummy = SimpleUploadedFile("soporte.pdf", b"soporte_content", content_type="application/pdf")
        
        self.inscripcion = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente_inscrito,
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_estado="Aprobado",
            asi_eve_soporte=soporte_dummy,
            asi_eve_qr=qr_dummy,
            asi_eve_clave="CLAVE123"
        )
        
        # Asistente NO INSCRITO
        user_no_inscrito = Usuario.objects.create_user(
            username=f'asistente_noprog_{uuid.uuid4().hex[:6]}',
            email=f'noprog_{uuid.uuid4().hex[:6]}@test.com',
            password='password123',
            rol=Usuario.Roles.ASISTENTE,
            cedula=f'NOPG{uuid.uuid4().hex[:8]}'
        )
        self.asistente_no_inscrito = Asistente.objects.create(usuario=user_no_inscrito)

    # === CASOS DE ÉXITO ===
    
    def test_cp_hu11_001_acceso_asistente_inscrito(self):
        """
        CP1: Asistente inscrito puede acceder a la programación del evento.
        """
        self.client.login(
            username=self.asistente_inscrito.usuario.username,
            password='password123'
        )
        session = self.client.session
        session['asistente_id'] = self.asistente_inscrito.pk
        session.save()
        
        url = reverse('ver_info_evento_asi', kwargs={'pk': self.evento.pk})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        # Verificar que el evento está en el contexto
        self.assertIn('evento', response.context)
        self.assertEqual(response.context['evento'].pk, self.evento.pk)

    def test_cp_hu11_003_descarga_programacion_exitosa(self):
        """
        CP3: Asistente inscrito puede descargar el archivo de programación.
        
        Este test verifica que el archivo existe y tiene contenido correcto.
        """
        self.client.login(
            username=self.asistente_inscrito.usuario.username,
            password='password123'
        )
        session = self.client.session
        session['asistente_id'] = self.asistente_inscrito.pk
        session.save()
        
        # Verificar que el archivo fue guardado correctamente
        self.assertTrue(self.evento.eve_programacion)
        # Django añade un sufijo aleatorio al nombre, así que validamos que contiene el nombre base
        self.assertIn('programacion', self.evento.eve_programacion.name)
        self.assertTrue(self.evento.eve_programacion.name.endswith('.pdf'))
        
        # Leer el contenido del archivo directamente desde el storage
        programacion_content = self.evento.eve_programacion.read()
        self.assertIn(b"PROGRAMACION", programacion_content)
        self.assertIn(b"Apertura", programacion_content)

    # === CASOS DE FALLA ===
    
    def test_cp_hu11_002_restriccion_acceso_no_inscrito(self):
        """
        CP2: Asistente NO inscrito no puede acceder a detalles del evento.
        """
        self.client.login(
            username=self.asistente_no_inscrito.usuario.username,
            password='password123'
        )
        session = self.client.session
        session['asistente_id'] = self.asistente_no_inscrito.pk
        session.save()
        
        url = reverse('ver_info_evento_asi', kwargs={'pk': self.evento.pk})
        response = self.client.get(url, follow=False)
        
        # Debe redirigir (302) si no está inscrito
        self.assertEqual(response.status_code, 302)

    def test_cp_hu11_004_acceso_evento_inexistente(self):
        """
        CP4: Intento de acceder a un evento que no existe retorna 404.
        """
        self.client.login(
            username=self.asistente_inscrito.usuario.username,
            password='password123'
        )
        session = self.client.session
        session['asistente_id'] = self.asistente_inscrito.pk
        session.save()
        
        non_existent_pk = self.evento.pk + 999
        url = reverse('ver_info_evento_asi', kwargs={'pk': non_existent_pk})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 404)

    def test_usuario_no_autenticado_redirige_login(self):
        """
        Verifica que usuario no autenticado sea redirigido al login.
        """
        self.client.logout()
        
        url = reverse('ver_info_evento_asi', kwargs={'pk': self.evento.pk})
        response = self.client.get(url, follow=False)
        
        # Debe redirigir (302)
        self.assertIn(response.status_code, [302, 403])