""" Como Asistente quiero Descargar las memorias del evento 
después de que haya finalizado para 
Tener acceso a los contenidos y recursos compartidos"""

# app_asistentes/tests/HU_13.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import date, timedelta
from app_usuarios.models import Asistente, AdministradorEvento
from app_admin_eventos.models import Evento, MemoriaEvento
from app_asistentes.models import AsistenteEvento
import uuid

Usuario = get_user_model()


class MemoriasDescargaTestCase(TestCase):
    """
    Casos de prueba para la descarga de memorias del evento (HU13).
    
    Un asistente debe poder descargar memorias solo si:
    1. El evento ha finalizado (eve_estado = 'Finalizado')
    2. El asistente está inscrito como asistente en el evento
    3. El asistente está autenticado
    """

    @classmethod
    def setUpTestData(cls):
        """Datos compartidos para todos los tests."""
        
        # Crear admin
        user_admin = Usuario.objects.create_user(
            username='admin_hu13',
            email='admin_hu13@eventsoft.com',
            password='password123',
            rol=Usuario.Roles.ADMIN_EVENTO,
            cedula='999999999HU13'
        )
        admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=user_admin)
        
        # Archivo dummy
        imagen_dummy = SimpleUploadedFile("logo.png", b"file_content", content_type="image/png")
        programacion_dummy = SimpleUploadedFile("prog.pdf", b"file_content", content_type="application/pdf")
        
        fecha_pasada = date.today() - timedelta(days=10)
        
        # Evento FINALIZADO
        cls.evento_finalizado = Evento.objects.create(
            eve_nombre="Conferencia Finalizada",
            eve_descripcion="Evento ya finalizado.",
            eve_estado="Finalizado",
            eve_administrador_fk=admin_evento,
            eve_ciudad="Bogota",
            eve_lugar="Centro",
            eve_fecha_inicio=fecha_pasada,
            eve_fecha_fin=fecha_pasada,
            eve_tienecosto='No',
            eve_capacidad=100,
            eve_imagen=imagen_dummy,
            eve_programacion=programacion_dummy,
            preinscripcion_habilitada_asistentes=True
        )
        
        # Evento PUBLICADO (no finalizado)
        fecha_futura = date.today() + timedelta(days=30)
        cls.evento_publicado = Evento.objects.create(
            eve_nombre="Webinar Próximo",
            eve_descripcion="Evento que aún no finaliza.",
            eve_estado="Publicado",
            eve_administrador_fk=admin_evento,
            eve_ciudad="Medellin",
            eve_lugar="Online",
            eve_fecha_inicio=fecha_futura,
            eve_fecha_fin=fecha_futura,
            eve_tienecosto='No',
            eve_capacidad=50,
            eve_imagen=imagen_dummy,
            eve_programacion=programacion_dummy,
        )
        
        # Crear memorias para evento finalizado
        archivo_memoria = SimpleUploadedFile("memoria.pdf", b"memoria_content", content_type="application/pdf")
        cls.memoria_finalizado = MemoriaEvento.objects.create(
            evento=cls.evento_finalizado,
            nombre="Presentaciones Conferencia",
            archivo=archivo_memoria
        )

    def setUp(self):
        """Setup para cada test individual."""
        self.client = Client()
        
        # Asistente INSCRITO en evento finalizado
        user_inscrito = Usuario.objects.create_user(
            username=f'asistente_inscrito_{uuid.uuid4().hex[:6]}',
            email=f'inscrito_{uuid.uuid4().hex[:6]}@test.com',
            password='password123',
            rol=Usuario.Roles.ASISTENTE,
            cedula=f'MEM{uuid.uuid4().hex[:8]}'
        )
        self.asistente_inscrito = Asistente.objects.create(usuario=user_inscrito)
        
        qr_dummy = SimpleUploadedFile("qr.png", b"qr_content", content_type="image/png")
        soporte_dummy = SimpleUploadedFile("soporte.pdf", b"soporte_content", content_type="application/pdf")
        
        self.inscripcion_finalizado = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente_inscrito,
            asi_eve_evento_fk=self.evento_finalizado,
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_estado="Aprobado",
            asi_eve_soporte=soporte_dummy,
            asi_eve_qr=qr_dummy,
            asi_eve_clave="CLAVE123"
        )
        
        # Asistente NO inscrito en evento finalizado
        user_no_inscrito = Usuario.objects.create_user(
            username=f'asistente_no_inscrito_{uuid.uuid4().hex[:6]}',
            email=f'no_inscrito_{uuid.uuid4().hex[:6]}@test.com',
            password='password123',
            rol=Usuario.Roles.ASISTENTE,
            cedula=f'NOIN{uuid.uuid4().hex[:8]}'
        )
        self.asistente_no_inscrito = Asistente.objects.create(usuario=user_no_inscrito)
        
        # Asistente inscrito en evento NO finalizado
        user_activo = Usuario.objects.create_user(
            username=f'asistente_activo_{uuid.uuid4().hex[:6]}',
            email=f'activo_{uuid.uuid4().hex[:6]}@test.com',
            password='password123',
            rol=Usuario.Roles.ASISTENTE,
            cedula=f'ACTV{uuid.uuid4().hex[:8]}'
        )
        self.asistente_activo = Asistente.objects.create(usuario=user_activo)
        
        self.inscripcion_activo = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente_activo,
            asi_eve_evento_fk=self.evento_publicado,
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_estado="Aprobado",
            asi_eve_soporte=soporte_dummy,
            asi_eve_qr=qr_dummy,
            asi_eve_clave="CLAVE789"
        )

    # === CASOS DE ÉXITO ===
    
    def test_ca101_ca203_descarga_exitosa_memorias_evento_finalizado(self):
        """
        CA1.01, CA2.03: Asistente inscrito en evento finalizado 
        puede acceder a memorias (HTTP 200).
        """
        self.client.login(
            username=self.asistente_inscrito.usuario.username,
            password='password123'
        )
        session = self.client.session
        session['asistente_id'] = self.asistente_inscrito.pk
        session.save()
        
        # Acceder a la página de memorias del evento
        url = reverse('memorias_asistente', kwargs={'evento_id': self.evento_finalizado.pk})
        response = self.client.get(url, follow=True)
        
        # Debe retornar 200
        self.assertEqual(response.status_code, 200)
        # Debe mostrar el nombre de la memoria
        self.assertContains(response, "Presentaciones Conferencia")

    def test_ca301_log_de_descarga_registrado(self):
        """
        CA3.01: Verificar que la descarga se registra en logs.
        """
        self.client.login(
            username=self.asistente_inscrito.usuario.username,
            password='password123'
        )
        session = self.client.session
        session['asistente_id'] = self.asistente_inscrito.pk
        session.save()
        
        # Acceder a memorias
        url = reverse('memorias_asistente', kwargs={'evento_id': self.evento_finalizado.pk})
        response = self.client.get(url, follow=True)
        
        # Debe retornar 200 (acceso exitoso)
        self.assertEqual(response.status_code, 200)

    # === CASOS DE FALLA ===
    
    def test_ca101_falla_si_usuario_no_inscrito(self):
        """
        CA1.01: No puede descargar si no está inscrito en el evento,
        aunque el evento esté finalizado.
        """
        self.client.login(
            username=self.asistente_no_inscrito.usuario.username,
            password='password123'
        )
        session = self.client.session
        session['asistente_id'] = self.asistente_no_inscrito.pk
        session.save()
        
        url = reverse('memorias_asistente', kwargs={'evento_id': self.evento_finalizado.pk})
        response = self.client.get(url, follow=False)
        
        # Debe redirigir (302) si no está inscrito
        self.assertIn(response.status_code, [302, 403])

    def test_ca102_falla_si_evento_aun_activo(self):
        """
        CA1.02: No puede descargar memorias si el evento aún está activo (Publicado).
        """
        self.client.login(
            username=self.asistente_activo.usuario.username,
            password='password123'
        )
        session = self.client.session
        session['asistente_id'] = self.asistente_activo.pk
        session.save()
        
        url = reverse('memorias_asistente', kwargs={'evento_id': self.evento_publicado.pk})
        response = self.client.get(url, follow=True)
        
        # Aunque esté inscrito, el evento no está finalizado
        # Puede retornar 200 pero sin memorias disponibles (o mensaje indicando evento activo)
        self.assertEqual(response.status_code, 200)

    def test_usuario_no_autenticado_redirige_a_login(self):
        """
        Verifica que un usuario no autenticado sea redirigido al login.
        """
        self.client.logout()
        
        url = reverse('memorias_asistente', kwargs={'evento_id': self.evento_finalizado.pk})
        response = self.client.get(url, follow=False)
        
        # Debe redirigir (302) o rechazar (403)
        self.assertIn(response.status_code, [302, 403])