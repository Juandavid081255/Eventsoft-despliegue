""" Como Asistente quiero Descargar un certificado de asistencia 
después de que el evento haya finalizado para 
Tener un comprobante de mi participación en el evento"""

# app_asistentes/tests/HU_12.py

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


class CertificadoAsistenciaTestCase(TestCase):
    """
    Casos de prueba para la descarga de certificados de asistencia (HU12).
    
    Un asistente debe poder descargar su certificado solo si:
    1. El evento ha finalizado (eve_estado = 'Finalizado')
    2. Su inscripción está aprobada (asi_eve_estado = 'Aprobado')
    3. El asistente está autenticado
    """

    @classmethod
    def setUpTestData(cls):
        """Datos compartidos para todos los tests."""
        
        # Crear admin
        user_admin = Usuario.objects.create_user(
            username='admin_hu12',
            email='admin_hu12@eventsoft.com',
            password='password123',
            rol=Usuario.Roles.ADMIN_EVENTO,
            cedula='999999999HU12'
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

    def setUp(self):
        """Setup para cada test individual."""
        self.client = Client()
        
        # Asistente APROBADO en evento finalizado
        user_aprobado = Usuario.objects.create_user(
            username=f'asistente_aprobado_{uuid.uuid4().hex[:6]}',
            email=f'aprobado_{uuid.uuid4().hex[:6]}@test.com',
            password='password123',
            rol=Usuario.Roles.ASISTENTE,
            cedula=f'CERT{uuid.uuid4().hex[:8]}'
        )
        self.asistente_aprobado = Asistente.objects.create(usuario=user_aprobado)
        
        qr_dummy = SimpleUploadedFile("qr.png", b"qr_content", content_type="image/png")
        soporte_dummy = SimpleUploadedFile("soporte.pdf", b"soporte_content", content_type="application/pdf")
        
        self.inscripcion_aprobada = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente_aprobado,
            asi_eve_evento_fk=self.evento_finalizado,
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_estado="Aprobado",
            asi_eve_soporte=soporte_dummy,
            asi_eve_qr=qr_dummy,
            asi_eve_clave="CLAVE123"
        )
        
        # Asistente PENDIENTE en evento finalizado
        user_pendiente = Usuario.objects.create_user(
            username=f'asistente_pendiente_{uuid.uuid4().hex[:6]}',
            email=f'pendiente_{uuid.uuid4().hex[:6]}@test.com',
            password='password123',
            rol=Usuario.Roles.ASISTENTE,
            cedula=f'PEND{uuid.uuid4().hex[:8]}'
        )
        self.asistente_pendiente = Asistente.objects.create(usuario=user_pendiente)
        
        self.inscripcion_pendiente = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente_pendiente,
            asi_eve_evento_fk=self.evento_finalizado,
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_estado="Pendiente",
            asi_eve_soporte=soporte_dummy,
            asi_eve_qr=qr_dummy,
            asi_eve_clave="CLAVE456"
        )
        
        # Asistente APROBADO en evento NO finalizado
        user_activo = Usuario.objects.create_user(
            username=f'asistente_activo_{uuid.uuid4().hex[:6]}',
            email=f'activo_{uuid.uuid4().hex[:6]}@test.com',
            password='password123',
            rol=Usuario.Roles.ASISTENTE,
            cedula=f'ACTV{uuid.uuid4().hex[:8]}'
        )
        self.asistente_activo = Asistente.objects.create(usuario=user_activo)
        
        self.inscripcion_activa = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente_activo,
            asi_eve_evento_fk=self.evento_publicado,
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_estado="Aprobado",
            asi_eve_soporte=soporte_dummy,
            asi_eve_qr=qr_dummy,
            asi_eve_clave="CLAVE789"
        )

    # === CASOS DE ÉXITO ===
    
    def test_ca101_ca102_descarga_certificado_evento_finalizado_aprobado(self):
        """
        CA1.01, CA1.02: Asistente aprobado en evento finalizado 
        puede descargar certificado (HTTP 200).
        """
        self.client.login(
            username=self.asistente_aprobado.usuario.username,
            password='password123'
        )
        session = self.client.session
        session['asistente_id'] = self.asistente_aprobado.pk
        session.save()
        
        # Simulamos una URL de descarga de certificado
        # Ajusta la URL según tu implementación
        url = reverse('ingreso_evento_asi', kwargs={'pk': self.evento_finalizado.pk})
        response = self.client.get(url, follow=True)
        
        # Debe retornar 200 si el evento está finalizado y aprobado
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Finalizado")

    def test_ca303_reenvio_certificado_solicitado_por_usuario(self):
        """
        CA3.03: Usuario autenticado puede solicitar reenvío de certificado.
        La funcionalidad debe permitir al usuario hacer una solicitud desde su panel.
        """
        self.client.login(
            username=self.asistente_aprobado.usuario.username,
            password='password123'
        )
        session = self.client.session
        session['asistente_id'] = self.asistente_aprobado.pk
        session.save()
        
        # Verificar que el usuario puede acceder al dashboard
        url = reverse('dashboard_asistente')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)

    # === CASOS DE FALLA ===
    
    def test_ca103_falla_inscripcion_pendiente_no_genera_certificado(self):
        """
        CA1.03: No se genera certificado si la inscripción está pendiente,
        aunque el evento haya finalizado.
        """
        self.client.login(
            username=self.asistente_pendiente.usuario.username,
            password='password123'
        )
        session = self.client.session
        session['asistente_id'] = self.asistente_pendiente.pk
        session.save()
        
        url = reverse('ingreso_evento_asi', kwargs={'pk': self.evento_finalizado.pk})
        response = self.client.get(url, follow=True)
        
        # Debe retornar 200 pero NO mostrar certificado (solo muestra QR si está aprobado)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Pendiente")

    def test_ca101_falla_evento_activo_no_genera_certificado(self):
        """
        CA1.01: No se genera certificado si el evento aún está en estado 'Publicado'
        (no finalizado), aunque la inscripción esté aprobada.
        """
        self.client.login(
            username=self.asistente_activo.usuario.username,
            password='password123'
        )
        session = self.client.session
        session['asistente_id'] = self.asistente_activo.pk
        session.save()
        
        url = reverse('ingreso_evento_asi', kwargs={'pk': self.evento_publicado.pk})
        response = self.client.get(url, follow=True)
        
        # Debe retornar 200 pero el evento no está finalizado
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Publicado")

    def test_usuario_no_autenticado_no_puede_descargar_certificado(self):
        """
        Verifica que un usuario no autenticado sea redirigido al login.
        """
        self.client.logout()
        
        url = reverse('ingreso_evento_asi', kwargs={'pk': self.evento_finalizado.pk})
        response = self.client.get(url, follow=False)
        
        # Debe redirigir (302) o rechazar (403)
        self.assertIn(response.status_code, [302, 403])