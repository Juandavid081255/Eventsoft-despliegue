""" Como Administrador quiero Enviar notificaciones a asistentes para
Mantenerlos informados sobre los eventos en los que estén inscritos
"""

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core import mail
from django.utils import timezone
from datetime import date, timedelta
import uuid

from app_usuarios.models import Usuario, AdministradorEvento, Asistente
from app_asistentes.models import AsistenteEvento
from app_admin_eventos.models import Evento


class EnviarNotificacionAsistentesTest(TestCase):
    
    def setUp(self):
        self.client = Client()

        # === Crear usuario administrador (con cédula única) ===
        cedula_admin = f'ADM{uuid.uuid4().hex[:8].upper()}'
        self.admin_user = Usuario.objects.create_user(
            username=f'admin_{uuid.uuid4().hex[:6]}',
            password='admin123',
            email=f'admin_{uuid.uuid4().hex[:6]}@example.com',
            rol=Usuario.Roles.ADMIN_EVENTO,
            cedula=cedula_admin
        )
        self.admin_perfil, _ = AdministradorEvento.objects.get_or_create(usuario=self.admin_user)

        # === Archivos dummy ===
        self.imagen_dummy = SimpleUploadedFile("logo.png", b"image_content", content_type="image/png")
        self.programacion_dummy = SimpleUploadedFile("prog.pdf", b"program_content", content_type="application/pdf")
        
        # === Crear evento ===
        fecha_futura = date.today() + timedelta(days=30)
        self.evento = Evento.objects.create(
            eve_nombre="Evento de prueba",
            eve_descripcion="Un evento de prueba para tests",
            eve_estado="Publicado",
            eve_fecha_inicio=fecha_futura,
            eve_fecha_fin=fecha_futura + timedelta(days=2),
            eve_ciudad="Manizales",
            eve_lugar="Auditorio",
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_administrador_fk=self.admin_perfil,
            eve_programacion=self.programacion_dummy,
            eve_imagen=self.imagen_dummy
        )

        # === Crear usuarios asistentes (con cédulas únicas) ===
        cedula_aprobado = f'ASI{uuid.uuid4().hex[:8].upper()}'
        self.usuario_aprobado = Usuario.objects.create_user(
            username=f'asistente_aprobado_{uuid.uuid4().hex[:6]}',
            password='test123',
            email=f'aprobado_{uuid.uuid4().hex[:6]}@example.com',
            rol=Usuario.Roles.ASISTENTE,
            cedula=cedula_aprobado
        )
        
        cedula_pendiente = f'ASI{uuid.uuid4().hex[:8].upper()}'
        self.usuario_pendiente = Usuario.objects.create_user(
            username=f'asistente_pendiente_{uuid.uuid4().hex[:6]}',
            password='test123',
            email=f'pendiente_{uuid.uuid4().hex[:6]}@example.com',
            rol=Usuario.Roles.ASISTENTE,
            cedula=cedula_pendiente
        )

        # === Crear perfiles Asistente ===
        self.asistente_aprobado = Asistente.objects.create(usuario=self.usuario_aprobado)
        self.asistente_pendiente = Asistente.objects.create(usuario=self.usuario_pendiente)

        # === Archivos para inscripciones ===
        self.soporte_dummy = SimpleUploadedFile("soporte.pdf", b"soporte", content_type="application/pdf")
        self.qr_dummy = SimpleUploadedFile("qr.png", b"qrcontent", content_type="image/png")

        # === Crear inscripciones de asistentes ===
        self.inscripcion_aprobada = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente_aprobado,
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_estado='Aprobado',
            asi_eve_soporte=self.soporte_dummy,
            asi_eve_qr=self.qr_dummy,
            asi_eve_clave='clave123'
        )
        
        self.inscripcion_pendiente = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente_pendiente,
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_estado='Pendiente',
            asi_eve_soporte=self.soporte_dummy,
            asi_eve_qr=self.qr_dummy,
            asi_eve_clave='clave456'
        )

        # === Login del administrador ===
        self.client.login(username=self.admin_user.username, password='admin123')

        # === URL de la vista ===
        self.url = reverse('notificar_asistentes', kwargs={'evento_id': self.evento.id})
        self.url_dashboard = reverse('dashboard_asistente')

    # === CASO 1: Envío a aprobados ===
    def test_cp_as_not_001_envio_notificacion_a_aprobados(self):
        """Verifica que el administrador pueda enviar notificaciones a asistentes aprobados."""
        
        response = self.client.post(self.url, {
            'asistentes': [self.inscripcion_aprobada.id],
            'mensaje': 'Prueba de notificación para aprobados'
        }, follow=True)
        
        # Verificar redirección
        self.assertEqual(response.status_code, 200)
        
        # Verificar que se envió un email
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn(self.usuario_aprobado.email, mail.outbox[0].to)
        self.assertIn('Notificación', mail.outbox[0].subject)
        # Verificar que contiene el mensaje enviado
        self.assertIn('Prueba de notificación para aprobados', mail.outbox[0].body)

    # === CASO 2: Envío a pendientes ===
    def test_cp_as_not_002_envio_notificacion_a_pendientes(self):
        """Verifica que el administrador pueda enviar notificaciones a asistentes pendientes."""
        
        response = self.client.post(self.url, {
            'asistentes': [self.inscripcion_pendiente.id],
            'mensaje': 'Prueba de notificación para pendientes'
        }, follow=True)
        
        # Verificar redirección
        self.assertEqual(response.status_code, 200)
        
        # Verificar que se envió un email
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn(self.usuario_pendiente.email, mail.outbox[0].to)
        self.assertIn('Notificación', mail.outbox[0].subject)
        # Verificar que contiene el mensaje enviado
        self.assertIn('Prueba de notificación para pendientes', mail.outbox[0].body)

    # === CASO 3: Restricción por rol ===
    def test_cp_as_not_003_restriccion_por_rol(self):
        """Verifica que un usuario no administrador no pueda acceder a la vista."""
        
        self.client.logout()
        
        # Crear usuario asistente normal
        cedula_otro = f'ASI{uuid.uuid4().hex[:8].upper()}'
        normal_user = Usuario.objects.create_user(
            username=f'no_admin_{uuid.uuid4().hex[:6]}',
            password='test123',
            email=f'noadmin_{uuid.uuid4().hex[:6]}@example.com',
            rol=Usuario.Roles.ASISTENTE,
            cedula=cedula_otro
        )
        self.client.login(username=normal_user.username, password='test123')
        
        # Intentar acceder a la vista GET
        response = self.client.get(self.url)
        
        # Debe redirigir (302 o 403)
        self.assertIn(response.status_code, [302, 403])
        self.assertEqual(len(mail.outbox), 0)

    # === CASO 4: Mensaje vacío ===
    def test_cp_as_not_004_mensaje_vacio_falla(self):
        """Verifica que falle si el mensaje está vacío."""
        
        response = self.client.post(self.url, {
            'asistentes': [self.inscripcion_aprobada.id], 
            'mensaje': ''
        })
        
        # La vista debe rechazar y mostrar error (sin follow=True para ver el 200)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "El mensaje no puede estar vacío.")
        self.assertEqual(len(mail.outbox), 0)

    # === CASO 5: Sin asistentes seleccionados ===
    def test_cp_as_not_005_sin_asistentes_seleccionados_falla(self):
        """Verifica que falle si no se selecciona ningún asistente."""
        
        response = self.client.post(self.url, {
            'asistentes': [],
            'mensaje': 'Mensaje de prueba'
        })
        
        # La vista debe rechazar y mostrar error (sin follow=True para ver el 200)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No seleccionaste ningún asistente.")
        self.assertEqual(len(mail.outbox), 0)