""" Como Asistente quiero Cancelar mi inscripción a un evento para 
Liberar mi cupo y que pueda ser utilizado por otra persona
"""

from datetime import date, timedelta
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.files.uploadedfile import SimpleUploadedFile
import uuid

# Importaciones del proyecto
from app_asistentes.models import AsistenteEvento
from app_usuarios.models import Asistente, AdministradorEvento 
from app_admin_eventos.models import Evento 


class CancelacionEventoAsistenteTests(TestCase):
    
    def setUp(self):
        Usuario = get_user_model()
        
        # 1. Configuración de Usuario Asistente (con cédula única)
        cedula_asistente = f'ASI{uuid.uuid4().hex[:8].upper()}'
        self.user_asistente = Usuario.objects.create_user(
            username=f'testasi_{uuid.uuid4().hex[:6]}',
            email=f'asi_{uuid.uuid4().hex[:6]}@test.com',
            password='password123',
            cedula=cedula_asistente,
            rol=Usuario.Roles.ASISTENTE
        )
        self.asistente = Asistente.objects.create(usuario=self.user_asistente)
        
        # 2. Configuración de Usuario Administrador (con cédula única)
        cedula_admin = f'ADM{uuid.uuid4().hex[:8].upper()}'
        self.user_admin = Usuario.objects.create_user(
            username=f'testadmin_{uuid.uuid4().hex[:6]}',
            email=f'admin_{uuid.uuid4().hex[:6]}@test.com',
            password='password_admin123',
            cedula=cedula_admin,
            rol=Usuario.Roles.ADMIN_EVENTO
        )
        self.administrador, _ = AdministradorEvento.objects.get_or_create(usuario=self.user_admin)

        # Archivos dummy para eventos
        imagen_dummy = SimpleUploadedFile("logo.png", b"file_content", content_type="image/png")
        programacion_dummy = SimpleUploadedFile("prog.pdf", b"program", content_type="application/pdf")

        # 3. Evento Activo (Futuro)
        self.evento_activo = Evento.objects.create(
            eve_nombre="Conferencia Futura",
            eve_descripcion="Evento futuro para test",
            eve_ciudad="Manizales",
            eve_lugar="Auditorio",
            eve_fecha_inicio=date.today() + timedelta(days=5),
            eve_fecha_fin=date.today() + timedelta(days=10),
            eve_estado="Publicado",
            eve_tienecosto='No',
            eve_capacidad=100,
            eve_administrador_fk=self.administrador,
            eve_imagen=imagen_dummy,
            eve_programacion=programacion_dummy
        )

        # 4. Evento Finalizado (Pasado)
        self.evento_finalizado = Evento.objects.create(
            eve_nombre="Evento Pasado",
            eve_descripcion="Evento que ya finalizó",
            eve_ciudad="Manizales",
            eve_lugar="Teatro",
            eve_fecha_inicio=date.today() - timedelta(days=10),
            eve_fecha_fin=date.today() - timedelta(days=5),
            eve_estado="Finalizado",
            eve_tienecosto='No',
            eve_capacidad=50,
            eve_administrador_fk=self.administrador,
            eve_imagen=imagen_dummy,
            eve_programacion=programacion_dummy
        )

        # 5. Inscripción APROBADA al evento activo
        qr_dummy = SimpleUploadedFile("qr.png", b"qr_content", content_type="image/png")
        soporte_dummy = SimpleUploadedFile("soporte.pdf", b"soporte", content_type="application/pdf")
        
        self.inscripcion_activa = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente,
            asi_eve_evento_fk=self.evento_activo,
            asi_eve_estado='Aprobado',
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_qr=qr_dummy,
            asi_eve_soporte=soporte_dummy,
            asi_eve_clave="CLAVE123"
        )
        
        # 6. URLs
        self.url_cancelar_activo = reverse('cancelar_inscripcion_asistente', 
                                          kwargs={'evento_id': self.evento_activo.pk})
        self.url_cancelar_finalizado = reverse('cancelar_inscripcion_asistente', 
                                               kwargs={'evento_id': self.evento_finalizado.pk})
        self.url_dashboard = reverse('dashboard_asistente')

    # === CASOS DE PRUEBA ===

    def test_cshr_002_prohibir_cancelacion_evento_finalizado(self):
        """CP-SHR-002: Verifica que no se puede cancelar un evento que ya finalizó (CA-10.1)."""
        
        # Crear una inscripción aprobada para el evento pasado
        qr_dummy = SimpleUploadedFile("qr.png", b"qr_content", content_type="image/png")
        soporte_dummy = SimpleUploadedFile("soporte.pdf", b"soporte", content_type="application/pdf")
        
        inscripcion_finalizada = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente,
            asi_eve_evento_fk=self.evento_finalizado,
            asi_eve_estado='Aprobado',
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_qr=qr_dummy,
            asi_eve_soporte=soporte_dummy,
            asi_eve_clave="CLAVE456"
        )
        
        # Login del usuario
        self.client.force_login(self.user_asistente)
        session = self.client.session
        session['asistente_id'] = self.asistente.id
        session.save()

        # Intentar cancelar el evento finalizado
        response = self.client.post(self.url_cancelar_finalizado, follow=True)
        
        # Verificaciones
        self.assertRedirects(response, self.url_dashboard)
        self.assertContains(response, "No puedes cancelar una inscripción a un evento que ya finalizó.", 
                            status_code=200)

        # Verificar que el estado sigue siendo 'Aprobado'
        inscripcion_finalizada.refresh_from_db()
        self.assertEqual(inscripcion_finalizada.asi_eve_estado, 'Aprobado')

    def test_cshr_003_no_inscripcion_activa(self):
        """CP-SHR-003: Verifica que si no hay inscripción activa, muestra error (CA-10.5)."""
        
        # Eliminar la inscripción activa para este evento
        self.inscripcion_activa.delete()
        
        # Login del usuario
        self.client.force_login(self.user_asistente)
        session = self.client.session
        session['asistente_id'] = self.asistente.id
        session.save()
        
        # Intentar cancelar sin tener inscripción activa
        response = self.client.post(self.url_cancelar_activo, follow=True)
        
        # Verificaciones
        self.assertRedirects(response, self.url_dashboard)
        self.assertContains(response, "No tienes una inscripción activa para este evento.", 
                            status_code=200)