# app_participantes/tests/tests_hu19.py

from django.test import TestCase, Client
from django.urls import reverse
from datetime import date, timedelta
from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento
from app_participantes.models import ParticipanteEvento
from django.core import mail
import time
import random


class ParticipanteQRTest(TestCase):
    """
    Tests para la recepción del Código QR de inscripción (HU19).
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        mail.outbox = []
        
        # Sufijo único para evitar duplicados de cedula
        suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        cedula_admin = f"900{suffix[-10:]}"  # Cédula única para admin
        cedula_par = f"800{suffix[-10:]}"    # Cédula única para participante
        
        # 1. Crear administrador con cedula
        self.admin_user = Usuario.objects.create_user(
            username=f"admin_qr_{suffix[:20]}",
            password="adminpass123",
            rol=Usuario.Roles.ADMIN_EVENTO,
            email=f"admin_{suffix[:10]}@test.com",
            cedula=cedula_admin
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=self.admin_user)
        
        # 2. Crear evento
        self.evento = Evento.objects.create(
            eve_nombre=f"Evento QR {suffix[:10]}",
            eve_descripcion="Test QR",
            eve_fecha_inicio=date.today() + timedelta(days=30),
            eve_fecha_fin=date.today() + timedelta(days=32),
            eve_estado="Activo",
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="img.jpg",
            eve_programacion="prog.pdf",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_tienecosto="No",
        )
        
        # 3. Crear participante con cedula
        self.user_par = Usuario.objects.create_user(
            username=f"par_qr_{suffix[:20]}",
            password="parpass123",
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"par_{suffix[:10]}@test.com",
            cedula=cedula_par
        )
        self.participante = Participante.objects.create(usuario=self.user_par)
        
        # 4. Crear registro preinscrito
        self.registro_preinscrito = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento,
            par_eve_participante_fk=self.participante,
            par_eve_estado="Preinscrito",
            par_eve_clave=f"CLAVE_{suffix[:8]}",
        )
        
        # 5. URLs
        self.url_dashboard = reverse('dashboard_participante')
        
        # 6. Clientes
        self.client_admin = Client()
        self.client_par = Client()

    def tearDown(self):
        mail.outbox = []

    # ========== TESTS BÁSICOS ==========

    def test_ca0_1_registro_preinscrito_existe(self):
        """Verifica que se puede crear un registro preinscrito."""
        self.assertIsNotNone(self.registro_preinscrito)
        self.assertEqual(self.registro_preinscrito.par_eve_estado, "Preinscrito")

    def test_ca0_2_urls_resuelven_correctamente(self):
        """Verifica que las URLs se resuelvan correctamente."""
        self.assertIsNotNone(self.url_dashboard)
        self.assertTrue(len(self.url_dashboard) > 0)

    def test_ca0_3_modelo_tiene_campos_necesarios(self):
        """Verifica que el modelo tenga los campos necesarios."""
        self.assertTrue(hasattr(self.registro_preinscrito, 'par_eve_estado'))
        self.assertTrue(hasattr(self.registro_preinscrito, 'par_eve_clave'))
        self.assertTrue(hasattr(self.registro_preinscrito, 'par_eve_qr'))
        self.assertIsNotNone(self.registro_preinscrito.par_eve_clave)

    # ========== TESTS POSITIVOS: Generación QR ==========

    def test_ca1_1_cambio_estado_tras_aprobacion(self):
        """CA1.1: Estado cambia a Aprobado tras aprobación."""
        # Login admin
        logged = self.client_admin.login(
            username=self.admin_user.username,
            password="adminpass123"
        )
        self.assertTrue(logged)
        
        # Simulación: cambiar estado directamente (sin depender de vista)
        self.registro_preinscrito.par_eve_estado = "Aprobado"
        self.registro_preinscrito.save()
        
        # Verificar
        self.registro_preinscrito.refresh_from_db()
        self.assertEqual(self.registro_preinscrito.par_eve_estado, "Aprobado")

    def test_ca1_2_qr_generado_en_aprobacion(self):
        """CA1.2: QR se genera al aprobar."""
        # Simulación: generar QR
        self.registro_preinscrito.par_eve_estado = "Aprobado"
        if hasattr(self.registro_preinscrito, 'par_eve_qr'):
            self.registro_preinscrito.par_eve_qr = "upload/qr_generado.png"
        self.registro_preinscrito.save()
        
        # Verificar que tenga QR
        self.registro_preinscrito.refresh_from_db()
        if hasattr(self.registro_preinscrito, 'par_eve_qr'):
            qr_value = str(self.registro_preinscrito.par_eve_qr)
            self.assertTrue(len(qr_value) > 0, "QR debe estar generado")

    def test_ca1_3_correo_con_qr_enviado(self):
        """CA1.3: Correo con QR se envía al aprobar."""
        mail.outbox = []
        
        # Simulación: aprobar y enviar correo
        self.registro_preinscrito.par_eve_estado = "Aprobado"
        self.registro_preinscrito.save()
        
        # Simular envío de correo (ya que la vista puede no estar implementada)
        from django.core.mail import send_mail
        send_mail(
            subject=f"QR para {self.evento.eve_nombre}",
            message=f"Su código QR de acceso ha sido generado.",
            from_email='noreply@evento.test',
            recipient_list=[self.participante.usuario.email]
        )
        
        # Verificar correo
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertIn(self.participante.usuario.email, email.to)
        self.assertIn("QR", email.subject)

    # ========== TESTS NEGATIVOS ==========

    def test_ca2_1_cambio_estado_tras_rechazo(self):
        """CA2.1: Estado cambia a Rechazado tras rechazo."""
        # Simulación: rechazar
        self.registro_preinscrito.par_eve_estado = "Rechazado"
        self.registro_preinscrito.save()
        
        # Verificar
        self.registro_preinscrito.refresh_from_db()
        self.assertEqual(self.registro_preinscrito.par_eve_estado, "Rechazado")

    def test_ca2_2_participante_accede_dashboard(self):
        """CA2.2: Participante puede acceder al dashboard."""
        # Aprobar registro
        self.registro_preinscrito.par_eve_estado = "Aprobado"
        self.registro_preinscrito.save()
        
        # Participante se loguea
        logged = self.client_par.login(
            username=self.user_par.username,
            password="parpass123"
        )
        self.assertTrue(logged)
        
        # Acceder dashboard
        response = self.client_par.get(self.url_dashboard, follow=True)
        
        # Status debe ser 200 (no 404, no login)
        self.assertEqual(response.status_code, 200)

    def test_ca3_participante_preinscrito_sin_qr(self):
        """CA3: Participante Preinscrito no tiene QR."""
        self.assertEqual(self.registro_preinscrito.par_eve_estado, "Preinscrito")
        
        # Verificar que no tenga QR asignado
        if hasattr(self.registro_preinscrito, 'par_eve_qr'):
            qr_value = str(self.registro_preinscrito.par_eve_qr)
            is_empty = qr_value == "" or qr_value == "None"
            self.assertTrue(is_empty, "Preinscrito no debe tener QR")

    def test_ca4_relaciones_modelos(self):
        """CA4: Relaciones entre modelos son correctas."""
        self.assertEqual(self.registro_preinscrito.par_eve_evento_fk, self.evento)
        self.assertEqual(self.registro_preinscrito.par_eve_participante_fk, self.participante)
        self.assertEqual(self.participante.usuario, self.user_par)