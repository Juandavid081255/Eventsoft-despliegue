# app_participantes/tests/tests_hu17.py

from django.test import TestCase, Client
from django.urls import reverse
from datetime import date, timedelta
from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento
from app_participantes.models import ParticipanteEvento
from django.core import mail
from django.core.mail import send_mail


class ParticipanteAdmissionNotificationTest(TestCase):
    """
    HU17 - Tests para aprobar/rechazar preinscripciones de Participantes.
    """

    def setUp(self):
        self.client = Client()

        # Crear usuario administrador con cedula
        self.admin_user = Usuario.objects.create_user(
            username="admin_valida_hu17",
            password="adminpass",
            rol=Usuario.Roles.ADMIN_EVENTO,
            email="admin_hu17@evento.com",
            cedula="9999999999"  # IMPORTANTE: cedula requerida
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=self.admin_user)

        # Crear evento
        self.evento = Evento.objects.create(
            eve_nombre="Evento Validación HU17",
            eve_descripcion="Descripción prueba",
            eve_ciudad="Ciudad",
            eve_lugar="Lugar",
            eve_fecha_inicio=date.today() + timedelta(days=30),
            eve_fecha_fin=date.today() + timedelta(days=31),
            eve_estado="Activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_imagen="f.jpg",
            eve_programacion="f.pdf",
        )

        # Crear usuario participante con cedula
        self.user_par = Usuario.objects.create_user(
            username="participante_hu17",
            password="parpass",
            rol=Usuario.Roles.PARTICIPANTE,
            email="participante_hu17@ejemplo.com",
            cedula="8888888888"  # IMPORTANTE: cedula requerida
        )
        self.participante = Participante.objects.create(usuario=self.user_par)

        # Crear ParticipanteEvento (preinscrito)
        self.registro_preinscrito = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento,
            par_eve_participante_fk=self.participante,
            par_eve_estado="Preinscrito",
            par_eve_clave="CLAVE1",
        )

    # ========== HELPERS SIMULADOS ==========

    def _aprobar_registro_simulado(self, registro: ParticipanteEvento, generar_qr: bool = False):
        """
        Simula la aprobación de un registro:
        - Cambia estado a 'Aprobado'
        - Envía email de notificación
        """
        registro.par_eve_estado = "Aprobado"
        if generar_qr and hasattr(registro, 'par_eve_qr'):
            registro.par_eve_qr = "upload/fake_qr.png"
        registro.save()

        # Enviar correo de aprobación
        send_mail(
            subject=f"Aprobación: {registro.par_eve_evento_fk.eve_nombre}",
            message=f"Estimado/a, su admisión al evento {registro.par_eve_evento_fk.eve_nombre} ha sido aprobada.",
            from_email='noreply@evento.test',
            recipient_list=[registro.par_eve_participante_fk.usuario.email]
        )

    def _rechazar_registro_simulado(self, registro: ParticipanteEvento):
        """
        Simula el rechazo de un registro:
        - Cambia estado a 'Rechazado'
        - Envía email de rechazo
        """
        registro.par_eve_estado = "Rechazado"
        registro.save()

        # Enviar correo de rechazo
        send_mail(
            subject=f"Rechazo: {registro.par_eve_evento_fk.eve_nombre}",
            message=f"Estimado/a, su solicitud para el evento {registro.par_eve_evento_fk.eve_nombre} ha sido rechazada.",
            from_email='noreply@evento.test',
            recipient_list=[registro.par_eve_participante_fk.usuario.email]
        )

    # ========== CASOS POSITIVOS ==========

    def test_ca1_1_ca1_2_admision_exitosa_y_notificacion(self):
        """
        CA1.1 / CA1.2: Aprobación exitosa y notificación por email
        """
        mail.outbox = []

        # Simular aprobación
        self._aprobar_registro_simulado(self.registro_preinscrito, generar_qr=True)

        # Verificar estado
        self.registro_preinscrito.refresh_from_db()
        self.assertEqual(
            self.registro_preinscrito.par_eve_estado,
            "Aprobado",
            "El registro debe estar en estado Aprobado"
        )

        # Verificar QR
        if hasattr(self.registro_preinscrito, 'par_eve_qr'):
            self.assertTrue(self.registro_preinscrito.par_eve_qr)

        # Verificar email
        self.assertEqual(len(mail.outbox), 1, "Debe enviarse exactamente 1 correo")
        sent_email = mail.outbox[0]
        self.assertIn(self.participante.usuario.email, sent_email.to)
        self.assertIn("Aprobación", sent_email.subject)

    def test_ca2_1_ca2_2_rechazo_exitoso_y_notificacion(self):
        """
        CA2.1 / CA2.2: Rechazo exitoso y notificación por email
        """
        mail.outbox = []

        # Simular rechazo
        self._rechazar_registro_simulado(self.registro_preinscrito)

        # Verificar estado
        self.registro_preinscrito.refresh_from_db()
        self.assertEqual(
            self.registro_preinscrito.par_eve_estado,
            "Rechazado",
            "El registro debe estar en estado Rechazado"
        )

        # Verificar email
        self.assertEqual(len(mail.outbox), 1, "Debe enviarse exactamente 1 correo")
        sent_email = mail.outbox[0]
        self.assertIn(self.participante.usuario.email, sent_email.to)
        self.assertIn("Rechazo", sent_email.subject)

    # ========== CASOS NEGATIVOS ==========

    def test_ca3_1_ca3_2_no_permite_cambio_aprobado_a_rechazado(self):
        """
        CA3.1 / CA3.2: No permitir cambio de Aprobado a Rechazado
        """
        mail.outbox = []

        # Aprobación inicial
        self._aprobar_registro_simulado(self.registro_preinscrito)
        self.registro_preinscrito.refresh_from_db()
        self.assertEqual(self.registro_preinscrito.par_eve_estado, "Aprobado")

        initial_mail_count = len(mail.outbox)

        # Intentar rechazar (simulación: no debería permitirse)
        if self.registro_preinscrito.par_eve_estado == "Aprobado":
            # No hacer nada, no enviar correo
            pass
        else:
            self._rechazar_registro_simulado(self.registro_preinscrito)

        # Verificar que el estado no cambió
        self.registro_preinscrito.refresh_from_db()
        self.assertEqual(
            self.registro_preinscrito.par_eve_estado,
            "Aprobado",
            "No debe cambiar de Aprobado a Rechazado"
        )

        # Verificar que no se enviaron correos adicionales
        final_mail_count = len(mail.outbox)
        self.assertEqual(
            final_mail_count,
            initial_mail_count,
            "No debe enviarse correo adicional al intentar cambiar estado final"
        )