# app_participantes/tests/tests_hu18.py

from django.test import TestCase
from datetime import date, timedelta
from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento
from app_participantes.models import ParticipanteEvento
from django.core import mail
from django.core.mail import send_mail


class ParticipanteAccessKeyTest(TestCase):
    """
    HU18 - Tests para la clave de acceso del Participante.
    Verifica que la clave se incluya en correos de aprobación,
    se excluya de correos de rechazo, y que se valide correctamente.
    """

    def setUp(self):
        # Administrador con cedula
        self.admin_user = Usuario.objects.create_user(
            username="admin_clave_hu18",
            password="adminpass",
            rol=Usuario.Roles.ADMIN_EVENTO,
            email="admin_hu18@evento.com",
            cedula="9999999999"  # IMPORTANTE: cedula requerida
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=self.admin_user)

        # Evento
        self.evento = Evento.objects.create(
            eve_nombre="Evento Acceso Clave HU18",
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

        # Participante con cedula
        self.USER_CLAVE = "ACCESO456"
        self.user_par = Usuario.objects.create_user(
            username="par_clave_hu18",
            password="parpass",
            rol=Usuario.Roles.PARTICIPANTE,
            email="par.clave@ejemplo.com",
            cedula="8888888888"  # IMPORTANTE: cedula requerida
        )
        self.participante = Participante.objects.create(usuario=self.user_par)

        # ParticipanteEvento con clave
        self.registro_preinscrito = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento,
            par_eve_participante_fk=self.participante,
            par_eve_estado="Preinscrito",
            par_eve_clave=self.USER_CLAVE,
        )

    # ========== HELPERS ==========

    def _aprobar_simulado(self, registro: ParticipanteEvento):
        """Simula aprobación: cambia estado y envía email con clave"""
        registro.par_eve_estado = "Aprobado"
        registro.save()

        send_mail(
            subject=f"Aprobación: {registro.par_eve_evento_fk.eve_nombre}",
            message=(
                f"Estimado/a,\n\n"
                f"Su admisión al evento {registro.par_eve_evento_fk.eve_nombre} ha sido aprobada.\n"
                f"Clave de acceso: {registro.par_eve_clave}\n\n"
                "Presente esta clave al ingreso."
            ),
            from_email='noreply@evento.test',
            recipient_list=[registro.par_eve_participante_fk.usuario.email]
        )

    def _rechazar_simulado(self, registro: ParticipanteEvento):
        """Simula rechazo: cambia estado y envía email SIN clave"""
        registro.par_eve_estado = "Rechazado"
        registro.save()

        send_mail(
            subject=f"Rechazo: {registro.par_eve_evento_fk.eve_nombre}",
            message=(
                f"Estimado/a,\n\n"
                f"Lamentamos informarle que su solicitud para el evento "
                f"{registro.par_eve_evento_fk.eve_nombre} ha sido rechazada.\n"
            ),
            from_email='noreply@evento.test',
            recipient_list=[registro.par_eve_participante_fk.usuario.email]
        )

    def _validar_clave_local(self, registro: ParticipanteEvento, clave: str) -> bool:
        """Valida clave: True si está Aprobado y clave coincide"""
        registro.refresh_from_db()
        return registro.par_eve_estado == "Aprobado" and registro.par_eve_clave == clave

    # ========== TESTS ==========

    def test_ca1_2_clave_incluida_en_notificacion_aprobacion(self):
        """CA1.2: Clave debe incluirse en correo de aprobación"""
        mail.outbox = []

        self._aprobar_simulado(self.registro_preinscrito)

        self.assertEqual(len(mail.outbox), 1, "Debe enviarse 1 correo de aprobación")
        email = mail.outbox[0]

        # Verificar clave en correo
        self.assertIn(self.USER_CLAVE, email.body)
        self.assertIn("clave de acceso", email.body.lower())
        self.assertIn(self.evento.eve_nombre, email.body)

    def test_ca2_1_clave_no_incluida_en_notificacion_rechazo(self):
        """CA2.1: Clave NO debe incluirse en correo de rechazo"""
        mail.outbox = []

        self._rechazar_simulado(self.registro_preinscrito)

        self.assertEqual(len(mail.outbox), 1, "Debe enviarse 1 correo de rechazo")
        email = mail.outbox[0]

        # Verificar que clave NO está en correo
        self.assertNotIn(self.USER_CLAVE, email.body)
        self.assertIn("rechaz", email.subject.lower())

    def test_ca2_2_participante_accede_con_clave_correcta(self):
        """CA2.2: Participante puede acceder con clave correcta"""
        # Aprobar registro
        self.registro_preinscrito.par_eve_estado = "Aprobado"
        self.registro_preinscrito.save()

        # Acceso con clave correcta
        acceso_ok = self._validar_clave_local(self.registro_preinscrito, self.USER_CLAVE)
        self.assertTrue(acceso_ok, "Debe permitir acceso con clave correcta")

        # Acceso con clave incorrecta
        acceso_fallido = self._validar_clave_local(self.registro_preinscrito, "CLAVE_FALSA")
        self.assertFalse(acceso_fallido, "No debe permitir acceso con clave incorrecta")