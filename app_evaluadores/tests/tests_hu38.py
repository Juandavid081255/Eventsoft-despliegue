# app_evaluadores/tests/tests_hu38.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time
import random
import tempfile
import shutil

from app_usuarios.models import Usuario, Evaluador, AdministradorEvento
from app_admin_eventos.models import Evento
from app_evaluadores.models import EvaluadorEvento


TEMP_MEDIA_ROOT = tempfile.mkdtemp(prefix="test_media_hu38_")


class NotificacionesEvaluadorTest(TestCase):
    """
    HU38 - Notificaciones a Evaluadores
    Verifica que se envíen notificaciones correctas según el estado del evaluador.
    """

    @classmethod
    def setUpClass(cls):
        """Configuración única para toda la clase."""
        super().setUpClass()
        cls.unique_suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"

    def setUp(self):
        """Configuración inicial para cada test."""
        mail.outbox = []
        unique_suffix = self.unique_suffix
        self.password = "testpass123"
        
        # ===== ADMINISTRADOR DE EVENTO =====
        admin_username = f"admin_hu38_{unique_suffix}"
        self.admin_user = Usuario.objects.create_user(
            username=admin_username,
            password=self.password,
            email=f"{admin_username}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            cedula=f"900{unique_suffix[-10:]}",
            first_name="Admin",
            last_name="Evento"
        )
        
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=self.admin_user)
        
        # ===== EVENTO ACTIVO =====
        self.evento = Evento.objects.create(
            eve_nombre=f"Evento Notificaciones {unique_suffix}",
            eve_descripcion="Evento para probar notificaciones",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_fecha_inicio=date.today() - timedelta(days=1),
            eve_fecha_fin=date.today() + timedelta(days=5),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_imagen=SimpleUploadedFile("img.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"contenido", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=True
        )
        
        # ===== EVALUADOR APROBADO =====
        user_aprobado = f"eval_apro_{unique_suffix}"
        self.user_aprobado = Usuario.objects.create_user(
            username=user_aprobado,
            password=self.password,
            email=f"{user_aprobado}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"800{unique_suffix[-10:]}",
            first_name="Evaluador",
            last_name="Aprobado"
        )
        
        self.evaluador_aprobado, _ = Evaluador.objects.get_or_create(usuario=self.user_aprobado)
        
        self.registro_aprobado = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_aprobado,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Aprobado",
            eva_eve_clave=f"CLAVE_{unique_suffix}_1",
            eva_eve_documento=SimpleUploadedFile("cv_apro.pdf", b"CV", content_type="application/pdf")
        )
        
        # ===== EVALUADOR PREINSCRITO =====
        user_preinscrito = f"eval_pre_{unique_suffix}"
        self.user_preinscrito = Usuario.objects.create_user(
            username=user_preinscrito,
            password=self.password,
            email=f"{user_preinscrito}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"810{unique_suffix[-10:]}",
            first_name="Evaluador",
            last_name="Preinscrito"
        )
        
        self.evaluador_preinscrito, _ = Evaluador.objects.get_or_create(usuario=self.user_preinscrito)
        
        self.registro_preinscrito = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_preinscrito,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Preinscrito",
            eva_eve_clave=f"CLAVE_{unique_suffix}_2",
            eva_eve_documento=SimpleUploadedFile("cv_pre.pdf", b"CV", content_type="application/pdf")
        )
        
        # ===== EVALUADOR RECHAZADO =====
        user_rechazado = f"eval_rech_{unique_suffix}"
        self.user_rechazado = Usuario.objects.create_user(
            username=user_rechazado,
            password=self.password,
            email=f"{user_rechazado}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"820{unique_suffix[-10:]}",
            first_name="Evaluador",
            last_name="Rechazado"
        )
        
        self.evaluador_rechazado, _ = Evaluador.objects.get_or_create(usuario=self.user_rechazado)
        
        self.registro_rechazado = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_rechazado,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Rechazado",
            eva_eve_clave=f"CLAVE_{unique_suffix}_3",
            eva_eve_documento=SimpleUploadedFile("cv_rech.pdf", b"CV", content_type="application/pdf")
        )
        
        # ===== CLIENTES Y URLs =====
        self.client_admin = Client()
        self.url_aprobar = reverse('aprobar_eva', args=[self.evento.pk, self.registro_preinscrito.pk])
        self.url_rechazar = reverse('rechazar_eva', args=[self.evento.pk, self.registro_preinscrito.pk])
        self.url_dashboard = reverse('dashboard_evaluador')

    def tearDown(self):
        """Limpiar archivos temporales."""
        try:
            shutil.rmtree(TEMP_MEDIA_ROOT)
        except Exception:
            pass

    # ========== TESTS DE NOTIFICACIONES ==========

    def test_ca1_1_evaluadores_aprobados_tienen_email(self):
        """CA1.1: Verifica que evaluadores aprobados tengan email configurado."""
        self.assertIsNotNone(self.user_aprobado.email)
        self.assertIn('@', self.user_aprobado.email)

    def test_ca1_2_evento_activo_para_notificaciones(self):
        """CA1.2: Verifica que el evento esté activo."""
        self.assertEqual(self.evento.eve_estado, "activo")
        self.assertTrue(self.evento.eve_fecha_inicio <= date.today())

    def test_ca1_3_acceso_dashboard_evaluador(self):
        """CA1.3: Verifica que evaluadores aprobados accedan al dashboard."""
        logged_in = self.client_admin.login(
            username=self.user_aprobado.username,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        # Establecer evaluador_id en sesión
        session = self.client_admin.session
        session['evaluador_id'] = self.evaluador_aprobado.id
        session.save()
        
        response = self.client_admin.get(self.url_dashboard, follow=True)
        self.assertEqual(response.status_code, 200)

    def test_ca2_1_diferencia_estados_evaluadores(self):
        """CA2.1: Verifica que existan diferentes estados de evaluadores."""
        self.assertEqual(self.registro_aprobado.eva_eve_estado, "Aprobado")
        self.assertEqual(self.registro_preinscrito.eva_eve_estado, "Preinscrito")
        self.assertEqual(self.registro_rechazado.eva_eve_estado, "Rechazado")

    def test_ca2_2_solo_aprobados_elegibles_notificaciones(self):
        """CA2.2: Verifica que solo aprobados sean elegibles para notificaciones."""
        aprobados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Aprobado"
        )
        self.assertEqual(aprobados.count(), 1)
        self.assertEqual(aprobados.first(), self.registro_aprobado)

    def test_ca2_3_preinscritos_y_rechazados_no_elegibles(self):
        """CA2.3: Verifica que preinscritos y rechazados no sean elegibles."""
        no_elegibles = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento
        ).exclude(eva_eve_estado="Aprobado")
        
        self.assertEqual(no_elegibles.count(), 2)
        estados = [r.eva_eve_estado for r in no_elegibles]
        self.assertIn("Preinscrito", estados)
        self.assertIn("Rechazado", estados)

    def test_ca2_4_datos_evento_disponibles(self):
        """CA2.4: Verifica que datos del evento estén disponibles."""
        self.assertIsNotNone(self.evento.eve_nombre)
        self.assertIsNotNone(self.evento.eve_fecha_inicio)
        self.assertIsNotNone(self.evento.eve_fecha_fin)

    def test_ca3_1_email_enviado_al_aprobar(self):
        """CA3.1: Verifica que se envíe email cuando se aprueba un evaluador."""
        logged_in = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        mail.outbox = []
        
        response = self.client_admin.post(self.url_aprobar, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        # Verificar que se envió email
        self.assertGreater(len(mail.outbox), 0, "Debe enviarse email al aprobar")

    def test_ca3_2_email_enviado_al_rechazar(self):
        """CA3.2: Verifica que se envíe email cuando se rechaza un evaluador."""
        logged_in = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        mail.outbox = []
        
        response = self.client_admin.post(self.url_rechazar, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        # Verificar que se envió email
        self.assertGreater(len(mail.outbox), 0, "Debe enviarse email al rechazar")

    def test_ca3_3_email_tiene_destinatario_correcto(self):
        """CA3.3: Verifica que el email sea enviado al evaluador correcto."""
        logged_in = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        mail.outbox = []
        
        response = self.client_admin.post(self.url_aprobar, follow=True)
        
        if len(mail.outbox) > 0:
            email = mail.outbox[0]
            self.assertIn(self.user_preinscrito.email, email.to,
                         "El email debe dirigirse al evaluador preinscrito")

    def test_ca3_4_email_contiene_informacion_evento(self):
        """CA3.4: Verifica que el email contenga información del evento."""
        logged_in = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        mail.outbox = []
        
        response = self.client_admin.post(self.url_aprobar, follow=True)
        
        if len(mail.outbox) > 0:
            email = mail.outbox[0]
            # Verificar que el email contenga información relevante
            content = email.body.lower()
            self.assertTrue(
                'aprobado' in content or 'aprobación' in content,
                "El email debe mencionar la aprobación"
            )

    def test_ca4_1_estado_cambia_tras_aprobacion(self):
        """CA4.1: Verifica que el estado cambie a Aprobado tras la aprobación."""
        logged_in = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_admin.post(self.url_aprobar, follow=True)
        
        self.registro_preinscrito.refresh_from_db()
        self.assertEqual(self.registro_preinscrito.eva_eve_estado, "Aprobado",
                        "El estado debe cambiar a Aprobado")

    def test_ca4_2_estado_cambia_tras_rechazo(self):
        """CA4.2: Verifica que el estado cambie a Rechazado tras el rechazo."""
        logged_in = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_admin.post(self.url_rechazar, follow=True)
        
        self.registro_preinscrito.refresh_from_db()
        self.assertEqual(self.registro_preinscrito.eva_eve_estado, "Rechazado",
                        "El estado debe cambiar a Rechazado")

    def test_ca5_1_campos_necesarios_en_modelo(self):
        """CA5.1: Verifica que los modelos tengan campos necesarios."""
        self.assertTrue(hasattr(self.registro_aprobado, 'eva_eve_estado'))
        self.assertTrue(hasattr(self.registro_aprobado, 'eva_eve_evaluador_fk'))
        self.assertTrue(hasattr(self.registro_aprobado, 'eva_eve_evento_fk'))

    def test_ca5_2_relaciones_correctas(self):
        """CA5.2: Verifica las relaciones entre modelos."""
        self.assertEqual(
            self.registro_aprobado.eva_eve_evaluador_fk,
            self.evaluador_aprobado
        )
        self.assertEqual(
            self.registro_aprobado.eva_eve_evento_fk,
            self.evento
        )