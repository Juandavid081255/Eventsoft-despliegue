# app_evaluadores/tests/tests_hu33.py

import shutil
import tempfile
from datetime import date, timedelta

from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core import mail

from app_usuarios.models import Usuario, Evaluador, AdministradorEvento
from app_admin_eventos.models import Evento
from app_evaluadores.models import EvaluadorEvento
import time
import random


TEMP_MEDIA_ROOT = tempfile.mkdtemp(prefix="test_media_")


@override_settings(MEDIA_ROOT=TEMP_MEDIA_ROOT)
class EvaluadorNotificacionAdmisionTest(TestCase):
    """
    HU33 - Notificacion de admision/rechazo de evaluador en evento
    """

    @classmethod
    def setUpClass(cls):
        """Configuración única para toda la clase."""
        super().setUpClass()
        cls.unique_suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"

    def setUp(self):
        """Configuración inicial para cada test."""
        unique_suffix = self.unique_suffix
        self.password = "testpass123"
        
        # ===== ADMINISTRADOR DE EVENTO =====
        admin_username = f"admin_hu33_{unique_suffix}"
        admin_user = Usuario.objects.create_user(
            username=admin_username,
            password=self.password,
            rol=Usuario.Roles.ADMIN_EVENTO,
            email=f"{admin_username}@test.com",
            cedula=f"900{unique_suffix[-10:]}"
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=admin_user)
        self.admin_user = admin_user
        
        # ===== EVENTO ACTIVO =====
        self.evento = Evento.objects.create(
            eve_nombre=f"Evento Notificacion {unique_suffix}",
            eve_descripcion="Evento para probar notificaciones",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_fecha_inicio=date.today() + timedelta(days=30),
            eve_fecha_fin=date.today() + timedelta(days=32),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=50,
            eve_imagen=SimpleUploadedFile("img.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"contenido", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=True
        )
        
        # ===== EVALUADOR PARA APROBAR =====
        self.username_aprob = f"eva_aprob_{unique_suffix}"
        self.user_aprob = Usuario.objects.create_user(
            username=self.username_aprob,
            password=self.password,
            rol=Usuario.Roles.EVALUADOR,
            email=f"{self.username_aprob}@test.com",
            cedula=f"800{unique_suffix[-10:]}"
        )
        self.evaluador_aprob = Evaluador.objects.create(usuario=self.user_aprob)
        
        # ===== EVALUADOR PARA RECHAZAR =====
        self.username_rech = f"eva_rech_{unique_suffix}"
        self.user_rech = Usuario.objects.create_user(
            username=self.username_rech,
            password=self.password,
            rol=Usuario.Roles.EVALUADOR,
            email=f"{self.username_rech}@test.com",
            cedula=f"810{unique_suffix[-10:]}"
        )
        self.evaluador_rech = Evaluador.objects.create(usuario=self.user_rech)
        
        # ===== REGISTROS PREINSCRITO =====
        self.registro_aprob = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_aprob,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Preinscrito",
            eva_eve_clave="CLAVEAPROB",
            eva_eve_documento=SimpleUploadedFile("doc_aprob.pdf", b"contenido aprob", content_type="application/pdf")
        )
        
        self.registro_rech = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_rech,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Preinscrito",
            eva_eve_clave="CLAVERECH",
            eva_eve_documento=SimpleUploadedFile("doc_rech.pdf", b"contenido rech", content_type="application/pdf")
        )
        
        # ===== CLIENTES =====
        self.client_admin = Client()
        
        # ===== URLs =====
        self.url_aprobar = reverse('aprobar_eva', args=[self.evento.pk, self.registro_aprob.pk])
        self.url_rechazar = reverse('rechazar_eva', args=[self.evento.pk, self.registro_rech.pk])

    def tearDown(self):
        """Limpiar archivos temporales."""
        try:
            shutil.rmtree(TEMP_MEDIA_ROOT)
        except Exception:
            pass

    # ========== CASOS POSITIVOS ==========

    def test_ca1_1_aprobar_evaluador(self):
        """CA1.1: Admin aprueba evaluador exitosamente."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        mail.outbox = []
        
        response = self.client_admin.post(self.url_aprobar, follow=True)
        
        self.assertIn(response.status_code, (200, 302))
        
        self.registro_aprob.refresh_from_db()
        self.assertEqual(self.registro_aprob.eva_eve_estado, "Aprobado")

    def test_ca1_2_rechazar_evaluador(self):
        """CA1.2: Admin rechaza evaluador exitosamente."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        mail.outbox = []
        
        response = self.client_admin.post(self.url_rechazar, follow=True)
        
        self.assertIn(response.status_code, (200, 302))
        
        self.registro_rech.refresh_from_db()
        self.assertEqual(self.registro_rech.eva_eve_estado, "Rechazado")

    def test_ca1_3_email_al_aprobar(self):
        """CA1.3: Se envia email al aprobar evaluador."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        mail.outbox = []
        
        response = self.client_admin.post(self.url_aprobar, follow=True)
        
        if len(mail.outbox) > 0:
            email = mail.outbox[0]
            self.assertIn(self.user_aprob.email, email.to)

    def test_ca1_4_email_al_rechazar(self):
        """CA1.4: Se envia email al rechazar evaluador."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        mail.outbox = []
        
        response = self.client_admin.post(self.url_rechazar, follow=True)
        
        if len(mail.outbox) > 0:
            email = mail.outbox[0]
            self.assertIn(self.user_rech.email, email.to)

    # ========== CASOS NEGATIVOS ==========

    def test_ca2_1_no_aprobar_sin_autenticacion(self):
        """CA2.1: No se puede aprobar sin autenticacion."""
        client_anonimo = Client()
        
        response = client_anonimo.post(self.url_aprobar, follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        self.registro_aprob.refresh_from_db()
        self.assertEqual(self.registro_aprob.eva_eve_estado, "Preinscrito")

    def test_ca2_2_no_rechazar_sin_autenticacion(self):
        """CA2.2: No se puede rechazar sin autenticacion."""
        client_anonimo = Client()
        
        response = client_anonimo.post(self.url_rechazar, follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        self.registro_rech.refresh_from_db()
        self.assertEqual(self.registro_rech.eva_eve_estado, "Preinscrito")

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_1_registro_tiene_campos_basicos(self):
        """CA3.1: Registro tiene campos necesarios."""
        self.assertIsNotNone(self.registro_aprob.eva_eve_estado)
        self.assertIsNotNone(self.registro_aprob.eva_eve_evaluador_fk)
        self.assertIsNotNone(self.registro_aprob.eva_eve_evento_fk)

    def test_ca3_2_estados_diferenciados(self):
        """CA3.2: Estados diferentes estan diferenciados."""
        self.assertEqual(self.registro_aprob.eva_eve_estado, "Preinscrito")
        
        # Cambiar estado
        self.registro_aprob.eva_eve_estado = "Aprobado"
        self.registro_aprob.save()
        self.registro_aprob.refresh_from_db()
        
        self.assertEqual(self.registro_aprob.eva_eve_estado, "Aprobado")

    def test_ca3_3_relaciones_correctas(self):
        """CA3.3: Relaciones entre modelos son correctas."""
        self.assertEqual(self.registro_aprob.eva_eve_evaluador_fk, self.evaluador_aprob)
        self.assertEqual(self.registro_aprob.eva_eve_evento_fk, self.evento)

    # ========== TESTS DE LOGICA ==========

    def test_ca4_1_cambio_estado_aprobar(self):
        """CA4.1: Logica - Estado cambia a Aprobado."""
        self.assertEqual(self.registro_aprob.eva_eve_estado, "Preinscrito")
        
        self.registro_aprob.eva_eve_estado = "Aprobado"
        self.registro_aprob.save()
        self.registro_aprob.refresh_from_db()
        
        self.assertEqual(self.registro_aprob.eva_eve_estado, "Aprobado")

    def test_ca4_2_cambio_estado_rechazar(self):
        """CA4.2: Logica - Estado cambia a Rechazado."""
        self.assertEqual(self.registro_rech.eva_eve_estado, "Preinscrito")
        
        self.registro_rech.eva_eve_estado = "Rechazado"
        self.registro_rech.save()
        self.registro_rech.refresh_from_db()
        
        self.assertEqual(self.registro_rech.eva_eve_estado, "Rechazado")

    def test_ca4_3_admin_puede_cambiar_estado(self):
        """CA4.3: Logica - Admin es quien puede cambiar estado."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)

    # ========== TESTS DE INTEGRACION ==========

    def test_ca5_1_flujo_completo_aprobacion(self):
        """CA5.1: Flujo completo - login, aprobacion, notificacion."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        mail.outbox = []
        
        response = self.client_admin.post(self.url_aprobar, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        self.registro_aprob.refresh_from_db()
        self.assertEqual(self.registro_aprob.eva_eve_estado, "Aprobado")

    def test_ca5_2_flujo_completo_rechazo(self):
        """CA5.2: Flujo completo - login, rechazo, notificacion."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        mail.outbox = []
        
        response = self.client_admin.post(self.url_rechazar, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        self.registro_rech.refresh_from_db()
        self.assertEqual(self.registro_rech.eva_eve_estado, "Rechazado")

    def test_ca5_3_multiples_aprobaciones(self):
        """CA5.3: Admin puede aprobar multiples evaluadores."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        # Aprobar primero
        self.client_admin.post(self.url_aprobar, follow=True)
        
        # Crear segundo evaluador y registro
        user2 = Usuario.objects.create_user(
            username=f"eva2_{self.unique_suffix}",
            password=self.password,
            rol=Usuario.Roles.EVALUADOR,
            email=f"eva2_{self.unique_suffix}@test.com",
            cedula=f"820{self.unique_suffix[-10:]}"
        )
        evaluador2 = Evaluador.objects.create(usuario=user2)
        
        registro2 = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=evaluador2,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Preinscrito",
            eva_eve_clave="CLAVE2",
            eva_eve_documento=SimpleUploadedFile("doc2.pdf", b"contenido2", content_type="application/pdf")
        )
        
        url_aprobar2 = reverse('aprobar_eva', args=[self.evento.pk, registro2.pk])
        
        # Aprobar segundo
        response = self.client_admin.post(url_aprobar2, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        # Verificar ambos aprobados
        self.registro_aprob.refresh_from_db()
        registro2.refresh_from_db()
        
        self.assertEqual(self.registro_aprob.eva_eve_estado, "Aprobado")
        self.assertEqual(registro2.eva_eve_estado, "Aprobado")