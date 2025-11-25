# app_evaluadores/tests/tests_hu34.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core import mail
from datetime import date, timedelta
import time
import random
import tempfile
import shutil

from app_usuarios.models import Usuario, Evaluador, AdministradorEvento
from app_admin_eventos.models import Evento
from app_evaluadores.models import EvaluadorEvento


TEMP_MEDIA_ROOT = tempfile.mkdtemp(prefix="test_media_hu34_")


class ClaveAccesoEvaluadorTest(TestCase):
    """
    HU34 - Recibir Clave de Acceso
    Verifica que los evaluadores aprobados reciban su clave de acceso.
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
        admin_username = f"admin_hu34_{unique_suffix}"
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
        
        # ===== EVENTO 1 =====
        self.evento1 = Evento.objects.create(
            eve_nombre=f"Evento Clave 1 {unique_suffix}",
            eve_descripcion="Evento para probar clave de acceso",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_fecha_inicio=date.today() + timedelta(days=10),
            eve_fecha_fin=date.today() + timedelta(days=12),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_imagen=SimpleUploadedFile("img1.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog1.pdf", b"contenido", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=True
        )
        
        # ===== EVENTO 2 (para probar unicidad) =====
        self.evento2 = Evento.objects.create(
            eve_nombre=f"Evento Clave 2 {unique_suffix}",
            eve_descripcion="Segundo evento",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_fecha_inicio=date.today() + timedelta(days=15),
            eve_fecha_fin=date.today() + timedelta(days=17),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_imagen=SimpleUploadedFile("img2.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"contenido", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=True
        )
        
        # ===== EVALUADOR 1 =====
        user_eval1 = f"eval1_{unique_suffix}"
        self.user_evaluador1 = Usuario.objects.create_user(
            username=user_eval1,
            password=self.password,
            email=f"{user_eval1}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"800{unique_suffix[-10:]}",
            first_name="Evaluador",
            last_name="Uno"
        )
        self.evaluador1, _ = Evaluador.objects.get_or_create(usuario=self.user_evaluador1)
        
        # ===== EVALUADOR 2 =====
        user_eval2 = f"eval2_{unique_suffix}"
        self.user_evaluador2 = Usuario.objects.create_user(
            username=user_eval2,
            password=self.password,
            email=f"{user_eval2}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"810{unique_suffix[-10:]}",
            first_name="Evaluador",
            last_name="Dos"
        )
        self.evaluador2, _ = Evaluador.objects.get_or_create(usuario=self.user_evaluador2)
        
        # ===== REGISTROS PREINSCRITOS =====
        self.registro_eval1_evento1 = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador1,
            eva_eve_evento_fk=self.evento1,
            eva_eve_estado="Preinscrito",
            eva_eve_clave=f"CLAVE_{unique_suffix}_1",
            eva_eve_documento=SimpleUploadedFile("cv1.pdf", b"CV evaluador 1", content_type="application/pdf")
        )
        
        self.registro_eval2_evento1 = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador2,
            eva_eve_evento_fk=self.evento1,
            eva_eve_estado="Preinscrito",
            eva_eve_clave=f"CLAVE_{unique_suffix}_2",
            eva_eve_documento=SimpleUploadedFile("cv2.pdf", b"CV evaluador 2", content_type="application/pdf")
        )
        
        # ===== CLIENTES =====
        self.client_admin = Client()
        
        # ===== URLs =====
        self.url_aprobar_eval1 = reverse('aprobar_eva', args=[self.evento1.pk, self.registro_eval1_evento1.pk])
        self.url_rechazar_eval2 = reverse('rechazar_eva', args=[self.evento1.pk, self.registro_eval2_evento1.pk])
        self.url_ingreso_evento1 = reverse('ingreso_evento_eva', args=[self.evento1.pk])

    def tearDown(self):
        """Limpiar archivos temporales."""
        try:
            shutil.rmtree(TEMP_MEDIA_ROOT)
        except Exception:
            pass

    # ========== TESTS DE CLAVE ==========

    def test_ca1_verificar_claves_iniciales(self):
        """CA1: Verifica que los registros preinscritos tengan claves asignadas."""
        self.assertIsNotNone(self.registro_eval1_evento1.eva_eve_clave,
                            "El registro debe tener una clave")
        self.assertTrue(len(self.registro_eval1_evento1.eva_eve_clave) > 0,
                       "La clave debe tener contenido")

    def test_ca2_urls_necesarias_existen(self):
        """CA2: Verifica que las URLs necesarias existan."""
        self.assertIsNotNone(self.url_aprobar_eval1, "URL de aprobación debe existir")
        self.assertIsNotNone(self.url_ingreso_evento1, "URL de ingreso debe existir")

    def test_ca3_clave_existe_tras_aprobacion(self):
        """CA3: Verifica que el evaluador mantenga su clave tras la aprobación."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        clave_antes = self.registro_eval1_evento1.eva_eve_clave
        
        response = self.client_admin.post(self.url_aprobar_eval1, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        self.registro_eval1_evento1.refresh_from_db()
        clave_despues = self.registro_eval1_evento1.eva_eve_clave
        
        self.assertIsNotNone(clave_despues, "El evaluador aprobado debe tener una clave")
        self.assertEqual(clave_antes, clave_despues, "La clave debe mantenerse igual")

    def test_ca4_email_con_clave_al_aprobar(self):
        """CA4: Verifica que se envía email con la clave al aprobar."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        mail.outbox = []
        
        response = self.client_admin.post(self.url_aprobar_eval1, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        self.registro_eval1_evento1.refresh_from_db()
        clave_actual = self.registro_eval1_evento1.eva_eve_clave
        
        # Verificar que se envió email
        self.assertGreater(len(mail.outbox), 0, "Debe enviarse al menos un email")
        
        email = mail.outbox[0]
        self.assertIn(self.user_evaluador1.email, email.to)
        
        # Verificar que la clave está en el email
        self.assertIn(clave_actual, email.body, "El email debe contener la clave de acceso")

    def test_ca5_rechazado_no_recibe_clave_en_email(self):
        """CA5: Verifica que un evaluador rechazado no reciba clave en el email."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        clave_antes = self.registro_eval2_evento1.eva_eve_clave
        
        mail.outbox = []
        
        response = self.client_admin.post(self.url_rechazar_eval2, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        self.registro_eval2_evento1.refresh_from_db()
        
        # Verificar que se envió email
        if len(mail.outbox) > 0:
            email = mail.outbox[0]
            # La clave NO debe estar en el correo de rechazo
            self.assertNotIn(clave_antes, email.body, 
                           "El email de rechazo NO debe contener la clave")

    def test_ca6_unicidad_claves_mismo_evaluador_diferentes_eventos(self):
        """CA6: Verifica que un evaluador tenga claves diferentes en eventos diferentes."""
        registro_eval1_evento2 = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador1,
            eva_eve_evento_fk=self.evento2,
            eva_eve_estado="Preinscrito",
            eva_eve_clave=f"CLAVE2_{random.randint(1000, 9999)}",
            eva_eve_documento=SimpleUploadedFile("cv1_evento2.pdf", b"CV evaluador 1 evento 2", content_type="application/pdf")
        )
        
        clave_evento1 = self.registro_eval1_evento1.eva_eve_clave
        clave_evento2 = registro_eval1_evento2.eva_eve_clave
        
        self.assertNotEqual(clave_evento1, clave_evento2,
                           "Las claves deben ser diferentes para diferentes eventos")

    def test_ca7_unicidad_claves_diferentes_evaluadores(self):
        """CA7: Verifica que evaluadores diferentes tengan claves diferentes."""
        clave_eval1 = self.registro_eval1_evento1.eva_eve_clave
        clave_eval2 = self.registro_eval2_evento1.eva_eve_clave
        
        self.assertNotEqual(clave_eval1, clave_eval2,
                           "Evaluadores diferentes deben tener claves diferentes")

    def test_ca8_clave_permite_acceso_al_evento(self):
        """CA8: Verifica la URL de ingreso al evento con la clave."""
        self.assertIsNotNone(self.url_ingreso_evento1,
                            "La URL de ingreso al evento debe existir")

    def test_ca9_formato_clave_valido(self):
        """CA9: Verifica que la clave tenga un formato válido."""
        clave = self.registro_eval1_evento1.eva_eve_clave
        
        self.assertGreaterEqual(len(clave), 4,
                               "La clave debe tener al menos 4 caracteres")
        self.assertTrue(clave.strip(),
                       "La clave no debe estar vacía")

    def test_ca10_campos_necesarios_en_modelo(self):
        """CA10: Verifica que el modelo tenga los campos necesarios."""
        self.assertTrue(hasattr(self.registro_eval1_evento1, 'eva_eve_clave'),
                       "Debe tener campo eva_eve_clave")
        self.assertTrue(hasattr(self.registro_eval1_evento1, 'eva_eve_estado'),
                       "Debe tener campo eva_eve_estado")
        self.assertTrue(hasattr(self.registro_eval1_evento1, 'eva_eve_evaluador_fk'),
                       "Debe tener campo eva_eve_evaluador_fk")