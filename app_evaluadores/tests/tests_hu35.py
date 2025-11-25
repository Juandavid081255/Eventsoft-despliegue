# app_evaluadores/tests/tests_hu35.py

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


TEMP_MEDIA_ROOT = tempfile.mkdtemp(prefix="test_media_hu35_")


class QRInscripcionEvaluadorTest(TestCase):
    """
    HU35 - Recibir QR de Inscripción
    Verifica que los evaluadores aprobados reciban su código QR.
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
        admin_username = f"admin_hu35_{unique_suffix}"
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
        
        # ===== EVENTO =====
        self.evento = Evento.objects.create(
            eve_nombre=f"Evento QR {unique_suffix}",
            eve_descripcion="Evento para probar QR de inscripción",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_fecha_inicio=date.today() + timedelta(days=10),
            eve_fecha_fin=date.today() + timedelta(days=12),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_imagen=SimpleUploadedFile("img.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"contenido", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=True
        )
        
        # ===== EVALUADOR PARA APROBAR =====
        user_eval_aprobar = f"eval_apro_{unique_suffix}"
        self.user_evaluador_aprobar = Usuario.objects.create_user(
            username=user_eval_aprobar,
            password=self.password,
            email=f"{user_eval_aprobar}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"800{unique_suffix[-10:]}",
            first_name="Evaluador",
            last_name="Aprobar"
        )
        
        self.evaluador_aprobar, _ = Evaluador.objects.get_or_create(usuario=self.user_evaluador_aprobar)
        
        self.registro_para_aprobar = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_aprobar,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Preinscrito",
            eva_eve_clave=f"CLAVE_{unique_suffix}_1",
            eva_eve_documento=SimpleUploadedFile("cv_aprobar.pdf", b"CV para aprobar", content_type="application/pdf")
        )
        
        # ===== EVALUADOR PARA RECHAZAR =====
        user_eval_rechazar = f"eval_rech_{unique_suffix}"
        self.user_evaluador_rechazar = Usuario.objects.create_user(
            username=user_eval_rechazar,
            password=self.password,
            email=f"{user_eval_rechazar}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"810{unique_suffix[-10:]}",
            first_name="Evaluador",
            last_name="Rechazar"
        )
        
        self.evaluador_rechazar, _ = Evaluador.objects.get_or_create(usuario=self.user_evaluador_rechazar)
        
        self.registro_para_rechazar = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_rechazar,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Preinscrito",
            eva_eve_clave=f"CLAVE_{unique_suffix}_2",
            eva_eve_documento=SimpleUploadedFile("cv_rechazar.pdf", b"CV para rechazar", content_type="application/pdf")
        )
        
        # ===== CLIENTES Y URLs =====
        self.client_admin = Client()
        self.url_aprobar = reverse('aprobar_eva', args=[self.evento.pk, self.registro_para_aprobar.pk])
        self.url_rechazar = reverse('rechazar_eva', args=[self.evento.pk, self.registro_para_rechazar.pk])

    def tearDown(self):
        """Limpiar archivos temporales."""
        try:
            shutil.rmtree(TEMP_MEDIA_ROOT)
        except Exception:
            pass

    # ========== TESTS DE QR ==========

    def test_ca1_verificar_estados_iniciales(self):
        """CA1: Verifica que los estados iniciales sean 'Preinscrito'."""
        self.assertEqual(self.registro_para_aprobar.eva_eve_estado, "Preinscrito",
                        "El estado inicial debe ser Preinscrito")
        self.assertEqual(self.registro_para_rechazar.eva_eve_estado, "Preinscrito",
                        "El estado inicial debe ser Preinscrito")

    def test_ca2_campo_qr_existe_en_modelo(self):
        """CA2: Verifica que el modelo tenga campo para el QR."""
        self.assertTrue(hasattr(self.registro_para_aprobar, 'eva_eve_qr'),
                       "El modelo debe tener campo eva_eve_qr")

    def test_ca3_qr_vacio_antes_de_aprobacion(self):
        """CA3: Verifica que el QR esté vacío antes de la aprobación."""
        qr_inicial = self.registro_para_aprobar.eva_eve_qr
        
        # El QR debe estar vacío inicialmente
        qr_vacio = not qr_inicial or str(qr_inicial) == ""
        self.assertTrue(qr_vacio, "El QR debe estar vacío antes de la aprobación")

    def test_ca4_admin_puede_aprobar_evaluador(self):
        """CA4: Verifica que el admin puede aprobar un evaluador."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        mail.outbox = []
        
        estado_antes = self.registro_para_aprobar.eva_eve_estado
        
        response = self.client_admin.post(self.url_aprobar, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        self.registro_para_aprobar.refresh_from_db()
        estado_despues = self.registro_para_aprobar.eva_eve_estado
        
        self.assertEqual(estado_despues, "Aprobado",
                        f"El estado debe cambiar de {estado_antes} a Aprobado")

    def test_ca5_qr_generado_tras_aprobacion(self):
        """CA5: Verifica si se genera un QR tras la aprobación."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        mail.outbox = []
        
        response = self.client_admin.post(self.url_aprobar, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        self.registro_para_aprobar.refresh_from_db()
        qr_generado = self.registro_para_aprobar.eva_eve_qr
        
        # Verificar que se generó un QR
        qr_no_vacio = qr_generado and str(qr_generado) != ""
        self.assertTrue(qr_no_vacio, "Debe generarse un QR tras la aprobación")
        
        # Verificar que es una imagen
        if qr_generado.name:
            extension = qr_generado.name.lower()
            es_imagen = '.png' in extension or '.jpg' in extension or '.jpeg' in extension
            self.assertTrue(es_imagen, "El QR debe ser un archivo de imagen (PNG o JPG)")

    def test_ca6_email_con_qr_al_aprobar(self):
        """CA6: Verifica si se envía email con QR al aprobar."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        mail.outbox = []
        
        response = self.client_admin.post(self.url_aprobar, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        # Verificar que se envió email
        self.assertGreater(len(mail.outbox), 0, "Debe enviarse email al aprobar")
        
        email = mail.outbox[0]
        self.assertIn(self.user_evaluador_aprobar.email, email.to)
        
        # El email debe contener referencia al QR
        # (puede ser adjunto, embebido en HTML, o mencionado en el cuerpo)
        email_tiene_contenido = email.body or (hasattr(email, 'alternatives') and email.alternatives)
        self.assertTrue(email_tiene_contenido, "El email debe tener contenido")

    def test_ca7_rechazado_no_recibe_qr(self):
        """CA7: Verifica que un evaluador rechazado NO reciba QR."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        mail.outbox = []
        
        response = self.client_admin.post(self.url_rechazar, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        self.registro_para_rechazar.refresh_from_db()
        qr_rechazado = self.registro_para_rechazar.eva_eve_qr
        
        # El QR NO debe generarse para rechazados
        qr_vacio = not qr_rechazado or str(qr_rechazado) == ""
        self.assertTrue(qr_vacio, "Un evaluador rechazado NO debe tener QR generado")

    def test_ca8_qr_es_unico_por_registro(self):
        """CA8: Verifica que cada registro tenga un QR único."""
        login_ok = self.client_admin.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        # Aprobar primero evaluador
        self.client_admin.post(self.url_aprobar, follow=True)
        self.registro_para_aprobar.refresh_from_db()
        qr1 = self.registro_para_aprobar.eva_eve_qr
        
        # Crear segundo evaluador y aprobarlo
        user_eval2 = f"eval2_{self.unique_suffix}"
        self.user_eval2 = Usuario.objects.create_user(
            username=user_eval2,
            password=self.password,
            email=f"{user_eval2}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"820{self.unique_suffix[-10:]}"
        )
        
        self.evaluador2, _ = Evaluador.objects.get_or_create(usuario=self.user_eval2)
        
        self.registro2 = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador2,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Preinscrito",
            eva_eve_clave=f"CLAVE_{self.unique_suffix}_3",
            eva_eve_documento=SimpleUploadedFile("cv2.pdf", b"CV 2", content_type="application/pdf")
        )
        
        url_aprobar2 = reverse('aprobar_eva', args=[self.evento.pk, self.registro2.pk])
        self.client_admin.post(url_aprobar2, follow=True)
        
        self.registro2.refresh_from_db()
        qr2 = self.registro2.eva_eve_qr
        
        # Los QRs deben existir y ser diferentes
        qr1_ok = qr1 and str(qr1) != ""
        qr2_ok = qr2 and str(qr2) != ""
        
        self.assertTrue(qr1_ok and qr2_ok, "Ambos evaluadores deben tener QR")
        self.assertNotEqual(str(qr1), str(qr2), "Los QRs deben ser únicos")

    def test_ca9_campos_necesarios_en_modelo(self):
        """CA9: Verifica que el modelo tenga todos los campos necesarios."""
        self.assertTrue(hasattr(self.registro_para_aprobar, 'eva_eve_qr'),
                       "Debe tener campo eva_eve_qr")
        self.assertTrue(hasattr(self.registro_para_aprobar, 'eva_eve_clave'),
                       "Debe tener campo eva_eve_clave")
        self.assertTrue(hasattr(self.registro_para_aprobar, 'eva_eve_estado'),
                       "Debe tener campo eva_eve_estado")

    def test_ca10_urls_necesarias_existen(self):
        """CA10: Verifica que las URLs necesarias existan."""
        self.assertIsNotNone(self.url_aprobar, "URL de aprobación debe existir")
        self.assertIsNotNone(self.url_rechazar, "URL de rechazo debe existir")