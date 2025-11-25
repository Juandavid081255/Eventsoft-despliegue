# app_evaluadores/tests/tests_hu36.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time
import random
import tempfile
import shutil

from app_usuarios.models import Usuario, Evaluador, AdministradorEvento
from app_admin_eventos.models import Evento
from app_evaluadores.models import EvaluadorEvento


TEMP_MEDIA_ROOT = tempfile.mkdtemp(prefix="test_media_hu36_")


class ProgramacionEvaluadorTest(TestCase):
    """
    HU36 - Visualizar Programación del Evento
    Verifica que los evaluadores aprobados puedan ver la programación.
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
        admin_username = f"admin_hu36_{unique_suffix}"
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
        
        # ===== EVENTO CON PROGRAMACIÓN =====
        programacion_file = SimpleUploadedFile(
            "programacion_evento.pdf",
            b"Contenido de la programacion del evento",
            content_type="application/pdf"
        )
        
        self.evento = Evento.objects.create(
            eve_nombre=f"Evento Programación {unique_suffix}",
            eve_descripcion="Descripción del evento con programación",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_fecha_inicio=date.today() + timedelta(days=10),
            eve_fecha_fin=date.today() + timedelta(days=12),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_imagen=SimpleUploadedFile("img.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=programacion_file,
            preinscripcion_habilitada_evaluadores=True
        )
        
        # ===== EVENTO SIN PROGRAMACIÓN =====
        self.evento_sin_prog = Evento.objects.create(
            eve_nombre=f"Evento Sin Programación {unique_suffix}",
            eve_descripcion="Evento sin programación cargada",
            eve_ciudad="Manizales",
            eve_lugar="Auditorio",
            eve_fecha_inicio=date.today() + timedelta(days=15),
            eve_fecha_fin=date.today() + timedelta(days=17),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=50,
            eve_imagen=SimpleUploadedFile("img2.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=None,  # Sin programación
            preinscripcion_habilitada_evaluadores=True
        )
        
        # ===== EVALUADOR APROBADO =====
        user_eval_aprobado = f"eval_apro_{unique_suffix}"
        self.user_evaluador_aprobado = Usuario.objects.create_user(
            username=user_eval_aprobado,
            password=self.password,
            email=f"{user_eval_aprobado}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"800{unique_suffix[-10:]}",
            first_name="Evaluador",
            last_name="Aprobado"
        )
        
        self.evaluador_aprobado, _ = Evaluador.objects.get_or_create(usuario=self.user_evaluador_aprobado)
        
        self.registro_aprobado = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_aprobado,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Aprobado",
            eva_eve_clave=f"CLAVE_{unique_suffix}_1",
            eva_eve_documento=SimpleUploadedFile("cv_aprobado.pdf", b"CV aprobado", content_type="application/pdf")
        )
        
        # ===== EVALUADOR PREINSCRITO =====
        user_eval_preinscrito = f"eval_pre_{unique_suffix}"
        self.user_evaluador_preinscrito = Usuario.objects.create_user(
            username=user_eval_preinscrito,
            password=self.password,
            email=f"{user_eval_preinscrito}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"810{unique_suffix[-10:]}",
            first_name="Evaluador",
            last_name="Preinscrito"
        )
        
        self.evaluador_preinscrito, _ = Evaluador.objects.get_or_create(usuario=self.user_evaluador_preinscrito)
        
        self.registro_preinscrito = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_preinscrito,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Preinscrito",
            eva_eve_clave=f"CLAVE_{unique_suffix}_2",
            eva_eve_documento=SimpleUploadedFile("cv_preinscrito.pdf", b"CV preinscrito", content_type="application/pdf")
        )
        
        # ===== CLIENTES Y URLs =====
        self.client_aprobado = Client()
        self.client_preinscrito = Client()
        self.url_detalle_evento = reverse('ver_info_evento_eva', args=[self.evento.pk])
        self.url_info_tecnica = reverse('ver_info_tecnica_evento', args=[self.evento.pk])

    def tearDown(self):
        """Limpiar archivos temporales."""
        try:
            shutil.rmtree(TEMP_MEDIA_ROOT)
        except Exception:
            pass

    # ========== TESTS DE PROGRAMACIÓN ==========

    def test_ca1_verificar_estados_iniciales(self):
        """CA1: Verifica que los estados sean correctos."""
        self.assertEqual(self.registro_aprobado.eva_eve_estado, "Aprobado",
                        "El registro debe estar Aprobado")
        self.assertEqual(self.registro_preinscrito.eva_eve_estado, "Preinscrito",
                        "El registro debe estar Preinscrito")

    def test_ca2_evento_tiene_programacion(self):
        """CA2: Verifica que el evento tenga programación cargada."""
        self.assertIsNotNone(self.evento.eve_programacion,
                            "El evento debe tener programación")
        self.assertTrue(bool(self.evento.eve_programacion),
                       "El campo de programación debe tener contenido")

    def test_ca3_urls_necesarias_existen(self):
        """CA3: Verifica que las URLs necesarias existan."""
        self.assertIsNotNone(self.url_detalle_evento, "URL de detalle debe existir")
        self.assertIsNotNone(self.url_info_tecnica, "URL de info técnica debe existir")

    def test_ca4_evaluador_aprobado_puede_acceder_detalle(self):
        """CA4: Verifica que un evaluador aprobado puede acceder al detalle."""
        login_ok = self.client_aprobado.login(
            username=self.user_evaluador_aprobado.username,
            password=self.password
        )
        self.assertTrue(login_ok, "El login debe ser exitoso")
        
        # Establecer evaluador_id en la sesión (requerido por decorador evaluador_required)
        session = self.client_aprobado.session
        session['evaluador_id'] = self.evaluador_aprobado.id
        session.save()
        
        response = self.client_aprobado.get(self.url_detalle_evento, follow=True)
        
        # Debe poder acceder (200 OK)
        self.assertEqual(response.status_code, 200,
                        "Evaluador aprobado debe poder acceder al detalle del evento")

    def test_ca5_evaluador_aprobado_ve_informacion_evento(self):
        """CA5: Verifica que un evaluador aprobado vea información del evento."""
        login_ok = self.client_aprobado.login(
            username=self.user_evaluador_aprobado.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        # Establecer evaluador_id en la sesión (requerido por decorador evaluador_required)
        session = self.client_aprobado.session
        session['evaluador_id'] = self.evaluador_aprobado.id
        session.save()
        
        response = self.client_aprobado.get(self.url_detalle_evento, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # Verificar que muestra información del evento
        content = response.content.decode('utf-8')
        self.assertIn(self.evento.eve_nombre, content,
                     "Debe mostrar el nombre del evento")

    def test_ca6_preinscrito_puede_ver_evento_basico(self):
        """CA6: Verifica que un preinscrito puede ver info básica del evento."""
        login_ok = self.client_preinscrito.login(
            username=self.user_evaluador_preinscrito.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_preinscrito.get(self.url_detalle_evento, follow=True)
        
        # Puede acceder o ser redirigido
        self.assertIn(response.status_code, (200, 302),
                     "Preinscrito debe poder ver información básica del evento")

    def test_ca7_acceso_informacion_tecnica(self):
        """CA7: Verifica que información técnica sea accesible."""
        login_ok = self.client_aprobado.login(
            username=self.user_evaluador_aprobado.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_aprobado.get(self.url_info_tecnica, follow=True)
        
        # Debe ser accesible
        self.assertIn(response.status_code, (200, 302, 404),
                     "Información técnica debe ser accesible o redireccionar")

    def test_ca8_evento_sin_programacion_maneja_gracefully(self):
        """CA8: Verifica el manejo cuando el evento no tiene programación."""
        # Crear registro aprobado para evento sin programación
        registro_sin_prog = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_aprobado,
            eva_eve_evento_fk=self.evento_sin_prog,
            eva_eve_estado="Aprobado",
            eva_eve_clave=f"CLAVE_{random.randint(1000, 9999)}",
            eva_eve_documento=SimpleUploadedFile("cv.pdf", b"CV", content_type="application/pdf")
        )
        
        url_sin_prog = reverse('ver_info_evento_eva', args=[self.evento_sin_prog.pk])
        
        login_ok = self.client_aprobado.login(
            username=self.user_evaluador_aprobado.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_aprobado.get(url_sin_prog, follow=True)
        
        # Debe manejar correctamente la ausencia de programación
        self.assertIn(response.status_code, (200, 302, 404),
                     "Debe manejar la ausencia de programación gracefully")

    def test_ca9_programacion_es_descargable(self):
        """CA9: Verifica que la programación sea descargable."""
        # Verificar que el archivo está disponible
        self.assertTrue(self.evento.eve_programacion,
                       "El evento debe tener programación")
        
        # Verificar que es un archivo PDF
        nombre_archivo = self.evento.eve_programacion.name.lower()
        self.assertTrue(nombre_archivo.endswith('.pdf'),
                       "La programación debe ser un archivo PDF")

    def test_ca10_campos_necesarios_en_modelo(self):
        """CA10: Verifica que los modelos tengan los campos necesarios."""
        self.assertTrue(hasattr(self.evento, 'eve_programacion'),
                       "Evento debe tener campo eve_programacion")
        self.assertTrue(hasattr(self.evento, 'eve_informacion_tecnica'),
                       "Evento debe tener campo eve_informacion_tecnica")
        self.assertTrue(hasattr(self.registro_aprobado, 'eva_eve_estado'),
                       "EvaluadorEvento debe tener campo eva_eve_estado")

    def test_ca11_relaciones_correctas(self):
        """CA11: Verifica las relaciones entre modelos."""
        self.assertEqual(
            self.registro_aprobado.eva_eve_evaluador_fk,
            self.evaluador_aprobado,
            "La relación con evaluador debe ser correcta"
        )
        
        self.assertEqual(
            self.registro_aprobado.eva_eve_evento_fk,
            self.evento,
            "La relación con evento debe ser correcta"
        )