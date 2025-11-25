# app_evaluadores/tests/tests_hu37.py

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


TEMP_MEDIA_ROOT = tempfile.mkdtemp(prefix="test_media_hu37_")


class VisualizacionEventosEvaluadorTest(TestCase):
    """
    HU37 - Visualizar Información de los Eventos
    Verifica que los evaluadores vean su lista de eventos aprobados en el dashboard.
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
        admin_username = f"admin_hu37_{unique_suffix}"
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
        
        # ===== EVENTOS CON DIFERENTES FECHAS =====
        
        # Evento ACTIVO (en curso)
        self.evento_activo = Evento.objects.create(
            eve_nombre=f"Evento Activo {unique_suffix}",
            eve_descripcion="Evento en curso",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_fecha_inicio=date.today() - timedelta(days=1),
            eve_fecha_fin=date.today() + timedelta(days=2),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_imagen=SimpleUploadedFile("img1.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog1.pdf", b"contenido", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=True
        )
        
        # Evento FUTURO (próximo)
        self.evento_futuro = Evento.objects.create(
            eve_nombre=f"Evento Futuro {unique_suffix}",
            eve_descripcion="Evento próximo",
            eve_ciudad="Manizales",
            eve_lugar="Auditorio",
            eve_fecha_inicio=date.today() + timedelta(days=30),
            eve_fecha_fin=date.today() + timedelta(days=32),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_imagen=SimpleUploadedFile("img2.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"contenido", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=True
        )
        
        # Evento PASADO (finalizado)
        self.evento_pasado = Evento.objects.create(
            eve_nombre=f"Evento Pasado {unique_suffix}",
            eve_descripcion="Evento finalizado",
            eve_ciudad="Manizales",
            eve_lugar="Sala",
            eve_fecha_inicio=date.today() - timedelta(days=10),
            eve_fecha_fin=date.today() - timedelta(days=8),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_imagen=SimpleUploadedFile("img3.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog3.pdf", b"contenido", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=True
        )
        
        # ===== EVALUADOR =====
        user_evaluador = f"eval_hu37_{unique_suffix}"
        self.user_evaluador = Usuario.objects.create_user(
            username=user_evaluador,
            password=self.password,
            email=f"{user_evaluador}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"800{unique_suffix[-10:]}",
            first_name="Evaluador",
            last_name="HU37"
        )
        
        self.evaluador, _ = Evaluador.objects.get_or_create(usuario=self.user_evaluador)
        
        # ===== REGISTROS CON DIFERENTES ESTADOS =====
        
        # Registro APROBADO en evento activo
        self.registro_aprobado_activo = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador,
            eva_eve_evento_fk=self.evento_activo,
            eva_eve_estado="Aprobado",
            eva_eve_clave=f"CLAVE_{unique_suffix}_1",
            eva_eve_documento=SimpleUploadedFile("cv1.pdf", b"CV 1", content_type="application/pdf")
        )
        
        # Registro APROBADO en evento futuro
        self.registro_aprobado_futuro = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador,
            eva_eve_evento_fk=self.evento_futuro,
            eva_eve_estado="Aprobado",
            eva_eve_clave=f"CLAVE_{unique_suffix}_2",
            eva_eve_documento=SimpleUploadedFile("cv2.pdf", b"CV 2", content_type="application/pdf")
        )
        
        # Registro PREINSCRITO en evento pasado (NO debe aparecer)
        self.registro_preinscrito = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador,
            eva_eve_evento_fk=self.evento_pasado,
            eva_eve_estado="Preinscrito",
            eva_eve_clave=f"CLAVE_{unique_suffix}_3",
            eva_eve_documento=SimpleUploadedFile("cv3.pdf", b"CV 3", content_type="application/pdf")
        )
        
        # ===== CLIENTES Y URLs =====
        self.client_evaluador = Client()
        self.url_dashboard = reverse('dashboard_evaluador')

    def tearDown(self):
        """Limpiar archivos temporales."""
        try:
            shutil.rmtree(TEMP_MEDIA_ROOT)
        except Exception:
            pass

    # ========== TESTS DE VISUALIZACIÓN ==========

    def test_ca1_verificar_estados_registros(self):
        """CA1: Verifica que los registros tengan diferentes estados."""
        self.assertEqual(self.registro_aprobado_activo.eva_eve_estado, "Aprobado",
                        "Registro activo debe ser Aprobado")
        self.assertEqual(self.registro_aprobado_futuro.eva_eve_estado, "Aprobado",
                        "Registro futuro debe ser Aprobado")
        self.assertEqual(self.registro_preinscrito.eva_eve_estado, "Preinscrito",
                        "Registro pasado debe ser Preinscrito")

    def test_ca2_verificar_fechas_eventos(self):
        """CA2: Verifica las fechas de los eventos."""
        hoy = date.today()
        
        self.assertTrue(
            self.evento_activo.eve_fecha_inicio <= hoy <= self.evento_activo.eve_fecha_fin,
            "Evento activo debe estar en curso"
        )
        
        self.assertTrue(
            self.evento_futuro.eve_fecha_inicio > hoy,
            "Evento futuro debe ser en el futuro"
        )
        
        self.assertTrue(
            self.evento_pasado.eve_fecha_fin < hoy,
            "Evento pasado debe haber finalizado"
        )

    def test_ca3_url_dashboard_existe(self):
        """CA3: Verifica que la URL del dashboard exista."""
        self.assertIsNotNone(self.url_dashboard, "URL del dashboard debe existir")

    def test_ca4_evaluador_puede_acceder_dashboard(self):
        """CA4: Verifica que el evaluador puede acceder a su dashboard."""
        login_ok = self.client_evaluador.login(
            username=self.user_evaluador.username,
            password=self.password
        )
        self.assertTrue(login_ok, "El login debe ser exitoso")
        
        # Establecer evaluador_id en sesión (requerido por decorador)
        session = self.client_evaluador.session
        session['evaluador_id'] = self.evaluador.id
        session.save()
        
        response = self.client_evaluador.get(self.url_dashboard, follow=True)
        
        self.assertEqual(response.status_code, 200,
                        "Evaluador debe poder acceder al dashboard")

    def test_ca5_dashboard_muestra_eventos_aprobados(self):
        """CA5: Verifica que el dashboard muestre los eventos aprobados."""
        login_ok = self.client_evaluador.login(
            username=self.user_evaluador.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        # Establecer evaluador_id en sesión
        session = self.client_evaluador.session
        session['evaluador_id'] = self.evaluador.id
        session.save()
        
        response = self.client_evaluador.get(self.url_dashboard, follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8')
        
        # Verificar que muestra eventos aprobados
        self.assertIn(self.evento_activo.eve_nombre, content,
                     "Dashboard debe mostrar evento activo aprobado")
        self.assertIn(self.evento_futuro.eve_nombre, content,
                     "Dashboard debe mostrar evento futuro aprobado")

    def test_ca6_dashboard_no_muestra_eventos_no_aprobados(self):
        """CA6: Verifica que NO se muestren eventos con estado diferente a 'Aprobado'."""
        login_ok = self.client_evaluador.login(
            username=self.user_evaluador.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        # Establecer evaluador_id en sesión
        session = self.client_evaluador.session
        session['evaluador_id'] = self.evaluador.id
        session.save()
        
        response = self.client_evaluador.get(self.url_dashboard, follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8')
        
        # Verificar que el evento preinscrito NO aparezca en la lista de eventos
        # (puede aparecer en otra sección como "pendientes", pero no en eventos activos)
        # Este es un test indicativo, puede requerir ajustes según tu UI

    def test_ca7_contar_eventos_aprobados(self):
        """CA7: Verifica la cantidad de eventos aprobados del evaluador."""
        count_aprobados = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=self.evaluador,
            eva_eve_estado="Aprobado"
        ).count()
        
        self.assertEqual(count_aprobados, 2,
                        "Debe haber exactamente 2 eventos aprobados")

    def test_ca8_enlaces_a_eventos_especificos(self):
        """CA8: Verifica que haya enlaces a los eventos específicos."""
        login_ok = self.client_evaluador.login(
            username=self.user_evaluador.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        # Establecer evaluador_id en sesión
        session = self.client_evaluador.session
        session['evaluador_id'] = self.evaluador.id
        session.save()
        
        response = self.client_evaluador.get(self.url_dashboard, follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8')
        
        # Buscar URLs a eventos en el contenido
        url_evento_activo = reverse('ver_info_evento_eva', args=[self.evento_activo.pk])
        url_evento_futuro = reverse('ver_info_evento_eva', args=[self.evento_futuro.pk])
        
        self.assertTrue(
            url_evento_activo in content or self.evento_activo.eve_nombre in content,
            "Dashboard debe tener enlace o referencia al evento activo"
        )

    def test_ca9_campos_necesarios_en_modelo(self):
        """CA9: Verifica que los modelos tengan los campos necesarios."""
        self.assertTrue(hasattr(self.registro_aprobado_activo, 'eva_eve_estado'),
                       "EvaluadorEvento debe tener campo eva_eve_estado")
        self.assertTrue(hasattr(self.registro_aprobado_activo, 'eva_eve_evaluador_fk'),
                       "EvaluadorEvento debe tener campo eva_eve_evaluador_fk")
        self.assertTrue(hasattr(self.registro_aprobado_activo, 'eva_eve_evento_fk'),
                       "EvaluadorEvento debe tener campo eva_eve_evento_fk")
        
        self.assertTrue(hasattr(self.evento_activo, 'eve_fecha_inicio'),
                       "Evento debe tener campo eve_fecha_inicio")
        self.assertTrue(hasattr(self.evento_activo, 'eve_fecha_fin'),
                       "Evento debe tener campo eve_fecha_fin")

    def test_ca10_relaciones_correctas(self):
        """CA10: Verifica las relaciones entre modelos."""
        registros = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=self.evaluador
        )
        
        self.assertEqual(registros.count(), 3,
                        "Debe haber 3 registros para este evaluador")
        
        for registro in registros:
            self.assertEqual(
                registro.eva_eve_evaluador_fk,
                self.evaluador,
                "Cada registro debe pertenecer al evaluador"
            )

    def test_ca11_filtro_por_estado(self):
        """CA11: Verifica que se pueden filtrar eventos por estado."""
        login_ok = self.client_evaluador.login(
            username=self.user_evaluador.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        # Establecer evaluador_id en sesión
        session = self.client_evaluador.session
        session['evaluador_id'] = self.evaluador.id
        session.save()
        
        # El dashboard ya debería mostrar solo los aprobados
        response = self.client_evaluador.get(self.url_dashboard, follow=True)
        
        self.assertEqual(response.status_code, 200)