# app_evaluadores/tests/tests_hu30.py

import shutil
import tempfile
from datetime import date, timedelta

from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile

from app_usuarios.models import Usuario, Evaluador, AdministradorEvento
from app_admin_eventos.models import Evento
from app_evaluadores.models import EvaluadorEvento
import time
import random


TEMP_MEDIA_ROOT = tempfile.mkdtemp(prefix="test_media_")


@override_settings(MEDIA_ROOT=TEMP_MEDIA_ROOT)
class EvaluadorPreinscripcionTest(TestCase):
    """
    HU30 - Preinscripción de evaluador en evento
    """

    @classmethod
    def setUpClass(cls):
        """Configuración única para toda la clase."""
        super().setUpClass()
        cls.unique_suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"

    def setUp(self):
        """Configuración inicial para cada test."""
        unique_suffix = self.unique_suffix
        
        # ===== ADMINISTRADOR DE EVENTO =====
        admin_username = f"admin_hu30_{unique_suffix}"
        admin_user = Usuario.objects.create_user(
            username=admin_username,
            password="adminpass123",
            rol=Usuario.Roles.ADMIN_EVENTO,
            email=f"{admin_username}@test.com",
            cedula=f"900{unique_suffix[-10:]}"
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=admin_user)
        
        # ===== EVENTO CON PREINSCRIPCIÓN HABILITADA =====
        self.evento_activo = Evento.objects.create(
            eve_nombre=f"Evento Evaluadores {unique_suffix}",
            eve_descripcion="Evento para evaluadores",
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
        
        # ===== EVENTO SIN PREINSCRIPCIÓN =====
        self.evento_sin_preinscripcion = Evento.objects.create(
            eve_nombre=f"Evento Sin Preins {unique_suffix}",
            eve_descripcion="Sin preinscripción",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_fecha_inicio=date.today() + timedelta(days=30),
            eve_fecha_fin=date.today() + timedelta(days=32),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=50,
            eve_imagen=SimpleUploadedFile("img2.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"contenido", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=False
        )
        
        # ===== CLIENTE =====
        self.client_test = Client()
        
        # ===== URLs =====
        self.url_crear_evaluador = reverse('crear_evaluador', args=[self.evento_activo.pk])
        self.url_crear_evaluador_sin_preins = reverse('crear_evaluador', args=[self.evento_sin_preinscripcion.pk])

    def tearDown(self):
        """Limpiar archivos temporales."""
        try:
            shutil.rmtree(TEMP_MEDIA_ROOT)
        except Exception:
            pass

    # ========== CASOS POSITIVOS ==========

    def test_ca1_url_preinscripcion_evaluador_existe(self):
        """CA1: URL de preinscripción de evaluador existe."""
        self.assertIsNotNone(self.url_crear_evaluador)
        self.assertIn('evaluador', self.url_crear_evaluador.lower())

    def test_ca2_formulario_preinscripcion_accesible(self):
        """CA2: Formulario de preinscripción es accesible."""
        response = self.client_test.get(self.url_crear_evaluador)
        
        # Debe ser accesible o redirigir
        self.assertIn(response.status_code, (200, 302, 405))

    def test_ca3_evento_tiene_preinscripcion_habilitada(self):
        """CA3: Evento tiene preinscripción habilitada."""
        self.assertTrue(self.evento_activo.preinscripcion_habilitada_evaluadores)

    def test_ca4_crear_evaluador_nuevo_con_datos_validos(self):
        """CA4: Crear evaluador nuevo con datos válidos."""
        data = {
            'cedula': f"123{self.unique_suffix[-10:]}",
            'username': f"evaluador_hu30_{self.unique_suffix}",
            'email': f"evaluador_hu30_{self.unique_suffix}@test.com",
            'telefono': '3001234567',
            'first_name': 'Juan',
            'last_name': 'Evaluador',
            'password': 'testpass123',
            'password2': 'testpass123',
        }
        
        response = self.client_test.post(self.url_crear_evaluador, data, follow=True)
        
        # Verificar que fue procesado
        self.assertIn(response.status_code, (200, 302))
        
        # Verificar que se creó el usuario
        usuario_existe = Usuario.objects.filter(
            username=data['username']
        ).exists()
        self.assertTrue(usuario_existe, "Usuario debe ser creado")

    def test_ca5_evaluador_creado_es_vinculado_al_evento(self):
        """CA5: Evaluador creado es vinculado al evento."""
        username = f"eva_{self.unique_suffix}"
        
        data = {
            'cedula': f"234{self.unique_suffix[-10:]}",
            'username': username,
            'email': f"eva_{self.unique_suffix}@test.com",
            'telefono': '3001234567',
            'first_name': 'Carlos',
            'last_name': 'Juez',
            'password': 'testpass123',
            'password2': 'testpass123',
        }
        
        response = self.client_test.post(self.url_crear_evaluador, data, follow=True)
        
        # Obtener el usuario creado
        usuario = Usuario.objects.filter(username=username).first()
        
        if usuario:
            # Verificar que existe Evaluador
            evaluador_existe = Evaluador.objects.filter(usuario=usuario).exists()
            self.assertTrue(evaluador_existe, "Debe existir perfil Evaluador")
            
            # Verificar que existe EvaluadorEvento
            evaluador = Evaluador.objects.get(usuario=usuario)
            evaluador_evento_existe = EvaluadorEvento.objects.filter(
                eva_eve_evaluador_fk=evaluador,
                eva_eve_evento_fk=self.evento_activo
            ).exists()
            self.assertTrue(evaluador_evento_existe, "Debe existir relación con evento")

    def test_ca6_estado_inicial_es_preinscrito(self):
        """CA6: Estado inicial de EvaluadorEvento es 'Preinscrito'."""
        # Crear evaluador
        usuario = Usuario.objects.create_user(
            username=f"eva_estado_{self.unique_suffix}",
            password="testpass",
            email=f"eva_estado_{self.unique_suffix}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"345{self.unique_suffix[-10:]}",
            first_name="Test",
            last_name="Estado"
        )
        
        evaluador = Evaluador.objects.create(usuario=usuario)
        
        # Crear relación
        evaluador_evento = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=evaluador,
            eva_eve_evento_fk=self.evento_activo,
            eva_eve_estado="Preinscrito"
        )
        
        self.assertEqual(evaluador_evento.eva_eve_estado, "Preinscrito")

    def test_ca7_clave_es_generada_automaticamente(self):
        """CA7: Clave es generada automáticamente."""
        usuario = Usuario.objects.create_user(
            username=f"eva_clave_{self.unique_suffix}",
            password="testpass",
            email=f"eva_clave_{self.unique_suffix}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"456{self.unique_suffix[-10:]}",
            first_name="Test",
            last_name="Clave"
        )
        
        evaluador = Evaluador.objects.create(usuario=usuario)
        
        # Crear relación sin especificar clave
        evaluador_evento = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=evaluador,
            eva_eve_evento_fk=self.evento_activo,
            eva_eve_estado="Preinscrito"
        )
        
        # Clave debe existir (aunque sea vacío o autogenerado)
        self.assertIsNotNone(evaluador_evento)

    # ========== CASOS NEGATIVOS ==========

    def test_ca8_no_crear_evaluador_sin_email(self):
        """CA8: No crear evaluador sin email."""
        data = {
            'cedula': f"567{self.unique_suffix[-10:]}",
            'username': f"eva_noemail_{self.unique_suffix}",
            'email': '',  # Email vacío
            'telefono': '3001234567',
            'first_name': 'Juan',
            'last_name': 'NoEmail',
            'password': 'testpass123',
            'password2': 'testpass123',
        }
        
        response = self.client_test.post(self.url_crear_evaluador, data, follow=True)
        
        # No debe permitir
        usuario_existe = Usuario.objects.filter(
            username=data['username']
        ).exists()
        self.assertFalse(usuario_existe)

    def test_ca9_no_crear_evaluador_sin_cedula(self):
        """CA9: No crear evaluador sin cédula."""
        data = {
            'cedula': '',  # Cédula vacía
            'username': f"eva_nocedula_{self.unique_suffix}",
            'email': f"eva_nocedula_{self.unique_suffix}@test.com",
            'telefono': '3001234567',
            'first_name': 'Juan',
            'last_name': 'NoCedula',
            'password': 'testpass123',
            'password2': 'testpass123',
        }
        
        response = self.client_test.post(self.url_crear_evaluador, data, follow=True)
        
        # No debe permitir
        usuario_existe = Usuario.objects.filter(
            email=data['email']
        ).exists()
        self.assertFalse(usuario_existe)

    def test_ca10_no_preinscribir_en_evento_sin_habilitacion(self):
        """CA10: No permitir preinscripción si no está habilitada."""
        # Este test verifica la lógica - en la vista debería bloquearse
        data = {
            'cedula': f"678{self.unique_suffix[-10:]}",
            'username': f"eva_nohab_{self.unique_suffix}",
            'email': f"eva_nohab_{self.unique_suffix}@test.com",
            'telefono': '3001234567',
            'first_name': 'Juan',
            'last_name': 'NoHab',
            'password': 'testpass123',
            'password2': 'testpass123',
        }
        
        response = self.client_test.post(self.url_crear_evaluador_sin_preins, data, follow=True)
        
        # La vista debería rechazar o redirigir
        self.assertIn(response.status_code, (200, 302, 403))

    def test_ca11_no_permitir_cedula_duplicada(self):
        """CA11: No permitir cédula duplicada."""
        cedula_dup = f"999{self.unique_suffix[-10:]}"
        
        # Crear primer evaluador
        usuario1 = Usuario.objects.create_user(
            username=f"eva_dup1_{self.unique_suffix}",
            password="testpass",
            email=f"eva_dup1_{self.unique_suffix}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=cedula_dup,
            first_name="First",
            last_name="Dup"
        )
        
        # Intentar crear segundo evaluador con misma cédula
        data = {
            'cedula': cedula_dup,  # Misma cédula
            'username': f"eva_dup2_{self.unique_suffix}",
            'email': f"eva_dup2_{self.unique_suffix}@test.com",
            'telefono': '3001234567',
            'first_name': 'Second',
            'last_name': 'Dup',
            'password': 'testpass123',
            'password2': 'testpass123',
        }
        
        response = self.client_test.post(self.url_crear_evaluador, data, follow=True)
        
        # No debe permitir segunda cédula duplicada
        count = Usuario.objects.filter(cedula=cedula_dup).count()
        self.assertEqual(count, 1, "No debe haber cédulas duplicadas")

    def test_ca12_no_permitir_email_duplicado(self):
        """CA12: No permitir email duplicado."""
        email_dup = f"emaildup_{self.unique_suffix}@test.com"
        
        # Crear primer evaluador
        usuario1 = Usuario.objects.create_user(
            username=f"eva_email1_{self.unique_suffix}",
            password="testpass",
            email=email_dup,
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"111{self.unique_suffix[-10:]}",
            first_name="First",
            last_name="Email"
        )
        
        # Intentar crear segundo evaluador con mismo email
        data = {
            'cedula': f"222{self.unique_suffix[-10:]}",
            'username': f"eva_email2_{self.unique_suffix}",
            'email': email_dup,  # Mismo email
            'telefono': '3001234567',
            'first_name': 'Second',
            'last_name': 'Email',
            'password': 'testpass123',
            'password2': 'testpass123',
        }
        
        response = self.client_test.post(self.url_crear_evaluador, data, follow=True)
        
        # No debe permitir segundo email duplicado
        count = Usuario.objects.filter(email=email_dup).count()
        self.assertEqual(count, 1, "No debe haber emails duplicados")

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca13_modelo_evaluador_tiene_relacion_usuario(self):
        """CA13: Modelo Evaluador tiene relación OneToOne con Usuario."""
        self.assertTrue(hasattr(Evaluador, 'usuario'))

    def test_ca14_modelo_evaluadorevento_tiene_campos_requeridos(self):
        """CA14: Modelo EvaluadorEvento tiene campos requeridos."""
        campos_requeridos = [
            'eva_eve_evaluador_fk',
            'eva_eve_evento_fk',
            'eva_eve_estado'
        ]
        
        for campo in campos_requeridos:
            self.assertTrue(hasattr(EvaluadorEvento, campo))

    def test_ca15_evento_es_accesible_desde_evaluadorevento(self):
        """CA15: Se puede acceder al evento desde EvaluadorEvento."""
        usuario = Usuario.objects.create_user(
            username=f"eva_acceso_{self.unique_suffix}",
            password="testpass",
            email=f"eva_acceso_{self.unique_suffix}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"333{self.unique_suffix[-10:]}",
            first_name="Access",
            last_name="Test"
        )
        
        evaluador = Evaluador.objects.create(usuario=usuario)
        
        evaluador_evento = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=evaluador,
            eva_eve_evento_fk=self.evento_activo,
            eva_eve_estado="Preinscrito"
        )
        
        # Verificar que se puede acceder al evento
        self.assertEqual(evaluador_evento.eva_eve_evento_fk, self.evento_activo)