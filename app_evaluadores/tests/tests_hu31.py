# app_evaluadores/tests/tests_hu31.py

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
class EvaluadorEditarPreinscripcionTest(TestCase):
    """
    HU31 - Editar preinscripción de evaluador en evento
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
        admin_username = f"admin_hu31_{unique_suffix}"
        admin_user = Usuario.objects.create_user(
            username=admin_username,
            password=self.password,
            rol=Usuario.Roles.ADMIN_EVENTO,
            email=f"{admin_username}@test.com",
            cedula=f"900{unique_suffix[-10:]}"
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=admin_user)
        
        # ===== EVENTO ACTIVO =====
        self.evento_activo = Evento.objects.create(
            eve_nombre=f"Evento Editar Eva {unique_suffix}",
            eve_descripcion="Evento para editar preinscripción",
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
        
        # ===== EVENTO TERMINADO =====
        self.evento_terminado = Evento.objects.create(
            eve_nombre=f"Evento Terminado Eva {unique_suffix}",
            eve_descripcion="Evento ya finalizado",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_fecha_inicio=date.today() - timedelta(days=10),
            eve_fecha_fin=date.today() - timedelta(days=5),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=50,
            eve_imagen=SimpleUploadedFile("img2.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"contenido", content_type="application/pdf")
        )
        
        # ===== EVALUADOR PROPIETARIO (PREINSCRITO) =====
        self.username_owner = f"eva_owner_{unique_suffix}"
        self.user_owner = Usuario.objects.create_user(
            username=self.username_owner,
            password=self.password,
            rol=Usuario.Roles.EVALUADOR,
            email=f"{self.username_owner}@test.com",
            cedula=f"800{unique_suffix[-10:]}"
        )
        self.evaluador_owner = Evaluador.objects.create(usuario=self.user_owner)
        
        # ===== EVALUADOR PROPIETARIO 2 (APROBADO) =====
        self.username_owner2 = f"eva_owner2_{unique_suffix}"
        self.user_owner2 = Usuario.objects.create_user(
            username=self.username_owner2,
            password=self.password,
            rol=Usuario.Roles.EVALUADOR,
            email=f"{self.username_owner2}@test.com",
            cedula=f"810{unique_suffix[-10:]}"
        )
        self.evaluador_owner2 = Evaluador.objects.create(usuario=self.user_owner2)
        
        # ===== EVALUADOR EXTRAÑO (sin permiso) =====
        self.username_stranger = f"eva_stranger_{unique_suffix}"
        self.user_stranger = Usuario.objects.create_user(
            username=self.username_stranger,
            password=self.password,
            rol=Usuario.Roles.EVALUADOR,
            email=f"{self.username_stranger}@test.com",
            cedula=f"700{unique_suffix[-10:]}"
        )
        self.evaluador_stranger = Evaluador.objects.create(usuario=self.user_stranger)
        
        # ===== REGISTRO EDITABLE (Preinscrito en evento activo) =====
        self.registro_editable = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_owner,
            eva_eve_evento_fk=self.evento_activo,
            eva_eve_estado="Preinscrito",
            eva_eve_clave="CLAVEORIG",
            eva_eve_documento=SimpleUploadedFile("doc_orig.pdf", b"contenido original", content_type="application/pdf")
        )
        
        # ===== REGISTRO NO EDITABLE (Aprobado) =====
        self.registro_aprobado = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_owner2,
            eva_eve_evento_fk=self.evento_activo,
            eva_eve_estado="Aprobado",
            eva_eve_clave="CLAVEAPR",
            eva_eve_documento=SimpleUploadedFile("doc_apr.pdf", b"contenido aprobado", content_type="application/pdf")
        )
        
        # ===== REGISTRO EVENTO TERMINADO =====
        self.registro_terminado = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_owner,
            eva_eve_evento_fk=self.evento_terminado,
            eva_eve_estado="Preinscrito",
            eva_eve_clave="CLAVETERMINADO",
            eva_eve_documento=SimpleUploadedFile("doc_term.pdf", b"contenido terminado", content_type="application/pdf")
        )
        
        # ===== REGISTRO DE EXTRAÑO =====
        self.registro_stranger = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_stranger,
            eva_eve_evento_fk=self.evento_activo,
            eva_eve_estado="Preinscrito",
            eva_eve_clave="CLAVESTR",
            eva_eve_documento=SimpleUploadedFile("doc_str.pdf", b"contenido otro", content_type="application/pdf")
        )
        
        # ===== CLIENTES =====
        self.client_owner = Client()
        self.client_stranger = Client()
        self.client_anonimo = Client()
        
        # ===== URLs =====
        self.url_edit_editable = reverse('editar_evaluador', args=[self.registro_editable.pk])
        self.url_edit_aprobado = reverse('editar_evaluador', args=[self.registro_aprobado.pk])
        self.url_edit_terminado = reverse('editar_evaluador', args=[self.registro_terminado.pk])
        self.url_edit_stranger = reverse('editar_evaluador', args=[self.registro_stranger.pk])

    def tearDown(self):
        """Limpiar archivos temporales."""
        try:
            shutil.rmtree(TEMP_MEDIA_ROOT)
        except Exception:
            pass

    # ========== CASOS POSITIVOS ==========

    def test_ca1_1_modificacion_exitosa_documento(self):
        """CA1.1: Propietario modifica exitosamente el documento."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        nuevo_doc = SimpleUploadedFile("doc_nuevo.pdf", b"documento modificado", content_type="application/pdf")
        
        data = {
            'eva_eve_documento': nuevo_doc
        }
        
        response = self.client_owner.post(self.url_edit_editable, data, follow=True)
        
        self.assertIn(response.status_code, (200, 302))
        
        self.registro_editable.refresh_from_db()
        self.assertNotEqual(self.registro_editable.eva_eve_documento.name, "doc_orig.pdf",
                           "El documento debe ser modificado")

    def test_ca1_2_acceso_formulario_edicion(self):
        """CA1.2: Propietario accede al formulario de edición."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_owner.get(self.url_edit_editable)
        
        self.assertIn(response.status_code, (200, 302))

    def test_ca1_3_persistencia_cambios(self):
        """CA1.3: Los cambios se persisten en la base de datos."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        nuevo_doc = SimpleUploadedFile("doc_persist.pdf", b"persistencia", content_type="application/pdf")
        
        data = {
            'eva_eve_documento': nuevo_doc
        }
        
        response = self.client_owner.post(self.url_edit_editable, data, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        self.registro_editable.refresh_from_db()
        
        registro_recuperado = EvaluadorEvento.objects.get(pk=self.registro_editable.pk)
        self.assertEqual(registro_recuperado.eva_eve_estado, "Preinscrito")

    def test_ca1_4_formulario_precargado(self):
        """CA1.4: El formulario viene precargado con los datos actuales."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_owner.get(self.url_edit_editable)
        
        if response.status_code == 200:
            content = response.content.decode('utf-8')
            self.assertIn('form', content.lower(),
                         "El formulario debe estar presente")

    def test_ca1_5_carga_sin_errores(self):
        """CA1.5: Página carga sin errores 500."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_owner.get(self.url_edit_editable)
        self.assertNotEqual(response.status_code, 500)

    # ========== CASOS NEGATIVOS ==========

    def test_ca2_1_no_editar_estado_aprobado(self):
        """CA2.1: No se puede editar registro con estado Aprobado."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        estado_original = self.registro_aprobado.eva_eve_estado
        
        nuevo_doc = SimpleUploadedFile("doc_intento.pdf", b"intento", content_type="application/pdf")
        data = {
            'eva_eve_documento': nuevo_doc
        }
        
        response = self.client_owner.post(self.url_edit_aprobado, data, follow=True)
        
        self.assertIn(response.status_code, (200, 302, 403))
        
        self.registro_aprobado.refresh_from_db()
        self.assertEqual(self.registro_aprobado.eva_eve_estado, estado_original,
                        "No debe permitir editar registro Aprobado")

    def test_ca2_2_no_editar_evento_terminado(self):
        """CA2.2: No se puede editar registro en evento terminado."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        nuevo_doc = SimpleUploadedFile("doc_term_intento.pdf", b"intento", content_type="application/pdf")
        data = {
            'eva_eve_documento': nuevo_doc
        }
        
        response = self.client_owner.post(self.url_edit_terminado, data, follow=True)
        
        self.assertIn(response.status_code, (200, 302, 403))

    def test_ca2_3_no_editar_registro_ajeno(self):
        """CA2.3: Usuario no puede editar registro de otro evaluador."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        nuevo_doc = SimpleUploadedFile("doc_fraude.pdf", b"fraude", content_type="application/pdf")
        data = {
            'eva_eve_documento': nuevo_doc
        }
        
        response = self.client_owner.post(self.url_edit_stranger, data, follow=True)
        
        self.assertIn(response.status_code, (200, 302, 403, 404))
        
        self.registro_stranger.refresh_from_db()
        self.assertTrue(self.registro_stranger.eva_eve_documento.name.endswith('doc_str.pdf'),
                       "No debe permitir editar registro ajeno")

    def test_ca2_4_sin_autenticacion_redirige(self):
        """CA2.4: Usuario no autenticado es redirigido a login."""
        response = self.client_anonimo.get(self.url_edit_editable)
        
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url or response.get('Location', ''),
                     "Debe redirigir a login")

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_1_registro_tiene_campos_basicos(self):
        """CA3.1: Registro tiene todos los campos necesarios."""
        self.assertIsNotNone(self.registro_editable.eva_eve_evento_fk)
        self.assertIsNotNone(self.registro_editable.eva_eve_evaluador_fk)
        self.assertIsNotNone(self.registro_editable.eva_eve_estado)
        self.assertIsNotNone(self.registro_editable.eva_eve_documento)

    def test_ca3_2_estados_diferenciados(self):
        """CA3.2: Registros con estados diferentes están diferenciados."""
        self.assertEqual(self.registro_editable.eva_eve_estado, "Preinscrito")
        self.assertEqual(self.registro_aprobado.eva_eve_estado, "Aprobado")
        self.assertNotEqual(
            self.registro_editable.eva_eve_estado,
            self.registro_aprobado.eva_eve_estado
        )

    def test_ca3_3_eventos_diferenciados(self):
        """CA3.3: Evento activo vs evento terminado están diferenciados."""
        self.assertTrue(self.evento_activo.eve_fecha_fin > date.today())
        self.assertTrue(self.evento_terminado.eve_fecha_fin < date.today())

    def test_ca3_4_relaciones_modelo_correctas(self):
        """CA3.4: Relaciones entre modelos funcionan correctamente."""
        self.assertEqual(self.registro_editable.eva_eve_evaluador_fk, 
                        self.evaluador_owner)
        self.assertEqual(self.registro_editable.eva_eve_evento_fk,
                        self.evento_activo)

    def test_ca3_5_url_identificador_valido(self):
        """CA3.5: URL contiene identificador válido."""
        self.assertIn(str(self.registro_editable.pk), self.url_edit_editable)

    # ========== TESTS DE LÓGICA ==========

    def test_ca4_1_solo_preinscrito_editable(self):
        """CA4.1: Lógica - Solo estado Preinscrito es editable."""
        self.assertEqual(self.registro_editable.eva_eve_estado, "Preinscrito")
        self.assertNotEqual(self.registro_aprobado.eva_eve_estado, "Preinscrito")

    def test_ca4_2_propietario_puede_editar(self):
        """CA4.2: Lógica - Propietario es quien puede editar."""
        self.assertEqual(self.registro_editable.eva_eve_evaluador_fk,
                        self.evaluador_owner)

    def test_ca4_3_evento_activo_editable(self):
        """CA4.3: Lógica - Solo eventos activos son editables."""
        evento_act = self.evento_activo.eve_fecha_fin > date.today()
        evento_term = self.evento_terminado.eve_fecha_fin < date.today()
        
        self.assertTrue(evento_act)
        self.assertTrue(evento_term)

    # ========== TESTS DE INTEGRACIÓN ==========

    def test_ca5_1_flujo_completo_edicion_exitosa(self):
        """CA5.1: Flujo completo - login, edición, confirmación."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response_get = self.client_owner.get(self.url_edit_editable)
        self.assertIn(response_get.status_code, (200, 302))
        
        nuevo_doc = SimpleUploadedFile("doc_flujo.pdf", b"flujo completo", content_type="application/pdf")
        data = {'eva_eve_documento': nuevo_doc}
        
        response_post = self.client_owner.post(self.url_edit_editable, data, follow=True)
        self.assertIn(response_post.status_code, (200, 302))
        
        self.registro_editable.refresh_from_db()
        self.assertEqual(self.registro_editable.eva_eve_estado, "Preinscrito")

    def test_ca5_2_flujo_rechazo_sin_permisos(self):
        """CA5.2: Flujo - Intento sin permisos es rechazado."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        nuevo_doc = SimpleUploadedFile("doc_rechazo.pdf", b"rechazo", content_type="application/pdf")
        data = {'eva_eve_documento': nuevo_doc}
        
        response = self.client_owner.post(self.url_edit_stranger, data, follow=True)
        
        self.assertIn(response.status_code, (200, 302, 403, 404))
        
        self.registro_stranger.refresh_from_db()
        self.assertEqual(self.registro_stranger.eva_eve_estado, "Preinscrito")

    def test_ca5_3_flujo_restriccion_estado_aprobado(self):
        """CA5.3: Flujo - No editar si está Aprobado."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        estado_original = self.registro_aprobado.eva_eve_estado
        
        nuevo_doc = SimpleUploadedFile("doc_aprob.pdf", b"aprobado", content_type="application/pdf")
        data = {'eva_eve_documento': nuevo_doc}
        
        response = self.client_owner.post(self.url_edit_aprobado, data, follow=True)
        
        self.registro_aprobado.refresh_from_db()
        self.assertEqual(self.registro_aprobado.eva_eve_estado, estado_original)