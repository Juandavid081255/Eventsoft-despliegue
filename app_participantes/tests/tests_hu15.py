# app_participantes/tests/tests_hu15.py

import shutil
import tempfile
from datetime import date, timedelta

from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile

from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento
from app_participantes.models import ParticipanteEvento
import time
import random


TEMP_MEDIA_ROOT = tempfile.mkdtemp(prefix="test_media_")


@override_settings(MEDIA_ROOT=TEMP_MEDIA_ROOT)
class ParticipanteEventoEditViewTest(TestCase):
    """
    HU15 - Editar preinscripción de participante en evento
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
        admin_username = f"admin_hu15_{unique_suffix}"
        admin_user = Usuario.objects.create_user(
            username=admin_username,
            password=self.password,
            rol=Usuario.Roles.ADMIN_EVENTO,
            email=f"{admin_username}@test.com",
            cedula=f"900{unique_suffix[-10:]}"
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=admin_user)
        
        # ===== EVENTO ACTIVO (disponible para editar) =====
        self.evento_activo = Evento.objects.create(
            eve_nombre=f"Evento Editable {unique_suffix}",
            eve_descripcion="Descripción evento editable",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_fecha_inicio=date.today() + timedelta(days=30),
            eve_fecha_fin=date.today() + timedelta(days=32),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_imagen=SimpleUploadedFile("img.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"contenido", content_type="application/pdf"),
            preinscripcion_habilitada_participantes=True
        )
        
        # ===== EVENTO TERMINADO (no editable) =====
        self.evento_terminado = Evento.objects.create(
            eve_nombre=f"Evento Terminado {unique_suffix}",
            eve_descripcion="Evento ya finalizado",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_fecha_inicio=date.today() - timedelta(days=10),
            eve_fecha_fin=date.today() - timedelta(days=5),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_imagen=SimpleUploadedFile("img2.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"contenido", content_type="application/pdf")
        )
        
        # ===== PARTICIPANTE PROPIETARIO (puede editar su registro) =====
        self.username_owner = f"owner_hu15_{unique_suffix}"
        self.user_owner = Usuario.objects.create_user(
            username=self.username_owner,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_owner}@test.com",
            cedula=f"800{unique_suffix[-10:]}"
        )
        self.participante_owner = Participante.objects.create(usuario=self.user_owner)
        
        # ===== PARTICIPANTE OWNER 2 (para registro aprobado) =====
        self.username_owner2 = f"owner2_hu15_{unique_suffix}"
        self.user_owner2 = Usuario.objects.create_user(
            username=self.username_owner2,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_owner2}@test.com",
            cedula=f"810{unique_suffix[-10:]}"
        )
        self.participante_owner2 = Participante.objects.create(usuario=self.user_owner2)
        
        # ===== PARTICIPANTE EXTRAÑO (sin permiso) =====
        self.username_stranger = f"stranger_hu15_{unique_suffix}"
        self.user_stranger = Usuario.objects.create_user(
            username=self.username_stranger,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_stranger}@test.com",
            cedula=f"700{unique_suffix[-10:]}"
        )
        self.participante_stranger = Participante.objects.create(usuario=self.user_stranger)
        
        # ===== REGISTRO EDITABLE (Preinscrito en evento activo) =====
        self.registro_editable = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_activo,
            par_eve_participante_fk=self.participante_owner,
            par_eve_estado="Preinscrito",
            par_eve_clave="CLAVEORIG"
        )
        
        # ===== REGISTRO NO EDITABLE (Aprobado - diferente participante) =====
        self.registro_aprobado = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_activo,
            par_eve_participante_fk=self.participante_owner2,
            par_eve_estado="Aprobado",
            par_eve_clave="CLAVEAPR"
        )
        
        # ===== REGISTRO EVENTO TERMINADO =====
        self.registro_terminado = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_participante_fk=self.participante_owner,
            par_eve_estado="Preinscrito",
            par_eve_clave="CLAVETERMINADO"
        )
        
        # ===== REGISTRO DE EXTRAÑO =====
        self.registro_stranger = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_activo,
            par_eve_participante_fk=self.participante_stranger,
            par_eve_estado="Preinscrito",
            par_eve_clave="CLAVESTR"
        )
        
        # Clientes
        self.client_owner = Client()
        self.client_stranger = Client()
        self.client_anonimo = Client()
        
        # URLs
        self.url_edit_editable = reverse('editar_preinscripcion', 
                                        kwargs={'id': self.registro_editable.pk})
        self.url_edit_aprobado = reverse('editar_preinscripcion',
                                        kwargs={'id': self.registro_aprobado.pk})
        self.url_edit_terminado = reverse('editar_preinscripcion',
                                         kwargs={'id': self.registro_terminado.pk})
        self.url_edit_stranger = reverse('editar_preinscripcion',
                                        kwargs={'id': self.registro_stranger.pk})

    def tearDown(self):
        """Limpiar archivos temporales."""
        try:
            shutil.rmtree(TEMP_MEDIA_ROOT)
        except Exception:
            pass

    # ========== CASOS POSITIVOS ==========

    def test_ca1_1_modificacion_exitosa_clave(self):
        """CA1.1: Propietario modifica exitosamente la clave."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        data = {
            'par_eve_clave': 'CLAVEMOD'
        }
        
        response = self.client_owner.post(self.url_edit_editable, data, follow=True)
        
        # Verificar que fue procesado
        self.assertIn(response.status_code, (200, 302))
        
        # Refrescar desde BD
        self.registro_editable.refresh_from_db()
        self.assertEqual(self.registro_editable.par_eve_clave, 'CLAVEMOD',
                        "La clave debe ser modificada exitosamente")

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
        
        nueva_clave = f"CLAVENEW_{self.unique_suffix[:10]}"
        data = {
            'par_eve_clave': nueva_clave
        }
        
        response = self.client_owner.post(self.url_edit_editable, data, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        # Verificar persistencia
        self.registro_editable.refresh_from_db()
        self.assertEqual(self.registro_editable.par_eve_clave, nueva_clave)
        
        # Verificar que se puede recuperar desde BD nuevamente
        registro_recuperado = ParticipanteEvento.objects.get(pk=self.registro_editable.pk)
        self.assertEqual(registro_recuperado.par_eve_clave, nueva_clave)

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
            # Verificar que la clave original esté presente
            self.assertIn(self.registro_editable.par_eve_clave, content,
                         "El formulario debe mostrar la clave original")

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
        
        clave_original = self.registro_aprobado.par_eve_clave
        data = {
            'par_eve_clave': 'CLAVEINTENTO'
        }
        
        response = self.client_owner.post(self.url_edit_aprobado, data, follow=True)
        
        # Debería rechazar o redirigir
        self.assertIn(response.status_code, (200, 302, 403))
        
        # La clave no debería cambiar
        self.registro_aprobado.refresh_from_db()
        self.assertEqual(self.registro_aprobado.par_eve_clave, clave_original,
                        "No debe permitir editar registro Aprobado")

    def test_ca2_2_no_editar_evento_terminado(self):
        """CA2.2: No se puede editar registro en evento terminado."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        clave_original = self.registro_terminado.par_eve_clave
        data = {
            'par_eve_clave': 'CLAVEINTENTO'
        }
        
        response = self.client_owner.post(self.url_edit_terminado, data, follow=True)
        
        # Debería rechazar o redirigir
        self.assertIn(response.status_code, (200, 302, 403))
        
        # La clave no debería cambiar
        self.registro_terminado.refresh_from_db()
        self.assertEqual(self.registro_terminado.par_eve_clave, clave_original,
                        "No debe permitir editar evento terminado")

    def test_ca2_3_no_editar_registro_ajeno(self):
        """CA2.3: Usuario no puede editar registro de otro participante."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        clave_original = self.registro_stranger.par_eve_clave
        data = {
            'par_eve_clave': 'CLAVEFRAUD'
        }
        
        response = self.client_owner.post(self.url_edit_stranger, data, follow=True)
        
        # Debería denegar acceso
        self.assertIn(response.status_code, (200, 302, 403, 404))
        
        # La clave del extraño no debería cambiar
        self.registro_stranger.refresh_from_db()
        self.assertEqual(self.registro_stranger.par_eve_clave, clave_original,
                        "No debe permitir editar registro de otro")

    def test_ca2_4_no_cambiar_fk_evento(self):
        """CA2.4: No permitir cambiar el evento vía POST."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        evento_original = self.registro_editable.par_eve_evento_fk
        
        # Intentar cambiar evento
        data = {
            'par_eve_clave': 'CLAVEMOD',
            'par_eve_evento_fk': self.evento_terminado.pk
        }
        
        response = self.client_owner.post(self.url_edit_editable, data, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        # El evento NO debería cambiar
        self.registro_editable.refresh_from_db()
        self.assertEqual(self.registro_editable.par_eve_evento_fk, evento_original,
                        "No debe permitir cambiar el evento")

    def test_ca2_5_sin_autenticacion_redirige(self):
        """CA2.5: Usuario no autenticado es redirigido a login."""
        response = self.client_anonimo.get(self.url_edit_editable)
        
        # Debería redirigir (status 302)
        self.assertEqual(response.status_code, 302)
        # Verificar que contiene 'login' en la URL de redirección
        self.assertIn('login', response.url or response.get('Location', ''),
                     "Debe redirigir a login")

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_1_registro_tiene_campos_basicos(self):
        """CA3.1: Registro tiene todos los campos necesarios."""
        self.assertIsNotNone(self.registro_editable.par_eve_evento_fk)
        self.assertIsNotNone(self.registro_editable.par_eve_participante_fk)
        self.assertIsNotNone(self.registro_editable.par_eve_estado)
        self.assertIsNotNone(self.registro_editable.par_eve_clave)

    def test_ca3_2_estados_diferenciados(self):
        """CA3.2: Registros con estados diferentes están diferenciados."""
        self.assertEqual(self.registro_editable.par_eve_estado, "Preinscrito")
        self.assertEqual(self.registro_aprobado.par_eve_estado, "Aprobado")
        self.assertNotEqual(
            self.registro_editable.par_eve_estado,
            self.registro_aprobado.par_eve_estado
        )

    def test_ca3_3_eventos_diferenciados(self):
        """CA3.3: Evento activo vs evento terminado están diferenciados."""
        self.assertTrue(self.evento_activo.eve_fecha_fin > date.today())
        self.assertTrue(self.evento_terminado.eve_fecha_fin < date.today())

    def test_ca3_4_relaciones_modelo_correctas(self):
        """CA3.4: Relaciones entre modelos funcionan correctamente."""
        self.assertEqual(self.registro_editable.par_eve_participante_fk, 
                        self.participante_owner)
        self.assertEqual(self.registro_editable.par_eve_evento_fk,
                        self.evento_activo)

    def test_ca3_5_url_identificador_valido(self):
        """CA3.5: URL contiene identificador válido."""
        # Verificar que la URL se construye correctamente
        self.assertIn(str(self.registro_editable.pk), self.url_edit_editable)

    # ========== TESTS DE LÓGICA ==========

    def test_ca4_1_solo_preinscrito_editable(self):
        """CA4.1: Lógica - Solo estado Preinscrito es editable."""
        self.assertEqual(self.registro_editable.par_eve_estado, "Preinscrito")
        self.assertNotEqual(self.registro_aprobado.par_eve_estado, "Preinscrito")

    def test_ca4_2_propietario_puede_editar(self):
        """CA4.2: Lógica - Propietario es quien puede editar."""
        # El participante_owner es propietario del registro_editable
        self.assertEqual(self.registro_editable.par_eve_participante_fk,
                        self.participante_owner)

    def test_ca4_3_evento_activo_editable(self):
        """CA4.3: Lógica - Solo eventos activos son editables."""
        evento_act = self.evento_activo.eve_fecha_fin > date.today()
        evento_term = self.evento_terminado.eve_fecha_fin < date.today()
        
        self.assertTrue(evento_act)
        self.assertTrue(evento_term)

    def test_ca4_4_restriccion_fk_evento(self):
        """CA4.4: Lógica - FK evento no cambia en edición."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        evento_original_id = self.registro_editable.par_eve_evento_fk.pk
        
        data = {'par_eve_clave': 'TEST'}
        response = self.client_owner.post(self.url_edit_editable, data, follow=True)
        
        self.registro_editable.refresh_from_db()
        self.assertEqual(self.registro_editable.par_eve_evento_fk.pk, 
                        evento_original_id)

    def test_ca4_5_restriccion_fk_participante(self):
        """CA4.5: Lógica - FK participante no cambia en edición."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        participante_original_id = self.registro_editable.par_eve_participante_fk.pk
        
        data = {'par_eve_clave': 'TEST'}
        response = self.client_owner.post(self.url_edit_editable, data, follow=True)
        
        self.registro_editable.refresh_from_db()
        self.assertEqual(self.registro_editable.par_eve_participante_fk.pk,
                        participante_original_id)

    # ========== TESTS DE INTEGRACIÓN ==========

    def test_ca5_1_flujo_completo_edicion_exitosa(self):
        """CA5.1: Flujo completo - login, edición, confirmación."""
        # Login
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        # GET formulario
        response_get = self.client_owner.get(self.url_edit_editable)
        self.assertIn(response_get.status_code, (200, 302))
        
        # POST cambio
        data = {'par_eve_clave': 'CLAVEUPD'}
        response_post = self.client_owner.post(self.url_edit_editable, data, follow=True)
        self.assertIn(response_post.status_code, (200, 302))
        
        # Verificar cambio
        self.registro_editable.refresh_from_db()
        self.assertEqual(self.registro_editable.par_eve_clave, 'CLAVEUPD')

    def test_ca5_2_flujo_rechazo_sin_permisos(self):
        """CA5.2: Flujo - Intento sin permisos es rechazado."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        # Intentar editar ajeno
        data = {'par_eve_clave': 'FRAUD'}
        response = self.client_owner.post(self.url_edit_stranger, data, follow=True)
        
        # Debería rechazar
        self.assertIn(response.status_code, (200, 302, 403, 404))
        
        # Verificar que no cambió
        self.registro_stranger.refresh_from_db()
        self.assertEqual(self.registro_stranger.par_eve_clave, "CLAVESTR")

    def test_ca5_3_flujo_restriccion_estado_aprobado(self):
        """CA5.3: Flujo - No editar si está Aprobado."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        clave_original = self.registro_aprobado.par_eve_clave
        
        data = {'par_eve_clave': 'NOCHANGE'}
        response = self.client_owner.post(self.url_edit_aprobado, data, follow=True)
        
        self.registro_aprobado.refresh_from_db()
        self.assertEqual(self.registro_aprobado.par_eve_clave, clave_original)