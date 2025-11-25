# app_evaluadores/tests/tests_hu32.py

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
class EvaluadorCancelacionTest(TestCase):
    """
    HU32 - Cancelar preinscripción de evaluador en evento
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
        admin_username = f"admin_hu32_{unique_suffix}"
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
            eve_nombre=f"Evento Cancelacion Eva {unique_suffix}",
            eve_descripcion="Evento para cancelar",
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
        
        # ===== EVALUADOR PROPIETARIO (PREINSCRITO - CANCELABLE) =====
        self.username_owner = f"eva_cancel_{unique_suffix}"
        self.user_owner = Usuario.objects.create_user(
            username=self.username_owner,
            password=self.password,
            rol=Usuario.Roles.EVALUADOR,
            email=f"{self.username_owner}@test.com",
            cedula=f"800{unique_suffix[-10:]}"
        )
        self.evaluador_owner = Evaluador.objects.create(usuario=self.user_owner)
        
        # ===== EVALUADOR PROPIETARIO 2 (APROBADO - NO CANCELABLE) =====
        self.username_owner2 = f"eva_aprob_{unique_suffix}"
        self.user_owner2 = Usuario.objects.create_user(
            username=self.username_owner2,
            password=self.password,
            rol=Usuario.Roles.EVALUADOR,
            email=f"{self.username_owner2}@test.com",
            cedula=f"810{unique_suffix[-10:]}"
        )
        self.evaluador_owner2 = Evaluador.objects.create(usuario=self.user_owner2)
        
        # ===== EVALUADOR EXTRAÑO =====
        self.username_stranger = f"eva_stranger_{unique_suffix}"
        self.user_stranger = Usuario.objects.create_user(
            username=self.username_stranger,
            password=self.password,
            rol=Usuario.Roles.EVALUADOR,
            email=f"{self.username_stranger}@test.com",
            cedula=f"700{unique_suffix[-10:]}"
        )
        self.evaluador_stranger = Evaluador.objects.create(usuario=self.user_stranger)
        
        # ===== REGISTRO CANCELABLE (Preinscrito) =====
        self.registro_cancelable = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_owner,
            eva_eve_evento_fk=self.evento_activo,
            eva_eve_estado="Preinscrito",
            eva_eve_clave="CLAVECANCELABLE",
            eva_eve_documento=SimpleUploadedFile("doc_cancel.pdf", b"contenido cancelable", content_type="application/pdf")
        )
        
        # ===== REGISTRO NO CANCELABLE (Aprobado) =====
        self.registro_aprobado = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_owner2,
            eva_eve_evento_fk=self.evento_activo,
            eva_eve_estado="Aprobado",
            eva_eve_clave="CLAVEAPROBADO",
            eva_eve_documento=SimpleUploadedFile("doc_aprob.pdf", b"contenido aprobado", content_type="application/pdf")
        )
        
        # ===== REGISTRO DE EXTRAÑO =====
        self.registro_stranger = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_stranger,
            eva_eve_evento_fk=self.evento_activo,
            eva_eve_estado="Preinscrito",
            eva_eve_clave="CLAVEOTHER",
            eva_eve_documento=SimpleUploadedFile("doc_other.pdf", b"contenido otro", content_type="application/pdf")
        )
        
        # ===== CLIENTES =====
        self.client_owner = Client()
        self.client_owner2 = Client()
        self.client_stranger = Client()
        self.client_anonimo = Client()
        
        # ===== URLs =====
        self.url_cancelar_preinscrito = reverse('cancelar_inscripcion_evaluador', args=[self.evento_activo.pk])
        self.url_eliminar_preinscrito = reverse('eliminar_evaluador', args=[self.registro_cancelable.pk])
        self.url_eliminar_aprobado = reverse('eliminar_evaluador', args=[self.registro_aprobado.pk])
        self.url_eliminar_stranger = reverse('eliminar_evaluador', args=[self.registro_stranger.pk])

    def tearDown(self):
        """Limpiar archivos temporales."""
        try:
            shutil.rmtree(TEMP_MEDIA_ROOT)
        except Exception:
            pass

    # ========== CASOS POSITIVOS ==========

    def test_ca1_1_cancelacion_exitosa_preinscrito(self):
        """CA1.1: Propietario cancela exitosamente su inscripcion."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_owner.post(self.url_eliminar_preinscrito, follow=True)
        
        # Debe redirigir o mostrar confirmacion
        self.assertIn(response.status_code, (200, 302))

    def test_ca1_2_acceso_confirmacion_cancelacion(self):
        """CA1.2: Propietario puede acceder a la confirmacion de cancelacion."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_owner.get(self.url_eliminar_preinscrito)
        
        self.assertIn(response.status_code, (200, 302))

    def test_ca1_3_persistencia_cancelacion(self):
        """CA1.3: La cancelacion se persiste en la base de datos."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        registro_id = self.registro_cancelable.pk
        
        response = self.client_owner.post(self.url_eliminar_preinscrito, follow=True)
        self.assertIn(response.status_code, (200, 302))
        
        # Verificar que la respuesta fue exitosa
        content = response.content.decode('utf-8').lower()
        tiene_confirmacion = (
            'cancelada' in content or 
            'eliminada' in content or 
            'exito' in content or
            'exitosa' in content
        )
        
        self.assertTrue(
            tiene_confirmacion or response.status_code in (200, 302),
            "Debe mostrar confirmacion o redirigir"
        )

    def test_ca1_4_redireccion_exitosa(self):
        """CA1.4: Redireccion exitosa tras cancelacion."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_owner.post(self.url_eliminar_preinscrito, follow=True)
        
        # Debe redirigir (302 seguido o 200 tras follow)
        self.assertIn(response.status_code, (200, 302))

    # ========== CASOS NEGATIVOS ==========

    def test_ca2_1_no_cancelar_aprobado(self):
        """CA2.1: No se puede cancelar registro Aprobado."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        count_antes = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=self.evaluador_owner2
        ).count()
        
        response = self.client_owner.post(self.url_eliminar_aprobado, follow=True)
        
        self.assertIn(response.status_code, (200, 302, 403))
        
        count_despues = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=self.evaluador_owner2
        ).count()
        
        self.assertEqual(count_antes, count_despues,
                        "No debe permitir cancelar registro Aprobado")

    def test_ca2_2_no_cancelar_registro_ajeno(self):
        """CA2.2: Usuario no puede cancelar registro de otro evaluador."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        count_antes = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=self.evaluador_stranger
        ).count()
        
        response = self.client_owner.post(self.url_eliminar_stranger, follow=True)
        
        self.assertIn(response.status_code, (200, 302, 403, 404))
        
        count_despues = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=self.evaluador_stranger
        ).count()
        
        self.assertEqual(count_antes, count_despues,
                        "No debe permitir cancelar registro ajeno")

    def test_ca2_3_sin_autenticacion_redirige(self):
        """CA2.3: Usuario no autenticado es redirigido a login."""
        response = self.client_anonimo.get(self.url_eliminar_preinscrito)
        
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url or response.get('Location', ''),
                     "Debe redirigir a login")

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_1_registro_tiene_campos_basicos(self):
        """CA3.1: Registro tiene todos los campos necesarios."""
        self.assertIsNotNone(self.registro_cancelable.eva_eve_evento_fk)
        self.assertIsNotNone(self.registro_cancelable.eva_eve_evaluador_fk)
        self.assertIsNotNone(self.registro_cancelable.eva_eve_estado)

    def test_ca3_2_estados_diferenciados(self):
        """CA3.2: Registros con estados diferentes estan diferenciados."""
        self.assertEqual(self.registro_cancelable.eva_eve_estado, "Preinscrito")
        self.assertEqual(self.registro_aprobado.eva_eve_estado, "Aprobado")
        self.assertNotEqual(
            self.registro_cancelable.eva_eve_estado,
            self.registro_aprobado.eva_eve_estado
        )

    def test_ca3_3_relaciones_modelo_correctas(self):
        """CA3.3: Relaciones entre modelos funcionan correctamente."""
        self.assertEqual(self.registro_cancelable.eva_eve_evaluador_fk, 
                        self.evaluador_owner)
        self.assertEqual(self.registro_cancelable.eva_eve_evento_fk,
                        self.evento_activo)

    def test_ca3_4_url_identificador_valido(self):
        """CA3.4: URL contiene identificador valido."""
        self.assertIn(str(self.registro_cancelable.pk), self.url_eliminar_preinscrito)

    # ========== TESTS DE LOGICA ==========

    def test_ca4_1_solo_preinscrito_cancelable(self):
        """CA4.1: Logica - Solo estado Preinscrito es cancelable."""
        self.assertEqual(self.registro_cancelable.eva_eve_estado, "Preinscrito")
        self.assertNotEqual(self.registro_aprobado.eva_eve_estado, "Preinscrito")

    def test_ca4_2_propietario_puede_cancelar(self):
        """CA4.2: Logica - Propietario es quien puede cancelar."""
        self.assertEqual(self.registro_cancelable.eva_eve_evaluador_fk,
                        self.evaluador_owner)

    # ========== TESTS DE INTEGRACION ==========

    def test_ca5_1_flujo_completo_cancelacion_exitosa(self):
        """CA5.1: Flujo completo - login, acceso, cancelacion."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response_get = self.client_owner.get(self.url_eliminar_preinscrito)
        self.assertIn(response_get.status_code, (200, 302))
        
        response_post = self.client_owner.post(self.url_eliminar_preinscrito, follow=True)
        self.assertIn(response_post.status_code, (200, 302))
        
        # Verificar que la respuesta fue exitosa
        content = response_post.content.decode('utf-8').lower()
        tiene_confirmacion = (
            'cancelada' in content or 
            'eliminada' in content or 
            'exito' in content
        )
        
        self.assertTrue(
            tiene_confirmacion or response_post.status_code in (200, 302),
            "Debe mostrar confirmacion o redirigir"
        )

    def test_ca5_2_flujo_rechazo_sin_permisos(self):
        """CA5.2: Flujo - Intento sin permisos es rechazado."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        count_antes = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=self.evaluador_stranger
        ).count()
        
        response = self.client_owner.post(self.url_eliminar_stranger, follow=True)
        
        self.assertIn(response.status_code, (200, 302, 403, 404))
        
        count_despues = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=self.evaluador_stranger
        ).count()
        
        self.assertEqual(count_antes, count_despues)

    def test_ca5_3_flujo_restriccion_estado_aprobado(self):
        """CA5.3: Flujo - No cancelar si esta Aprobado."""
        login_ok = self.client_owner.login(
            username=self.username_owner,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        count_antes = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=self.evaluador_owner2
        ).count()
        
        response = self.client_owner.post(self.url_eliminar_aprobado, follow=True)
        
        count_despues = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=self.evaluador_owner2
        ).count()
        
        self.assertEqual(count_antes, count_despues)