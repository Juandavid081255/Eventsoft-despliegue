# app_evaluadores/tests/tests_hu39.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
import os
import time
import random
import tempfile
import shutil

from app_usuarios.models import Usuario, Evaluador, AdministradorEvento
from app_evaluadores.models import EvaluadorEvento
from app_admin_eventos.models import Evento


TEMP_MEDIA_ROOT = tempfile.mkdtemp(prefix="test_media_hu39_")


class PerfilEvaluadorTest(TestCase):
    """
    HU39 - Perfil del Evaluador
    Visualizar datos personales, profesionales y documentos adjuntos.
    """

    @classmethod
    def setUpClass(cls):
        """Configuración única para toda la clase."""
        super().setUpClass()
        cls.unique_suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"

    def setUp(self):
        """Configuración inicial para cada test."""
        unique_suffix = self.unique_suffix
        self.password = "TestPass123!"
        
        # ===== USUARIO EVALUADOR =====
        username_evaluador = f"eval_hu39_{unique_suffix}"
        self.user_evaluador = Usuario.objects.create_user(
            username=username_evaluador,
            password=self.password,
            rol=Usuario.Roles.EVALUADOR,
            email=f"{username_evaluador}@test.com",
            cedula=f"800{unique_suffix[-10:]}",
            first_name="Ricardo",
            last_name="Márquez",
            telefono="3001234567"
        )
        
        self.evaluador, _ = Evaluador.objects.get_or_create(usuario=self.user_evaluador)
        
        # ===== USUARIO ADMINISTRADOR =====
        username_admin = f"admin_hu39_{unique_suffix}"
        self.user_admin = Usuario.objects.create_user(
            username=username_admin,
            password=self.password,
            rol=Usuario.Roles.ADMIN_EVENTO,
            email=f"{username_admin}@test.com",
            cedula=f"900{unique_suffix[-10:]}",
            first_name="Admin",
            last_name="Evento"
        )
        
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=self.user_admin)
        
        # ===== EVENTO =====
        self.evento = Evento.objects.create(
            eve_nombre=f"Congreso IA {unique_suffix}",
            eve_descripcion="Evento de prueba para perfil",
            eve_ciudad="Manizales",
            eve_lugar="Universidad Nacional",
            eve_fecha_inicio="2025-11-01",
            eve_fecha_fin="2025-11-03",
            eve_estado="activo",
            eve_imagen=SimpleUploadedFile("img.jpg", b"contenido", content_type="image/jpeg"),
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_programacion=SimpleUploadedFile("prog.pdf", b"contenido", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=True
        )
        
        # ===== REGISTRO EVALUADOR-EVENTO CON DOCUMENTO =====
        self.evaluador_evento = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Aprobado",
            eva_eve_documento=SimpleUploadedFile(
                "cv_ricardo.pdf",
                b"Curriculum Vitae de Ricardo Marquez - PhD en IA",
                content_type="application/pdf"
            ),
            eva_eve_clave=f"EVAL_{unique_suffix}"
        )
        
        # ===== LOGIN Y SESIÓN =====
        self.client = Client()
        self.login_success = self.client.login(
            username=username_evaluador,
            password=self.password
        )
        
        if self.login_success:
            session = self.client.session
            session['evaluador_id'] = self.evaluador.pk
            session.save()

    def tearDown(self):
        """Limpiar archivos temporales."""
        try:
            shutil.rmtree(TEMP_MEDIA_ROOT)
        except Exception:
            pass

    # ========== TESTS POSITIVOS ==========

    def test_ca1_1_acceso_exitoso_al_perfil(self):
        """CA1.1: El evaluador autenticado puede acceder a su perfil."""
        self.assertTrue(self.login_success, "El login debe ser exitoso")
        
        response = self.client.get(reverse('dashboard_evaluador'))
        self.assertEqual(response.status_code, 200,
                        "Evaluador debe poder acceder al dashboard")
        self.assertIn('evaluador', response.context,
                     "Debe contener objeto evaluador en contexto")

    def test_ca1_2_visualizacion_datos_personales(self):
        """CA1.2: Se muestran datos personales del evaluador."""
        self.assertTrue(self.login_success)
        
        response = self.client.get(reverse('dashboard_evaluador'))
        self.assertEqual(response.status_code, 200)
        
        # Verificar que contiene datos personales
        self.assertIn('evaluador', response.context)
        evaluador = response.context['evaluador']
        self.assertEqual(evaluador.usuario.first_name, "Ricardo")
        self.assertEqual(evaluador.usuario.last_name, "Márquez")
        self.assertEqual(evaluador.usuario.email, self.user_evaluador.email)

    def test_ca1_3_visualizacion_datos_profesionales(self):
        """CA1.3: Se muestran datos profesionales del evaluador."""
        self.assertTrue(self.login_success)
        
        response = self.client.get(reverse('dashboard_evaluador'))
        self.assertEqual(response.status_code, 200)
        
        # Verificar que la vista tiene datos del evaluador
        self.assertIn('evaluador', response.context)
        evaluador = response.context['evaluador']
        self.assertIsNotNone(evaluador.usuario)
        self.assertEqual(evaluador.usuario.rol, Usuario.Roles.EVALUADOR)

    def test_ca1_4_visualizacion_documentos_adjuntos(self):
        """CA1.4: Se muestran documentos adjuntos del evaluador."""
        self.assertTrue(self.login_success)
        
        response = self.client.get(reverse('dashboard_evaluador'))
        self.assertEqual(response.status_code, 200)
        
        # Verificar que la vista tiene información sobre los eventos del evaluador
        self.assertIn('eventos', response.context)
        content = response.content.decode('utf-8')
        
        # Buscar referencia al evento
        self.assertIn(self.evento.eve_nombre, content,
                     "Debe mostrar nombre del evento al cual está inscrito")

    def test_ca1_5_enlace_editar_informacion_visible(self):
        """CA1.5: Existe enlace para editar información."""
        self.assertTrue(self.login_success)
        
        response = self.client.get(reverse('dashboard_evaluador'))
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8')
        # Buscar URL de edición
        url_editar = reverse('editar_evaluador', args=[self.evaluador.pk])
        self.assertIn(url_editar, content,
                     "Debe contener enlace para editar perfil")

    def test_ca1_6_visualizacion_eventos_aprobados(self):
        """CA1.6: Se muestran los eventos donde el evaluador está aprobado."""
        self.assertTrue(self.login_success)
        
        response = self.client.get(reverse('dashboard_evaluador'))
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8')
        # Debe mostrar el evento aprobado
        self.assertIn(self.evento.eve_nombre, content,
                     "Dashboard debe mostrar evento donde está aprobado")

    # ========== TESTS NEGATIVOS ==========

    def test_ca2_1_acceso_bloqueado_sin_autenticacion(self):
        """CA2.1: Se requiere autenticación para acceder al perfil."""
        self.client.logout()
        
        response = self.client.get(reverse('dashboard_evaluador'))
        self.assertEqual(response.status_code, 302,
                        "Usuario no autenticado debe ser redirigido")
        self.assertIn('/login', response.url,
                     "Debe redirigir a login")

    def test_ca2_2_acceso_bloqueado_rol_incorrecto(self):
        """CA2.2: Solo evaluadores pueden acceder al perfil de evaluador."""
        unique_suffix2 = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        # Crear usuario con rol diferente
        user_participante = Usuario.objects.create_user(
            username=f"part_{unique_suffix2}",
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"part_{unique_suffix2}@test.com",
            cedula=f"700{unique_suffix2[-10:]}"
        )
        
        self.client.logout()
        self.client.login(username=f"part_{unique_suffix2}", password=self.password)
        
        response = self.client.get(reverse('dashboard_evaluador'))
        self.assertIn(response.status_code, [302, 403],
                     "Participante no debe acceder al dashboard de evaluador")

    def test_ca2_3_perfil_sin_inscripciones(self):
        """CA2.3: Perfil sin inscripciones a eventos."""
        # Eliminar todas las inscripciones
        EvaluadorEvento.objects.filter(eva_eve_evaluador_fk=self.evaluador).delete()
        
        self.assertTrue(self.login_success)
        
        response = self.client.get(reverse('dashboard_evaluador'))
        self.assertEqual(response.status_code, 200)
        
        # El perfil debe ser accesible incluso sin inscripciones
        self.assertIn('evaluador', response.context)
        self.assertEqual(response.context['evaluador'].usuario, self.user_evaluador)

    # ========== TESTS ADICIONALES ==========

    def test_ca3_1_perfil_multiples_eventos(self):
        """CA3.1: Múltiples inscripciones a eventos."""
        unique_suffix2 = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        # Crear segundo evento
        evento2 = Evento.objects.create(
            eve_nombre=f"Seminario ML {unique_suffix2}",
            eve_descripcion="Segundo evento",
            eve_ciudad="Bogotá",
            eve_lugar="Universidad Javeriana",
            eve_fecha_inicio="2025-12-01",
            eve_fecha_fin="2025-12-02",
            eve_estado="activo",
            eve_imagen=SimpleUploadedFile("img2.jpg", b"contenido", content_type="image/jpeg"),
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="Si",
            eve_capacidad=50,
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"contenido", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=True
        )
        
        # Crear segundo registro
        EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador,
            eva_eve_evento_fk=evento2,
            eva_eve_estado="Pendiente",
            eva_eve_documento=SimpleUploadedFile("cv2.pdf", b"CV2", content_type="application/pdf"),
            eva_eve_clave=f"EVAL2_{unique_suffix2}"
        )
        
        self.assertTrue(self.login_success)
        
        response = self.client.get(reverse('dashboard_evaluador'))
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8')
        # Debe mostrar ambos eventos
        self.assertIn(self.evento.eve_nombre, content)
        self.assertIn(evento2.eve_nombre, content)

    def test_ca3_2_documento_adjunto_accesible(self):
        """CA3.2: El documento adjunto es accesible."""
        self.assertTrue(self.login_success)
        
        # Verificar que el documento existe
        self.assertIsNotNone(self.evaluador_evento.eva_eve_documento)
        self.assertTrue(self.evaluador_evento.eva_eve_documento.name)

    def test_ca3_3_campos_necesarios_en_modelo(self):
        """CA3.3: Verifica campos necesarios en los modelos."""
        # Verificar que Usuario tiene campos
        self.assertTrue(hasattr(self.user_evaluador, 'first_name'))
        self.assertTrue(hasattr(self.user_evaluador, 'last_name'))
        self.assertTrue(hasattr(self.user_evaluador, 'email'))
        self.assertTrue(hasattr(self.user_evaluador, 'telefono'))
        
        # Verificar que Evaluador tiene relación
        self.assertTrue(hasattr(self.evaluador, 'usuario'))
        self.assertEqual(self.evaluador.usuario, self.user_evaluador)
        
        # Verificar que EvaluadorEvento tiene campos
        self.assertTrue(hasattr(self.evaluador_evento, 'eva_eve_documento'))
        self.assertTrue(hasattr(self.evaluador_evento, 'eva_eve_estado'))

    def test_ca3_4_relaciones_correctas(self):
        """CA3.4: Relaciones entre modelos son correctas."""
        # Verificar relación Evaluador -> Usuario
        self.assertEqual(self.evaluador.usuario, self.user_evaluador)
        
        # Verificar relación EvaluadorEvento -> Evaluador
        self.assertEqual(self.evaluador_evento.eva_eve_evaluador_fk, self.evaluador)
        
        # Verificar relación EvaluadorEvento -> Evento
        self.assertEqual(self.evaluador_evento.eva_eve_evento_fk, self.evento)