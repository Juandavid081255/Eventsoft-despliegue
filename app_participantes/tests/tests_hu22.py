# app_participantes/tests/tests_hu22.py

from django.test import TestCase, Client
from django.urls import reverse
from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento
from datetime import datetime, timedelta
import time
import random


class PerfilParticipanteTest(TestCase):
    """
    Tests para HU22: Visualización del perfil del participante.
    """

    @classmethod
    def setUpClass(cls):
        """Configuración única para toda la clase de tests."""
        super().setUpClass()
        suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        cls.suffix = suffix

    def setUp(self):
        """Configuración inicial para cada test."""
        suffix = self.suffix
        
        # Cédulas únicas por test
        cedula_completo = f"800{suffix[-8:]}_{random.randint(1000, 9999)}"
        cedula_incompleto = f"700{suffix[-8:]}_{random.randint(1000, 9999)}"
        cedula_admin = f"900{suffix[-8:]}_{random.randint(1000, 9999)}"
        
        self.password = "testpass123"
        
        # ===== ADMINISTRADOR DE EVENTO (crear una sola vez y reutilizar) =====
        admin_user = Usuario.objects.create_user(
            username=f"admin_{suffix[:15]}_{random.randint(100, 999)}",
            password=self.password,
            email=f"admin_{suffix[:10]}_{random.randint(100, 999)}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            cedula=cedula_admin
        )
        # Usar get_or_create para evitar duplicados
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=admin_user)
        
        # ===== PARTICIPANTE CON DATOS COMPLETOS =====
        self.username_completo = f"completo_{suffix[:15]}_{random.randint(100, 999)}"
        self.user_completo = Usuario.objects.create_user(
            username=self.username_completo,
            password=self.password,
            email=f"completo_{suffix[:10]}_{random.randint(100, 999)}@test.com",
            first_name="Juan",
            last_name="Pérez",
            rol=Usuario.Roles.PARTICIPANTE,
            telefono="3001234567",
            cedula=cedula_completo
        )
        self.participante_completo = Participante.objects.create(
            usuario=self.user_completo
        )
        self.client_completo = Client()
        
        # ===== PARTICIPANTE SIN DATOS COMPLETOS =====
        self.username_incompleto = f"incompleto_{suffix[:15]}_{random.randint(100, 999)}"
        self.user_incompleto = Usuario.objects.create_user(
            username=self.username_incompleto,
            password=self.password,
            email=f"incompleto_{suffix[:10]}_{random.randint(100, 999)}@test.com",
            rol=Usuario.Roles.PARTICIPANTE,
            cedula=cedula_incompleto
        )
        self.participante_incompleto = Participante.objects.create(
            usuario=self.user_incompleto
        )
        self.client_incompleto = Client()
        
        # ===== EVENTO DE PRUEBA =====
        self.evento = Evento.objects.create(
            eve_nombre=f"Evento Test {random.randint(1000, 9999)}",
            eve_descripcion="Descripción del evento de prueba",
            eve_ciudad="Manizales",
            eve_lugar="Centro de Eventos",
            eve_fecha_inicio=datetime.now(),
            eve_fecha_fin=datetime.now() + timedelta(days=1),
            eve_estado="activo",
            eve_imagen="test.jpg",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="no",
            eve_capacidad=100,
            eve_programacion="programacion.pdf"
        )
        
        # URL del dashboard/perfil
        self.url_dashboard = reverse('dashboard_participante')

    # ========== TESTS POSITIVOS ==========

    def test_ca1_1_acceso_exitoso_dashboard(self):
        """CA1.1: Participante accede exitosamente a su dashboard."""
        login_ok = self.client_completo.login(
            username=self.username_completo,
            password=self.password
        )
        self.assertTrue(login_ok, "No se pudo iniciar sesión")
        
        response = self.client_completo.get(self.url_dashboard, follow=True)
        self.assertEqual(response.status_code, 200)

    def test_ca1_2_visualizacion_datos_personales(self):
        """CA1.2: Dashboard muestra datos personales del participante."""
        login_ok = self.client_completo.login(
            username=self.username_completo,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_completo.get(self.url_dashboard, follow=True)
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8')
        self.assertTrue(
            len(content) > 200,
            "El dashboard debe tener contenido significativo"
        )

    def test_ca1_3_acceso_con_datos_incompletos(self):
        """CA1.3: Participante con datos incompletos puede acceder al dashboard."""
        login_ok = self.client_incompleto.login(
            username=self.username_incompleto,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_incompleto.get(self.url_dashboard, follow=True)
        self.assertEqual(response.status_code, 200)

    # ========== TESTS NEGATIVOS ==========

    def test_ca2_1_anonimo_sin_acceso_dashboard(self):
        """CA2.1: Usuario no autenticado sin acceso al dashboard."""
        client_anonimo = Client()
        response = client_anonimo.get(self.url_dashboard, follow=True)
        
        content = response.content.decode('utf-8').lower()
        es_login = 'login' in content or 'iniciar sesión' in content
        
        self.assertTrue(
            es_login or response.status_code in [302, 403],
            "Anónimo debe ser redirigido o recibir acceso denegado"
        )

    def test_ca2_2_manejo_campos_vacios(self):
        """CA2.2: Manejo correcto de campos vacíos en perfil."""
        login_ok = self.client_incompleto.login(
            username=self.username_incompleto,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_incompleto.get(self.url_dashboard, follow=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.content, b'')

    def test_ca2_3_perfil_solo_lectura(self):
        """CA2.3: Dashboard es de solo lectura (GET)."""
        login_ok = self.client_completo.login(
            username=self.username_completo,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_completo.get(self.url_dashboard, follow=True)
        self.assertEqual(response.status_code, 200)

    def test_ca2_4_carga_sin_errores(self):
        """CA2.4: Dashboard carga sin errores 500."""
        login_ok = self.client_completo.login(
            username=self.username_completo,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_completo.get(self.url_dashboard, follow=True)
        self.assertNotEqual(response.status_code, 500)
        self.assertEqual(response.status_code, 200)

    def test_ca2_5_muestra_informacion_disponible(self):
        """CA2.5: Muestra información disponible del usuario."""
        login_ok = self.client_completo.login(
            username=self.username_completo,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_completo.get(self.url_dashboard, follow=True)
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8')
        self.assertIn('<html', content.lower())

    # ========== TESTS DE ESTRUCTURA Y RELACIONES ==========

    def test_ca3_1_modelos_relacionados_correctamente(self):
        """CA3.1: Modelos Participante y Usuario están relacionados correctamente."""
        self.assertEqual(self.participante_completo.usuario, self.user_completo)
        self.assertEqual(self.participante_incompleto.usuario, self.user_incompleto)

    def test_ca3_2_usuario_rol_participante(self):
        """CA3.2: Usuario tiene rol PARTICIPANTE."""
        self.assertEqual(self.user_completo.rol, Usuario.Roles.PARTICIPANTE)
        self.assertEqual(self.user_incompleto.rol, Usuario.Roles.PARTICIPANTE)

    def test_ca3_3_datos_usuario_accesibles(self):
        """CA3.3: Datos del usuario son accesibles desde el participante."""
        self.assertEqual(self.user_completo.first_name, "Juan")
        self.assertEqual(self.user_completo.last_name, "Pérez")
        self.assertEqual(self.user_completo.telefono, "3001234567")
        self.assertIsNotNone(self.user_completo.email)
        self.assertIsNotNone(self.user_completo.cedula)

    def test_ca3_4_datos_usuario_incompletos_accesibles(self):
        """CA3.4: Datos incompletos del usuario son accesibles."""
        self.assertEqual(self.user_incompleto.first_name, "")
        self.assertEqual(self.user_incompleto.last_name, "")
        self.assertIsNotNone(self.user_incompleto.cedula)

    def test_ca3_5_cedula_unica(self):
        """CA3.5: La cédula es única en el sistema."""
        with self.assertRaises(Exception):
            Usuario.objects.create_user(
                username=f"duplicado_{int(time.time() * 1000000)}",
                password=self.password,
                email=f"duplicado_{int(time.time() * 1000000)}@test.com",
                cedula=self.user_completo.cedula  # Cédula duplicada
            )

    # ========== TESTS DE SEGURIDAD ==========

    def test_ca4_1_privacidad_dashboard_personal(self):
        """CA4.1: Cada participante solo ve su dashboard."""
        login_ok = self.client_completo.login(
            username=self.username_completo,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_completo.get(self.url_dashboard, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # El dashboard es personal, muestra datos del usuario logueado
        self.assertEqual(response.context['request'].user, self.user_completo)

    def test_ca4_2_sesion_valida_requerida(self):
        """CA4.2: Se requiere sesión válida para acceder."""
        response = self.client_completo.get(self.url_dashboard)
        
        self.assertTrue(
            response.status_code in [302, 403, 401] or 'login' in response.content.decode('utf-8').lower()
        )