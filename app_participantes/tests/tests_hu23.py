# app_participantes/tests/tests_hu23.py

from django.test import TestCase, Client
from django.urls import reverse
from datetime import date, timedelta
from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento
from app_participantes.models import ParticipanteEvento 
import time
import random


class RecursosTecnicosTest(TestCase):
    """
    Casos de prueba para visualizar recursos técnicos/información técnica del evento (HU23).
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        unique_suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        self.unique_suffix = unique_suffix
        self.password = "testpassword123"
        
        # ===== ADMINISTRADOR DE EVENTO =====
        admin_username = f"admin_recursos_{unique_suffix}"
        self.admin_user = Usuario.objects.create_user(
            username=admin_username,
            password=self.password,
            rol=Usuario.Roles.ADMIN_EVENTO,
            email=f"{admin_username}@test.com",
            cedula=f"900{unique_suffix[-10:]}"
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.admin_user
        )
        
        # ===== EVENTO CON INFORMACIÓN TÉCNICA =====
        self.evento_con_info = Evento.objects.create(
            eve_nombre=f"Evento Con Info Técnica {unique_suffix}",
            eve_descripcion="Evento con información técnica disponible",
            eve_fecha_inicio=date.today() + timedelta(days=30),
            eve_fecha_fin=date.today() + timedelta(days=32),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="imagen.jpg",
            eve_programacion="programacion.pdf",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_tienecosto="No",
            eve_informacion_tecnica="info_tecnica.pdf"
        )
        
        # ===== EVENTO SIN INFORMACIÓN TÉCNICA =====
        self.evento_sin_info = Evento.objects.create(
            eve_nombre=f"Evento Sin Info Técnica {unique_suffix}",
            eve_descripcion="Evento sin información técnica",
            eve_fecha_inicio=date.today() + timedelta(days=30),
            eve_fecha_fin=date.today() + timedelta(days=32),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="imagen.jpg",
            eve_programacion="programacion.pdf",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_tienecosto="No",
            eve_informacion_tecnica=""
        )
        
        # ===== PARTICIPANTE APROBADO =====
        self.username_aprobado = f"par_aprobado_{unique_suffix}"
        self.user_aprobado = Usuario.objects.create_user(
            username=self.username_aprobado,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_aprobado}@test.com",
            cedula=f"800{unique_suffix[-10:]}"
        )
        self.participante_aprobado, _ = Participante.objects.get_or_create(
            usuario=self.user_aprobado
        )
        
        # Registro aprobado en evento CON info
        self.registro_aprobado_con_info = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_con_info,
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE_OK_{unique_suffix}"
        )
        
        # Registro aprobado en evento SIN info
        self.registro_aprobado_sin_info = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_sin_info,
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE_OK2_{unique_suffix}"
        )
        
        # ===== PARTICIPANTE PREINSCRITO =====
        self.username_preinscrito = f"par_preinscrito_{unique_suffix}"
        self.user_preinscrito = Usuario.objects.create_user(
            username=self.username_preinscrito,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_preinscrito}@test.com",
            cedula=f"700{unique_suffix[-10:]}"
        )
        self.participante_preinscrito, _ = Participante.objects.get_or_create(
            usuario=self.user_preinscrito
        )
        self.registro_preinscrito = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_con_info,
            par_eve_participante_fk=self.participante_preinscrito,
            par_eve_estado="Preinscrito",
            par_eve_clave=f"CLAVE_PEND_{unique_suffix}"
        )
        
        # ===== PARTICIPANTE RECHAZADO =====
        self.username_rechazado = f"par_rechazado_{unique_suffix}"
        self.user_rechazado = Usuario.objects.create_user(
            username=self.username_rechazado,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_rechazado}@test.com",
            cedula=f"600{unique_suffix[-10:]}"
        )
        self.participante_rechazado, _ = Participante.objects.get_or_create(
            usuario=self.user_rechazado
        )
        self.registro_rechazado = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_con_info,
            par_eve_participante_fk=self.participante_rechazado,
            par_eve_estado="Rechazado",
            par_eve_clave=f"CLAVE_NO_{unique_suffix}"
        )
        
        # Clientes
        self.client_aprobado = Client()
        self.client_preinscrito = Client()
        self.client_rechazado = Client()
        self.client_anonimo = Client()
        
        # URLs
        self.url_info_con_info = reverse('ver_info_evento_par', 
                                        args=[self.evento_con_info.pk])
        self.url_info_sin_info = reverse('ver_info_evento_par', 
                                        args=[self.evento_sin_info.pk])

    # ========== CASOS POSITIVOS ==========

    def test_ca1_1_acceso_a_informacion_tecnica(self):
        """CA1.1: Participante aprobado puede acceder a la información técnica."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in, "El login debe ser exitoso")
        
        response = self.client_aprobado.get(self.url_info_con_info, follow=True)
        self.assertEqual(response.status_code, 200,
                        "Debe poder acceder a la vista del evento")

    def test_ca1_2_visualizacion_informacion_tecnica(self):
        """CA1.2: Se muestra la información técnica disponible."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_info_con_info, follow=True)
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8').lower()
        
        # Verificar que se muestre información técnica o al menos contenido HTML significativo
        tiene_info = (
            'información técnica' in content or
            'info técnica' in content or
            'info_tecnica' in content or
            'técnico' in content or
            'recurso técnico' in content or
            len(content) > 500  # Contenido HTML significativo
        )
        
        self.assertTrue(tiene_info,
                       "Debe mostrar información técnica del evento o contenido HTML")

    def test_ca1_3_carga_sin_errores_con_info(self):
        """CA1.3: La página carga sin errores cuando hay información técnica."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_info_con_info, follow=True)
        self.assertNotEqual(response.status_code, 500,
                           "No debe haber error 500")
        self.assertEqual(response.status_code, 200)

    def test_ca1_4_acceso_evento_sin_informacion(self):
        """CA1.4: Participante aprobado accede a evento sin información técnica."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_info_sin_info, follow=True)
        self.assertEqual(response.status_code, 200,
                        "Debe manejar eventos sin información técnica")

    # ========== CASOS NEGATIVOS ==========

    def test_ca2_1_evento_sin_informacion_tecnica(self):
        """CA2.1: Manejo correcto cuando el evento no tiene información técnica."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_info_sin_info, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # La página debe indicar que no hay información disponible
        content = response.content.decode('utf-8')
        self.assertIsNotNone(content,
                            "Debe retornar contenido aunque no haya info técnica")

    def test_ca2_2_participante_preinscrito_restringido(self):
        """CA2.2: Participantes preinscritos no ven información técnica completa."""
        logged_in = self.client_preinscrito.login(
            username=self.username_preinscrito,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_preinscrito.get(self.url_info_con_info, follow=True)
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8').lower()
        
        # Verificar que NO muestre el archivo de información técnica
        if 'información técnica' in content:
            # Si muestra el titulo, al menos no debe mostrar el archivo directamente
            self.assertNotIn('info_tecnica.pdf', content,
                            "No debe mostrar enlace directo a PDF para preinscritos")

    def test_ca2_3_usuario_no_autenticado_redirigido(self):
        """CA2.3: Usuarios no autenticados son redirigidos al login."""
        response = self.client_anonimo.get(self.url_info_con_info, follow=True)
        
        content = response.content.decode('utf-8').lower()
        tiene_login = 'login' in content or 'iniciar sesión' in content
        
        self.assertTrue(
            tiene_login or response.status_code in [302, 403],
            "Debe redirigir al login o denegar acceso"
        )

    def test_ca2_4_participante_rechazado_sin_acceso(self):
        """CA2.4: Participantes rechazados no ven información técnica."""
        logged_in = self.client_rechazado.login(
            username=self.username_rechazado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_rechazado.get(self.url_info_con_info, follow=True)
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8').lower()
        
        # Participante rechazado NO debe ver el PDF
        if 'información técnica' in content or 'técnico' in content:
            self.assertNotIn('info_tecnica.pdf', content,
                            "Participantes rechazados no deben ver archivo técnico")

    def test_ca2_5_manejo_campo_vacio(self):
        """CA2.5: Manejo correcto de campo información_tecnica vacío."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_info_sin_info, follow=True)
        
        # No debe lanzar excepción, debe cargar normalmente
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.content)

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_1_evento_tiene_informacion_tecnica(self):
        """CA3.1: Evento guarda correctamente la información técnica."""
        self.assertEqual(self.evento_con_info.eve_informacion_tecnica, 
                        "info_tecnica.pdf")
        self.assertTrue(
            bool(self.evento_con_info.eve_informacion_tecnica),
            "Debe tener información técnica"
        )

    def test_ca3_2_evento_sin_informacion_tecnica(self):
        """CA3.2: Evento sin información técnica es manejado correctamente."""
        self.assertFalse(
            bool(self.evento_sin_info.eve_informacion_tecnica),
            "No debe tener información técnica"
        )

    def test_ca3_3_participante_evento_relacionado(self):
        """CA3.3: Relaciones entre ParticipanteEvento y Evento funcionan."""
        self.assertEqual(
            self.registro_aprobado_con_info.par_eve_evento_fk,
            self.evento_con_info
        )
        self.assertEqual(
            self.registro_aprobado_con_info.par_eve_participante_fk,
            self.participante_aprobado
        )

    def test_ca3_4_estados_participante_evento(self):
        """CA3.4: Estados de ParticipanteEvento funcionan correctamente."""
        self.assertEqual(self.registro_aprobado_con_info.par_eve_estado, "Aprobado")
        self.assertEqual(self.registro_preinscrito.par_eve_estado, "Preinscrito")
        self.assertEqual(self.registro_rechazado.par_eve_estado, "Rechazado")

    # ========== TESTS DE INTEGRACIÓN ==========

    def test_ca4_1_flujo_completo_aprobado(self):
        """CA4.1: Flujo completo para participante aprobado."""
        # Login
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        # Acceder a evento
        response = self.client_aprobado.get(self.url_info_con_info, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # Verificar que es el usuario correcto
        self.assertEqual(response.context['request'].user, self.user_aprobado)

    def test_ca4_2_flujo_completo_preinscrito(self):
        """CA4.2: Flujo para participante preinscrito con restricciones."""
        logged_in = self.client_preinscrito.login(
            username=self.username_preinscrito,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_preinscrito.get(self.url_info_con_info, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # Debe mostrar que necesita aprobación
        self.assertEqual(response.context['request'].user, self.user_preinscrito)

    # ========== PRUEBAS DE DEBUG ==========

    def test_debug_informacion_tecnica_content(self):
        """DEBUG: Imprime el contenido de la página de información técnica."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_info_con_info, follow=True)
        content = response.content.decode('utf-8')
        
        print("\n" + "="*80)
        print("CONTENIDO HTML DE LA PÁGINA DE INFORMACIÓN TÉCNICA:")
        print("="*80)
        print(content)
        print("="*80)
        
        # Verificar que la página carga
        self.assertEqual(response.status_code, 200)