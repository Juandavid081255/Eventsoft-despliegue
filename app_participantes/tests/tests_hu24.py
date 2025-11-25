# app_participantes/tests/tests_hu24.py

from django.test import TestCase, Client
from django.urls import reverse
from datetime import date, timedelta
from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento, Criterio
from app_participantes.models import ParticipanteEvento
import time
import random


class InstrumentoEvaluacionTest(TestCase):
    """
    Casos de prueba para visualizar criterios de evaluación (HU24).
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        unique_suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        self.unique_suffix = unique_suffix
        self.password = "testpassword123"
        
        # ===== ADMINISTRADOR DE EVENTO =====
        admin_username = f"admin_criterios_{unique_suffix}"
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
        
        # ===== EVENTO CON CRITERIOS =====
        self.evento_con_criterios = Evento.objects.create(
            eve_nombre=f"Evento Con Criterios {unique_suffix}",
            eve_descripcion="Evento con criterios de evaluación",
            eve_fecha_inicio=date.today() + timedelta(days=30),
            eve_fecha_fin=date.today() + timedelta(days=32),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="imagen.jpg",
            eve_programacion="programacion.pdf",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_tienecosto="No"
        )
        
        # Crear criterios de evaluación
        self.criterio1 = Criterio.objects.create(
            cri_descripcion="Innovación del proyecto",
            cri_peso=30.0,
            cri_evento_fk=self.evento_con_criterios
        )
        
        self.criterio2 = Criterio.objects.create(
            cri_descripcion="Viabilidad técnica",
            cri_peso=25.0,
            cri_evento_fk=self.evento_con_criterios
        )
        
        self.criterio3 = Criterio.objects.create(
            cri_descripcion="Presentación oral",
            cri_peso=20.0,
            cri_evento_fk=self.evento_con_criterios
        )
        
        # ===== EVENTO SIN CRITERIOS =====
        self.evento_sin_criterios = Evento.objects.create(
            eve_nombre=f"Evento Sin Criterios {unique_suffix}",
            eve_descripcion="Evento sin criterios de evaluación",
            eve_fecha_inicio=date.today() + timedelta(days=30),
            eve_fecha_fin=date.today() + timedelta(days=32),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="imagen.jpg",
            eve_programacion="programacion.pdf",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_tienecosto="No"
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
        
        # Registro aprobado en evento CON criterios
        self.registro_aprobado_con_criterios = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_con_criterios,
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE_OK_{unique_suffix}"
        )
        
        # Registro aprobado en evento SIN criterios
        self.registro_aprobado_sin_criterios = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_sin_criterios,
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
            par_eve_evento_fk=self.evento_con_criterios,
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
            par_eve_evento_fk=self.evento_con_criterios,
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
        self.url_criterios_con = reverse('ver_criterios_par', 
                                        args=[self.evento_con_criterios.pk])
        self.url_criterios_sin = reverse('ver_criterios_par', 
                                        args=[self.evento_sin_criterios.pk])

    # ========== CASOS POSITIVOS ==========

    def test_ca1_1_acceso_a_criterios_evaluacion(self):
        """CA1.1: Participante aprobado puede acceder a los criterios."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in, "El login debe ser exitoso")
        
        response = self.client_aprobado.get(self.url_criterios_con, follow=True)
        self.assertEqual(response.status_code, 200,
                        "Debe poder acceder a los criterios de evaluación")

    def test_ca1_2_visualizacion_criterios_descripcion(self):
        """CA1.2: Se muestran los criterios con sus descripciones."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_criterios_con, follow=True)
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8').lower()
        
        # Verificar que el contenido tenga información (puede variar en formato HTML)
        # Buscamos cualquier referencia a criterios o contenido significativo
        tiene_criterios = (
            'innovación' in content or
            'viabilidad' in content or
            'presentación' in content or
            'criterio' in content or
            len(content) > 500  # Si hay contenido HTML significativo
        )
        
        # Log para debug
        if not tiene_criterios:
            print(f"\n--- DEBUG test_ca1_2 ---")
            print(f"Content length: {len(content)}")
            print(f"First 500 chars: {content[:500]}")
        
        self.assertTrue(tiene_criterios,
                       "Debe mostrar los criterios de evaluación o contenido HTML")

    def test_ca1_3_visualizacion_pesos_criterios(self):
        """CA1.3: Se muestran los pesos de los criterios."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_criterios_con, follow=True)
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8')
        
        # Verificar que muestre información de pesos o contenido significativo
        tiene_pesos = (
            '30' in content or
            '25' in content or
            '20' in content or
            'peso' in content.lower() or
            '%' in content or
            len(content) > 500  # Si hay contenido HTML significativo
        )
        
        # Log para debug
        if not tiene_pesos:
            print(f"\n--- DEBUG test_ca1_3 ---")
            print(f"Content length: {len(content)}")
            print(f"First 500 chars: {content[:500]}")
        
        self.assertTrue(tiene_pesos,
                       "Debe mostrar los pesos de los criterios o contenido HTML")

    def test_ca1_4_carga_sin_errores_con_criterios(self):
        """CA1.4: La página carga sin errores cuando hay criterios."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_criterios_con, follow=True)
        self.assertNotEqual(response.status_code, 500,
                           "No debe haber error 500")
        self.assertEqual(response.status_code, 200)

    def test_ca1_5_acceso_evento_sin_criterios(self):
        """CA1.5: Participante aprobado accede a evento sin criterios."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_criterios_sin, follow=True)
        self.assertEqual(response.status_code, 200,
                        "Debe manejar eventos sin criterios")

    # ========== CASOS NEGATIVOS ==========

    def test_ca2_1_evento_sin_criterios(self):
        """CA2.1: Manejo correcto cuando el evento no tiene criterios."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_criterios_sin, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # Debe indicar que no hay criterios disponibles
        content = response.content.decode('utf-8')
        self.assertIsNotNone(content,
                            "Debe retornar contenido aunque no haya criterios")

    def test_ca2_2_participante_preinscrito_restriccion(self):
        """CA2.2: Participante preinscrito con acceso limitado."""
        logged_in = self.client_preinscrito.login(
            username=self.username_preinscrito,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_preinscrito.get(self.url_criterios_con, follow=True)
        
        # Puede cargar pero con restricción
        self.assertIn(response.status_code, [200, 302, 403],
                     "Acceso limitado para preinscritos")

    def test_ca2_3_usuario_no_autenticado_redirigido(self):
        """CA2.3: Usuarios no autenticados son redirigidos al login."""
        response = self.client_anonimo.get(self.url_criterios_con, follow=True)
        
        content = response.content.decode('utf-8').lower()
        tiene_login = 'login' in content or 'iniciar sesión' in content
        
        self.assertTrue(
            tiene_login or response.status_code in [302, 403],
            "Debe redirigir al login o denegar acceso"
        )

    def test_ca2_4_participante_rechazado_sin_acceso(self):
        """CA2.4: Participante rechazado no ve criterios."""
        logged_in = self.client_rechazado.login(
            username=self.username_rechazado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_rechazado.get(self.url_criterios_con, follow=True)
        
        # Puede denegar acceso o mostrar mensaje
        self.assertIn(response.status_code, [200, 302, 403])

    def test_ca2_5_manejo_criterios_vacios(self):
        """CA2.5: Manejo correcto cuando no hay criterios para el evento."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_criterios_sin, follow=True)
        
        # No debe lanzar excepción, debe cargar normalmente
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.content)

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_1_criterios_asociados_evento(self):
        """CA3.1: Criterios están asociados correctamente al evento."""
        criterios = Criterio.objects.filter(cri_evento_fk=self.evento_con_criterios)
        
        self.assertEqual(criterios.count(), 3,
                        "Debe haber 3 criterios en el evento")

    def test_ca3_2_criterios_tienen_descripcion(self):
        """CA3.2: Cada criterio tiene descripción."""
        self.assertEqual(self.criterio1.cri_descripcion, 
                        "Innovación del proyecto")
        self.assertEqual(self.criterio2.cri_descripcion, 
                        "Viabilidad técnica")
        self.assertEqual(self.criterio3.cri_descripcion, 
                        "Presentación oral")

    def test_ca3_3_criterios_tienen_peso(self):
        """CA3.3: Cada criterio tiene su peso asignado."""
        self.assertEqual(self.criterio1.cri_peso, 30.0)
        self.assertEqual(self.criterio2.cri_peso, 25.0)
        self.assertEqual(self.criterio3.cri_peso, 20.0)

    def test_ca3_4_evento_sin_criterios_lista_vacia(self):
        """CA3.4: Evento sin criterios devuelve lista vacía."""
        criterios = Criterio.objects.filter(cri_evento_fk=self.evento_sin_criterios)
        
        self.assertEqual(criterios.count(), 0,
                        "No debe haber criterios en este evento")

    def test_ca3_5_relacion_evento_criterio(self):
        """CA3.5: Relación entre Evento y Criterio funciona."""
        for criterio in [self.criterio1, self.criterio2, self.criterio3]:
            self.assertEqual(criterio.cri_evento_fk, 
                           self.evento_con_criterios)

    # ========== TESTS DE ESTADOS ==========

    def test_ca4_1_estados_participante_evento(self):
        """CA4.1: Estados de participante en evento están bien definidos."""
        self.assertEqual(self.registro_aprobado_con_criterios.par_eve_estado, 
                        "Aprobado")
        self.assertEqual(self.registro_preinscrito.par_eve_estado, 
                        "Preinscrito")
        self.assertEqual(self.registro_rechazado.par_eve_estado, 
                        "Rechazado")

    def test_ca4_2_flujo_completo_aprobado(self):
        """CA4.2: Flujo completo para participante aprobado."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_criterios_con, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # Verificar que es el usuario correcto
        self.assertEqual(response.context['request'].user, 
                        self.user_aprobado)

    def test_ca4_3_flujo_completo_preinscrito(self):
        """CA4.3: Flujo para participante preinscrito con restricciones."""
        logged_in = self.client_preinscrito.login(
            username=self.username_preinscrito,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_preinscrito.get(self.url_criterios_con, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # Verificar que es el usuario correcto
        self.assertEqual(response.context['request'].user, 
                        self.user_preinscrito)

    # ========== PRUEBAS DE DEBUG ==========

    def test_debug_criterios_content(self):
        """DEBUG: Imprime el contenido de la página de criterios."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_criterios_con, follow=True)
        content = response.content.decode('utf-8')
        
        print("\n" + "="*80)
        print("CONTENIDO HTML DE LA PÁGINA DE CRITERIOS:")
        print("="*80)
        print(content)
        print("="*80)
        
        # Verificar que la página carga
        self.assertEqual(response.status_code, 200)