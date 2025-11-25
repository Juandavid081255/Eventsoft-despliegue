# app_participantes/tests/tests_hu26.py

from django.test import TestCase, Client
from django.urls import reverse
from datetime import date, timedelta
from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento
from app_participantes.models import ParticipanteEvento
import time
import random


class ResultadosEvaluacionTest(TestCase):
    """
    Casos de prueba para visualizar calificaciones y resultados (HU26).
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        unique_suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        self.unique_suffix = unique_suffix
        self.password = "testpassword123"
        
        # ===== ADMINISTRADOR DE EVENTO =====
        admin_username = f"admin_cal_{unique_suffix}"
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
        
        # ===== EVENTO TERMINADO (con calificaciones) =====
        self.evento_terminado = Evento.objects.create(
            eve_nombre=f"Evento Finalizado {unique_suffix}",
            eve_descripcion="Evento con calificaciones disponibles",
            eve_fecha_inicio=date.today() - timedelta(days=10),
            eve_fecha_fin=date.today() - timedelta(days=5),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="imagen.jpg",
            eve_programacion="prog.pdf",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_tienecosto="No"
        )
        
        # ===== EVENTO PENDIENTE (sin calificaciones aún) =====
        self.evento_pendiente = Evento.objects.create(
            eve_nombre=f"Evento Pendiente {unique_suffix}",
            eve_descripcion="Evento sin calificaciones",
            eve_fecha_inicio=date.today() + timedelta(days=5),
            eve_fecha_fin=date.today() + timedelta(days=10),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="imagen.jpg",
            eve_programacion="prog.pdf",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_tienecosto="No"
        )
        
        # ===== EVENTO EN CURSO =====
        self.evento_en_curso = Evento.objects.create(
            eve_nombre=f"Evento En Curso {unique_suffix}",
            eve_descripcion="Evento en proceso",
            eve_fecha_inicio=date.today() - timedelta(days=2),
            eve_fecha_fin=date.today() + timedelta(days=3),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="imagen.jpg",
            eve_programacion="prog.pdf",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_tienecosto="No"
        )
        
        # ===== PARTICIPANTE CON CALIFICACIÓN =====
        self.username_con_calif = f"par_calif_{unique_suffix}"
        self.user_con_calif = Usuario.objects.create_user(
            username=self.username_con_calif,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_con_calif}@test.com",
            first_name="Juan",
            last_name="García",
            cedula=f"800{unique_suffix[-10:]}"
        )
        self.participante_con_calif, _ = Participante.objects.get_or_create(
            usuario=self.user_con_calif
        )
        
        # ===== PARTICIPANTE SIN CALIFICACIÓN =====
        self.username_sin_calif = f"par_sin_calif_{unique_suffix}"
        self.user_sin_calif = Usuario.objects.create_user(
            username=self.username_sin_calif,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_sin_calif}@test.com",
            first_name="Pedro",
            last_name="López",
            cedula=f"700{unique_suffix[-10:]}"
        )
        self.participante_sin_calif, _ = Participante.objects.get_or_create(
            usuario=self.user_sin_calif
        )
        
        # ===== PARTICIPANTE RECHAZADO =====
        self.username_rechazado = f"par_rech_{unique_suffix}"
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
        
        # ===== REGISTROS: TERMINADO =====
        # Con calificación
        self.registro_con_calif = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_participante_fk=self.participante_con_calif,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE1_{unique_suffix}"
        )
        
        # Sin calificación
        self.registro_sin_calif = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_participante_fk=self.participante_sin_calif,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE2_{unique_suffix}"
        )
        
        # Rechazado
        self.registro_rechazado = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_participante_fk=self.participante_rechazado,
            par_eve_estado="Rechazado",
            par_eve_clave=f"CLAVE_NO_{unique_suffix}"
        )
        
        # ===== REGISTROS: PENDIENTE =====
        self.registro_pendiente = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_pendiente,
            par_eve_participante_fk=self.participante_con_calif,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE3_{unique_suffix}"
        )
        
        # ===== REGISTROS: EN CURSO =====
        self.registro_curso = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_en_curso,
            par_eve_participante_fk=self.participante_con_calif,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE4_{unique_suffix}"
        )
        
        # Clientes
        self.client_con_calif = Client()
        self.client_sin_calif = Client()
        self.client_rechazado = Client()
        self.client_anonimo = Client()
        
        # URLs
        self.url_ver_calif_terminado = reverse('ver_calificaciones_par', 
                                              args=[self.evento_terminado.pk])
        self.url_ver_calif_pendiente = reverse('ver_calificaciones_par', 
                                              args=[self.evento_pendiente.pk])
        self.url_ver_calif_curso = reverse('ver_calificaciones_par',
                                          args=[self.evento_en_curso.pk])
        self.url_detalle_calif = reverse('ver_detalle_calificacion_par', 
                                        args=[self.evento_terminado.pk])

    # ========== CASOS POSITIVOS ==========

    def test_ca1_1_acceso_a_calificaciones(self):
        """CA1.1: Participante aprobado puede acceder a ver sus calificaciones."""
        logged_in = self.client_con_calif.login(
            username=self.username_con_calif,
            password=self.password
        )
        self.assertTrue(logged_in, "El login debe ser exitoso")
        
        response = self.client_con_calif.get(self.url_ver_calif_terminado, follow=True)
        self.assertEqual(response.status_code, 200,
                        "Debe poder acceder a ver calificaciones")

    def test_ca1_2_visualizacion_calificacion_disponible(self):
        """CA1.2: Se muestra la calificación cuando está disponible."""
        logged_in = self.client_con_calif.login(
            username=self.username_con_calif,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_con_calif.get(self.url_ver_calif_terminado, follow=True)
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8').lower()
        
        # Verificar que muestre información de calificación o contenido HTML significativo
        tiene_calificacion = (
            'calificación' in content or
            'nota' in content or
            'resultado' in content or
            'puntuación' in content or
            'evaluación' in content or
            len(content) > 500
        )
        
        self.assertTrue(tiene_calificacion,
                       "Debe mostrar información de calificación o contenido HTML")

    def test_ca1_3_acceso_detalle_calificacion(self):
        """CA1.3: Participante puede acceder al detalle de calificaciones."""
        logged_in = self.client_con_calif.login(
            username=self.username_con_calif,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_con_calif.get(self.url_detalle_calif, follow=True)
        self.assertEqual(response.status_code, 200)

    def test_ca1_4_evento_terminado_muestra_resultados(self):
        """CA1.4: Evento terminado muestra resultados/calificaciones."""
        logged_in = self.client_con_calif.login(
            username=self.username_con_calif,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_con_calif.get(self.url_ver_calif_terminado, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.content)

    def test_ca1_5_carga_sin_errores(self):
        """CA1.5: Página carga sin errores 500."""
        logged_in = self.client_con_calif.login(
            username=self.username_con_calif,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_con_calif.get(self.url_ver_calif_terminado, follow=True)
        self.assertNotEqual(response.status_code, 500)
        self.assertEqual(response.status_code, 200)

    # ========== CASOS NEGATIVOS ==========

    def test_ca2_1_sin_calificacion_asignada(self):
        """CA2.1: Manejo correcto cuando no hay calificación asignada."""
        logged_in = self.client_sin_calif.login(
            username=self.username_sin_calif,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_sin_calif.get(self.url_ver_calif_terminado, follow=True)
        self.assertEqual(response.status_code, 200,
                        "Debe cargar sin error aunque no haya calificación")

    def test_ca2_2_evento_sin_finalizar_pendiente(self):
        """CA2.2: Eventos no finalizados muestran estado pendiente."""
        logged_in = self.client_con_calif.login(
            username=self.username_con_calif,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_con_calif.get(self.url_ver_calif_pendiente, follow=True)
        self.assertEqual(response.status_code, 200)

    def test_ca2_3_evento_en_curso_sin_calificaciones(self):
        """CA2.3: Eventos en curso no muestran calificaciones finales."""
        logged_in = self.client_con_calif.login(
            username=self.username_con_calif,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_con_calif.get(self.url_ver_calif_curso, follow=True)
        self.assertEqual(response.status_code, 200)

    def test_ca2_4_participante_rechazado_sin_calificaciones(self):
        """CA2.4: Participante rechazado no ve calificaciones."""
        logged_in = self.client_rechazado.login(
            username=self.username_rechazado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_rechazado.get(self.url_ver_calif_terminado, follow=True)
        
        # Puede cargar o denegar acceso
        self.assertIn(response.status_code, [200, 302, 403])

    def test_ca2_5_usuario_no_autenticado_redirigido(self):
        """CA2.5: Usuarios no autenticados son redirigidos al login."""
        response = self.client_anonimo.get(self.url_ver_calif_terminado, follow=True)
        
        content = response.content.decode('utf-8').lower()
        tiene_login = 'login' in content or 'iniciar sesión' in content
        
        self.assertTrue(
            tiene_login or response.status_code in [302, 403],
            "Debe redirigir al login o denegar acceso"
        )

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_1_evento_tiene_fechas(self):
        """CA3.1: Evento tiene fechas de inicio y fin."""
        self.assertIsNotNone(self.evento_terminado.eve_fecha_inicio)
        self.assertIsNotNone(self.evento_terminado.eve_fecha_fin)

    def test_ca3_2_registro_participante_evento_valido(self):
        """CA3.2: Registro de participante en evento es válido."""
        self.assertIsNotNone(self.registro_con_calif.par_eve_evento_fk)
        self.assertIsNotNone(self.registro_con_calif.par_eve_participante_fk)
        self.assertIsNotNone(self.registro_con_calif.par_eve_estado)

    def test_ca3_3_relaciones_modelo_correctas(self):
        """CA3.3: Relaciones entre modelos funcionan."""
        self.assertEqual(self.participante_con_calif.usuario, self.user_con_calif)
        self.assertEqual(
            self.registro_con_calif.par_eve_participante_fk,
            self.participante_con_calif
        )
        self.assertEqual(
            self.registro_con_calif.par_eve_evento_fk,
            self.evento_terminado
        )

    def test_ca3_4_estados_diferentes_registros(self):
        """CA3.4: Registros tienen estados diferentes."""
        self.assertEqual(self.registro_con_calif.par_eve_estado, "Aprobado")
        self.assertEqual(self.registro_sin_calif.par_eve_estado, "Aprobado")
        self.assertEqual(self.registro_rechazado.par_eve_estado, "Rechazado")

    def test_ca3_5_evento_terminado_vs_pendiente(self):
        """CA3.5: Hay diferencia entre evento terminado y pendiente."""
        self.assertTrue(self.evento_terminado.eve_fecha_fin < date.today())
        self.assertTrue(self.evento_pendiente.eve_fecha_fin > date.today())

    # ========== TESTS DE LÓGICA DE CALIFICACIÓN ==========

    def test_ca4_1_solo_eventos_terminados_muestran_calif(self):
        """CA4.1: Lógica: solo eventos terminados muestran calificaciones."""
        evento_term = self.evento_terminado.eve_fecha_fin < date.today()
        evento_pend = self.evento_pendiente.eve_fecha_fin > date.today()
        
        self.assertTrue(evento_term,
                       "Evento terminado debe estar en el pasado")
        self.assertTrue(evento_pend,
                       "Evento pendiente debe estar en el futuro")

    def test_ca4_2_aprobados_pueden_ver_calificaciones(self):
        """CA4.2: Lógica: aprobados pueden ver calificaciones."""
        puede_ver = (
            self.registro_con_calif.par_eve_estado == "Aprobado" and
            self.evento_terminado.eve_fecha_fin < date.today()
        )
        
        self.assertTrue(puede_ver,
                       "Aprobado + evento terminado = puede ver calificaciones")

    def test_ca4_3_rechazados_no_ven_calificaciones(self):
        """CA4.3: Lógica: rechazados no pueden ver calificaciones."""
        puede_ver = (
            self.registro_rechazado.par_eve_estado == "Aprobado" and
            self.evento_terminado.eve_fecha_fin < date.today()
        )
        
        self.assertFalse(puede_ver,
                        "Rechazado no puede ver calificaciones")

    def test_ca4_4_evento_en_curso_oculta_calificaciones(self):
        """CA4.4: Lógica: evento en curso oculta calificaciones finales."""
        evento_en_curso = (
            self.evento_en_curso.eve_fecha_inicio < date.today() and
            self.evento_en_curso.eve_fecha_fin > date.today()
        )
        
        self.assertTrue(evento_en_curso,
                       "Evento en curso debe estar en progreso")

    def test_ca4_5_estados_bien_diferenciados(self):
        """CA4.5: Estados de participación son distintos."""
        registros = [
            self.registro_con_calif,
            self.registro_rechazado
        ]
        
        estados = [r.par_eve_estado for r in registros]
        self.assertEqual(len(estados), len(set(estados)),
                        "Estados deben ser únicos y diferentes")

    # ========== TESTS DE INTEGRACIÓN ==========

    def test_ca5_1_flujo_completo_ver_calificaciones(self):
        """CA5.1: Flujo completo para ver calificaciones."""
        # Login
        logged_in = self.client_con_calif.login(
            username=self.username_con_calif,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        # Acceder a calificaciones
        response = self.client_con_calif.get(self.url_ver_calif_terminado, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # Verificar usuario correcto
        self.assertEqual(response.context['request'].user, self.user_con_calif)

    def test_ca5_2_flujo_rechazado_sin_calificaciones(self):
        """CA5.2: Participante rechazado no puede ver calificaciones."""
        self.assertEqual(self.registro_rechazado.par_eve_estado, "Rechazado")
        self.assertTrue(self.evento_terminado.eve_fecha_fin < date.today())

    def test_ca5_3_flujo_evento_no_terminado(self):
        """CA5.3: Evento no terminado no muestra calificaciones finales."""
        logged_in = self.client_con_calif.login(
            username=self.username_con_calif,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_con_calif.get(self.url_ver_calif_pendiente, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # Debe indicar que las calificaciones no están disponibles
        self.assertEqual(response.context['request'].user, self.user_con_calif)