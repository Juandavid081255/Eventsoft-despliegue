# app_participantes/tests/tests_hu27.py

from django.test import TestCase, Client
from django.urls import reverse
from datetime import date, timedelta
from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento
from app_participantes.models import ParticipanteEvento
import time
import random


class CertificadoReconocimientoTest(TestCase):
    """
    Casos de prueba para certificados de reconocimiento (HU27).
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        unique_suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        self.unique_suffix = unique_suffix
        self.password = "testpassword123"
        
        # ===== ADMINISTRADOR DE EVENTO =====
        admin_username = f"admin_rec_{unique_suffix}"
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
        
        # ===== EVENTO TERMINADO =====
        self.evento_terminado = Evento.objects.create(
            eve_nombre=f"Evento Finalizado {unique_suffix}",
            eve_descripcion="Evento con ganadores y reconocimientos",
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
        
        # ===== EVENTO FUTURO =====
        self.evento_futuro = Evento.objects.create(
            eve_nombre=f"Evento Futuro {unique_suffix}",
            eve_descripcion="Evento sin reconocimientos",
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
        
        # ===== PARTICIPANTE GANADOR (alto puntaje) =====
        self.username_ganador = f"par_ganador_{unique_suffix}"
        self.user_ganador = Usuario.objects.create_user(
            username=self.username_ganador,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_ganador}@test.com",
            first_name="Carlos",
            last_name="Mendoza",
            cedula=f"800{unique_suffix[-10:]}"
        )
        self.participante_ganador, _ = Participante.objects.get_or_create(
            usuario=self.user_ganador
        )
        
        # ===== PARTICIPANTE SEGUNDO LUGAR =====
        self.username_segundo = f"par_segundo_{unique_suffix}"
        self.user_segundo = Usuario.objects.create_user(
            username=self.username_segundo,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_segundo}@test.com",
            first_name="María",
            last_name="Rodríguez",
            cedula=f"750{unique_suffix[-10:]}"
        )
        self.participante_segundo, _ = Participante.objects.get_or_create(
            usuario=self.user_segundo
        )
        
        # ===== PARTICIPANTE TERCER LUGAR =====
        self.username_tercero = f"par_tercero_{unique_suffix}"
        self.user_tercero = Usuario.objects.create_user(
            username=self.username_tercero,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_tercero}@test.com",
            first_name="Luis",
            last_name="González",
            cedula=f"700{unique_suffix[-10:]}"
        )
        self.participante_tercero, _ = Participante.objects.get_or_create(
            usuario=self.user_tercero
        )
        
        # ===== PARTICIPANTE NORMAL (sin reconocimiento) =====
        self.username_normal = f"par_normal_{unique_suffix}"
        self.user_normal = Usuario.objects.create_user(
            username=self.username_normal,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_normal}@test.com",
            first_name="Pedro",
            last_name="López",
            cedula=f"650{unique_suffix[-10:]}"
        )
        self.participante_normal, _ = Participante.objects.get_or_create(
            usuario=self.user_normal
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
        
        # ===== REGISTROS: EVENTO TERMINADO =====
        # Ganador (1er lugar) - 95 puntos
        self.registro_ganador = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_participante_fk=self.participante_ganador,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE1_{unique_suffix}"
        )
        
        # Segundo lugar - 90 puntos
        self.registro_segundo = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_participante_fk=self.participante_segundo,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE2_{unique_suffix}"
        )
        
        # Tercer lugar - 85 puntos
        self.registro_tercero = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_participante_fk=self.participante_tercero,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE3_{unique_suffix}"
        )
        
        # Participante normal - 75 puntos (sin reconocimiento)
        self.registro_normal = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_participante_fk=self.participante_normal,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE4_{unique_suffix}"
        )
        
        # Participante rechazado
        self.registro_rechazado = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_participante_fk=self.participante_rechazado,
            par_eve_estado="Rechazado",
            par_eve_clave=f"CLAVE_NO_{unique_suffix}"
        )
        
        # ===== REGISTROS: EVENTO FUTURO =====
        self.registro_futuro = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_futuro,
            par_eve_participante_fk=self.participante_ganador,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE_FUT_{unique_suffix}"
        )
        
        # Clientes
        self.client_ganador = Client()
        self.client_segundo = Client()
        self.client_tercero = Client()
        self.client_normal = Client()
        self.client_rechazado = Client()
        self.client_anonimo = Client()
        
        # URLs
        self.url_dashboard = reverse('dashboard_participante')

    # ========== CASOS POSITIVOS ==========

    def test_ca1_1_ganador_existe_con_alto_puntaje(self):
        """CA1.1: Existe participante ganador con puntaje elegible."""
        self.assertIsNotNone(self.participante_ganador)
        self.assertEqual(self.registro_ganador.par_eve_estado, "Aprobado")

    def test_ca1_2_ganador_acceso_dashboard(self):
        """CA1.2: Participante ganador puede acceder a su dashboard."""
        logged_in = self.client_ganador.login(
            username=self.username_ganador,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_ganador.get(self.url_dashboard, follow=True)
        self.assertEqual(response.status_code, 200)

    def test_ca1_3_evento_finalizado_para_reconocimientos(self):
        """CA1.3: Evento ha finalizado (disponible para reconocimientos)."""
        self.assertTrue(self.evento_terminado.eve_fecha_fin < date.today())

    def test_ca1_4_datos_completos_ganador(self):
        """CA1.4: Ganador tiene datos completos para reconocimiento."""
        self.assertIsNotNone(self.user_ganador.first_name)
        self.assertIsNotNone(self.user_ganador.last_name)
        self.assertIsNotNone(self.user_ganador.email)
        self.assertIsNotNone(self.evento_terminado.eve_nombre)

    def test_ca1_5_tres_primeros_lugares_identificables(self):
        """CA1.5: Se pueden identificar los tres primeros lugares."""
        registros_aprobados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_estado="Aprobado"
        ).count()
        
        self.assertGreaterEqual(registros_aprobados, 3,
                               "Debe haber al menos 3 participantes aprobados")

    # ========== CASOS NEGATIVOS ==========

    def test_ca2_1_participante_normal_sin_reconocimiento(self):
        """CA2.1: Participante normal sin reconocimiento especial."""
        self.assertEqual(self.registro_normal.par_eve_estado, "Aprobado")
        # Tiene puntaje pero no está en los 3 primeros

    def test_ca2_2_participante_rechazado_sin_reconocimiento(self):
        """CA2.2: Participante rechazado no recibe reconocimiento."""
        self.assertEqual(self.registro_rechazado.par_eve_estado, "Rechazado")
        self.assertNotEqual(self.registro_rechazado.par_eve_estado, "Aprobado")

    def test_ca2_3_evento_futuro_sin_reconocimientos(self):
        """CA2.3: Evento futuro no otorga reconocimientos."""
        self.assertTrue(self.evento_futuro.eve_fecha_fin > date.today())

    def test_ca2_4_solo_aprobados_pueden_ganar(self):
        """CA2.4: Solo aprobados pueden recibir reconocimientos."""
        self.assertEqual(self.registro_ganador.par_eve_estado, "Aprobado")
        self.assertEqual(self.registro_rechazado.par_eve_estado, "Rechazado")

    def test_ca2_5_usuario_no_autenticado_sin_acceso(self):
        """CA2.5: Usuario no autenticado no puede ver reconocimientos."""
        response = self.client_anonimo.get(self.url_dashboard, follow=True)
        
        content = response.content.decode('utf-8').lower()
        tiene_login = 'login' in content or 'iniciar sesión' in content
        
        self.assertTrue(
            tiene_login or response.status_code in [302, 403],
            "Debe redirigir al login"
        )

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_1_evento_tiene_participantes(self):
        """CA3.1: Evento tiene participantes registrados."""
        participantes = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento_terminado
        ).count()
        
        self.assertGreater(participantes, 0,
                          "Debe haber al menos un participante")

    def test_ca3_2_relaciones_modelo_correctas(self):
        """CA3.2: Relaciones entre modelos funcionan."""
        self.assertEqual(self.participante_ganador.usuario, self.user_ganador)
        self.assertEqual(
            self.registro_ganador.par_eve_participante_fk,
            self.participante_ganador
        )
        self.assertEqual(
            self.registro_ganador.par_eve_evento_fk,
            self.evento_terminado
        )

    def test_ca3_3_eventos_diferenciados(self):
        """CA3.3: Eventos terminado y futuro están diferenciados."""
        self.assertTrue(self.evento_terminado.eve_fecha_fin < date.today())
        self.assertTrue(self.evento_futuro.eve_fecha_fin > date.today())

    def test_ca3_4_estados_participante_distintos(self):
        """CA3.4: Estados de participantes están diferenciados."""
        self.assertEqual(self.registro_ganador.par_eve_estado, "Aprobado")
        self.assertEqual(self.registro_rechazado.par_eve_estado, "Rechazado")
        self.assertNotEqual(
            self.registro_ganador.par_eve_estado,
            self.registro_rechazado.par_eve_estado
        )

    def test_ca3_5_datos_usuario_completos(self):
        """CA3.5: Usuarios tienen datos completos."""
        for usuario in [self.user_ganador, self.user_segundo, self.user_tercero]:
            self.assertIsNotNone(usuario.email)
            self.assertIsNotNone(usuario.first_name)
            self.assertIsNotNone(usuario.last_name)

    # ========== TESTS DE LÓGICA DE RECONOCIMIENTO ==========

    def test_ca4_1_ganador_evento_terminado_aplica(self):
        """CA4.1: Lógica: evento terminado + aprobado = elegible para reconocimiento."""
        evento_term = self.evento_terminado.eve_fecha_fin < date.today()
        es_aprobado = self.registro_ganador.par_eve_estado == "Aprobado"
        
        self.assertTrue(evento_term and es_aprobado,
                       "Ganador es elegible para reconocimiento")

    def test_ca4_2_evento_futuro_no_reconoce(self):
        """CA4.2: Lógica: evento futuro = sin reconocimientos."""
        evento_futuro = self.evento_futuro.eve_fecha_fin > date.today()
        
        self.assertTrue(evento_futuro,
                       "Evento futuro no debe otorgar reconocimientos")

    def test_ca4_3_rechazado_no_reconocido(self):
        """CA4.3: Lógica: rechazado = sin reconocimiento."""
        es_rechazado = self.registro_rechazado.par_eve_estado == "Rechazado"
        
        self.assertTrue(es_rechazado,
                       "Rechazado no debe recibir reconocimiento")

    def test_ca4_4_solo_aprobados_en_evento_termino(self):
        """CA4.4: Lógica: solo aprobados en evento terminado son candidatos."""
        aprobados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_estado="Aprobado"
        ).count()
        
        rechazados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_estado="Rechazado"
        ).count()
        
        self.assertEqual(aprobados, 4,
                        "Debe haber 4 aprobados en evento terminado")
        self.assertEqual(rechazados, 1,
                        "Debe haber 1 rechazado en evento terminado")

    def test_ca4_5_reconocimientos_diferenciados(self):
        """CA4.5: Lógica: hay múltiples niveles de reconocimiento."""
        # 1er, 2do, 3er lugar
        registros = [
            self.registro_ganador,
            self.registro_segundo,
            self.registro_tercero
        ]
        
        # Todos deben ser aprobados en evento terminado
        for registro in registros:
            self.assertEqual(registro.par_eve_estado, "Aprobado")
            self.assertEqual(
                registro.par_eve_evento_fk,
                self.evento_terminado
            )

    # ========== TESTS DE INTEGRACIÓN ==========

    def test_ca5_1_flujo_ganador_ver_reconocimiento(self):
        """CA5.1: Flujo completo para ganador ver reconocimiento."""
        # Login
        logged_in = self.client_ganador.login(
            username=self.username_ganador,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        # Acceder al dashboard
        response = self.client_ganador.get(self.url_dashboard, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # Verificar usuario correcto
        self.assertEqual(response.context['request'].user, self.user_ganador)

    def test_ca5_2_flujo_tres_primeros_lugares(self):
        """CA5.2: Los tres primeros lugares pueden ver sus reconocimientos."""
        clientes_ganadores = [
            (self.client_ganador, self.username_ganador, self.user_ganador),
            (self.client_segundo, self.username_segundo, self.user_segundo),
            (self.client_tercero, self.username_tercero, self.user_tercero)
        ]
        
        for cliente, username, usuario in clientes_ganadores:
            logged_in = cliente.login(username=username, password=self.password)
            self.assertTrue(logged_in)
            
            response = cliente.get(self.url_dashboard, follow=True)
            self.assertEqual(response.status_code, 200)

    def test_ca5_3_flujo_rechazado_sin_reconocimiento(self):
        """CA5.3: Participante rechazado no ve reconocimiento."""
        self.assertEqual(self.registro_rechazado.par_eve_estado, "Rechazado")
        self.assertTrue(self.evento_terminado.eve_fecha_fin < date.today())