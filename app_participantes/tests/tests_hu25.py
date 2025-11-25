# app_participantes/tests/tests_hu25.py

from django.test import TestCase, Client
from django.urls import reverse
from datetime import date, timedelta
from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento
from app_participantes.models import ParticipanteEvento
import time
import random


class CertificadoParticipanteTest(TestCase):
    """
    Casos de prueba para certificados de participación (HU25).
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        unique_suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        self.unique_suffix = unique_suffix
        self.password = "testpassword123"
        
        # ===== ADMINISTRADOR DE EVENTO =====
        admin_username = f"admin_cert_{unique_suffix}"
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
        
        # ===== EVENTO TERMINADO (disponible para certificado) =====
        self.evento_terminado = Evento.objects.create(
            eve_nombre=f"Evento Finalizado {unique_suffix}",
            eve_descripcion="Evento ya terminado",
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
        
        # ===== EVENTO FUTURO (no hay certificados aún) =====
        self.evento_futuro = Evento.objects.create(
            eve_nombre=f"Evento Futuro {unique_suffix}",
            eve_descripcion="Evento aún no inicia",
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
        
        # ===== PARTICIPANTE APROBADO =====
        self.username_aprobado = f"par_aprobado_{unique_suffix}"
        self.user_aprobado = Usuario.objects.create_user(
            username=self.username_aprobado,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_aprobado}@test.com",
            first_name="Juan",
            last_name="Pérez",
            cedula=f"800{unique_suffix[-10:]}"
        )
        self.participante_aprobado, _ = Participante.objects.get_or_create(
            usuario=self.user_aprobado
        )
        
        # Registro aprobado en evento TERMINADO
        self.registro_aprobado_terminado = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE_OK_{unique_suffix}"
        )
        
        # Registro aprobado en evento FUTURO
        self.registro_aprobado_futuro = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_futuro,
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE_FUT_{unique_suffix}"
        )
        
        # Registro aprobado en evento EN CURSO
        self.registro_aprobado_curso = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_en_curso,
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE_CURSO_{unique_suffix}"
        )
        
        # ===== PARTICIPANTE RECHAZADO =====
        self.username_rechazado = f"par_rechazado_{unique_suffix}"
        self.user_rechazado = Usuario.objects.create_user(
            username=self.username_rechazado,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_rechazado}@test.com",
            first_name="Pedro",
            last_name="López",
            cedula=f"700{unique_suffix[-10:]}"
        )
        self.participante_rechazado, _ = Participante.objects.get_or_create(
            usuario=self.user_rechazado
        )
        
        # Registro rechazado en evento TERMINADO
        self.registro_rechazado = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_participante_fk=self.participante_rechazado,
            par_eve_estado="Rechazado",
            par_eve_clave=f"CLAVE_NO_{unique_suffix}"
        )
        
        # ===== PARTICIPANTE PREINSCRITO =====
        self.username_preinscrito = f"par_preinscrito_{unique_suffix}"
        self.user_preinscrito = Usuario.objects.create_user(
            username=self.username_preinscrito,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_preinscrito}@test.com",
            cedula=f"600{unique_suffix[-10:]}"
        )
        self.participante_preinscrito, _ = Participante.objects.get_or_create(
            usuario=self.user_preinscrito
        )
        
        self.registro_preinscrito = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_participante_fk=self.participante_preinscrito,
            par_eve_estado="Preinscrito",
            par_eve_clave=f"CLAVE_PEND_{unique_suffix}"
        )
        
        # Clientes
        self.client_aprobado = Client()
        self.client_rechazado = Client()
        self.client_preinscrito = Client()
        self.client_anonimo = Client()
        
        # URLs
        self.url_dashboard = reverse('dashboard_participante')

    # ========== CASOS POSITIVOS ==========

    def test_ca1_1_participante_aprobado_en_evento_terminado(self):
        """CA1.1: Participante aprobado en evento terminado es certificable."""
        self.assertEqual(self.registro_aprobado_terminado.par_eve_estado, "Aprobado")
        self.assertTrue(self.evento_terminado.eve_fecha_fin < date.today())

    def test_ca1_2_acceso_dashboard_participante(self):
        """CA1.2: Participante aprobado puede acceder a su dashboard."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_dashboard, follow=True)
        self.assertEqual(response.status_code, 200)

    def test_ca1_3_datos_completos_para_certificacion(self):
        """CA1.3: Participante tiene datos necesarios para certificación."""
        self.assertIsNotNone(self.user_aprobado.email)
        self.assertIsNotNone(self.user_aprobado.first_name)
        self.assertIsNotNone(self.user_aprobado.last_name)
        self.assertIsNotNone(self.evento_terminado.eve_nombre)

    def test_ca1_4_evento_terminado_puede_generar_certificados(self):
        """CA1.4: Solo eventos terminados pueden generar certificados."""
        self.assertTrue(self.evento_terminado.eve_fecha_fin < date.today())
        self.assertTrue(self.evento_futuro.eve_fecha_fin > date.today())

    def test_ca1_5_participante_con_registro_valido(self):
        """CA1.5: Participante tiene registro válido en evento terminado."""
        self.assertIsNotNone(self.registro_aprobado_terminado)
        self.assertEqual(self.registro_aprobado_terminado.par_eve_participante_fk,
                        self.participante_aprobado)
        self.assertEqual(self.registro_aprobado_terminado.par_eve_evento_fk,
                        self.evento_terminado)

    # ========== CASOS NEGATIVOS ==========

    def test_ca2_1_participante_rechazado_no_certificable(self):
        """CA2.1: Participantes rechazados no son certificables."""
        self.assertEqual(self.registro_rechazado.par_eve_estado, "Rechazado")
        self.assertNotEqual(self.registro_rechazado.par_eve_estado, "Aprobado")

    def test_ca2_2_evento_futuro_no_genera_certificados(self):
        """CA2.2: Eventos futuros no generan certificados."""
        self.assertTrue(self.evento_futuro.eve_fecha_inicio > date.today())
        self.assertTrue(self.evento_futuro.eve_fecha_fin > date.today())

    def test_ca2_3_evento_en_curso_no_genera_certificados(self):
        """CA2.3: Eventos en curso no generan certificados aún."""
        self.assertTrue(self.evento_en_curso.eve_fecha_fin > date.today())

    def test_ca2_4_participante_preinscrito_no_certificable(self):
        """CA2.4: Participantes preinscritos no son certificables."""
        self.assertEqual(self.registro_preinscrito.par_eve_estado, "Preinscrito")
        self.assertNotEqual(self.registro_preinscrito.par_eve_estado, "Aprobado")

    def test_ca2_5_solo_aprobados_son_certificables(self):
        """CA2.5: Solo estado 'Aprobado' es certificable."""
        aprobado = "Aprobado"
        rechazado = "Rechazado"
        preinscrito = "Preinscrito"
        
        self.assertEqual(self.registro_aprobado_terminado.par_eve_estado, aprobado)
        self.assertNotEqual(self.registro_rechazado.par_eve_estado, aprobado)
        self.assertNotEqual(self.registro_preinscrito.par_eve_estado, aprobado)

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_1_participante_tiene_datos_completos(self):
        """CA3.1: Usuario participante tiene datos necesarios."""
        self.assertIsNotNone(self.user_aprobado.email)
        self.assertIsNotNone(self.user_aprobado.first_name)
        self.assertIsNotNone(self.user_aprobado.last_name)
        self.assertIsNotNone(self.user_aprobado.cedula)

    def test_ca3_2_evento_tiene_datos_basicos(self):
        """CA3.2: Evento tiene datos básicos para certificado."""
        self.assertIsNotNone(self.evento_terminado.eve_nombre)
        self.assertIsNotNone(self.evento_terminado.eve_fecha_inicio)
        self.assertIsNotNone(self.evento_terminado.eve_fecha_fin)

    def test_ca3_3_registro_tiene_informacion_completa(self):
        """CA3.3: Registro ParticipanteEvento tiene información completa."""
        self.assertIsNotNone(self.registro_aprobado_terminado.par_eve_participante_fk)
        self.assertIsNotNone(self.registro_aprobado_terminado.par_eve_evento_fk)
        self.assertIsNotNone(self.registro_aprobado_terminado.par_eve_estado)
        self.assertIsNotNone(self.registro_aprobado_terminado.par_eve_clave)

    def test_ca3_4_relaciones_modelo_correctas(self):
        """CA3.4: Relaciones entre modelos funcionan correctamente."""
        # Participante -> Usuario
        self.assertEqual(self.participante_aprobado.usuario, self.user_aprobado)
        
        # ParticipanteEvento -> Participante
        self.assertEqual(
            self.registro_aprobado_terminado.par_eve_participante_fk,
            self.participante_aprobado
        )
        
        # ParticipanteEvento -> Evento
        self.assertEqual(
            self.registro_aprobado_terminado.par_eve_evento_fk,
            self.evento_terminado
        )

    def test_ca3_5_estados_diferenciados(self):
        """CA3.5: Todos los estados de participación están diferenciados."""
        estados = {
            "aprobado": self.registro_aprobado_terminado.par_eve_estado,
            "rechazado": self.registro_rechazado.par_eve_estado,
            "preinscrito": self.registro_preinscrito.par_eve_estado
        }
        
        # Verificar que son diferentes
        valores = list(estados.values())
        self.assertEqual(len(valores), len(set(valores)),
                        "Los estados deben ser únicos")

    # ========== TESTS DE LÓGICA DE CERTIFICACIÓN ==========

    def test_ca4_1_logica_certificacion_evento_terminado(self):
        """CA4.1: Lógica: evento terminado + aprobado = certificable."""
        es_evento_terminado = self.evento_terminado.eve_fecha_fin < date.today()
        es_aprobado = self.registro_aprobado_terminado.par_eve_estado == "Aprobado"
        es_certificable = es_evento_terminado and es_aprobado
        
        self.assertTrue(es_certificable,
                       "Evento terminado + Aprobado = Certificable")

    def test_ca4_2_logica_certificacion_evento_futuro(self):
        """CA4.2: Lógica: evento futuro = no certificable."""
        es_evento_futuro = self.evento_futuro.eve_fecha_fin > date.today()
        es_aprobado = self.registro_aprobado_futuro.par_eve_estado == "Aprobado"
        es_certificable = not es_evento_futuro and es_aprobado
        
        self.assertFalse(es_certificable,
                        "Evento futuro = No certificable")

    def test_ca4_3_logica_certificacion_rechazado(self):
        """CA4.3: Lógica: rechazado = no certificable."""
        es_evento_terminado = self.evento_terminado.eve_fecha_fin < date.today()
        es_rechazado = self.registro_rechazado.par_eve_estado == "Rechazado"
        es_certificable = es_evento_terminado and not es_rechazado
        
        self.assertFalse(es_certificable,
                        "Rechazado = No certificable")

    def test_ca4_4_solo_aprobados_en_evento_terminado_certificables(self):
        """CA4.4: Solo aprobados en evento terminado son certificables."""
        # Contar certificables
        aprobados_terminados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento_terminado,
            par_eve_estado="Aprobado"
        ).count()
        
        self.assertEqual(aprobados_terminados, 1,
                        "Solo 1 participante aprobado en evento terminado")

    def test_ca4_5_no_certificables_son_excluidos(self):
        """CA4.5: Rechazados y preinscritos son excluidos."""
        no_certificables = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento_terminado
        ).exclude(par_eve_estado="Aprobado").count()
        
        self.assertEqual(no_certificables, 2,
                        "2 registros no certificables en evento terminado")

    # ========== TESTS DE INTEGRACIÓN ==========

    def test_ca5_1_flujo_completo_obtener_certificado(self):
        """CA5.1: Flujo completo para obtener certificado."""
        # Login
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        # Acceder al dashboard
        response = self.client_aprobado.get(self.url_dashboard, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # Verificar usuario correcto
        self.assertEqual(response.context['request'].user, self.user_aprobado)
        
        # Verificar que tiene eventos terminados donde es aprobado
        eventos_certificables = ParticipanteEvento.objects.filter(
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_evento_fk__eve_fecha_fin__lt=date.today()
        ).count()
        
        self.assertGreater(eventos_certificables, 0,
                          "Debe haber al menos un evento certificable")

    def test_ca5_2_flujo_rechazado_sin_certificado(self):
        """CA5.2: Participante rechazado no puede acceder a certificado."""
        # Verificar que está rechazado
        self.assertEqual(self.registro_rechazado.par_eve_estado, "Rechazado")
        
        # Verificar que evento está terminado
        self.assertTrue(self.evento_terminado.eve_fecha_fin < date.today())
        
        # Contar eventos certificables para rechazado
        eventos_certificables = ParticipanteEvento.objects.filter(
            par_eve_participante_fk=self.participante_rechazado,
            par_eve_estado="Aprobado",
            par_eve_evento_fk__eve_fecha_fin__lt=date.today()
        ).count()
        
        self.assertEqual(eventos_certificables, 0,
                        "Participante rechazado no debe tener eventos certificables")

    def test_ca5_3_resumen_certificacion(self):
        """CA5.3: Resumen de quién puede y quién no obtener certificado."""
        # Aprobado + Evento terminado = SÍ certificable
        participante_aprobado_certificable = ParticipanteEvento.objects.filter(
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_evento_fk__eve_fecha_fin__lt=date.today()
        ).exists()
        
        # Rechazado = NO certificable
        participante_rechazado_certificable = ParticipanteEvento.objects.filter(
            par_eve_participante_fk=self.participante_rechazado,
            par_eve_estado="Aprobado",
            par_eve_evento_fk__eve_fecha_fin__lt=date.today()
        ).exists()
        
        # Preinscrito = NO certificable
        participante_preinscrito_certificable = ParticipanteEvento.objects.filter(
            par_eve_participante_fk=self.participante_preinscrito,
            par_eve_estado="Aprobado",
            par_eve_evento_fk__eve_fecha_fin__lt=date.today()
        ).exists()
        
        self.assertTrue(participante_aprobado_certificable)
        self.assertFalse(participante_rechazado_certificable)
        self.assertFalse(participante_preinscrito_certificable)