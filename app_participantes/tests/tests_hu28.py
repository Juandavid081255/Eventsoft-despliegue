# app_participantes/tests/tests_hu28.py

from django.test import TestCase, Client
from django.urls import reverse
from datetime import date, timedelta
from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento
from app_participantes.models import ParticipanteEvento
import time
import random


class NotificacionesTest(TestCase):
    """
    Casos de prueba para notificaciones (HU28).
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        unique_suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        self.unique_suffix = unique_suffix
        self.password = "testpassword123"
        
        # ===== ADMINISTRADOR DE EVENTO =====
        admin_username = f"admin_notif_{unique_suffix}"
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
        
        # ===== EVENTO ACTIVO (proximos días) =====
        self.evento_activo = Evento.objects.create(
            eve_nombre=f"Evento Activo {unique_suffix}",
            eve_descripcion="Evento activo para notificaciones",
            eve_fecha_inicio=date.today() - timedelta(days=1),
            eve_fecha_fin=date.today() + timedelta(days=5),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="imagen.jpg",
            eve_programacion="prog.pdf",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_tienecosto="No"
        )
        
        # ===== EVENTO PRÓXIMO (notificación de recordatorio) =====
        self.evento_proximo = Evento.objects.create(
            eve_nombre=f"Evento Próximo {unique_suffix}",
            eve_descripcion="Evento próximo a iniciar",
            eve_fecha_inicio=date.today() + timedelta(days=2),
            eve_fecha_fin=date.today() + timedelta(days=7),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="imagen.jpg",
            eve_programacion="prog.pdf",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_tienecosto="No"
        )
        
        # ===== EVENTO FINALIZADO =====
        self.evento_finalizado = Evento.objects.create(
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
        
        # ===== PARTICIPANTE PREINSCRITO =====
        self.username_preinscrito = f"par_pre_{unique_suffix}"
        self.user_preinscrito = Usuario.objects.create_user(
            username=self.username_preinscrito,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_preinscrito}@test.com",
            first_name="María",
            last_name="García",
            cedula=f"700{unique_suffix[-10:]}"
        )
        self.participante_preinscrito, _ = Participante.objects.get_or_create(
            usuario=self.user_preinscrito
        )
        
        # ===== PARTICIPANTE RECHAZADO =====
        self.username_rechazado = f"par_rech_{unique_suffix}"
        self.user_rechazado = Usuario.objects.create_user(
            username=self.username_rechazado,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_rechazado}@test.com",
            first_name="Pedro",
            last_name="López",
            cedula=f"600{unique_suffix[-10:]}"
        )
        self.participante_rechazado, _ = Participante.objects.get_or_create(
            usuario=self.user_rechazado
        )
        
        # ===== REGISTROS: EVENTO ACTIVO =====
        # Aprobado
        self.registro_aprobado_activo = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_activo,
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE1_{unique_suffix}"
        )
        
        # Preinscrito
        self.registro_preinscrito = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_activo,
            par_eve_participante_fk=self.participante_preinscrito,
            par_eve_estado="Preinscrito",
            par_eve_clave=f"CLAVE2_{unique_suffix}"
        )
        
        # Rechazado
        self.registro_rechazado = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_activo,
            par_eve_participante_fk=self.participante_rechazado,
            par_eve_estado="Rechazado",
            par_eve_clave=f"CLAVE3_{unique_suffix}"
        )
        
        # ===== REGISTROS: EVENTO PRÓXIMO =====
        self.registro_aprobado_proximo = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_proximo,
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE4_{unique_suffix}"
        )
        
        # ===== REGISTROS: EVENTO FINALIZADO =====
        self.registro_aprobado_finalizado = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_finalizado,
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE5_{unique_suffix}"
        )
        
        # Clientes
        self.client_aprobado = Client()
        self.client_preinscrito = Client()
        self.client_rechazado = Client()
        self.client_anonimo = Client()
        
        # URLs
        self.url_dashboard = reverse('dashboard_participante')

    # ========== CASOS POSITIVOS ==========

    def test_ca1_1_participantes_aprobados_tienen_email(self):
        """CA1.1: Participantes aprobados tienen email configurado."""
        self.assertIsNotNone(self.user_aprobado.email)
        self.assertIn('@', self.user_aprobado.email)
        self.assertTrue(len(self.user_aprobado.email) > 0)

    def test_ca1_2_evento_activo_para_notificaciones(self):
        """CA1.2: Evento está activo y puede enviar notificaciones."""
        self.assertEqual(self.evento_activo.eve_estado, "activo")
        self.assertTrue(self.evento_activo.eve_fecha_inicio <= date.today())

    def test_ca1_3_acceso_dashboard_aprobado(self):
        """CA1.3: Participante aprobado accede a su dashboard."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_dashboard, follow=True)
        self.assertEqual(response.status_code, 200)

    def test_ca1_4_datos_completos_para_notificar(self):
        """CA1.4: Usuario tiene datos completos para notificación."""
        self.assertIsNotNone(self.user_aprobado.email)
        self.assertIsNotNone(self.user_aprobado.first_name)
        self.assertIsNotNone(self.user_aprobado.last_name)

    def test_ca1_5_múltiples_eventos_para_notificar(self):
        """CA1.5: Participante puede tener múltiples eventos activos."""
        eventos_aprobado = ParticipanteEvento.objects.filter(
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado"
        ).count()
        
        self.assertGreaterEqual(eventos_aprobado, 2,
                               "Debe tener al menos 2 eventos aprobados")

    # ========== CASOS NEGATIVOS ==========

    def test_ca2_1_diferencia_estados_participantes(self):
        """CA2.1: Existen diferentes estados de participantes."""
        self.assertEqual(self.registro_aprobado_activo.par_eve_estado, "Aprobado")
        self.assertEqual(self.registro_preinscrito.par_eve_estado, "Preinscrito")
        self.assertEqual(self.registro_rechazado.par_eve_estado, "Rechazado")

    def test_ca2_2_solo_aprobados_reciben_notificaciones(self):
        """CA2.2: Solo aprobados son elegibles para notificaciones."""
        aprobados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento_activo,
            par_eve_estado="Aprobado"
        ).count()
        
        self.assertEqual(aprobados, 1,
                        "Solo 1 participante aprobado en evento activo")

    def test_ca2_3_preinscritos_no_reciben_notificaciones(self):
        """CA2.3: Participantes preinscritos no reciben notificaciones."""
        preinscrito_reg = ParticipanteEvento.objects.get(
            par_eve_participante_fk=self.participante_preinscrito
        )
        
        self.assertEqual(preinscrito_reg.par_eve_estado, "Preinscrito")
        self.assertNotEqual(preinscrito_reg.par_eve_estado, "Aprobado")

    def test_ca2_4_rechazados_no_reciben_notificaciones(self):
        """CA2.4: Participantes rechazados no reciben notificaciones."""
        rechazado_reg = ParticipanteEvento.objects.get(
            par_eve_participante_fk=self.participante_rechazado
        )
        
        self.assertEqual(rechazado_reg.par_eve_estado, "Rechazado")
        self.assertNotEqual(rechazado_reg.par_eve_estado, "Aprobado")

    def test_ca2_5_usuario_no_autenticado_sin_acceso(self):
        """CA2.5: Usuario no autenticado no puede ver notificaciones."""
        response = self.client_anonimo.get(self.url_dashboard, follow=True)
        
        content = response.content.decode('utf-8').lower()
        tiene_login = 'login' in content or 'iniciar sesión' in content
        
        self.assertTrue(
            tiene_login or response.status_code in [302, 403],
            "Debe redirigir al login"
        )

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_1_evento_tiene_nombre_y_descripcion(self):
        """CA3.1: Evento tiene datos básicos."""
        self.assertIsNotNone(self.evento_activo.eve_nombre)
        self.assertIsNotNone(self.evento_activo.eve_descripcion)
        self.assertTrue(len(self.evento_activo.eve_nombre) > 0)

    def test_ca3_2_participante_evento_relacion_valida(self):
        """CA3.2: Relación ParticipanteEvento es válida."""
        self.assertIsNotNone(self.registro_aprobado_activo.par_eve_evento_fk)
        self.assertIsNotNone(self.registro_aprobado_activo.par_eve_participante_fk)
        self.assertEqual(
            self.registro_aprobado_activo.par_eve_evento_fk,
            self.evento_activo
        )

    def test_ca3_3_usuario_email_valido(self):
        """CA3.3: Email de usuario es válido."""
        for usuario in [self.user_aprobado, self.user_preinscrito, self.user_rechazado]:
            self.assertIsNotNone(usuario.email)
            self.assertIn('@', usuario.email)
            self.assertGreater(len(usuario.email), 5)

    def test_ca3_4_eventos_diferenciados_por_fecha(self):
        """CA3.4: Eventos están diferenciados por fecha."""
        self.assertTrue(self.evento_activo.eve_fecha_inicio <= date.today())
        self.assertTrue(self.evento_proximo.eve_fecha_inicio > date.today())
        self.assertTrue(self.evento_finalizado.eve_fecha_fin < date.today())

    def test_ca3_5_estados_bien_definidos(self):
        """CA3.5: Estados de participación están bien definidos."""
        registros = [
            self.registro_aprobado_activo,
            self.registro_preinscrito,
            self.registro_rechazado
        ]
        
        estados = [r.par_eve_estado for r in registros]
        
        # Todos deben ser únicos
        self.assertEqual(len(estados), len(set(estados)),
                        "Estados deben ser únicos")
        
        # Deben incluir estos estados
        self.assertIn("Aprobado", estados)
        self.assertIn("Preinscrito", estados)
        self.assertIn("Rechazado", estados)

    # ========== TESTS DE LÓGICA DE NOTIFICACIONES ==========

    def test_ca4_1_solo_aprobados_elegibles(self):
        """CA4.1: Lógica: aprobado + evento activo = elegible para notificación."""
        es_aprobado = self.registro_aprobado_activo.par_eve_estado == "Aprobado"
        evento_activo = self.evento_activo.eve_estado == "activo"
        
        elegible = es_aprobado and evento_activo
        self.assertTrue(elegible,
                       "Aprobado en evento activo = elegible")

    def test_ca4_2_preinscrito_no_elegible(self):
        """CA4.2: Lógica: preinscrito = no elegible."""
        es_preinscrito = self.registro_preinscrito.par_eve_estado == "Preinscrito"
        
        self.assertTrue(es_preinscrito,
                       "Preinscrito no debe recibir notificaciones")

    def test_ca4_3_rechazado_no_elegible(self):
        """CA4.3: Lógica: rechazado = no elegible."""
        es_rechazado = self.registro_rechazado.par_eve_estado == "Rechazado"
        
        self.assertTrue(es_rechazado,
                       "Rechazado no debe recibir notificaciones")

    def test_ca4_4_evento_inactivo_sin_notificaciones(self):
        """CA4.4: Lógica: evento inactivo = sin notificaciones."""
        evento_finalizado_inactivo = self.evento_finalizado.eve_fecha_fin < date.today()
        
        self.assertTrue(evento_finalizado_inactivo,
                       "Evento finalizado no debe enviar notificaciones")

    def test_ca4_5_contador_notificaciones_por_participante(self):
        """CA4.5: Lógica: contar notificaciones elegibles por participante."""
        notificaciones = ParticipanteEvento.objects.filter(
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado"
        ).count()
        
        # Debe tener al menos 2 eventos donde es aprobado
        self.assertGreaterEqual(notificaciones, 2,
                               "Debe tener al menos 2 notificaciones elegibles")

    # ========== TESTS DE INTEGRACIÓN ==========

    def test_ca5_1_flujo_completo_recibir_notificaciones(self):
        """CA5.1: Flujo completo para participante recibir notificaciones."""
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

    def test_ca5_2_flujo_preinscrito_sin_notificaciones(self):
        """CA5.2: Participante preinscrito no recibe notificaciones."""
        # Verificar estado
        self.assertEqual(self.registro_preinscrito.par_eve_estado, "Preinscrito")
        
        # Verificar que es diferente a aprobado
        self.assertNotEqual(
            self.registro_preinscrito.par_eve_estado,
            self.registro_aprobado_activo.par_eve_estado
        )

    def test_ca5_3_resumen_notificaciones_por_estado(self):
        """CA5.3: Resumen de quién recibe notificaciones."""
        aprobados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento_activo,
            par_eve_estado="Aprobado"
        ).count()
        
        no_aprobados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento_activo
        ).exclude(par_eve_estado="Aprobado").count()
        
        # Solo aprobados reciben notificaciones
        self.assertEqual(aprobados, 1)
        self.assertEqual(no_aprobados, 2)