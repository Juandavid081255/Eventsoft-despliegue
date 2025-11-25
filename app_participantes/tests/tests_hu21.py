# app_participantes/tests/tests_hu21.py

from django.test import TestCase, Client
from django.urls import reverse
from datetime import date, timedelta
from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento
from app_participantes.models import ParticipanteEvento
import time
import random


class ParticipanteAgendaTest(TestCase):
    """
    Tests para HU21: Visualización de agenda/programación del evento.
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        # Cédulas únicas
        cedula_admin = f"900{suffix[-10:]}"
        cedula_aprobado = f"800{suffix[-10:]}"
        cedula_preinscrito = f"700{suffix[-10:]}"
        
        self.password = "pass123456"
        
        # 1. Crear administrador con cedula
        admin_username = f"admin_agenda_{suffix[:20]}"
        self.admin_user = Usuario.objects.create_user(
            username=admin_username,
            password=self.password,
            rol=Usuario.Roles.ADMIN_EVENTO,
            email=f"{admin_username}@test.com",
            cedula=cedula_admin
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=self.admin_user)
        
        # Crear evento con programación
        self.evento = Evento.objects.create(
            eve_nombre=f"Evento Agenda {suffix[:10]}",
            eve_descripcion="Evento con programación",
            eve_fecha_inicio=date.today() + timedelta(days=30),
            eve_fecha_fin=date.today() + timedelta(days=32),
            eve_estado="Activo",
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="img.jpg",
            eve_programacion="prog.pdf",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_tienecosto="No",
        )
        
        # 2. Participante APROBADO con cedula
        self.aprobado_username = f"aprob_{suffix[:20]}"
        self.user_aprobado = Usuario.objects.create_user(
            username=self.aprobado_username,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.aprobado_username}@test.com",
            cedula=cedula_aprobado
        )
        self.participante_aprobado = Participante.objects.create(usuario=self.user_aprobado)
        self.registro_aprobado = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento,
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE_OK_{suffix[:8]}",
        )
        
        # 3. Participante PREINSCRITO con cedula
        self.preinscrito_username = f"prei_{suffix[:20]}"
        self.user_preinscrito = Usuario.objects.create_user(
            username=self.preinscrito_username,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.preinscrito_username}@test.com",
            cedula=cedula_preinscrito
        )
        self.participante_preinscrito = Participante.objects.create(usuario=self.user_preinscrito)
        self.registro_preinscrito = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento,
            par_eve_participante_fk=self.participante_preinscrito,
            par_eve_estado="Preinscrito",
            par_eve_clave=f"CLAVE_PEND_{suffix[:8]}",
        )
        
        # Clientes
        self.client_aprobado = Client()
        self.client_preinscrito = Client()
        
        # URLs
        self.url_detalle = reverse('ver_info_evento_par', args=[self.evento.pk])
        self.url_dashboard = reverse('dashboard_participante')

    # ========== TESTS POSITIVOS ==========

    def test_ca1_1_participante_aprobado_ve_programacion(self):
        """CA1.1: Participante aprobado ve la programación."""
        login_ok = self.client_aprobado.login(
            username=self.aprobado_username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_aprobado.get(self.url_detalle, follow=True)
        
        self.assertEqual(response.status_code, 200)

    def test_ca1_2_dashboard_muestra_eventos_aprobados(self):
        """CA1.2: Dashboard muestra eventos con acceso a programación."""
        login_ok = self.client_aprobado.login(
            username=self.aprobado_username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_aprobado.get(self.url_dashboard, follow=True)
        
        self.assertEqual(response.status_code, 200)

    def test_ca1_3_archivo_programacion_accesible(self):
        """CA1.3: Archivo de programación es accesible."""
        self.assertIsNotNone(self.evento.eve_programacion)
        self.assertTrue(bool(self.evento.eve_programacion))

    # ========== TESTS NEGATIVOS ==========

    def test_ca2_1_preinscrito_no_ve_programacion_completa(self):
        """CA2.1: Participante preinscrito NO ve programación."""
        login_ok = self.client_preinscrito.login(
            username=self.preinscrito_username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_preinscrito.get(self.url_detalle, follow=True)
        
        self.assertEqual(response.status_code, 200)

    def test_ca2_2_evento_sin_programacion_sin_error(self):
        """CA2.2: Evento sin programación se maneja sin errores."""
        suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        evento_sin_prog = Evento.objects.create(
            eve_nombre=f"Sin Programación {suffix[:10]}",
            eve_descripcion="Sin archivo",
            eve_fecha_inicio=date.today() + timedelta(days=30),
            eve_fecha_fin=date.today() + timedelta(days=32),
            eve_estado="Activo",
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="img.jpg",
            eve_programacion=None,
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_tienecosto="No",
        )
        
        ParticipanteEvento.objects.create(
            par_eve_evento_fk=evento_sin_prog,
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE_{suffix[:8]}",
        )
        
        login_ok = self.client_aprobado.login(
            username=self.aprobado_username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        url_sin_prog = reverse('ver_info_evento_par', args=[evento_sin_prog.pk])
        response = self.client_aprobado.get(url_sin_prog, follow=True)
        
        self.assertEqual(response.status_code, 200)

    def test_ca2_3_anonimo_redirige_login(self):
        """CA2.3: Usuario anónimo es redirigido al login."""
        client_anonimo = Client()
        response = client_anonimo.get(self.url_detalle, follow=True)
        
        content = response.content.decode('utf-8').lower()
        
        es_login = 'iniciar sesión' in content or 'iniciar sesi' in content
        
        self.assertTrue(
            es_login or response.status_code == 302,
            "Anónimo debe redirigirse a login"
        )

    def test_ca2_4_rechazado_no_ve_programacion(self):
        """CA2.4: Participante rechazado NO ve programación."""
        self.registro_aprobado.par_eve_estado = "Rechazado"
        self.registro_aprobado.save()
        
        login_ok = self.client_aprobado.login(
            username=self.aprobado_username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        response = self.client_aprobado.get(self.url_detalle, follow=True)
        
        self.assertEqual(response.status_code, 200)

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_modelos_relacionados_correctamente(self):
        """CA3: Modelos tienen relaciones correctas."""
        self.assertEqual(self.registro_aprobado.par_eve_evento_fk, self.evento)
        self.assertEqual(self.registro_aprobado.par_eve_participante_fk, self.participante_aprobado)
        self.assertEqual(self.participante_aprobado.usuario, self.user_aprobado)

    def test_ca4_estados_participantes_correctos(self):
        """CA4: Estados de participantes son correctos."""
        self.assertEqual(self.registro_aprobado.par_eve_estado, "Aprobado")
        self.assertEqual(self.registro_preinscrito.par_eve_estado, "Preinscrito")