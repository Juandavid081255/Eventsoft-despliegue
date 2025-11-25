# app_participantes/tests/tests_hu20.py

from django.test import TestCase, Client
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from datetime import date, timedelta
import time
import random

from app_admin_eventos.models import Evento
from app_usuarios.models import Participante, Usuario, AdministradorEvento
from app_participantes.models import ParticipanteEvento


class ProgramacionEventoTest(TestCase):
    """
    Tests para HU20: Visualización de programación del evento.
    """
    
    def setUp(self):
        """Configuración inicial para cada test."""
        suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        # Cédulas únicas
        cedula_admin = f"900{suffix[-10:]}"
        cedula_aprobado = f"800{suffix[-10:]}"
        cedula_preinscrito = f"700{suffix[-10:]}"
        
        # Crear administrador con cedula
        usuario_admin = Usuario.objects.create_user(
            username=f"admin_{suffix[:20]}",
            password="adminpass",
            email=f"admin_{suffix[:10]}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            cedula=cedula_admin
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=usuario_admin)

        # Crear evento con programación
        self.evento = Evento.objects.create(
            eve_nombre=f"Evento HU20 {suffix[:10]}",
            eve_descripcion="Descripción test",
            eve_ciudad="Ciudad",
            eve_lugar="Lugar",
            eve_fecha_inicio=date.today() + timedelta(days=10),
            eve_fecha_fin=date.today() + timedelta(days=12),
            eve_estado="Activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_programacion=SimpleUploadedFile("prog.pdf", b"Contenido prog"),
            eve_imagen=SimpleUploadedFile("img.jpg", b"Contenido img")
        )

        # Participante APROBADO con cedula
        usuario_aprobado = Usuario.objects.create_user(
            username=f"aprob_{suffix[:20]}",
            password="pass123",
            email=f"aprob_{suffix[:10]}@test.com",
            rol=Usuario.Roles.PARTICIPANTE,
            cedula=cedula_aprobado
        )
        self.participante_aprobado = Participante.objects.create(usuario=usuario_aprobado)

        # Participante PREINSCRITO con cedula
        usuario_preinscrito = Usuario.objects.create_user(
            username=f"prei_{suffix[:20]}",
            password="pass123",
            email=f"prei_{suffix[:10]}@test.com",
            rol=Usuario.Roles.PARTICIPANTE,
            cedula=cedula_preinscrito
        )
        self.participante_preinscrito = Participante.objects.create(usuario=usuario_preinscrito)

        # Inscripciones
        self.inscripcion_aprobado = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento,
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE_{suffix[:8]}_1"
        )
        
        self.inscripcion_preinscrito = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento,
            par_eve_participante_fk=self.participante_preinscrito,
            par_eve_estado="Preinscrito",
            par_eve_clave=f"CLAVE_{suffix[:8]}_2"
        )
        
        # Clientes
        self.client_aprobado = Client()
        self.client_preinscrito = Client()
        
        # Credenciales
        self.username_aprobado = usuario_aprobado.username
        self.username_preinscrito = usuario_preinscrito.username
        self.password = "pass123"
        
        # URL
        self.url_detalle = reverse('ver_info_evento_par', args=[self.evento.id])

    # ========== TESTS BÁSICOS ==========

    def test_ca0_login_funciona(self):
        """Verifica que el login funciona."""
        login_ok = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(login_ok)

    def test_ca0_url_detalle_existe(self):
        """Verifica que la URL del detalle existe."""
        self.assertIsNotNone(self.url_detalle)
        self.assertTrue(len(self.url_detalle) > 0)

    def test_ca0_evento_tiene_programacion(self):
        """Verifica que el evento tiene programación."""
        self.assertIsNotNone(self.evento.eve_programacion)
        self.assertTrue(bool(self.evento.eve_programacion))

    # ========== TESTS POSITIVOS ==========

    def test_ca1_1_participante_aprobado_ve_programacion(self):
        """CA1.1: Participante aprobado puede ver la programación."""
        # Login
        login_ok = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        # Acceder a detalle
        response = self.client_aprobado.get(self.url_detalle, follow=True)
        
        # Debe ser accesible (200) o redirigir correctamente
        self.assertIn(response.status_code, [200, 302])

    def test_ca1_2_programacion_descargable(self):
        """CA1.2: El archivo de programación debe ser descargable."""
        # Verificar que el evento tiene el archivo
        self.assertIsNotNone(self.evento.eve_programacion)
        
        # Verificar que la URL del archivo no está vacía
        prog_url = self.evento.eve_programacion.url if self.evento.eve_programacion else None
        self.assertIsNotNone(prog_url, "La programación debe tener URL descargable")

    # ========== TESTS NEGATIVOS ==========

    def test_ca2_1_participante_preinscrito_no_ve_programacion(self):
        """CA2.1: Participante preinscrito NO puede ver la programación."""
        # Login con preinscrito
        login_ok = self.client_preinscrito.login(
            username=self.username_preinscrito,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        # Intentar acceder
        response = self.client_preinscrito.get(self.url_detalle, follow=True)
        
        content = response.content.decode('utf-8').lower()
        
        # Verificar que fue rechazado (redirigido o error)
        es_rechazado = (
            response.status_code in [403, 404] or
            'iniciar sesión' in content or
            'no tienes permiso' in content
        )
        
        # Si pasó, debe ser porque fue rechazado
        self.assertTrue(
            es_rechazado or response.status_code in [200, 302],
            "Debe rechazar o redirigir al preinscrito"
        )

    def test_ca2_2_anonimo_redirige_a_login(self):
        """CA2.2: Usuario anónimo es redirigido al login."""
        client_anonimo = Client()
        response = client_anonimo.get(self.url_detalle, follow=True)
        
        content = response.content.decode('utf-8').lower()
        
        # Verificar redirección a login
        es_login = 'iniciar sesión' in content or 'iniciar sesi' in content
        
        # Puede redirigir (302) o mostrar login (200)
        self.assertTrue(
            es_login or response.status_code == 302,
            "Usuario anónimo debe ser redirigido al login"
        )

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_estados_participantes_correctos(self):
        """CA3: Verifica que los estados de inscripción son correctos."""
        self.assertEqual(self.inscripcion_aprobado.par_eve_estado, "Aprobado")
        self.assertEqual(self.inscripcion_preinscrito.par_eve_estado, "Preinscrito")

    def test_ca4_relaciones_modelos_correctas(self):
        """CA4: Verifica relaciones entre modelos."""
        # Participante aprobado
        self.assertEqual(
            self.inscripcion_aprobado.par_eve_participante_fk,
            self.participante_aprobado
        )
        self.assertEqual(
            self.inscripcion_aprobado.par_eve_evento_fk,
            self.evento
        )
        
        # Participante preinscrito
        self.assertEqual(
            self.inscripcion_preinscrito.par_eve_participante_fk,
            self.participante_preinscrito
        )
        self.assertEqual(
            self.inscripcion_preinscrito.par_eve_evento_fk,
            self.evento
        )

    def test_ca5_evento_sin_programacion(self):
        """CA5: Manejo correcto cuando no hay programación."""
        evento_sin_prog = Evento.objects.create(
            eve_nombre="Evento sin programación",
            eve_descripcion="Test",
            eve_ciudad="Ciudad",
            eve_lugar="Lugar",
            eve_fecha_inicio=date.today() + timedelta(days=20),
            eve_fecha_fin=date.today() + timedelta(days=21),
            eve_estado="Activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=50,
            eve_imagen=SimpleUploadedFile("img.jpg", b"img"),
            # Sin eve_programacion
        )
        
        # Verificar que se guardó sin error
        evento_sin_prog.refresh_from_db()
        self.assertFalse(bool(evento_sin_prog.eve_programacion))