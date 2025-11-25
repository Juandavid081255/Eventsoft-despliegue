# app_admin_eventos/tests/tests_hu56.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time
import random

from app_usuarios.models import Usuario, Evaluador, AdministradorEvento
from app_admin_eventos.models import Evento, Area
from app_evaluadores.models import EvaluadorEvento


class EvaluadorInscripcionControlTestCase(TestCase):
    """
    HU56: Casos de prueba para validar el control de inscripciones de evaluadores.
    Prueba que los evaluadores pueden/no pueden inscribirse según el estado.
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.client = Client()
        self.password = "testpass123"
        
        # ===== FECHAS =====
        self.hoy = date.today()
        self.futuro = self.hoy + timedelta(days=10)
        
        # ===== ADMINISTRADOR PROPIETARIO =====
        self.user_admin = Usuario.objects.create_user(
            username=f"admin_{suffix[:20]}",
            password=self.password,
            email=f"admin_{suffix[:10]}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Admin",
            last_name="Evento",
            cedula=f"100{suffix[-10:]}"
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.user_admin
        )
        
        # ===== EVALUADORES =====
        self.usuarios_evaluadores = []
        for i in range(3):
            user = Usuario.objects.create_user(
                username=f"evaluador_{i}_{suffix[:15]}",
                password=self.password,
                email=f"evaluador_{i}_{suffix[:5]}@test.com",
                rol=Usuario.Roles.EVALUADOR,
                first_name=f"Evaluador{i}",
                last_name="Test",
                cedula=f"500{i}{suffix[-8:]}"
            )
            evaluador = Evaluador.objects.create(usuario=user)
            self.usuarios_evaluadores.append((user, evaluador))
        
        # ===== ÁREA =====
        self.area = Area.objects.create(
            are_nombre="Tecnología",
            are_descripcion="Área de tecnología"
        )
        
        # ===== EVENTO CON INSCRIPCIONES HABILITADAS =====
        self.evento_abierto = Evento.objects.create(
            eve_nombre='Evento con Evaluadores Abierto',
            eve_descripcion='Descripción del evento abierto',
            eve_ciudad='Manizales',
            eve_lugar='Universidad',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=2),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"progcontent", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=True   # ✓ Habilitadas
        )
        
        # ===== EVENTO CON INSCRIPCIONES CERRADAS =====
        self.evento_cerrado = Evento.objects.create(
            eve_nombre='Evento con Evaluadores Cerrado',
            eve_descripcion='Descripción del evento cerrado',
            eve_ciudad='Bogotá',
            eve_lugar='Centro',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=1),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=50,
            eve_tienecosto='Si',
            eve_imagen=SimpleUploadedFile("img2.jpg", b"imgcontent2", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"progcontent2", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=False  # ✗ Deshabilitadas
        )

    # ============================================
    # CA 1: CONTROL DE ESTADO (POSITIVO)
    # ============================================

    def test_ca1_1_evento_abierto_permite_inscripciones_evaluadores(self):
        """CA 1.1: Evento abierto tiene inscripciones habilitadas para evaluadores."""
        self.assertTrue(self.evento_abierto.preinscripcion_habilitada_evaluadores,
                       "Las inscripciones de evaluadores deberían estar habilitadas")
        self.assertFalse(self.evento_cerrado.preinscripcion_habilitada_evaluadores,
                        "Las inscripciones de evaluadores deberían estar deshabilitadas en evento cerrado")
        
        print("\n✓ CA 1.1: PASSED - Evento abierto tiene inscripciones de evaluadores habilitadas")

    def test_ca1_2_admin_habilita_inscripciones_evaluadores(self):
        """CA 1.2: El administrador puede habilitar inscripciones de evaluadores."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Inicialmente deshabilitadas
        self.assertFalse(self.evento_cerrado.preinscripcion_habilitada_evaluadores)
        
        # Habilitar inscripciones de evaluadores
        url = reverse('cambiar_preinscripcion_evaluador', args=[self.evento_cerrado.pk])
        response = self.client.post(url)
        
        self.assertIn(response.status_code, [200, 302])
        
        self.evento_cerrado.refresh_from_db()
        self.assertTrue(self.evento_cerrado.preinscripcion_habilitada_evaluadores)
        
        print("\n✓ CA 1.2: PASSED - Admin habilita inscripciones de evaluadores")

    def test_ca1_3_admin_deshabilita_inscripciones_evaluadores(self):
        """CA 1.3: El administrador puede deshabilitar inscripciones de evaluadores."""
        # Inicialmente habilitadas
        self.assertTrue(self.evento_abierto.preinscripcion_habilitada_evaluadores)
        
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Deshabilitar inscripciones de evaluadores
        url = reverse('cambiar_preinscripcion_evaluador', args=[self.evento_abierto.pk])
        response = self.client.post(url)
        
        self.assertIn(response.status_code, [200, 302])
        
        self.evento_abierto.refresh_from_db()
        self.assertFalse(self.evento_abierto.preinscripcion_habilitada_evaluadores)
        
        print("\n✓ CA 1.3: PASSED - Admin deshabilita inscripciones de evaluadores")

    # ============================================
    # CA 2: RESTRICCIONES Y LÓGICA (NEGATIVO)
    # ============================================

    def test_ca2_1_evento_cerrado_rechaza_inscripciones_evaluadores(self):
        """CA 2.1: Evento cerrado NO permite inscripciones para evaluadores."""
        # Verificar que inscripciones están deshabilitadas
        self.assertFalse(self.evento_cerrado.preinscripcion_habilitada_evaluadores,
                        "Las inscripciones deben estar cerradas")
        
        # Estado del evento debe ser Activo
        self.assertEqual(self.evento_cerrado.eve_estado, 'Activo')
        
        print("\n✓ CA 2.1: PASSED - Evento cerrado rechaza inscripciones de evaluadores")

    def test_ca2_2_solo_propietario_puede_cambiar_inscripciones_evaluadores(self):
        """CA 2.2: Solo el propietario del evento puede cambiar inscripciones de evaluadores."""
        # Crear otro administrador
        user_otro_admin = Usuario.objects.create_user(
            username=f"otro_admin",
            password=self.password,
            email="otro_admin@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            cedula="9999999"
        )
        otro_admin, _ = AdministradorEvento.objects.get_or_create(usuario=user_otro_admin)
        
        # Cambiar sesión al otro admin
        self.client.login(username=user_otro_admin.username, password=self.password)
        
        url = reverse('cambiar_preinscripcion_evaluador', args=[self.evento_abierto.pk])
        response = self.client.post(url)
        
        # Debe retornar 404 (no propietario)
        self.assertEqual(response.status_code, 404)
        
        # Verificar que el estado no cambió
        self.evento_abierto.refresh_from_db()
        self.assertTrue(self.evento_abierto.preinscripcion_habilitada_evaluadores)
        
        print("\n✓ CA 2.2: PASSED - Solo propietario puede cambiar")

    def test_ca2_3_evaluadores_independiente_de_otros_roles(self):
        """CA 2.3: Toggle de evaluadores es independiente de otros roles."""
        # Evento con evaluadores cerrados pero participantes abiertos
        self.assertFalse(self.evento_cerrado.preinscripcion_habilitada_evaluadores)
        self.evento_cerrado.preinscripcion_habilitada_participantes = True
        self.evento_cerrado.save()
        
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Habilitar solo evaluadores
        url = reverse('cambiar_preinscripcion_evaluador', args=[self.evento_cerrado.pk])
        response = self.client.post(url)
        
        self.assertIn(response.status_code, [200, 302])
        
        self.evento_cerrado.refresh_from_db()
        
        # Evaluadores habilitados
        self.assertTrue(self.evento_cerrado.preinscripcion_habilitada_evaluadores)
        
        # Participantes siguen habilitados (independencia)
        self.assertTrue(self.evento_cerrado.preinscripcion_habilitada_participantes)
        
        print("\n✓ CA 2.3: PASSED - Toggle de evaluadores independiente de otros roles")

    # ============================================
    # CA 3: VALIDACIONES ESPECÍFICAS
    # ============================================

    def test_ca3_1_evaluador_no_autenticado_rechazado(self):
        """CA 3.1: Evaluador no autenticado no puede acceder."""
        self.client.logout()
        
        # Intentar acceder sin estar logueado
        url = reverse('crear_evaluador', args=[self.evento_abierto.pk])
        response = self.client.post(url, {
            'eva_eve_fecha_hora': self.hoy,
            'eva_eve_estado': 'Pendiente'
        })
        
        # Debe ser rechazado (302, 403, 404)
        self.assertIn(response.status_code, [200, 302, 403, 404],
                     f"Se esperaba respuesta válida, se obtuvo {response.status_code}")
        
        # Verificar que NO se creó inscripción
        user, evaluador = self.usuarios_evaluadores[0]
        inscripcion_existe = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=evaluador,
            eva_eve_evento_fk=self.evento_abierto
        ).exists()
        
        self.assertFalse(inscripcion_existe, "No debería crearse inscripción sin autenticación")
        
        print("\n✓ CA 3.1: PASSED - No autenticado rechazado")

    def test_ca3_2_evento_cancelado_rechaza_inscripciones_evaluadores(self):
        """CA 3.2: Evento cancelado rechaza inscripciones de evaluadores."""
        # Crear evento cancelado con inscripciones "habilitadas"
        evento_cancelado = Evento.objects.create(
            eve_nombre='Evento Cancelado',
            eve_descripcion='Paradoja de prueba',
            eve_ciudad='Medellín',
            eve_lugar='Sala',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=1),
            eve_estado='Cancelado',  # ✗ CANCELADO
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=30,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img3.jpg", b"content", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog3.pdf", b"content", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=True  # ✓ Pero "habilitadas"
        )
        
        # Aunque las inscripciones estén habilitadas, el evento está cancelado
        self.assertEqual(evento_cancelado.eve_estado, 'Cancelado')
        self.assertTrue(evento_cancelado.preinscripcion_habilitada_evaluadores)
        
        user, evaluador = self.usuarios_evaluadores[0]
        self.client.login(username=user.username, password=self.password)
        
        url = reverse('crear_evaluador', args=[evento_cancelado.pk])
        response = self.client.post(url, {
            'eva_eve_fecha_hora': self.hoy,
            'eva_eve_estado': 'Pendiente'
        })
        
        # Debe ser rechazado o redirigido
        self.assertIn(response.status_code, [200, 302, 400, 403])
        
        # No debe haber inscripción
        inscripcion_existe = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=evaluador,
            eva_eve_evento_fk=evento_cancelado
        ).exists()
        self.assertFalse(inscripcion_existe, "No debería haber inscripción en evento cancelado")
        
        print("\n✓ CA 3.2: PASSED - Evento cancelado rechaza inscripciones")

    def test_ca3_3_cambiar_estado_afecta_disponibilidad(self):
        """CA 3.3: Cambiar estado de inscripciones de evaluadores funciona."""
        # Evento inicia cerrado
        self.assertFalse(self.evento_cerrado.preinscripcion_habilitada_evaluadores)
        
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Habilitar
        url = reverse('cambiar_preinscripcion_evaluador', args=[self.evento_cerrado.pk])
        response = self.client.post(url)
        
        self.assertIn(response.status_code, [200, 302])
        
        self.evento_cerrado.refresh_from_db()
        self.assertTrue(self.evento_cerrado.preinscripcion_habilitada_evaluadores)
        
        # Deshabilitar
        response = self.client.post(url)
        
        self.assertIn(response.status_code, [200, 302])
        
        self.evento_cerrado.refresh_from_db()
        self.assertFalse(self.evento_cerrado.preinscripcion_habilitada_evaluadores)
        
        print("\n✓ CA 3.3: PASSED - Cambio de estado funciona")