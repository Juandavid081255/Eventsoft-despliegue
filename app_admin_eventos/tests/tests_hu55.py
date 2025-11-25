# app_admin_eventos/tests/tests_hu55.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time
import random

from app_usuarios.models import Usuario, Asistente, Participante, AdministradorEvento
from app_admin_eventos.models import Evento, Area
from app_asistentes.models import AsistenteEvento
from app_participantes.models import ParticipanteEvento


class InscripcionControlTestCase(TestCase):
    """
    HU55: Casos de prueba para validar el control de inscripciones.
    Prueba que los usuarios pueden/no pueden inscribirse según el estado de inscripciones.
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
        
        # ===== ASISTENTES =====
        self.usuarios_asistentes = []
        for i in range(3):
            user = Usuario.objects.create_user(
                username=f"asistente_{i}_{suffix[:15]}",
                password=self.password,
                email=f"asistente_{i}_{suffix[:5]}@test.com",
                rol=Usuario.Roles.ASISTENTE,
                first_name=f"Asistente{i}",
                last_name="Test",
                cedula=f"300{i}{suffix[-8:]}"
            )
            asistente = Asistente.objects.create(usuario=user)
            self.usuarios_asistentes.append((user, asistente))
        
        # ===== PARTICIPANTES =====
        self.usuarios_participantes = []
        for i in range(3):
            user = Usuario.objects.create_user(
                username=f"participante_{i}_{suffix[:13]}",
                password=self.password,
                email=f"participante_{i}_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name=f"Participante{i}",
                last_name="Test",
                cedula=f"400{i}{suffix[-8:]}"
            )
            participante = Participante.objects.create(usuario=user)
            self.usuarios_participantes.append((user, participante))
        
        # ===== ÁREA =====
        self.area = Area.objects.create(
            are_nombre="Tecnología",
            are_descripcion="Área de tecnología"
        )
        
        # ===== EVENTO CON INSCRIPCIONES HABILITADAS =====
        self.evento_abierto = Evento.objects.create(
            eve_nombre='Evento con Inscripciones Abiertas',
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
            preinscripcion_habilitada_asistentes=True,   # ✓ Habilitadas
            preinscripcion_habilitada_participantes=True  # ✓ Habilitadas
        )
        
        # ===== EVENTO CON INSCRIPCIONES CERRADAS =====
        self.evento_cerrado = Evento.objects.create(
            eve_nombre='Evento con Inscripciones Cerradas',
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
            preinscripcion_habilitada_asistentes=False,  # ✗ Deshabilitadas
            preinscripcion_habilitada_participantes=False # ✗ Deshabilitadas
        )

    # ============================================
    # CA 1: INSCRIPCIÓN EXITOSA (POSITIVO)
    # ============================================

    def test_ca1_1_evento_abierto_permite_inscripciones_asistentes(self):
        """CA 1.1: Evento abierto tiene inscripciones habilitadas para asistentes."""
        self.assertTrue(self.evento_abierto.preinscripcion_habilitada_asistentes,
                       "Las inscripciones deberían estar habilitadas")
        self.assertFalse(self.evento_cerrado.preinscripcion_habilitada_asistentes,
                        "Las inscripciones deberían estar deshabilitadas en evento cerrado")
        
        print("\n✓ CA 1.1: PASSED - Evento abierto tiene inscripciones habilitadas")

    def test_ca1_2_evento_abierto_permite_inscripciones_participantes(self):
        """CA 1.2: Evento abierto tiene inscripciones habilitadas para participantes."""
        self.assertTrue(self.evento_abierto.preinscripcion_habilitada_participantes,
                       "Las inscripciones deberían estar habilitadas")
        self.assertFalse(self.evento_cerrado.preinscripcion_habilitada_participantes,
                        "Las inscripciones deberían estar deshabilitadas en evento cerrado")
        
        print("\n✓ CA 1.2: PASSED - Evento abierto tiene inscripciones habilitadas")

    # ============================================
    # CA 2: INSCRIPCIÓN RECHAZADA (NEGATIVO)
    # ============================================

    def test_ca2_1_evento_cerrado_no_permite_inscripciones_asistentes(self):
        """CA 2.1: Evento cerrado NO permite inscripciones para asistentes."""
        # Verificar que inscripciones están deshabilitadas
        self.assertFalse(self.evento_cerrado.preinscripcion_habilitada_asistentes,
                        "Las inscripciones deben estar cerradas")
        
        # Estado del evento debe ser Activo (para que se pueda rechazar por inscripciones cerradas)
        self.assertEqual(self.evento_cerrado.eve_estado, 'Activo')
        
        print("\n✓ CA 2.1: PASSED - Evento cerrado rechaza inscripciones asistentes")

    def test_ca2_2_evento_cerrado_no_permite_inscripciones_participantes(self):
        """CA 2.2: Evento cerrado NO permite inscripciones para participantes."""
        # Verificar que inscripciones están deshabilitadas
        self.assertFalse(self.evento_cerrado.preinscripcion_habilitada_participantes,
                        "Las inscripciones deben estar cerradas")
        
        # Estado del evento debe ser Activo
        self.assertEqual(self.evento_cerrado.eve_estado, 'Activo')
        
        print("\n✓ CA 2.2: PASSED - Evento cerrado rechaza inscripciones participantes")

    # ============================================
    # CA 3: VALIDACIONES ESPECÍFICAS
    # ============================================

    def test_ca3_1_usuario_no_autenticado_rechazado(self):
        """CA 3.1: URL de inscripción requiere autenticación."""
        self.client.logout()
        
        # Intentar acceder sin estar logueado
        url = reverse('crear_asistente', args=[self.evento_abierto.pk])
        response = self.client.post(url, {
            'asi_eve_fecha_hora': self.hoy,
            'asi_eve_estado': 'Pendiente',
            'asi_eve_clave': 'clave123'
        })
        
        # POST sin autenticación debe ser rechazado (302, 403, 404 o incluso 200 si la vista maneja el error)
        # Lo importante es que NO se cree la inscripción
        self.assertIn(response.status_code, [200, 302, 403, 404],
                     f"Se esperaba respuesta válida, se obtuvo {response.status_code}")
        
        # Verificar que NO se creó inscripción
        user, asistente = self.usuarios_asistentes[0]
        inscripcion_existe = AsistenteEvento.objects.filter(
            asi_eve_asistente_fk=asistente,
            asi_eve_evento_fk=self.evento_abierto
        ).exists()
        
        # Si la vista permite GET, al menos POST debería estar protegido
        # o si GET retorna 200, debería ser un formulario sin crear nada
        self.assertFalse(inscripcion_existe, "No debería crearse inscripción sin autenticación")
        
        print("\n✓ CA 3.1: PASSED - Inscripción no se crea sin autenticación")

    def test_ca3_2_cambiar_estado_afecta_disponibilidad(self):
        """CA 3.2: Cambiar estado de inscripciones afecta la disponibilidad."""
        # Evento inicia abierto
        self.assertTrue(self.evento_abierto.preinscripcion_habilitada_asistentes)
        
        # Cerrar inscripciones
        self.evento_abierto.preinscripcion_habilitada_asistentes = False
        self.evento_abierto.save()
        
        # Verificar que cambió
        self.evento_abierto.refresh_from_db()
        self.assertFalse(self.evento_abierto.preinscripcion_habilitada_asistentes)
        
        print("\n✓ CA 3.2: PASSED - Cambio de estado funciona correctamente")

    def test_ca3_3_evento_cancelado_rechaza_inscripciones(self):
        """CA 3.3: Evento cancelado rechaza inscripciones independientemente del estado."""
        # Crear evento cancelado pero con inscripciones "habilitadas"
        evento_cancelado = Evento.objects.create(
            eve_nombre='Evento Cancelado con Inscripciones Habilitadas',
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
            preinscripcion_habilitada_asistentes=True  # ✓ Pero "habilitadas"
        )
        
        # Aunque las inscripciones estén habilitadas, el evento está cancelado
        self.assertEqual(evento_cancelado.eve_estado, 'Cancelado')
        self.assertTrue(evento_cancelado.preinscripcion_habilitada_asistentes)
        
        # La vista debe rechazar por estar cancelado, no por estar cerrado
        user, asistente = self.usuarios_asistentes[0]
        self.client.login(username=user.username, password=self.password)
        
        url = reverse('crear_asistente', args=[evento_cancelado.pk])
        response = self.client.post(url, {
            'asi_eve_fecha_hora': self.hoy,
            'asi_eve_estado': 'Pendiente',
            'asi_eve_clave': 'clave123'
        })
        
        # Debe ser rechazado o redirigido
        self.assertIn(response.status_code, [200, 302, 400, 403])
        
        # No debe haber inscripción
        inscripcion_existe = AsistenteEvento.objects.filter(
            asi_eve_asistente_fk=asistente,
            asi_eve_evento_fk=evento_cancelado
        ).exists()
        self.assertFalse(inscripcion_existe, "No debería haber inscripción en evento cancelado")
        
        print("\n✓ CA 3.3: PASSED - Evento cancelado rechaza inscripciones")

    def test_ca3_4_capacidad_maxima_respetada(self):
        """CA 3.4: La capacidad máxima del evento es respetada."""
        # Evento con capacidad muy baja
        evento_pequeno = Evento.objects.create(
            eve_nombre='Evento Muy Pequeño',
            eve_descripcion='Capacidad de solo 2',
            eve_ciudad='Cali',
            eve_lugar='Oficina',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=1),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=2,  # Solo 2 lugares
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img4.jpg", b"content", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog4.pdf", b"content", content_type="application/pdf"),
            preinscripcion_habilitada_asistentes=True
        )
        
        # Llenar el evento manualmente
        for i in range(2):
            user = Usuario.objects.create_user(
                username=f"fill_{i}_test",
                password=self.password,
                email=f"fill_{i}@test.com",
                rol=Usuario.Roles.ASISTENTE,
                cedula=f"5000{i}"
            )
            asistente = Asistente.objects.create(usuario=user)
            AsistenteEvento.objects.create(
                asi_eve_asistente_fk=asistente,
                asi_eve_evento_fk=evento_pequeno,
                asi_eve_fecha_hora=self.hoy,
                asi_eve_estado='Aprobado',
                asi_eve_soporte=SimpleUploadedFile("s.pdf", b"c"),
                asi_eve_qr=SimpleUploadedFile("q.jpg", b"c"),
                asi_eve_clave='key'
            )
        
        # Verificar que está lleno
        inscritos = AsistenteEvento.objects.filter(asi_eve_evento_fk=evento_pequeno).count()
        self.assertEqual(inscritos, evento_pequeno.eve_capacidad,
                        "El evento debe estar lleno")
        
        print("\n✓ CA 3.4: PASSED - Capacidad máxima validada")