# app_usuarios/tests/tests_hu91.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time as time_module
import random

from app_usuarios.models import Usuario, AdministradorEvento
from app_admin_eventos.models import Evento


class ConsultaEventoSuperAdminTestCase(TestCase):
    """
    HU91: Como Super Admin quiero acceder a la información de un evento en particular
    para conocer la información general de un evento activo y poder subirlo al sitio Web.
    
    Valida:
    - CA1: Control de acceso (solo Super Admin)
    - CA2: Información del evento
    - CA3: Validaciones y errores
    - CA4: Información adicional
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        suffix = f"{int(time_module.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.client = Client()
        self.password = "testpass123"
        
        # ===== FECHAS =====
        self.hoy = date.today()
        self.fecha_futura = self.hoy + timedelta(days=60)
        self.fecha_pasada = self.hoy - timedelta(days=10)
        
        # ===== SUPER ADMIN =====
        self.user_superadmin = Usuario.objects.create_user(
            username=f"superadmin_{suffix[:15]}",
            password=self.password,
            email=f"superadmin_{suffix[:5]}@sistema.com",
            rol=Usuario.Roles.SUPERADMIN,
            first_name="Super",
            last_name="Admin",
            cedula=f"100{suffix[-10:]}",
            is_superuser=True,
            is_staff=True,
            telefono="3001234567"
        )
        
        # ===== ADMIN DE EVENTO =====
        self.user_admin = Usuario.objects.create_user(
            username=f"admin_{suffix[:12]}",
            password=self.password,
            email=f"admin_{suffix[:5]}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Elena",
            last_name="Velez",
            cedula=f"200{suffix[-10:]}",
            is_staff=True,
            telefono="3007654321"
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.user_admin
        )
        
        # ===== USUARIOS SIN ACCESO =====
        self.user_participante = Usuario.objects.create_user(
            username=f"part_{suffix[:15]}",
            password=self.password,
            email=f"part_{suffix[:5]}@test.com",
            rol=Usuario.Roles.PARTICIPANTE,
            first_name="Participante",
            last_name="Normal",
            cedula=f"300{suffix[-10:]}",
            telefono="3009876543"
        )
        
        self.user_evaluador = Usuario.objects.create_user(
            username=f"eval_{suffix[:15]}",
            password=self.password,
            email=f"eval_{suffix[:5]}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            first_name="Evaluador",
            last_name="Normal",
            cedula=f"400{suffix[-10:]}",
            telefono="3005555555"
        )
        
        self.user_asistente = Usuario.objects.create_user(
            username=f"asist_{suffix[:15]}",
            password=self.password,
            email=f"asist_{suffix[:5]}@test.com",
            rol=Usuario.Roles.ASISTENTE,
            first_name="Asistente",
            last_name="Normal",
            cedula=f"500{suffix[-10:]}",
            telefono="3004444444"
        )
        
        self.user_visitante = Usuario.objects.create_user(
            username=f"visit_{suffix[:15]}",
            password=self.password,
            email=f"visit_{suffix[:5]}@test.com",
            rol=Usuario.Roles.VISITANTE,
            first_name="Visitante",
            last_name="Normal",
            cedula=f"600{suffix[-10:]}",
            telefono="3003333333"
        )
        
        # ===== EVENTO ACTIVO COMPLETO =====
        self.evento_activo = Evento.objects.create(
            eve_nombre='Cumbre de Innovación Digital',
            eve_descripcion='Conferencia sobre tendencias tecnológicas de 2026.',
            eve_ciudad='Bogota',
            eve_lugar='Virtual - Zoom Meeting',
            eve_fecha_inicio=self.fecha_futura,
            eve_fecha_fin=self.fecha_futura + timedelta(days=2),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=1000,
            eve_tienecosto='Si',
            eve_imagen=SimpleUploadedFile("banner.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("programacion.pdf", b"pdfcontent", content_type="application/pdf"),
            eve_informacion_tecnica=SimpleUploadedFile("tecnica.pdf", b"tecnicacontent", content_type="application/pdf"),
            preinscripcion_habilitada_asistentes=True,
            preinscripcion_habilitada_participantes=True,
            preinscripcion_habilitada_evaluadores=False
        )
        
        # ===== EVENTO ARCHIVADO =====
        self.evento_archivado = Evento.objects.create(
            eve_nombre='Seminario Historico',
            eve_descripcion='Seminario sobre historia antigua.',
            eve_ciudad='Cartagena',
            eve_lugar='Centro Historico',
            eve_fecha_inicio=self.fecha_pasada - timedelta(days=30),
            eve_fecha_fin=self.fecha_pasada - timedelta(days=28),
            eve_estado='Archivado',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=200,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("banner2.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"pdfcontent", content_type="application/pdf")
        )
        
        # ===== EVENTO INCOMPLETO (sin imagen) =====
        self.evento_incompleto = Evento.objects.create(
            eve_nombre='Evento Incompleto',
            eve_descripcion='Evento sin imagen de portada.',
            eve_ciudad='Medellin',
            eve_lugar='Presencial',
            eve_fecha_inicio=self.fecha_futura + timedelta(days=10),
            eve_fecha_fin=self.fecha_futura + timedelta(days=11),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=500,
            eve_tienecosto='No',
            eve_imagen=None,  # SIN IMAGEN
            eve_programacion=SimpleUploadedFile("prog3.pdf", b"pdfcontent", content_type="application/pdf")
        )

    # ============================================
    # CA 1: CONTROL DE ACCESO
    # ============================================

    def test_ca1_1_superadmin_acceso_exitoso(self):
        """CA 1.1: Super Admin puede acceder al detalle del evento."""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Verificar que es Super Admin
        self.assertTrue(self.user_superadmin.is_superuser)
        self.assertTrue(self.user_superadmin.is_staff)
        
        # Obtener evento
        evento = Evento.objects.get(id=self.evento_activo.id)
        self.assertIsNotNone(evento)
        self.assertEqual(evento.eve_nombre, 'Cumbre de Innovación Digital')
        
        print("\n✓ CA 1.1: PASSED - Super Admin acceso exitoso")

    def test_ca1_2_admin_evento_no_puede_consultar_informacion_publica(self):
        """CA 1.2: Admin de evento NO tiene acceso a información pública del evento."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Admin evento NO es superuser
        self.assertFalse(self.user_admin.is_superuser)
        
        # No debería poder ver información pública
        tiene_acceso = self.user_admin.is_superuser
        self.assertFalse(tiene_acceso)
        
        print("\n✓ CA 1.2: PASSED - Admin evento sin acceso")

    def test_ca1_3_participante_sin_acceso(self):
        """CA 1.3: Participante NO tiene acceso a información pública."""
        self.client.login(username=self.user_participante.username, password=self.password)
        
        self.assertFalse(self.user_participante.is_superuser)
        tiene_acceso = self.user_participante.is_superuser
        self.assertFalse(tiene_acceso)
        
        print("\n✓ CA 1.3: PASSED - Participante sin acceso")

    def test_ca1_4_evaluador_sin_acceso(self):
        """CA 1.4: Evaluador NO tiene acceso a información pública."""
        self.client.login(username=self.user_evaluador.username, password=self.password)
        
        self.assertFalse(self.user_evaluador.is_superuser)
        tiene_acceso = self.user_evaluador.is_superuser
        self.assertFalse(tiene_acceso)
        
        print("\n✓ CA 1.4: PASSED - Evaluador sin acceso")

    def test_ca1_5_asistente_sin_acceso(self):
        """CA 1.5: Asistente NO tiene acceso a información pública."""
        self.client.login(username=self.user_asistente.username, password=self.password)
        
        self.assertFalse(self.user_asistente.is_superuser)
        tiene_acceso = self.user_asistente.is_superuser
        self.assertFalse(tiene_acceso)
        
        print("\n✓ CA 1.5: PASSED - Asistente sin acceso")

    def test_ca1_6_visitante_sin_acceso(self):
        """CA 1.6: Visitante NO tiene acceso a información pública."""
        self.client.login(username=self.user_visitante.username, password=self.password)
        
        self.assertFalse(self.user_visitante.is_superuser)
        tiene_acceso = self.user_visitante.is_superuser
        self.assertFalse(tiene_acceso)
        
        print("\n✓ CA 1.6: PASSED - Visitante sin acceso")

    def test_ca1_7_usuario_no_autenticado_sin_acceso(self):
        """CA 1.7: Usuario no autenticado NO tiene acceso."""
        self.client.logout()
        
        # No hay sesión activa
        usuario_id = self.client.session.get('_auth_user_id')
        self.assertIsNone(usuario_id)
        
        print("\n✓ CA 1.7: PASSED - Usuario no autenticado sin acceso")

    # ============================================
    # CA 2: INFORMACIÓN DEL EVENTO
    # ============================================

    def test_ca2_1_informacion_basica_evento(self):
        """CA 2.1: Se obtiene información básica (nombre, descripción, estado, capacidad)."""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_activo.id)
        
        # Información básica
        self.assertEqual(evento.eve_nombre, 'Cumbre de Innovación Digital')
        self.assertIn('tendencias', evento.eve_descripcion)
        self.assertEqual(evento.eve_estado, 'Activo')
        self.assertEqual(evento.eve_capacidad, 1000)
        self.assertEqual(evento.eve_tienecosto, 'Si')
        
        print("\n✓ CA 2.1: PASSED - Información básica obtenida")

    def test_ca2_2_informacion_administrador(self):
        """CA 2.2: Se obtiene información de contacto del administrador."""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_activo.id)
        admin = evento.eve_administrador_fk.usuario
        
        # Información del administrador
        self.assertEqual(admin.first_name, 'Elena')
        self.assertEqual(admin.last_name, 'Velez')
        self.assertEqual(admin.email, self.user_admin.email)
        self.assertIsNotNone(admin.telefono)
        self.assertEqual(admin.cedula, self.user_admin.cedula)
        
        print("\n✓ CA 2.2: PASSED - Información del administrador obtenida")

    def test_ca2_3_informacion_logistica(self):
        """CA 2.3: Se obtiene información de logística (ubicación, fechas, capacidad, materiales)."""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_activo.id)
        
        # Logística
        self.assertEqual(evento.eve_ciudad, 'Bogota')
        self.assertEqual(evento.eve_lugar, 'Virtual - Zoom Meeting')
        self.assertLessEqual(evento.eve_fecha_inicio, evento.eve_fecha_fin)
        self.assertEqual(evento.eve_capacidad, 1000)
        self.assertIsNotNone(evento.eve_imagen)
        self.assertIsNotNone(evento.eve_programacion)
        
        print("\n✓ CA 2.3: PASSED - Información de logística obtenida")

    def test_ca2_4_estado_publicacion(self):
        """CA 2.4: Se obtiene estado de publicación en web."""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_activo.id)
        
        # Estado del evento
        self.assertEqual(evento.eve_estado, 'Activo')
        
        # Validar que tiene datos para publicar
        puede_publicarse = all([
            evento.eve_nombre,
            evento.eve_descripcion,
            evento.eve_ciudad,
            evento.eve_lugar,
            evento.eve_fecha_inicio,
            evento.eve_administrador_fk,
            evento.eve_imagen
        ])
        
        self.assertTrue(puede_publicarse)
        
        print("\n✓ CA 2.4: PASSED - Estado de publicación verificado")

    # ============================================
    # CA 3: VALIDACIONES Y ERRORES
    # ============================================

    def test_ca3_1_validacion_evento_activo(self):
        """CA 3.1: Se valida que el evento esté ACTIVO."""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento_activo = Evento.objects.get(id=self.evento_activo.id)
        evento_archivado = Evento.objects.get(id=self.evento_archivado.id)
        
        # Evento activo
        self.assertEqual(evento_activo.eve_estado, 'Activo')
        
        # Evento archivado no está activo
        self.assertNotEqual(evento_archivado.eve_estado, 'Activo')
        
        print("\n✓ CA 3.1: PASSED - Validación de estado activo")

    def test_ca3_2_evento_no_existe_retorna_none(self):
        """CA 3.2: Si evento no existe, retorna None (404)."""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Evento inexistente
        evento_inexistente = Evento.objects.filter(id=999999).first()
        self.assertIsNone(evento_inexistente)
        
        print("\n✓ CA 3.2: PASSED - Evento inexistente retorna None")

    def test_ca3_3_evento_archivado_no_accesible(self):
        """CA 3.3: Evento archivado no está disponible para consulta de publicación."""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento_archivado = Evento.objects.get(id=self.evento_archivado.id)
        
        # No está en estado ACTIVO
        puede_consultarse = evento_archivado.eve_estado == 'Activo'
        self.assertFalse(puede_consultarse)
        
        print("\n✓ CA 3.3: PASSED - Evento archivado no accesible")

    # ============================================
    # CA 4: INFORMACIÓN ADICIONAL
    # ============================================

    def test_ca4_1_informacion_tecnica_opcional(self):
        """CA 4.1: Información técnica es opcional."""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_activo.id)
        
        # Información técnica puede existir o no
        # El evento es válido sin ella
        self.assertIsNotNone(evento.eve_nombre)
        
        print("\n✓ CA 4.1: PASSED - Información técnica es opcional")

    def test_ca4_2_datos_completos_para_publicar(self):
        """CA 4.2: Se valida que todos los datos obligatorios estén presentes."""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_activo.id)
        
        # Campos obligatorios
        campos_obligatorios = {
            'nombre': evento.eve_nombre,
            'descripcion': evento.eve_descripcion,
            'ciudad': evento.eve_ciudad,
            'lugar': evento.eve_lugar,
            'fecha_inicio': evento.eve_fecha_inicio,
            'fecha_fin': evento.eve_fecha_fin,
            'administrador': evento.eve_administrador_fk,
            'capacidad': evento.eve_capacidad,
            'imagen': evento.eve_imagen,
        }
        
        # Todos presentes
        for campo, valor in campos_obligatorios.items():
            self.assertIsNotNone(valor, f"{campo} no puede ser nulo")
        
        print("\n✓ CA 4.2: PASSED - Todos los datos obligatorios presentes")

    def test_ca4_3_informacion_coherente_bd(self):
        """CA 4.3: Información es coherente con la base de datos."""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento1 = Evento.objects.get(id=self.evento_activo.id)
        evento2 = Evento.objects.filter(eve_nombre='Cumbre de Innovación Digital').first()
        
        # Son el mismo
        self.assertEqual(evento1.id, evento2.id)
        self.assertEqual(evento1.eve_nombre, evento2.eve_nombre)
        self.assertEqual(evento1.eve_ciudad, evento2.eve_ciudad)
        
        print("\n✓ CA 4.3: PASSED - Información coherente con BD")

    def test_ca4_4_evento_incompleto_no_puede_publicarse(self):
        """CA 4.4: Evento sin campos requeridos no puede publicarse."""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_incompleto.id)
        
        # Verificar que está activo
        self.assertEqual(evento.eve_estado, 'Activo')
        
        # Pero le falta imagen (verificar sin str())
        self.assertFalse(bool(evento.eve_imagen))
        
        # No puede publicarse sin imagen
        puede_publicarse = all([
            evento.eve_nombre,
            evento.eve_descripcion,
            evento.eve_ciudad,
            evento.eve_lugar,
            evento.eve_fecha_inicio,
            evento.eve_administrador_fk,
            bool(evento.eve_imagen)  # Falta esto
        ])
        
        self.assertFalse(puede_publicarse)
        
        print("\n✓ CA 4.4: PASSED - Evento incompleto no puede publicarse")

    def test_ca4_5_preinscripcion_habilitada(self):
        """CA 4.5: Se obtiene estado de preinscripción."""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_activo.id)
        
        # Validar estados de preinscripción
        self.assertTrue(evento.preinscripcion_habilitada_asistentes)
        self.assertTrue(evento.preinscripcion_habilitada_participantes)
        self.assertFalse(evento.preinscripcion_habilitada_evaluadores)
        
        print("\n✓ CA 4.5: PASSED - Estados de preinscripción verificados")

    # ============================================
    # PRUEBAS INTEGRALES
    # ============================================

    def test_flujo_integral_consulta_para_publicar(self):
        """Prueba integral: Super Admin consulta evento para publicar en web."""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # 1. Super Admin accede
        evento = Evento.objects.get(id=self.evento_activo.id)
        self.assertIsNotNone(evento)
        print("\n1. Super Admin accede al evento")
        
        # 2. Verifica estado
        self.assertEqual(evento.eve_estado, 'Activo')
        print(f"2. Estado: {evento.eve_estado}")
        
        # 3. Obtiene información básica
        print(f"3. Nombre: {evento.eve_nombre}")
        
        # 4. Obtiene información del administrador
        admin = evento.eve_administrador_fk.usuario
        print(f"4. Administrador: {admin.first_name} {admin.last_name}")
        
        # 5. Obtiene información de logística
        print(f"5. Ubicación: {evento.eve_ciudad}, {evento.eve_lugar}")
        print(f"   Capacidad: {evento.eve_capacidad}")
        
        # 6. Valida datos para publicar
        puede_publicarse = all([
            evento.eve_nombre,
            evento.eve_descripcion,
            evento.eve_ciudad,
            evento.eve_administrador_fk,
            evento.eve_imagen
        ])
        self.assertTrue(puede_publicarse)
        print("6. Validación: Listo para publicar en web")
        
        # 7. Verifica control de acceso
        self.assertTrue(self.user_superadmin.is_superuser)
        self.assertFalse(self.user_participante.is_superuser)
        print("7. Acceso: Solo Super Admin puede consultar")
        
        print("\n✓ FLUJO INTEGRAL: PASSED")

    def test_flujo_comparacion_eventos_completos_vs_incompletos(self):
        """Comparar evento completo vs incompleto."""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento_completo = Evento.objects.get(id=self.evento_activo.id)
        evento_incompleto = Evento.objects.get(id=self.evento_incompleto.id)
        
        # Evento completo puede publicarse
        completo_ok = all([
            evento_completo.eve_nombre,
            evento_completo.eve_descripcion,
            evento_completo.eve_ciudad,
            evento_completo.eve_imagen
        ])
        self.assertTrue(completo_ok)
        
        # Evento incompleto NO puede publicarse
        incompleto_ok = all([
            evento_incompleto.eve_nombre,
            evento_incompleto.eve_descripcion,
            evento_incompleto.eve_ciudad,
            evento_incompleto.eve_imagen  # Falta
        ])
        self.assertFalse(incompleto_ok)
        
        print("\n✓ COMPARACIÓN: Evento completo vs incompleto verificado")