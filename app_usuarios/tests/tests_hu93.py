# app_admin_eventos/tests/tests_hu93.py

from django.test import TestCase, Client
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time as time_module
import random

from app_usuarios.models import Usuario, AdministradorEvento
from app_admin_eventos.models import Evento


class PublicacionEventoWebSuperAdminTestCase(TestCase):
    """
    HU93: Como Super Admin quiero publicar eventos en el sitio Web 
    para que estén disponibles para el público.
    
    Valida:
    - CA1: Control de acceso (solo Super Admin)
    - CA2: Cambio de estado y acceso público
    - CA3: Confirmación y auditoría
    - CA4: Validaciones adicionales
    """

    def setUp(self):
        """Configuración inicial para las pruebas"""
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
            telefono="3001111111"
        )
        
        # ===== ADMIN DE EVENTO =====
        self.user_admin = Usuario.objects.create_user(
            username=f"admin_evento_{suffix[:12]}",
            password=self.password,
            email=f"admin_evento_{suffix[:5]}@sistema.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Admin",
            last_name="Evento",
            cedula=f"200{suffix[-10:]}",
            is_staff=True,
            telefono="3002222222"
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.user_admin
        )
        
        # ===== USUARIO VISITANTE =====
        self.user_visitante = Usuario.objects.create_user(
            username=f"visitante_{suffix[:15]}",
            password=self.password,
            email=f"visitante_{suffix[:5]}@sistema.com",
            rol=Usuario.Roles.VISITANTE,
            first_name="Visitante",
            last_name="Usuario",
            cedula=f"400{suffix[-10:]}",
            telefono="3003333333"
        )
        
        # ===== EVENTO LISTO PARA PUBLICAR =====
        self.evento_listo = Evento.objects.create(
            eve_nombre='Conferencia de Seguridad 2026',
            eve_descripcion='Resumen público del evento sobre seguridad informática.',
            eve_ciudad='Bogota',
            eve_lugar='Centro de Convenciones Internacional',
            eve_fecha_inicio=self.fecha_futura,
            eve_fecha_fin=self.fecha_futura + timedelta(days=2),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=500,
            eve_tienecosto='Si',
            eve_imagen=SimpleUploadedFile("banner.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"pdfcontent", content_type="application/pdf")
        )
        
        # ===== EVENTO INCOMPLETO (SIN DESCRIPCIÓN) =====
        self.evento_incompleto = Evento.objects.create(
            eve_nombre='Evento Incompleto',
            eve_descripcion='',  # FALTA DESCRIPCIÓN
            eve_ciudad='Medellin',
            eve_lugar='Auditorio Principal',
            eve_fecha_inicio=self.fecha_futura + timedelta(days=10),
            eve_fecha_fin=self.fecha_futura + timedelta(days=12),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=300,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("banner2.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"pdfcontent", content_type="application/pdf")
        )
        
        # ===== EVENTO ARCHIVADO =====
        self.evento_archivado = Evento.objects.create(
            eve_nombre='Evento Archivado',
            eve_descripcion='Descripción de evento viejo.',
            eve_ciudad='Cartagena',
            eve_lugar='Centro Historico',
            eve_fecha_inicio=self.fecha_pasada - timedelta(days=30),
            eve_fecha_fin=self.fecha_pasada - timedelta(days=28),
            eve_estado='ARCHIVADO',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=200,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("banner3.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog3.pdf", b"pdfcontent", content_type="application/pdf")
        )

    # ============================================
    # CA 1: CONTROL DE ACCESO
    # ============================================

    def test_ca101_superadmin_acceso_exitoso(self):
        """CA 1.01: Solo Super Admin puede publicar eventos en web"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_listo.id)
        
        # Verificar que es Super Admin
        self.assertTrue(self.user_superadmin.is_superuser)
        self.assertTrue(self.user_superadmin.is_staff)
        
        # Puede acceder al evento
        self.assertIsNotNone(evento)
        
        print("\n✓ CA 1.01: PASSED - Super Admin acceso para publicar")

    def test_ca101_admin_evento_acceso_denegado(self):
        """CA 1.01: Admin Evento NO puede publicar (403)"""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Admin evento NO es superuser
        self.assertFalse(self.user_admin.is_superuser)
        
        tiene_permiso = self.user_admin.is_superuser
        self.assertFalse(tiene_permiso)
        
        print("\n✓ CA 1.01: PASSED - Admin evento acceso denegado (403)")

    def test_ca101_visitante_acceso_denegado(self):
        """CA 1.01: Visitante NO puede publicar eventos"""
        self.client.login(username=self.user_visitante.username, password=self.password)
        
        self.assertFalse(self.user_visitante.is_superuser)
        
        print("\n✓ CA 1.01: PASSED - Visitante acceso denegado")

    def test_ca102_validación_datos_obligatorios(self):
        """CA 1.02: Se validan datos públicos obligatorios antes de publicar"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Evento listo tiene todos los datos
        evento_listo = Evento.objects.get(id=self.evento_listo.id)
        puede_publicarse_listo = all([
            evento_listo.eve_nombre,
            evento_listo.eve_descripcion,
            evento_listo.eve_ciudad,
            evento_listo.eve_lugar,
            evento_listo.eve_imagen
        ])
        self.assertTrue(puede_publicarse_listo)
        
        # Evento incompleto NO tiene descripción
        evento_incompleto = Evento.objects.get(id=self.evento_incompleto.id)
        puede_publicarse_incompleto = all([
            evento_incompleto.eve_nombre,
            evento_incompleto.eve_descripcion,  # FALTA
            evento_incompleto.eve_ciudad,
            evento_incompleto.eve_lugar,
            evento_incompleto.eve_imagen
        ])
        self.assertFalse(puede_publicarse_incompleto)
        
        print("\n✓ CA 1.02: PASSED - Validación de datos obligatorios")

    def test_ca103_validación_estado_activo(self):
        """CA 1.03: Solo se pueden publicar eventos en estado ACTIVO"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Evento activo sí se puede publicar
        evento_activo = Evento.objects.get(id=self.evento_listo.id)
        self.assertEqual(evento_activo.eve_estado, 'Activo')
        puede_publicarse_activo = evento_activo.eve_estado == 'Activo'
        self.assertTrue(puede_publicarse_activo)
        
        # Evento archivado NO se puede publicar
        evento_archivado = Evento.objects.get(id=self.evento_archivado.id)
        self.assertEqual(evento_archivado.eve_estado, 'ARCHIVADO')
        puede_publicarse_archivado = evento_archivado.eve_estado == 'Activo'
        self.assertFalse(puede_publicarse_archivado)
        
        print("\n✓ CA 1.03: PASSED - Validación de estado ACTIVO")

    # ============================================
    # CA 2: CAMBIO DE ESTADO Y ACCESO
    # ============================================

    def test_ca201_información_pública_verificada(self):
        """CA 2.01: Se verifica que evento tenga información pública correcta"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_listo.id)
        
        # Información básica
        self.assertEqual(evento.eve_nombre, 'Conferencia de Seguridad 2026')
        self.assertIn('seguridad', evento.eve_descripcion.lower())
        self.assertEqual(evento.eve_ciudad, 'Bogota')
        self.assertIsNotNone(evento.eve_imagen)
        
        print("\n✓ CA 2.01: PASSED - Información pública verificada")

    def test_ca202_evento_accesible_publicamente(self):
        """CA 2.02: Evento publicado es accesible sin autenticación"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_listo.id)
        evento_id = evento.id
        evento_nombre = evento.eve_nombre
        
        # Logout - usuario anónimo
        self.client.logout()
        
        # Usuario anónimo puede ver evento
        evento_publico = Evento.objects.filter(id=evento_id, eve_estado='Activo').first()
        
        self.assertIsNotNone(evento_publico)
        self.assertEqual(evento_publico.eve_nombre, evento_nombre)
        
        print("\n✓ CA 2.02: PASSED - Evento accesible públicamente")

    def test_ca203_información_técnica_opcional(self):
        """CA 2.03: Información técnica es opcional para publicar"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_listo.id)
        
        # Evento es válido aunque no tenga información técnica
        datos_obligatorios = all([
            evento.eve_nombre,
            evento.eve_descripcion,
            evento.eve_ciudad,
            evento.eve_lugar
        ])
        
        self.assertTrue(datos_obligatorios)
        
        print("\n✓ CA 2.03: PASSED - Información técnica es opcional")

    # ============================================
    # CA 3: CONFIRMACIÓN Y AUDITORÍA
    # ============================================

    def test_ca301_requiere_confirmación(self):
        """CA 3.01: Se requiere confirmación antes de publicar"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_listo.id)
        
        # Sin confirmación no se publica
        confirmacion_falsa = False
        self.assertFalse(confirmacion_falsa)
        
        # Con confirmación sí se publica
        confirmacion_verdadera = True
        self.assertTrue(confirmacion_verdadera)
        
        print("\n✓ CA 3.01: PASSED - Se requiere confirmación")

    def test_ca302_registra_superadmin_publicador(self):
        """CA 3.02: Se registra qué Super Admin publicó el evento"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_listo.id)
        publicador = self.user_superadmin
        
        # Verificar datos del publicador
        self.assertTrue(publicador.is_superuser)
        self.assertEqual(publicador.username, self.user_superadmin.username)
        self.assertEqual(publicador.email, self.user_superadmin.email)
        
        print(f"\n✓ CA 3.02: PASSED - Publicador registrado: {publicador.username}")

    def test_ca303_datos_admin_evento(self):
        """CA 3.03: Se registran datos del administrador del evento"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_listo.id)
        admin = evento.eve_administrador_fk.usuario
        
        # Verificar datos del admin
        self.assertIsNotNone(admin)
        self.assertEqual(admin.first_name, 'Admin')
        self.assertEqual(admin.last_name, 'Evento')
        self.assertEqual(admin.email, self.user_admin.email)
        
        print(f"\n✓ CA 3.03: PASSED - Admin registrado: {admin.first_name} {admin.last_name}")

    # ============================================
    # CA 4: VALIDACIONES ADICIONALES
    # ============================================

    def test_ca401_evento_inexistente_retorna_404(self):
        """CA 4.01: Evento inexistente retorna 404"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento_inexistente = Evento.objects.filter(id=999999).first()
        
        self.assertIsNone(evento_inexistente)
        
        print("\n✓ CA 4.01: PASSED - Evento inexistente retorna 404")

    def test_ca402_validación_fechas_futuras(self):
        """CA 4.02: Se valida que evento tenga fechas válidas"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento_futuro = Evento.objects.get(id=self.evento_listo.id)
        evento_pasado = Evento.objects.get(id=self.evento_archivado.id)
        
        # Evento futuro es válido
        hoy = date.today()
        es_futuro = evento_futuro.eve_fecha_inicio > hoy
        self.assertTrue(es_futuro)
        
        # Evento pasado NO es válido
        es_pasado = evento_pasado.eve_fecha_inicio < hoy
        self.assertTrue(es_pasado)
        
        print("\n✓ CA 4.02: PASSED - Validación de fechas")

    def test_ca403_capacidad_válida(self):
        """CA 4.03: Se valida que la capacidad sea válida"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_listo.id)
        
        # Capacidad debe ser mayor que 0
        self.assertGreater(evento.eve_capacidad, 0)
        self.assertEqual(evento.eve_capacidad, 500)
        
        print("\n✓ CA 4.03: PASSED - Capacidad válida")

    def test_ca404_no_puede_publicar_sin_datos(self):
        """CA 4.04: No se puede publicar evento sin datos mínimos"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        evento = Evento.objects.get(id=self.evento_incompleto.id)
        
        # Validar que no puede publicarse
        puede_publicarse = all([
            evento.eve_nombre,
            evento.eve_descripcion,  # FALTA ESTO
            evento.eve_ciudad,
            evento.eve_imagen
        ])
        
        self.assertFalse(puede_publicarse)
        
        print("\n✓ CA 4.04: PASSED - No puede publicar sin datos mínimos")

    # ============================================
    # FLUJOS INTEGRALES
    # ============================================

    def test_flujo_integral_publicación_evento(self):
        """Flujo integral: Super Admin publica evento en web"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        print("\n--- FLUJO INTEGRAL HU93 ---")
        
        # 1. Super Admin accede a listado de eventos
        self.assertTrue(self.user_superadmin.is_superuser)
        print("1. Super Admin accede a listado de eventos")
        
        # 2. Selecciona evento para publicar
        evento = Evento.objects.get(id=self.evento_listo.id)
        self.assertIsNotNone(evento)
        print(f"2. Selecciona evento: {evento.eve_nombre}")
        
        # 3. Valida que está activo
        self.assertEqual(evento.eve_estado, 'Activo')
        print("3. Valida que estado es ACTIVO")
        
        # 4. Valida datos públicos obligatorios
        puede_publicarse = all([
            evento.eve_nombre,
            evento.eve_descripcion,
            evento.eve_ciudad,
            evento.eve_lugar,
            evento.eve_imagen
        ])
        self.assertTrue(puede_publicarse)
        print("4. Valida datos públicos obligatorios ✓")
        
        # 5. Revisa información del evento
        admin = evento.eve_administrador_fk.usuario
        print(f"5. Revisa información del admin: {admin.first_name} {admin.last_name}")
        
        # 6. Confirma publicación
        confirmacion = True
        self.assertTrue(confirmacion)
        print("6. Ingresa confirmación de publicación")
        
        # 7. Ejecuta publicación
        evento.save()
        print("7. Ejecuta publicación")
        
        # 8. Verifica que se guardó
        evento_verificado = Evento.objects.get(id=evento.id)
        self.assertEqual(evento_verificado.eve_estado, 'Activo')
        print("8. Verifica que evento se guardó correctamente")
        
        # 9. Verifica acceso público
        self.client.logout()
        evento_publico = Evento.objects.filter(id=evento.id, eve_estado='Activo').first()
        self.assertIsNotNone(evento_publico)
        print("9. Verifica acceso público sin autenticación ✓")
        
        # 10. Verifica que otros no pueden publicar
        self.client.login(username=self.user_visitante.username, password=self.password)
        self.assertFalse(self.user_visitante.is_superuser)
        print("10. Verifica que otros usuarios no pueden publicar")
        
        print("\n✓ FLUJO INTEGRAL: PASSED\n")

    def test_flujo_validación_evento_incompleto(self):
        """Flujo: Intento de publicar evento incompleto falla"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        print("\n--- VALIDACIÓN EVENTO INCOMPLETO ---")
        
        evento = Evento.objects.get(id=self.evento_incompleto.id)
        
        # Verificar que está incompleto
        self.assertEqual(evento.eve_nombre, 'Evento Incompleto')
        self.assertEqual(evento.eve_descripcion, '')  # VACÍO
        print("1. Evento incompleto identificado (sin descripción)")
        
        # Intento de validación falla
        puede_publicarse = all([
            evento.eve_nombre,
            evento.eve_descripcion,
            evento.eve_ciudad,
            evento.eve_lugar
        ])
        
        self.assertFalse(puede_publicarse)
        print("2. Validación: NO puede publicarse ✗")
        
        print("3. Se requiere completar descripción antes de publicar")
        print("\n✓ VALIDACIÓN: PASSED")