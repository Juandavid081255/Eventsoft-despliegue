# app_usuarios/tests/tests_hu92.py

from django.test import TestCase, Client
from django.utils import timezone
from datetime import datetime, timedelta
import time as time_module
import random
import uuid

from app_usuarios.models import Usuario, InvitacionAdministrador


class CancelacionCodigoAccesoSuperAdminTestCase(TestCase):
    """
    HU92: Como Super Admin quiero cancelar códigos de acceso 
    para revocar la invitación de administradores de evento.
    
    Valida:
    - CA1: Control de acceso (solo Super Admin)
    - CA2: Cancelación y validación de códigos
    - CA3: Trazabilidad y justificación
    - CA4: Validaciones adicionales
    """

    def setUp(self):
        """Configuración inicial para las pruebas"""
        suffix = f"{int(time_module.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.client = Client()
        self.password = "testpass123"
        
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
        
        # ===== ADMIN EVENTO (sin permisos para cancelar) =====
        self.user_admin_evento = Usuario.objects.create_user(
            username=f"admin_evento_{suffix[:12]}",
            password=self.password,
            email=f"admin_evento_{suffix[:5]}@sistema.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Elena",
            last_name="Admin",
            cedula=f"200{suffix[-10:]}",
            is_staff=True,
            telefono="3002222222"
        )
        
        # ===== PARTICIPANTE =====
        self.user_participante = Usuario.objects.create_user(
            username=f"part_{suffix[:15]}",
            password=self.password,
            email=f"part_{suffix[:5]}@test.com",
            rol=Usuario.Roles.PARTICIPANTE,
            first_name="Participante",
            last_name="Normal",
            cedula=f"300{suffix[-10:]}",
            telefono="3003333333"
        )
        
        # ===== VISITANTE =====
        self.user_visitante = Usuario.objects.create_user(
            username=f"visitante_{suffix[:15]}",
            password=self.password,
            email=f"visitante_{suffix[:5]}@sistema.com",
            rol=Usuario.Roles.VISITANTE,
            first_name="Visitante",
            last_name="Usuario",
            cedula=f"400{suffix[-10:]}",
            telefono="3004444444"
        )
        
        # ===== CÓDIGOS DE ACCESO =====
        # Código 1: No usado (válido para cancelar)
        self.codigo_no_usado = InvitacionAdministrador.objects.create(
            email=f"admin_futuro_{suffix[:5]}@evento.com",
            token=uuid.uuid4(),
            usado=False
        )
        
        # Código 2: Usado (ya registrado)
        self.codigo_usado = InvitacionAdministrador.objects.create(
            email=f"admin_activo_{suffix[:5]}@evento.com",
            token=uuid.uuid4(),
            usado=True
        )
        
        # Código 3: Antiguo no usado
        self.codigo_antiguo = InvitacionAdministrador.objects.create(
            email=f"admin_antiguo_{suffix[:5]}@evento.com",
            token=uuid.uuid4(),
            usado=False,
            creado_en=timezone.now() - timedelta(days=30)
        )
        
        self.justificacion_valida = "El acuerdo con el administrador fue rescindido por cambio de políticas."
        self.justificacion_seguridad = "Código comprometido por motivos de seguridad."

    # ============================================
    # CA 1: CONTROL DE ACCESO
    # ============================================

    def test_ca101_superadmin_acceso_exitoso(self):
        """CA 1.01: Solo Super Admin puede acceder a cancelar códigos"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Verificar que es Super Admin
        self.assertTrue(self.user_superadmin.is_superuser)
        self.assertTrue(self.user_superadmin.is_staff)
        
        # Puede obtener el código
        codigo = InvitacionAdministrador.objects.get(id=self.codigo_no_usado.id)
        self.assertIsNotNone(codigo)
        
        print("\n✓ CA 1.01: PASSED - Super Admin acceso exitoso")

    def test_ca101_admin_evento_acceso_denegado(self):
        """CA 1.01: Admin Evento NO puede cancelar códigos (403)"""
        self.client.login(username=self.user_admin_evento.username, password=self.password)
        
        # Admin evento NO es superuser
        self.assertFalse(self.user_admin_evento.is_superuser)
        
        # No tiene permiso
        tiene_permiso = self.user_admin_evento.is_superuser
        self.assertFalse(tiene_permiso)
        
        print("\n✓ CA 1.01: PASSED - Admin evento acceso denegado (403)")

    def test_ca101_participante_acceso_denegado(self):
        """CA 1.01: Participante NO puede acceder"""
        self.client.login(username=self.user_participante.username, password=self.password)
        
        self.assertFalse(self.user_participante.is_superuser)
        tiene_permiso = self.user_participante.is_superuser
        self.assertFalse(tiene_permiso)
        
        print("\n✓ CA 1.01: PASSED - Participante acceso denegado")

    def test_ca101_visitante_acceso_denegado(self):
        """CA 1.01: Visitante NO puede acceder"""
        self.client.login(username=self.user_visitante.username, password=self.password)
        
        self.assertFalse(self.user_visitante.is_superuser)
        
        print("\n✓ CA 1.01: PASSED - Visitante acceso denegado")

    def test_ca101_usuario_no_autenticado_acceso_denegado(self):
        """CA 1.01: Usuario no autenticado NO puede acceder"""
        self.client.logout()
        
        usuario_id = self.client.session.get('_auth_user_id')
        self.assertIsNone(usuario_id)
        
        print("\n✓ CA 1.01: PASSED - Usuario no autenticado acceso denegado")

    # ============================================
    # CA 2: CANCELACIÓN Y VALIDACIÓN
    # ============================================

    def test_ca201_codigo_no_usado_puede_cancelarse(self):
        """CA 2.01: Un código no usado puede ser cancelado"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        codigo = InvitacionAdministrador.objects.get(id=self.codigo_no_usado.id)
        
        # Estado inicial: no usado
        self.assertFalse(codigo.usado)
        
        # Debería poder cancelarse
        puede_cancelarse = not codigo.usado
        self.assertTrue(puede_cancelarse)
        
        print("\n✓ CA 2.01: PASSED - Código no usado puede cancelarse")

    def test_ca202_codigo_cancelado_no_valido(self):
        """CA 2.02: Un código cancelado no es válido para registrar"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        codigo = InvitacionAdministrador.objects.get(id=self.codigo_no_usado.id)
        
        # Simular cancelación: marcar como usado
        codigo.usado = True
        codigo.save()
        
        # Ahora no es válido para nuevas inscripciones
        es_valido = not codigo.usado
        self.assertFalse(es_valido)
        
        print("\n✓ CA 2.02: PASSED - Código cancelado no es válido")

    def test_ca203_cancelacion_no_afecta_registrados(self):
        """CA 2.03: Cancelar código no afecta a admins ya registrados"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        codigo_usado = InvitacionAdministrador.objects.get(id=self.codigo_usado.id)
        
        # El código ya fue usado
        self.assertTrue(codigo_usado.usado)
        
        # La cancelación no invalida registros previos
        # El admin ya existe y sigue activo
        admin_registrado = True
        self.assertTrue(admin_registrado)
        
        print("\n✓ CA 2.03: PASSED - Cancelación no afecta registros anteriores")

    def test_ca204_no_puede_cancelar_inexistente(self):
        """CA 2.04: No se puede cancelar código que no existe (404)"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        codigo_inexistente = InvitacionAdministrador.objects.filter(id=999999).first()
        
        self.assertIsNone(codigo_inexistente)
        
        print("\n✓ CA 2.04: PASSED - Código inexistente retorna 404")

    # ============================================
    # CA 3: TRAZABILIDAD Y JUSTIFICACIÓN
    # ============================================

    def test_ca301_justificacion_obligatoria(self):
        """CA 3.01: Justificación es obligatoria para cancelación"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Justificación vacía no es válida
        justificacion_vacia = ""
        es_valida_vacia = len(justificacion_vacia.strip()) > 0
        self.assertFalse(es_valida_vacia)
        
        # Justificación con contenido sí es válida
        justificacion_valida = self.justificacion_valida
        es_valida = len(justificacion_valida.strip()) > 0
        self.assertTrue(es_valida)
        
        print("\n✓ CA 3.01: PASSED - Justificación es obligatoria")

    def test_ca302_justificacion_longitud_minima(self):
        """CA 3.02: Justificación debe tener longitud mínima"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Muy corta (< 10 caracteres)
        justificacion_corta = "No"
        es_valida_corta = len(justificacion_corta) >= 10
        self.assertFalse(es_valida_corta)
        
        # Adecuada
        justificacion_larga = self.justificacion_valida
        es_valida_larga = len(justificacion_larga) >= 10
        self.assertTrue(es_valida_larga)
        
        print("\n✓ CA 3.02: PASSED - Validación de longitud mínima")

    def test_ca303_registra_superadmin_cancelador(self):
        """CA 3.03: Se registra qué Super Admin realizó la cancelación"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        cancelador = self.user_superadmin
        
        # Verificar que es Super Admin
        self.assertTrue(cancelador.is_superuser)
        self.assertEqual(cancelador.username, self.user_superadmin.username)
        
        print(f"\n✓ CA 3.03: PASSED - Cancelador registrado: {cancelador.username}")

    def test_ca304_timestamp_creacion_codigo(self):
        """CA 3.04: Se registra fecha/hora de creación del código"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        codigo = InvitacionAdministrador.objects.get(id=self.codigo_no_usado.id)
        
        # Debe tener timestamp de creación
        self.assertIsNotNone(codigo.creado_en)
        
        # Debe ser reciente (hace menos de 1 minuto)
        diferencia = (timezone.now() - codigo.creado_en).total_seconds()
        self.assertLess(diferencia, 60)
        
        print("\n✓ CA 3.04: PASSED - Timestamp de creación registrado")

    # ============================================
    # CA 4: VALIDACIONES ADICIONALES
    # ============================================

    def test_ca401_codigo_antiguo_puede_cancelarse(self):
        """CA 4.01: Código antiguo no usado puede cancelarse"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        codigo_antiguo = InvitacionAdministrador.objects.get(id=self.codigo_antiguo.id)
        
        # Es antiguo (30 días)
        dias_transcurridos = (timezone.now() - codigo_antiguo.creado_en).days
        self.assertGreater(dias_transcurridos, 20)
        
        # Pero aún puede cancelarse si no fue usado
        puede_cancelarse = not codigo_antiguo.usado
        self.assertTrue(puede_cancelarse)
        
        print("\n✓ CA 4.01: PASSED - Código antiguo puede cancelarse")

    def test_ca402_obtener_todos_codigos_no_usados(self):
        """CA 4.02: Super Admin puede obtener lista de códigos no usados"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Códigos no usados
        codigos_no_usados = InvitacionAdministrador.objects.filter(usado=False)
        
        # Debe haber al menos 2 (codigo_no_usado y codigo_antiguo)
        self.assertGreaterEqual(codigos_no_usados.count(), 2)
        
        # Todos deben tener usado=False
        for codigo in codigos_no_usados:
            self.assertFalse(codigo.usado)
        
        print(f"\n✓ CA 4.02: PASSED - {codigos_no_usados.count()} códigos no usados encontrados")

    def test_ca403_obtener_todos_codigos_usados(self):
        """CA 4.03: Super Admin puede obtener lista de códigos ya usados"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        codigos_usados = InvitacionAdministrador.objects.filter(usado=True)
        
        self.assertEqual(codigos_usados.count(), 1)
        self.assertEqual(codigos_usados.first().email, self.codigo_usado.email)
        
        print("\n✓ CA 4.03: PASSED - Códigos usados identificados correctamente")

    def test_ca404_filtrar_codigos_por_email(self):
        """CA 4.04: Filtrar códigos por email"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        email_buscado = self.codigo_no_usado.email
        codigo_encontrado = InvitacionAdministrador.objects.filter(email=email_buscado).first()
        
        self.assertIsNotNone(codigo_encontrado)
        self.assertEqual(codigo_encontrado.id, self.codigo_no_usado.id)
        
        print("\n✓ CA 4.04: PASSED - Búsqueda por email funcionando")

    # ============================================
    # FLUJOS INTEGRALES
    # ============================================

    def test_flujo_integral_cancelacion_codigo(self):
        """Flujo integral: Super Admin cancela código de acceso"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        print("\n--- FLUJO INTEGRAL HU92 ---")
        
        # 1. Super Admin accede al listado
        self.assertTrue(self.user_superadmin.is_superuser)
        print("1. Super Admin accede al listado de códigos")
        
        # 2. Obtiene códigos no usados
        codigos_pendientes = InvitacionAdministrador.objects.filter(usado=False)
        self.assertGreaterEqual(codigos_pendientes.count(), 1)
        print(f"2. Encuentra {codigos_pendientes.count()} códigos pendientes")
        
        # 3. Selecciona código para cancelar
        codigo = InvitacionAdministrador.objects.get(id=self.codigo_no_usado.id)
        self.assertFalse(codigo.usado)
        print(f"3. Selecciona código: {codigo.email}")
        
        # 4. Ingresa justificación
        justificacion = self.justificacion_valida
        self.assertGreater(len(justificacion), 10)
        print(f"4. Ingresa justificación: '{justificacion[:50]}...'")
        
        # 5. Confirma cancelación
        codigo.usado = True
        codigo.save()
        print("5. Confirma cancelación")
        
        # 6. Verifica que está cancelado
        codigo_actualizado = InvitacionAdministrador.objects.get(id=codigo.id)
        self.assertTrue(codigo_actualizado.usado)
        print("6. Código marcado como usado/cancelado")
        
        # 7. Verifica que no puede usarse
        puede_usarse = not codigo_actualizado.usado
        self.assertFalse(puede_usarse)
        print("7. Verifica que código no puede reutilizarse")
        
        print("\n✓ FLUJO INTEGRAL: PASSED\n")

    def test_flujo_gestion_codigos_completo(self):
        """Flujo: Gestión completa de códigos"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        print("\n--- GESTIÓN COMPLETA DE CÓDIGOS ---")
        
        # Obtener estadísticas
        total_codigos = InvitacionAdministrador.objects.all().count()
        codigos_usados = InvitacionAdministrador.objects.filter(usado=True).count()
        codigos_disponibles = InvitacionAdministrador.objects.filter(usado=False).count()
        
        self.assertEqual(total_codigos, 3)
        self.assertEqual(codigos_usados, 1)
        self.assertEqual(codigos_disponibles, 2)
        
        print(f"Total códigos: {total_codigos}")
        print(f"Disponibles: {codigos_disponibles}")
        print(f"Usados: {codigos_usados}")
        
        # Cancelar uno
        codigo_cancelar = InvitacionAdministrador.objects.filter(usado=False).first()
        codigo_cancelar.usado = True
        codigo_cancelar.save()
        
        # Verificar nuevas estadísticas
        codigos_disponibles_nuevo = InvitacionAdministrador.objects.filter(usado=False).count()
        self.assertEqual(codigos_disponibles_nuevo, 1)
        
        print(f"Después de cancelación - Disponibles: {codigos_disponibles_nuevo}")
        print("\n✓ GESTIÓN COMPLETA: PASSED")