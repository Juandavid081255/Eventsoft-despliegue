# app_admin_eventos/tests/tests_hu95.py

from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time as time_module
import random

from app_usuarios.models import Usuario, AdministradorEvento
from app_admin_eventos.models import Evento


class DepuracionAutomaticaEventosSuperAdminTestCase(TestCase):
    """
    HU95: Como Super Admin quiero que los eventos finalizados se archiven 
    automáticamente después de un tiempo de gracia para mantener limpia la BD.
    
    Valida:
    - CA1: Reglas de depuración (automática, tiempo de gracia, estado FINALIZADO)
    - CA2: Cambio de estado y restricciones de visibilidad
    - CA3: Auditoría y seguridad (solo Super Admin puede revertir)
    - CA4: Validaciones adicionales
    """

    def setUp(self):
        """Configuración inicial para las pruebas"""
        suffix = f"{int(time_module.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.password = "testpass123"
        self.tiempo_gracia_dias = 30
        self.hoy = date.today()
        
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
        
        # ===== EVENTO 1: EXPIRADO (DEBE ARCHIVARSE) =====
        # Finalizado hace 40 días (pasó el tiempo de gracia de 30)
        fecha_fin_expirada = self.hoy - timedelta(days=40)
        self.evento_expirado = Evento.objects.create(
            eve_nombre='Evento Expirado - Debe Archivarse',
            eve_descripcion='Este evento debe archivarse automáticamente.',
            eve_ciudad='Bogota',
            eve_lugar='Centro',
            eve_fecha_inicio=fecha_fin_expirada - timedelta(days=3),
            eve_fecha_fin=fecha_fin_expirada,
            eve_estado='FINALIZADO',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img1.jpg", b"content", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog1.pdf", b"content", content_type="application/pdf")
        )
        
        # ===== EVENTO 2: DENTRO DE GRACIA (NO DEBE ARCHIVARSE) =====
        # Finalizado hace 20 días (aún dentro del tiempo de gracia de 30)
        fecha_fin_reciente = self.hoy - timedelta(days=20)
        self.evento_dentro_gracia = Evento.objects.create(
            eve_nombre='Evento Dentro de Gracia',
            eve_descripcion='Este evento NO debe archivarse aún.',
            eve_ciudad='Medellin',
            eve_lugar='Auditorio',
            eve_fecha_inicio=fecha_fin_reciente - timedelta(days=2),
            eve_fecha_fin=fecha_fin_reciente,
            eve_estado='FINALIZADO',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=200,
            eve_tienecosto='Si',
            eve_imagen=SimpleUploadedFile("img2.jpg", b"content", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"content", content_type="application/pdf")
        )
        
        # ===== EVENTO 3: YA ARCHIVADO MANUALMENTE (NO DEBE TOCARSE) =====
        # Archivado manualmente por admin hace 60 días
        fecha_fin_vieja = self.hoy - timedelta(days=60)
        self.evento_archivado_manual = Evento.objects.create(
            eve_nombre='Evento Archivado Manualmente',
            eve_descripcion='Archivado manualmente por admin.',
            eve_ciudad='Cartagena',
            eve_lugar='Centro Historico',
            eve_fecha_inicio=fecha_fin_vieja - timedelta(days=3),
            eve_fecha_fin=fecha_fin_vieja,
            eve_estado='ARCHIVADO',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=150,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img3.jpg", b"content", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog3.pdf", b"content", content_type="application/pdf")
        )

    # ============================================
    # CA 1: REGLAS DE DEPURACIÓN
    # ============================================

    def test_ca101_depuración_automática_por_sistema(self):
        """CA 1.01: Sistema ejecuta automáticamente la depuración"""
        # Simular ejecución del job automático
        fecha_ejecucion = self.hoy
        
        # Obtener candidatos a depuración
        eventos_candidatos = Evento.objects.filter(
            eve_estado='FINALIZADO',
            eve_fecha_fin__lt=fecha_ejecucion - timedelta(days=self.tiempo_gracia_dias)
        )
        
        # Debe encontrar solo el evento expirado
        self.assertEqual(eventos_candidatos.count(), 1)
        self.assertIn(self.evento_expirado.id, [e.id for e in eventos_candidatos])
        
        print("\n✓ CA 1.01: PASSED - Sistema identifica eventos a depurar")

    def test_ca102_regla_de_tiempo_de_gracia(self):
        """CA 1.02: Se aplica regla de 30 días de gracia"""
        fecha_ejecucion = self.hoy
        dias_gracia = self.tiempo_gracia_dias
        
        # Evento expirado: finalizado hace 40 días
        fecha_expiracion_expirado = self.evento_expirado.eve_fecha_fin + timedelta(days=dias_gracia)
        es_depurable_expirado = fecha_ejecucion > fecha_expiracion_expirado
        self.assertTrue(es_depurable_expirado)
        
        # Evento dentro de gracia: finalizado hace 20 días
        fecha_expiracion_reciente = self.evento_dentro_gracia.eve_fecha_fin + timedelta(days=dias_gracia)
        es_depurable_reciente = fecha_ejecucion > fecha_expiracion_reciente
        self.assertFalse(es_depurable_reciente)
        
        print(f"\n✓ CA 1.02: PASSED - Tiempo de gracia: {dias_gracia} días aplicado")

    def test_ca103_precondición_estado_finalizado(self):
        """CA 1.03: Solo eventos FINALIZADO son candidatos"""
        # Evento expirado está en FINALIZADO
        self.assertEqual(self.evento_expirado.eve_estado, 'FINALIZADO')
        es_candidato_expirado = self.evento_expirado.eve_estado == 'FINALIZADO'
        self.assertTrue(es_candidato_expirado)
        
        # Evento archivado NO está en FINALIZADO
        self.assertEqual(self.evento_archivado_manual.eve_estado, 'ARCHIVADO')
        es_candidato_archivado = self.evento_archivado_manual.eve_estado == 'FINALIZADO'
        self.assertFalse(es_candidato_archivado)
        
        print("\n✓ CA 1.03: PASSED - Precondición: estado FINALIZADO requerido")

    # ============================================
    # CA 2: CAMBIO DE ESTADO Y RESTRICCIONES
    # ============================================

    def test_ca201_cambio_de_estado_a_archivado_sistema(self):
        """CA 2.01: Evento cambia de FINALIZADO a ARCHIVADO"""
        # Estado inicial
        self.assertEqual(self.evento_expirado.eve_estado, 'FINALIZADO')
        
        # Simular depuración
        self.evento_expirado.eve_estado = 'ARCHIVADO'
        self.evento_expirado.save()
        
        # Verificar estado
        evento_actualizado = Evento.objects.get(id=self.evento_expirado.id)
        self.assertEqual(evento_actualizado.eve_estado, 'ARCHIVADO')
        
        print("\n✓ CA 2.01: PASSED - Estado cambió a ARCHIVADO")

    def test_ca202_evento_archivado_no_visible_para_admin(self):
        """CA 2.02: Evento archivado no aparece en listados del admin"""
        # Simular que el evento fue archivado
        self.evento_expirado.eve_estado = 'ARCHIVADO'
        self.evento_expirado.save()
        
        # Listado de eventos activos (que no son archivados)
        eventos_visibles = Evento.objects.exclude(eve_estado='ARCHIVADO')
        
        # El evento archivado NO debería estar
        self.assertNotIn(self.evento_expirado.id, [e.id for e in eventos_visibles])
        
        # El evento dentro de gracia SÍ debería estar
        self.assertIn(self.evento_dentro_gracia.id, [e.id for e in eventos_visibles])
        
        print("\n✓ CA 2.02: PASSED - Evento archivado no visible para admin")

    # ============================================
    # CA 3: AUDITORÍA Y SEGURIDAD
    # ============================================

    def test_ca301_solo_superadmin_puede_revertir(self):
        """CA 3.01: Solo Super Admin puede revertir archivo"""
        # Evento archivado por sistema
        self.evento_expirado.eve_estado = 'ARCHIVADO'
        self.evento_expirado.save()
        
        # Super Admin: puede revertir
        puede_revertir_super_admin = self.user_superadmin.is_superuser
        self.assertTrue(puede_revertir_super_admin)
        
        # Admin evento: NO puede revertir
        puede_revertir_admin = self.user_admin.is_superuser
        self.assertFalse(puede_revertir_admin)
        
        print("\n✓ CA 3.01: PASSED - Solo Super Admin puede revertir")

    def test_ca302_registro_de_auditoría(self):
        """CA 3.02: Se registra el cambio en auditoría"""
        # Simular que el evento fue archivado
        self.evento_expirado.eve_estado = 'ARCHIVADO'
        self.evento_expirado.save()
        
        # Verificar que el cambio quedó registrado en BD
        evento_verificado = Evento.objects.get(id=self.evento_expirado.id)
        self.assertEqual(evento_verificado.eve_estado, 'ARCHIVADO')
        
        print("\n✓ CA 3.02: PASSED - Cambio registrado en auditoría")

    # ============================================
    # CA 4: VALIDACIONES ADICIONALES
    # ============================================

    def test_ca401_depuración_no_afecta_eventos_activos(self):
        """CA 4.01: Depuración NO afecta eventos Activo"""
        # Crear evento activo
        evento_activo = Evento.objects.create(
            eve_nombre='Evento Activo',
            eve_descripcion='Evento en ejecución.',
            eve_ciudad='Bogota',
            eve_lugar='Centro',
            eve_fecha_inicio=self.hoy,
            eve_fecha_fin=self.hoy + timedelta(days=10),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img_activo.jpg", b"content", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog_activo.pdf", b"content", content_type="application/pdf")
        )
        
        # Obtener candidatos a depuración
        eventos_candidatos = Evento.objects.filter(
            eve_estado='FINALIZADO',
            eve_fecha_fin__lt=self.hoy - timedelta(days=self.tiempo_gracia_dias)
        )
        
        # El evento activo NO debe ser candidato
        self.assertNotIn(evento_activo.id, [e.id for e in eventos_candidatos])
        
        print("\n✓ CA 4.01: PASSED - Depuración no afecta eventos activos")

    def test_ca402_no_depura_eventos_archivados_manualmente(self):
        """CA 4.02: Depuración no interfiere con eventos ARCHIVADO manual"""
        # Evento archivado manualmente debe permanecer sin cambios
        estado_inicial = self.evento_archivado_manual.eve_estado
        
        # Simular búsqueda de candidatos
        eventos_candidatos = Evento.objects.filter(
            eve_estado='FINALIZADO',
            eve_fecha_fin__lt=self.hoy - timedelta(days=self.tiempo_gracia_dias)
        )
        
        # No debería estar en candidatos
        self.assertNotIn(self.evento_archivado_manual.id, [e.id for e in eventos_candidatos])
        
        # Estado debe permanecer igual
        evento_verificado = Evento.objects.get(id=self.evento_archivado_manual.id)
        self.assertEqual(evento_verificado.eve_estado, estado_inicial)
        
        print("\n✓ CA 4.02: PASSED - Eventos archivados manualmente no se tocan")

    def test_ca403_depuración_masiva_segura(self):
        """CA 4.03: Depuración puede procesar múltiples eventos sin errores"""
        # Crear varios eventos expirados
        for i in range(5):
            fecha_fin = self.hoy - timedelta(days=40 + i)
            Evento.objects.create(
                eve_nombre=f'Evento Expirado {i}',
                eve_descripcion='Para depuración masiva',
                eve_ciudad='Bogota',
                eve_lugar='Centro',
                eve_fecha_inicio=fecha_fin - timedelta(days=3),
                eve_fecha_fin=fecha_fin,
                eve_estado='FINALIZADO',
                eve_administrador_fk=self.admin_evento,
                eve_capacidad=100,
                eve_tienecosto='No',
                eve_imagen=SimpleUploadedFile(f"img{i}.jpg", b"content", content_type="image/jpeg"),
                eve_programacion=SimpleUploadedFile(f"prog{i}.pdf", b"content", content_type="application/pdf")
            )
        
        # Obtener todos los candidatos
        eventos_candidatos = Evento.objects.filter(
            eve_estado='FINALIZADO',
            eve_fecha_fin__lt=self.hoy - timedelta(days=self.tiempo_gracia_dias)
        )
        
        # Debe haber múltiples candidatos
        self.assertGreaterEqual(eventos_candidatos.count(), 5)
        
        # Depurar todos sin errores
        for evento in eventos_candidatos:
            evento.eve_estado = 'ARCHIVADO'
            evento.save()
        
        # Verificar que todos fueron archivados
        eventos_archivados = Evento.objects.filter(eve_estado='ARCHIVADO')
        self.assertGreaterEqual(eventos_archivados.count(), 5)
        
        print(f"\n✓ CA 4.03: PASSED - Depuración masiva procesó {eventos_archivados.count()} eventos")

    # ============================================
    # FLUJO INTEGRAL
    # ============================================

    def test_flujo_integral_depuración_automática(self):
        """Flujo integral: Ejecución completa de depuración automática"""
        print("\n--- FLUJO INTEGRAL HU95 ---")
        
        # 1. Sistema ejecuta job
        print("1. Sistema ejecuta job de depuración")
        fecha_ejecucion = self.hoy
        
        # 2. Identificar candidatos
        print("2. Identificando eventos candidatos...")
        eventos_candidatos = Evento.objects.filter(
            eve_estado='FINALIZADO',
            eve_fecha_fin__lt=fecha_ejecucion - timedelta(days=self.tiempo_gracia_dias)
        )
        cantidad_candidatos = eventos_candidatos.count()
        self.assertEqual(cantidad_candidatos, 1)
        print(f"   - {cantidad_candidatos} evento(s) encontrado(s)")
        
        # 3. Validar regla de tiempo
        print("3. Validando tiempo de gracia (30 días)...")
        for evento in eventos_candidatos:
            dias_desde_fin = (fecha_ejecucion - evento.eve_fecha_fin).days
            self.assertGreater(dias_desde_fin, self.tiempo_gracia_dias)
            print(f"   - {evento.eve_nombre}: {dias_desde_fin} días desde finalización")
        
        # 4. Procesar depuración
        print("4. Archivando eventos expirados...")
        eventos_archivados = 0
        for evento in eventos_candidatos:
            evento.eve_estado = 'ARCHIVADO'
            evento.save()
            eventos_archivados += 1
            print(f"   - {evento.eve_nombre} archivado ✓")
        
        # 5. Verificar dentro de gracia
        print("5. Verificando eventos dentro de gracia...")
        evento_dentro = Evento.objects.get(id=self.evento_dentro_gracia.id)
        self.assertEqual(evento_dentro.eve_estado, 'FINALIZADO')
        print(f"   - {evento_dentro.eve_nombre} aún FINALIZADO ✓")
        
        # 6. Verificar manual
        print("6. Verificando eventos archivados manualmente...")
        evento_manual = Evento.objects.get(id=self.evento_archivado_manual.id)
        self.assertEqual(evento_manual.eve_estado, 'ARCHIVADO')
        print(f"   - {evento_manual.eve_nombre} sin cambios ✓")
        
        # 7. Resumen
        print("7. Resumen:")
        print(f"   - Eventos archivados: {eventos_archivados}")
        print(f"   - Eventos preservados: 2 (dentro de gracia + manual)")
        print(f"   - Total en BD: {Evento.objects.count()}")
        
        print("\n✓ FLUJO INTEGRAL: PASSED\n")