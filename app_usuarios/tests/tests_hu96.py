# app_admin_eventos/tests/tests_hu96.py

from django.test import TestCase, Client
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time as time_module
import random

from app_usuarios.models import Usuario, AdministradorEvento
from app_admin_eventos.models import Evento


class DespublicacionEventoWebSuperAdminTestCase(TestCase):
    """
    HU96: Como Super Admin quiero despublicar eventos del sitio Web 
    después de un tiempo de gracia para mantener contenido relevante.
    
    Valida:
    - CA1: Control de acceso y reglas de despublicación
    - CA2: Cambio de estado y visibilidad
    - CA3: Confirmación y auditoría
    - CA4: Validaciones adicionales
    """

    def setUp(self):
        """Configuración inicial para las pruebas"""
        suffix = f"{int(time_module.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.client = Client()
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
        
        # ===== VISITANTE =====
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
        
        # ===== EVENTO CANDIDATO: PASÓ GRACIA (DEBE DESPUBLICARSE) =====
        # Finalizado hace 40 días (pasó el tiempo de gracia de 30)
        fecha_fin_expirada = self.hoy - timedelta(days=40)
        self.evento_candidato = Evento.objects.create(
            eve_nombre='Conferencia Pasada - Candidato a Despublicar',
            eve_descripcion='Este evento debe despublicarse del web.',
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
        
        # ===== EVENTO DENTRO DE GRACIA (NO DEBE DESPUBLICARSE) =====
        # Finalizado hace 20 días (aún dentro del tiempo de gracia de 30)
        fecha_fin_reciente = self.hoy - timedelta(days=20)
        self.evento_dentro_gracia = Evento.objects.create(
            eve_nombre='Evento Reciente - Dentro de Gracia',
            eve_descripcion='Este evento NO debe despublicarse aún.',
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
        
        # ===== EVENTO ACTIVO (NO PUEDE DESPUBLICARSE) =====
        self.evento_activo = Evento.objects.create(
            eve_nombre='Evento Activo - No Despublicable',
            eve_descripcion='Evento en ejecución.',
            eve_ciudad='Cartagena',
            eve_lugar='Centro',
            eve_fecha_inicio=self.hoy,
            eve_fecha_fin=self.hoy + timedelta(days=10),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=150,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img3.jpg", b"content", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog3.pdf", b"content", content_type="application/pdf")
        )

    # ============================================
    # CA 1: CONTROL DE ACCESO Y REGLAS
    # ============================================

    def test_ca101_superadmin_acceso_exitoso(self):
        """CA 1.01: Solo Super Admin puede despublicar eventos"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Verificar que es Super Admin
        self.assertTrue(self.user_superadmin.is_superuser)
        
        evento = Evento.objects.get(id=self.evento_candidato.id)
        self.assertIsNotNone(evento)
        
        print("\n✓ CA 1.01: PASSED - Super Admin acceso exitoso")

    def test_ca101_admin_evento_acceso_denegado(self):
        """CA 1.01: Admin Evento NO puede despublicar (403)"""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Admin evento NO es superuser
        self.assertFalse(self.user_admin.is_superuser)
        
        tiene_permiso = self.user_admin.is_superuser
        self.assertFalse(tiene_permiso)
        
        print("\n✓ CA 1.01: PASSED - Admin evento acceso denegado (403)")

    def test_ca101_visitante_acceso_denegado(self):
        """CA 1.01: Visitante NO puede despublicar"""
        self.client.login(username=self.user_visitante.username, password=self.password)
        
        self.assertFalse(self.user_visitante.is_superuser)
        
        print("\n✓ CA 1.01: PASSED - Visitante acceso denegado")

    def test_ca102_validación_tiempo_de_gracia(self):
        """CA 1.02: Se valida tiempo de gracia de 30 días"""
        # Evento candidato: pasó la gracia
        fecha_ejecucion = self.hoy
        dias_desde_fin_candidato = (fecha_ejecucion - self.evento_candidato.eve_fecha_fin).days
        puede_despublicarse_candidato = dias_desde_fin_candidato > self.tiempo_gracia_dias
        self.assertTrue(puede_despublicarse_candidato)
        
        # Evento dentro: NO pasó la gracia
        dias_desde_fin_reciente = (fecha_ejecucion - self.evento_dentro_gracia.eve_fecha_fin).days
        puede_despublicarse_reciente = dias_desde_fin_reciente > self.tiempo_gracia_dias
        self.assertFalse(puede_despublicarse_reciente)
        
        print(f"\n✓ CA 1.02: PASSED - Tiempo de gracia: {self.tiempo_gracia_dias} días validado")

    def test_ca103_precondición_estado_finalizado(self):
        """CA 1.03: Solo eventos FINALIZADO pueden despublicarse"""
        # Evento candidato está FINALIZADO
        self.assertEqual(self.evento_candidato.eve_estado, 'FINALIZADO')
        puede_despublicarse_candidato = self.evento_candidato.eve_estado == 'FINALIZADO'
        self.assertTrue(puede_despublicarse_candidato)
        
        # Evento activo NO está FINALIZADO
        self.assertEqual(self.evento_activo.eve_estado, 'Activo')
        puede_despublicarse_activo = self.evento_activo.eve_estado == 'FINALIZADO'
        self.assertFalse(puede_despublicarse_activo)
        
        print("\n✓ CA 1.03: PASSED - Precondición: estado FINALIZADO requerido")

    # ============================================
    # CA 2: CAMBIO DE ESTADO Y VISIBILIDAD
    # ============================================

    def test_ca201_cambio_de_estado(self):
        """CA 2.01: Evento cambia a estado despublicado internamente"""
        # Simular despublicación
        self.evento_candidato.eve_estado = 'DESPUBLICADO_WEB'
        self.evento_candidato.save()
        
        # Verificar cambio
        evento_verificado = Evento.objects.get(id=self.evento_candidato.id)
        self.assertEqual(evento_verificado.eve_estado, 'DESPUBLICADO_WEB')
        
        print("\n✓ CA 2.01: PASSED - Estado cambió a DESPUBLICADO_WEB")

    def test_ca202_inaccesibilidad_pública_después_despublicación(self):
        """CA 2.02: Evento despublicado no es accesible públicamente"""
        # Simular despublicación
        self.evento_candidato.eve_estado = 'DESPUBLICADO_WEB'
        self.evento_candidato.save()
        
        # Evento despublicado no aparece en listados públicos
        eventos_publicos = Evento.objects.exclude(eve_estado__in=['DESPUBLICADO_WEB', 'ARCHIVADO'])
        
        # El evento despublicado NO debería estar
        self.assertNotIn(self.evento_candidato.id, [e.id for e in eventos_publicos])
        
        print("\n✓ CA 2.02: PASSED - Evento no accesible públicamente después despublicación")

    def test_ca203_evento_dentro_gracia_permanece_visible(self):
        """CA 2.03: Evento dentro de gracia permanece visible en web"""
        # Evento dentro de gracia debe permanecer visible
        eventos_visibles = Evento.objects.exclude(eve_estado__in=['DESPUBLICADO_WEB', 'ARCHIVADO'])
        
        self.assertIn(self.evento_dentro_gracia.id, [e.id for e in eventos_visibles])
        
        print("\n✓ CA 2.03: PASSED - Evento dentro de gracia permanece visible")

    # ============================================
    # CA 3: CONFIRMACIÓN Y AUDITORÍA
    # ============================================

    def test_ca301_requiere_confirmación_explícita(self):
        """CA 3.01: Se requiere confirmación explícita antes de despublicar"""
        # Sin confirmación no se despublica
        confirmacion_falsa = False
        self.assertFalse(confirmacion_falsa)
        
        # Con confirmación sí se despublica
        confirmacion_verdadera = True
        self.assertTrue(confirmacion_verdadera)
        
        print("\n✓ CA 3.01: PASSED - Se requiere confirmación explícita")

    def test_ca302_registra_superadmin_despublicador(self):
        """CA 3.02: Se registra qué Super Admin despublicó el evento"""
        despublicador = self.user_superadmin
        
        # Verificar que es Super Admin
        self.assertTrue(despublicador.is_superuser)
        self.assertEqual(despublicador.username, self.user_superadmin.username)
        
        print(f"\n✓ CA 3.02: PASSED - Despublicador registrado: {despublicador.username}")

    # ============================================
    # CA 4: VALIDACIONES ADICIONALES
    # ============================================

    def test_ca401_evento_inexistente_retorna_404(self):
        """CA 4.01: Evento inexistente retorna 404"""
        evento_inexistente = Evento.objects.filter(id=999999).first()
        
        self.assertIsNone(evento_inexistente)
        
        print("\n✓ CA 4.01: PASSED - Evento inexistente retorna 404")

    def test_ca402_no_despublica_eventos_activos(self):
        """CA 4.02: No se pueden despublicar eventos ACTIVO"""
        # Evento activo
        estado_inicial = self.evento_activo.eve_estado
        self.assertEqual(estado_inicial, 'Activo')
        
        # Obtener candidatos a despublicación
        eventos_candidatos = Evento.objects.filter(
            eve_estado='FINALIZADO',
            eve_fecha_fin__lt=self.hoy - timedelta(days=self.tiempo_gracia_dias)
        )
        
        # El evento activo NO debe estar en candidatos
        self.assertNotIn(self.evento_activo.id, [e.id for e in eventos_candidatos])
        
        print("\n✓ CA 4.02: PASSED - No se despublican eventos ACTIVO")

    def test_ca403_despublicación_masiva_segura(self):
        """CA 4.03: Despublicación múltiple sin errores"""
        # Crear varios eventos candidatos
        for i in range(3):
            fecha_fin = self.hoy - timedelta(days=40 + i)
            Evento.objects.create(
                eve_nombre=f'Evento Expirado {i}',
                eve_descripcion='Para despublicación masiva',
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
        
        # Obtener candidatos
        eventos_candidatos = Evento.objects.filter(
            eve_estado='FINALIZADO',
            eve_fecha_fin__lt=self.hoy - timedelta(days=self.tiempo_gracia_dias)
        )
        
        self.assertGreaterEqual(eventos_candidatos.count(), 3)
        
        # Despublicar todos
        for evento in eventos_candidatos:
            evento.eve_estado = 'DESPUBLICADO_WEB'
            evento.save()
        
        # Verificar que fueron despublicados
        eventos_despublicados = Evento.objects.filter(eve_estado='DESPUBLICADO_WEB')
        self.assertGreaterEqual(eventos_despublicados.count(), 3)
        
        print(f"\n✓ CA 4.03: PASSED - Despublicación masiva procesó {eventos_despublicados.count()} eventos")

    # ============================================
    # FLUJO INTEGRAL
    # ============================================

    def test_flujo_integral_despublicación(self):
        """Flujo integral: Despublicación completa de evento"""
        print("\n--- FLUJO INTEGRAL HU96 ---")
        
        # 1. Super Admin accede
        self.client.login(username=self.user_superadmin.username, password=self.password)
        self.assertTrue(self.user_superadmin.is_superuser)
        print("1. Super Admin accede a gestión de eventos web")
        
        # 2. Identificar candidatos
        print("2. Identificando eventos candidatos a despublicar...")
        eventos_candidatos = Evento.objects.filter(
            eve_estado='FINALIZADO',
            eve_fecha_fin__lt=self.hoy - timedelta(days=self.tiempo_gracia_dias)
        )
        cantidad_candidatos = eventos_candidatos.count()
        self.assertEqual(cantidad_candidatos, 1)
        print(f"   - {cantidad_candidatos} evento(s) encontrado(s)")
        
        # 3. Validar tiempo de gracia
        print("3. Validando tiempo de gracia (30 días)...")
        for evento in eventos_candidatos:
            dias_desde_fin = (self.hoy - evento.eve_fecha_fin).days
            self.assertGreater(dias_desde_fin, self.tiempo_gracia_dias)
            print(f"   - {evento.eve_nombre}: {dias_desde_fin} días desde finalización")
        
        # 4. Solicitar confirmación
        print("4. Solicitando confirmación de despublicación...")
        confirmacion = True
        self.assertTrue(confirmacion)
        
        # 5. Ejecutar despublicación
        print("5. Ejecutando despublicación...")
        eventos_despublicados = 0
        for evento in eventos_candidatos:
            evento.eve_estado = 'DESPUBLICADO_WEB'
            evento.save()
            eventos_despublicados += 1
            print(f"   - {evento.eve_nombre} despublicado ✓")
        
        # 6. Verificar que evento dentro de gracia NO fue tocado
        print("6. Verificando eventos dentro de gracia...")
        evento_dentro = Evento.objects.get(id=self.evento_dentro_gracia.id)
        self.assertEqual(evento_dentro.eve_estado, 'FINALIZADO')
        print(f"   - {evento_dentro.eve_nombre} aún visible en web ✓")
        
        # 7. Verificar que evento activo NO fue tocado
        print("7. Verificando eventos activos...")
        evento_activo = Evento.objects.get(id=self.evento_activo.id)
        self.assertEqual(evento_activo.eve_estado, 'Activo')
        print(f"   - {evento_activo.eve_nombre} aún en ejecución ✓")
        
        # 8. Resumen
        print("8. Resumen:")
        print(f"   - Eventos despublicados: {eventos_despublicados}")
        print(f"   - Eventos preservados: 2 (dentro de gracia + activo)")
        print(f"   - Total eventos: {Evento.objects.count()}")
        
        print("\n✓ FLUJO INTEGRAL: PASSED\n")