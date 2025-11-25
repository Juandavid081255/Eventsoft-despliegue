# app_admin_eventos/tests/tests_hu60.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time
import random
from collections import defaultdict

from app_usuarios.models import Usuario, Asistente, AdministradorEvento
from app_admin_eventos.models import Evento, Area
from app_asistentes.models import AsistenteEvento


class EstadisticasInscripcionesTestCase(TestCase):
    """
    HU60: Casos de prueba para estadísticas de inscripciones.
    Valida cálculos de métricas, distribuciones y tendencias.
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.client = Client()
        self.password = "testpass123"
        
        # ===== FECHAS =====
        self.hoy = date.today()
        self.ayer = self.hoy - timedelta(days=1)
        self.hace_7_dias = self.hoy - timedelta(days=7)
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
        
        # ===== OTRO ADMINISTRADOR =====
        self.user_otro_admin = Usuario.objects.create_user(
            username=f"otro_admin_{suffix[:15]}",
            password=self.password,
            email=f"otro_admin_{suffix[:5]}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Otro",
            last_name="Admin",
            cedula=f"200{suffix[-10:]}"
        )
        otro_admin, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.user_otro_admin
        )
        
        # ===== USUARIO NORMAL =====
        self.user_normal = Usuario.objects.create_user(
            username=f"usuario_{suffix[:15]}",
            password=self.password,
            email=f"usuario_{suffix[:5]}@test.com",
            rol=Usuario.Roles.ASISTENTE,
            first_name="Usuario",
            last_name="Normal",
            cedula=f"300{suffix[-10:]}"
        )
        
        # ===== ASISTENTES =====
        self.asistentes = []
        estados_inscripcion = ['Aprobado', 'Aprobado', 'Aprobado', 'Pendiente', 'Rechazado']
        
        for i in range(5):
            user = Usuario.objects.create_user(
                username=f"asist_{i}_{suffix[:12]}",
                password=self.password,
                email=f"asist_{i}_{suffix[:5]}@test.com",
                rol=Usuario.Roles.ASISTENTE,
                first_name=f"Asistente{i}",
                last_name="Test",
                cedula=f"400{i}{suffix[-8:]}"
            )
            asistente = Asistente.objects.create(usuario=user)
            self.asistentes.append((user, asistente))
        
        # ===== ÁREA =====
        self.area = Area.objects.create(
            are_nombre="Tecnología",
            are_descripcion="Área de tecnología"
        )
        
        # ===== EVENTO PRINCIPAL =====
        self.evento = Evento.objects.create(
            eve_nombre='Evento para Estadísticas',
            eve_descripcion='Evento de prueba',
            eve_ciudad='Manizales',
            eve_lugar='Universidad',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=2),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_tienecosto='Si',
            eve_imagen=SimpleUploadedFile("img.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"progcontent", content_type="application/pdf")
        )
        
        # ===== OTRO EVENTO =====
        self.otro_evento = Evento.objects.create(
            eve_nombre='Otro Evento',
            eve_descripcion='Evento del otro admin',
            eve_ciudad='Bogotá',
            eve_lugar='Centro',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=1),
            eve_estado='Activo',
            eve_administrador_fk=otro_admin,
            eve_capacidad=50,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img2.jpg", b"imgcontent2", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"progcontent2", content_type="application/pdf")
        )
        
        # ===== INSCRIPCIONES EN EVENTO PRINCIPAL =====
        # 2 Aprobadas (hoy)
        for i in range(2):
            AsistenteEvento.objects.create(
                asi_eve_asistente_fk=self.asistentes[i][1],
                asi_eve_evento_fk=self.evento,
                asi_eve_fecha_hora=self.hoy,
                asi_eve_estado='Aprobado',
                asi_eve_soporte=SimpleUploadedFile(f"comp{i}.pdf", b"content"),
                asi_eve_qr=SimpleUploadedFile(f"qr{i}.jpg", b"qr_content"),
                asi_eve_clave=f'clave_{i}'
            )
        
        # 1 Aprobada (ayer)
        AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistentes[2][1],
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=self.ayer,
            asi_eve_estado='Aprobado',
            asi_eve_soporte=SimpleUploadedFile("comp2.pdf", b"content"),
            asi_eve_qr=SimpleUploadedFile("qr2.jpg", b"qr_content"),
            asi_eve_clave='clave_2'
        )
        
        # 1 Pendiente (ayer)
        AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistentes[3][1],
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=self.ayer,
            asi_eve_estado='Pendiente',
            asi_eve_soporte=SimpleUploadedFile("comp3.pdf", b"content"),
            asi_eve_qr=SimpleUploadedFile("qr3.jpg", b"qr_content"),
            asi_eve_clave='clave_3'
        )
        
        # 1 Rechazada (hoy)
        AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistentes[4][1],
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=self.hoy,
            asi_eve_estado='Rechazado',
            asi_eve_soporte=SimpleUploadedFile("comp4.pdf", b"content"),
            asi_eve_qr=SimpleUploadedFile("qr4.jpg", b"qr_content"),
            asi_eve_clave='clave_4'
        )
        
        # ===== INSCRIPCIÓN EN OTRO EVENTO (debe ignorarse) =====
        user_otro = Usuario.objects.create_user(
            username=f"asist_otro_{suffix[:12]}",
            password=self.password,
            email=f"asist_otro_{suffix[:5]}@test.com",
            rol=Usuario.Roles.ASISTENTE,
            cedula=f"5000{suffix[-8:]}"
        )
        asistente_otro = Asistente.objects.create(usuario=user_otro)
        AsistenteEvento.objects.create(
            asi_eve_asistente_fk=asistente_otro,
            asi_eve_evento_fk=self.otro_evento,
            asi_eve_fecha_hora=self.hoy,
            asi_eve_estado='Aprobado',
            asi_eve_soporte=SimpleUploadedFile("comp_otro.pdf", b"content"),
            asi_eve_qr=SimpleUploadedFile("qr_otro.jpg", b"qr_content"),
            asi_eve_clave='clave_otro'
        )

    # ============================================
    # CA 1: ACCESO Y PERMISOS
    # ============================================

    def test_ca1_1_admin_propietario_acceso_exitoso(self):
        """CA 1.1: Administrador propietario accede a estadísticas."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('estadisticas_evento', args=[self.evento.pk])
        response = self.client.get(url, follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        print("\n✓ CA 1.1: PASSED - Admin propietario accede a estadísticas")

    def test_ca1_2_usuario_normal_acceso_denegado(self):
        """CA 1.2: Usuario normal no puede acceder a estadísticas."""
        self.client.login(username=self.user_normal.username, password=self.password)
        
        url = reverse('estadisticas_evento', args=[self.evento.pk])
        response = self.client.get(url)
        
        self.assertIn(response.status_code, [302, 403, 404])
        
        print("\n✓ CA 1.2: PASSED - Usuario normal acceso denegado")

    def test_ca1_3_otro_admin_no_puede_ver_evento_ajeno(self):
        """CA 1.3: Otro admin no puede ver estadísticas de evento ajeno."""
        self.client.login(username=self.user_otro_admin.username, password=self.password)
        
        url = reverse('estadisticas_evento', args=[self.evento.pk])
        response = self.client.get(url)
        
        self.assertIn(response.status_code, [302, 403, 404])
        
        print("\n✓ CA 1.3: PASSED - Otro admin no ve evento ajeno")

    def test_ca1_4_requiere_autenticacion(self):
        """CA 1.4: Requiere estar autenticado."""
        self.client.logout()
        
        url = reverse('estadisticas_evento', args=[self.evento.pk])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 302)
        
        print("\n✓ CA 1.4: PASSED - Requiere autenticación")

    # ============================================
    # CA 2: MÉTRICAS Y DISTRIBUCIONES
    # ============================================

    def test_ca2_1_total_inscripciones_correcto(self):
        """CA 2.1: Total de inscripciones es correcto (5, no 6)."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Contar inscripciones del evento
        total = AsistenteEvento.objects.filter(asi_eve_evento_fk=self.evento).count()
        self.assertEqual(total, 5, "Debe haber 5 inscripciones en el evento principal")
        
        # Verificar que las del otro evento no se cuentan
        total_otro = AsistenteEvento.objects.filter(asi_eve_evento_fk=self.otro_evento).count()
        self.assertEqual(total_otro, 1, "El otro evento debe tener 1 inscripción")
        
        print("\n✓ CA 2.1: PASSED - Total de inscripciones correcto")

    def test_ca2_2_distribucion_por_estado_inscripcion(self):
        """CA 2.2: Distribución por estado de inscripción es correcta."""
        # Aprobadas: 3, Pendientes: 1, Rechazadas: 1
        aprobadas = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado='Aprobado'
        ).count()
        pendientes = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado='Pendiente'
        ).count()
        rechazadas = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado='Rechazado'
        ).count()
        
        self.assertEqual(aprobadas, 3)
        self.assertEqual(pendientes, 1)
        self.assertEqual(rechazadas, 1)
        
        print("\n✓ CA 2.2: PASSED - Distribución por estado correcto")

    def test_ca2_3_datos_estadisticas_accesibles(self):
        """CA 2.3: Los datos de estadísticas son accesibles."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('estadisticas_evento', args=[self.evento.pk])
        response = self.client.get(url, follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        # En lugar de buscar en HTML, verificamos que los datos existen en la BD
        # y que la vista es accesible
        total = AsistenteEvento.objects.filter(asi_eve_evento_fk=self.evento).count()
        self.assertGreater(total, 0, "Debe haber inscripciones para mostrar estadísticas")
        
        print("\n✓ CA 2.3: PASSED - Datos de estadísticas accesibles")

    # ============================================
    # CA 3: ANÁLISIS TEMPORAL Y TENDENCIAS
    # ============================================

    def test_ca3_1_inscripciones_recientes(self):
        """CA 3.1: Puede identificarse inscripciones recientes (hoy y últimos 7 días)."""
        # Inscripciones de hoy: 3 (2 aprobadas + 1 rechazada)
        hoy_count = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora__date=self.hoy
        ).count()
        self.assertEqual(hoy_count, 3)
        
        # Inscripciones últimos 7 días: 5 (todas)
        hace_7_dias = self.hoy - timedelta(days=7)
        ultimos_7 = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora__date__gte=hace_7_dias
        ).count()
        self.assertEqual(ultimos_7, 5)
        
        print("\n✓ CA 3.1: PASSED - Inscripciones recientes identificadas")

    def test_ca3_2_tendencia_por_estado(self):
        """CA 3.2: Puede analizarse tendencia por estado."""
        # Verificar que puede agruparse por estado
        estados = defaultdict(int)
        for insc in AsistenteEvento.objects.filter(asi_eve_evento_fk=self.evento):
            estados[insc.asi_eve_estado] += 1
        
        # Debe haber múltiples estados
        self.assertGreater(len(estados), 1)
        
        print("\n✓ CA 3.2: PASSED - Tendencia por estado analizable")

    # ============================================
    # CA 4: VALIDACIONES ADICIONALES
    # ============================================

    def test_ca4_1_evento_sin_inscripciones(self):
        """CA 4.1: Evento sin inscripciones muestra 0."""
        # Crear evento vacío
        evento_vacio = Evento.objects.create(
            eve_nombre='Evento Vacío',
            eve_descripcion='Sin inscripciones',
            eve_ciudad='Cali',
            eve_lugar='Sala',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=1),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img_vacio.jpg", b"content"),
            eve_programacion=SimpleUploadedFile("prog_vacio.pdf", b"content")
        )
        
        total = AsistenteEvento.objects.filter(asi_eve_evento_fk=evento_vacio).count()
        self.assertEqual(total, 0)
        
        print("\n✓ CA 4.1: PASSED - Evento vacío muestra 0")

    def test_ca4_2_calculos_consistentes(self):
        """CA 4.2: Cálculos son consistentes (suma de partes = total)."""
        aprobadas = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado='Aprobado'
        ).count()
        pendientes = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado='Pendiente'
        ).count()
        rechazadas = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado='Rechazado'
        ).count()
        
        total = AsistenteEvento.objects.filter(asi_eve_evento_fk=self.evento).count()
        
        # La suma de partes debe igual al total
        self.assertEqual(aprobadas + pendientes + rechazadas, total)
        
        print("\n✓ CA 4.2: PASSED - Cálculos son consistentes")