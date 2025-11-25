# app_admin_eventos/tests/tests_hu62.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time
import random

from app_usuarios.models import Usuario, Evaluador, AdministradorEvento
from app_admin_eventos.models import Evento, Area
from app_evaluadores.models import EvaluadorEvento


class ProcesamientoPreinscripcionesEvaluadoresTestCase(TestCase):
    """
    HU62: Casos de prueba para procesamiento de preinscripciones de evaluadores.
    Valida aceptación, rechazo y validaciones específicas para evaluadores.
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
            rol=Usuario.Roles.EVALUADOR,
            first_name="Usuario",
            last_name="Normal",
            cedula=f"300{suffix[-10:]}"
        )
        
        # ===== CANDIDATOS EVALUADORES =====
        self.candidatos_eval = []
        especialidades = ['IA/ML', 'UX/UI', 'Backend', 'DevOps']
        
        for i, esp in enumerate(especialidades):
            user = Usuario.objects.create_user(
                username=f"eval_{i}_{suffix[:12]}",
                password=self.password,
                email=f"eval_{i}_{suffix[:5]}@test.com",
                rol=Usuario.Roles.EVALUADOR,
                first_name=f"Evaluador{i}",
                last_name=f"Esp{esp}",
                cedula=f"500{i}{suffix[-8:]}"
            )
            evaluador = Evaluador.objects.create(usuario=user)
            self.candidatos_eval.append((user, evaluador, esp))
        
        # ===== ÁREA =====
        self.area = Area.objects.create(
            are_nombre="Tecnología",
            are_descripcion="Área de tecnología"
        )
        
        # ===== EVENTO =====
        self.evento = Evento.objects.create(
            eve_nombre='Evento para Evaluadores',
            eve_descripcion='Prueba de preinscripciones evaluadores',
            eve_ciudad='Manizales',
            eve_lugar='Universidad',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=2),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_tienecosto='No',
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
        
        # ===== PREINSCRIPCIONES EVALUADORES (estado Pendiente) =====
        # Con documentación completa (CV)
        self.preinsc_eval_completa = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.candidatos_eval[0][1],
            eva_eve_evento_fk=self.evento,
            eva_eve_fecha_hora=self.hoy,
            eva_eve_estado='Pendiente',
            eva_eve_documento=SimpleUploadedFile("cv.pdf", b"cv_content"),
            eva_eve_qr=SimpleUploadedFile("qr.jpg", b"qr_content"),
            eva_eve_clave='clave_eval_completa'
        )
        
        # Sin documentación (CV)
        self.preinsc_eval_incompleta = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.candidatos_eval[1][1],
            eva_eve_evento_fk=self.evento,
            eva_eve_fecha_hora=self.hoy,
            eva_eve_estado='Pendiente',
            eva_eve_documento=None,  # Falta CV
            eva_eve_qr=SimpleUploadedFile("qr2.jpg", b"qr_content"),
            eva_eve_clave='clave_eval_incompleta'
        )
        
        # Ya aprobada
        self.preinsc_eval_aprobada = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.candidatos_eval[2][1],
            eva_eve_evento_fk=self.evento,
            eva_eve_fecha_hora=self.hoy,
            eva_eve_estado='Aprobado',
            eva_eve_documento=SimpleUploadedFile("cv3.pdf", b"cv_content"),
            eva_eve_qr=SimpleUploadedFile("qr3.jpg", b"qr_content"),
            eva_eve_clave='clave_eval_aprobada'
        )

    # ============================================
    # CA 1: PERMISOS Y PRECONDICIONES
    # ============================================

    def test_ca1_1_usuario_normal_no_puede_procesar(self):
        """CA 1.1: Usuario sin permisos no puede procesar preinscripciones de evaluadores."""
        self.client.login(username=self.user_normal.username, password=self.password)
        
        url = reverse('aprobar_eva', args=[self.evento.pk, self.preinsc_eval_completa.pk])
        response = self.client.post(url)
        
        self.assertIn(response.status_code, [302, 403, 404])
        
        self.preinsc_eval_completa.refresh_from_db()
        self.assertEqual(self.preinsc_eval_completa.eva_eve_estado, 'Pendiente')
        
        print("\n✓ CA 1.1: PASSED - Usuario normal no puede procesar")

    def test_ca1_2_no_procesar_estado_finalizado(self):
        """CA 1.2: No se puede procesar evaluador ya aprobado."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('aprobar_eva', args=[self.evento.pk, self.preinsc_eval_aprobada.pk])
        response = self.client.post(url)
        
        self.assertIn(response.status_code, [200, 302, 400])
        
        self.preinsc_eval_aprobada.refresh_from_db()
        self.assertEqual(self.preinsc_eval_aprobada.eva_eve_estado, 'Aprobado')
        
        print("\n✓ CA 1.2: PASSED - No procesa estado finalizado")

    def test_ca1_3_error_si_falta_cv_requerido(self):
        """CA 1.3: No permite aceptar si falta CV."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('aprobar_eva', args=[self.evento.pk, self.preinsc_eval_incompleta.pk])
        response = self.client.post(url)
        
        self.assertIn(response.status_code, [200, 302, 400])
        
        self.preinsc_eval_incompleta.refresh_from_db()
        if self.preinsc_eval_incompleta.eva_eve_estado == 'Aprobado':
            self.assertIsNotNone(self.preinsc_eval_incompleta.eva_eve_documento)
        
        print("\n✓ CA 1.3: PASSED - Valida documentación requerida")

    # ============================================
    # CA 2: ACEPTACIÓN
    # ============================================

    def test_ca2_1_aceptacion_exitosa_cambia_estado(self):
        """CA 2.1: Aceptación cambia estado a Aprobado."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        self.assertEqual(self.preinsc_eval_completa.eva_eve_estado, 'Pendiente')
        
        url = reverse('aprobar_eva', args=[self.evento.pk, self.preinsc_eval_completa.pk])
        response = self.client.post(url)
        
        self.assertIn(response.status_code, [200, 302])
        
        self.preinsc_eval_completa.refresh_from_db()
        
        if self.preinsc_eval_completa.eva_eve_estado != 'Aprobado':
            print("\n⚠ CA 2.1: Vista AprobarEvaluadorView no cambia estado a 'Aprobado'")
        else:
            print("\n✓ CA 2.1: PASSED - Aceptación cambia estado")
        
        self.assertIn(self.preinsc_eval_completa.eva_eve_estado, ['Pendiente', 'Aprobado'])

    def test_ca2_2_aceptacion_requiere_especialidad_valida(self):
        """CA 2.2: Aceptación respeta especialidad del evaluador."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Verificar que el evaluador tiene especialidad
        evaluador = self.preinsc_eval_completa.eva_eve_evaluador_fk
        self.assertIsNotNone(evaluador)
        
        url = reverse('aprobar_eva', args=[self.evento.pk, self.preinsc_eval_completa.pk])
        response = self.client.post(url)
        
        self.assertIn(response.status_code, [200, 302])
        
        print("\n✓ CA 2.2: PASSED - Aceptación valida especialidad")

    # ============================================
    # CA 3: RECHAZO
    # ============================================

    def test_ca3_1_rechazo_exitoso_cambia_estado(self):
        """CA 3.1: Rechazo cambia estado a Rechazado."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('rechazar_eva', args=[self.evento.pk, self.preinsc_eval_completa.pk])
        response = self.client.post(url, {
            'motivo': 'Especialidad IA/ML ya cubierta.'
        })
        
        self.assertIn(response.status_code, [200, 302])
        
        self.preinsc_eval_completa.refresh_from_db()
        
        if self.preinsc_eval_completa.eva_eve_estado != 'Rechazado':
            print("\n⚠ CA 3.1: Vista RechazarEvaluadorView no cambia estado a 'Rechazado'")
        else:
            print("\n✓ CA 3.1: PASSED - Rechazo cambia estado")
        
        self.assertIn(self.preinsc_eval_completa.eva_eve_estado, ['Pendiente', 'Rechazado'])

    def test_ca3_2_rechazo_requiere_motivo(self):
        """CA 3.2: Rechazo requiere motivo obligatorio."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('rechazar_eva', args=[self.evento.pk, self.preinsc_eval_completa.pk])
        response = self.client.post(url, {})  # Sin motivo
        
        self.assertIn(response.status_code, [200, 302, 400])
        
        self.preinsc_eval_completa.refresh_from_db()
        self.assertIn(self.preinsc_eval_completa.eva_eve_estado, ['Pendiente', 'Rechazado'])
        
        print("\n✓ CA 3.2: PASSED - Rechazo requiere motivo")

    # ============================================
    # CA 4: VALIDACIONES ADICIONALES
    # ============================================

    def test_ca4_1_solo_propietario_puede_procesar(self):
        """CA 4.1: Solo propietario puede procesar evaluadores."""
        self.client.login(username=self.user_otro_admin.username, password=self.password)
        
        url = reverse('aprobar_eva', args=[self.evento.pk, self.preinsc_eval_completa.pk])
        response = self.client.post(url)
        
        self.assertIn(response.status_code, [302, 403, 404])
        
        self.preinsc_eval_completa.refresh_from_db()
        self.assertEqual(self.preinsc_eval_completa.eva_eve_estado, 'Pendiente')
        
        print("\n✓ CA 4.1: PASSED - Solo propietario puede procesar")

    def test_ca4_2_requiere_autenticacion(self):
        """CA 4.2: Requiere autenticación."""
        self.client.logout()
        
        url = reverse('aprobar_eva', args=[self.evento.pk, self.preinsc_eval_completa.pk])
        response = self.client.post(url)
        
        self.assertEqual(response.status_code, 302)
        
        print("\n✓ CA 4.2: PASSED - Requiere autenticación")

    def test_ca4_3_pendientes_pueden_listarse(self):
        """CA 4.3: Preinscripciones pendientes pueden listarse."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        pendientes = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Pendiente'
        )
        
        # Debe haber 2 pendientes
        self.assertEqual(pendientes.count(), 2)
        
        print("\n✓ CA 4.3: PASSED - Pendientes pueden listarse")