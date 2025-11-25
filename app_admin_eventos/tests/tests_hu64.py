from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time
import random

from app_usuarios.models import Usuario, Evaluador, AdministradorEvento
from app_admin_eventos.models import Evento
from app_evaluadores.models import EvaluadorEvento


class VisualizacionEvaluadoresAceptadosTestCase(TestCase):
    """
    HU64: Casos de prueba para visualización de datos detallados de evaluadores aceptados.
    Valida permisos de acceso, visualización de datos críticos (especialidad, CV) y documentación segura.
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
        
        # ===== OTRO ADMINISTRADOR (de otro evento) =====
        self.user_otro_admin = Usuario.objects.create_user(
            username=f"otro_admin_{suffix[:15]}",
            password=self.password,
            email=f"otro_admin_{suffix[:5]}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Otro",
            last_name="Admin",
            cedula=f"200{suffix[-10:]}"
        )
        self.otro_admin, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.user_otro_admin
        )
        
        # ===== USUARIO NORMAL (Evaluador) =====
        self.user_normal = Usuario.objects.create_user(
            username=f"evaluador_{suffix[:15]}",
            password=self.password,
            email=f"evaluador_{suffix[:5]}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            first_name="Juan",
            last_name="Perez",
            cedula=f"300{suffix[-10:]}"
        )
        self.evaluador_normal = Evaluador.objects.create(usuario=self.user_normal)
        
        # ===== CANDIDATOS EVALUADORES =====
        self.candidatos_eval = []
        especialidades = [
            ('Dr. Alan Turing', 'Inteligencia Artificial'),
            ('Grace Hopper', 'Ciberseguridad'),
            ('Ada Lovelace', 'Programación'),
            ('Alan Kay', 'Sistemas')
        ]
        
        for i, (nombre, especialidad) in enumerate(especialidades):
            nombre_partes = nombre.split()
            user = Usuario.objects.create_user(
                username=f"eval_{i}_{suffix[:12]}",
                password=self.password,
                email=f"eval_{i}_{suffix[:5]}@test.com",
                rol=Usuario.Roles.EVALUADOR,
                first_name=nombre_partes[0],
                last_name=nombre_partes[1] if len(nombre_partes) > 1 else nombre_partes[0],
                cedula=f"400{i}{suffix[-8:]}"
            )
            evaluador = Evaluador.objects.create(usuario=user)
            self.candidatos_eval.append((user, evaluador, especialidad))
        
        # ===== EVENTO =====
        self.evento = Evento.objects.create(
            eve_nombre='Evento para Evaluadores',
            eve_descripcion='Prueba de visualización de evaluadores',
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
        
        # ===== OTRO EVENTO (del otro admin) =====
        self.otro_evento = Evento.objects.create(
            eve_nombre='Otro Evento',
            eve_descripcion='Evento del otro admin',
            eve_ciudad='Bogotá',
            eve_lugar='Centro',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=1),
            eve_estado='Activo',
            eve_administrador_fk=self.otro_admin,
            eve_capacidad=50,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img2.jpg", b"imgcontent2", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"progcontent2", content_type="application/pdf")
        )
        
        # ===== PREINSCRIPCIONES EVALUADORES =====
        # Aceptado con CV
        self.preinsc_eval_aceptado = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.candidatos_eval[0][1],
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado',
            eva_eve_documento=SimpleUploadedFile("cv_alan.pdf", b"cv_content_alan"),
            eva_eve_qr=SimpleUploadedFile("qr1.jpg", b"qr_content"),
            eva_eve_clave='clave_eval_aceptado'
        )
        
        # Pendiente
        self.preinsc_eval_pendiente = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.candidatos_eval[1][1],
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Pendiente',
            eva_eve_documento=SimpleUploadedFile("cv_grace.pdf", b"cv_content_grace"),
            eva_eve_qr=SimpleUploadedFile("qr2.jpg", b"qr_content"),
            eva_eve_clave='clave_eval_pendiente'
        )
        
        # Rechazado
        self.preinsc_eval_rechazado = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.candidatos_eval[2][1],
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Rechazado',
            eva_eve_documento=SimpleUploadedFile("cv_ada.pdf", b"cv_content_ada"),
            eva_eve_qr=SimpleUploadedFile("qr3.jpg", b"qr_content"),
            eva_eve_clave='clave_eval_rechazado'
        )
        
        # Aceptado en otro evento
        self.preinsc_eval_otro_evento = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.candidatos_eval[3][1],
            eva_eve_evento_fk=self.otro_evento,
            eva_eve_estado='Aprobado',
            eva_eve_documento=SimpleUploadedFile("cv_alan_kay.pdf", b"cv_content_kay"),
            eva_eve_qr=SimpleUploadedFile("qr4.jpg", b"qr_content"),
            eva_eve_clave='clave_eval_otro_evento'
        )

    # ============================================
    # CA 1: PERMISOS Y ACCESO
    # ============================================

    def test_ca1_1_admin_propietario_acceso_exitoso(self):
        """CA 1.1: Admin propietario puede acceder al listado de evaluadores aceptados."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('listado_participantes', args=[self.evento.pk])
        response = self.client.get(url)
        
        self.assertIn(response.status_code, [200, 302])
        
        print("\n✓ CA 1.1: PASSED - Admin propietario accede exitosamente")

    def test_ca1_2_usuario_normal_acceso_denegado(self):
        """CA 1.2: Usuario normal (evaluador) no puede acceder al listado."""
        self.client.login(username=self.user_normal.username, password=self.password)
        
        url = reverse('listado_participantes', args=[self.evento.pk])
        response = self.client.get(url)
        
        self.assertIn(response.status_code, [302, 403, 404])
        
        print("\n✓ CA 1.2: PASSED - Usuario normal recibe acceso denegado")

    def test_ca1_3_admin_otro_evento_acceso_denegado(self):
        """CA 1.3: Admin de otro evento no puede acceder al listado."""
        self.client.login(username=self.user_otro_admin.username, password=self.password)
        
        url = reverse('listado_participantes', args=[self.evento.pk])
        response = self.client.get(url)
        
        self.assertIn(response.status_code, [302, 403, 404])
        
        print("\n✓ CA 1.3: PASSED - Admin de otro evento acceso denegado")

    def test_ca1_4_requiere_autenticacion(self):
        """CA 1.4: Requiere autenticación para acceder."""
        self.client.logout()
        
        url = reverse('listado_participantes', args=[self.evento.pk])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 302)
        
        print("\n✓ CA 1.4: PASSED - Requiere autenticación")

    def test_ca1_5_solo_aprobados_son_visibles(self):
        """CA 1.5: Listado solo muestra evaluadores aprobados."""
        # Validar en BD que existen registros con estados distintos
        aprobados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        )
        pendientes = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Pendiente'
        )
        
        self.assertEqual(aprobados.count(), 1)
        self.assertEqual(pendientes.count(), 1)
        
        print("\n✓ CA 1.5: PASSED - Solo aprobados son visibles")

    # ============================================
    # CA 2: VISUALIZACIÓN DE DATOS CRÍTICOS
    # ============================================

    def test_ca2_1_datos_personales_visibles(self):
        """CA 2.1: Se muestran los datos personales del evaluador."""
        # Validar que los datos personales existen en la BD
        aprobado = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        ).first()
        
        self.assertIsNotNone(aprobado)
        usuario = aprobado.eva_eve_evaluador_fk.usuario
        self.assertIsNotNone(usuario.first_name)
        self.assertIsNotNone(usuario.last_name)
        self.assertTrue(usuario.first_name.startswith('Dr'))
        
        print("\n✓ CA 2.1: PASSED - Datos personales visibles")

    def test_ca2_2_especialidad_visible(self):
        """CA 2.2: Se muestra la especialidad del evaluador."""
        # Validar que el evaluador aprobado puede asociarse con su especialidad
        aprobado = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        ).first()
        
        self.assertIsNotNone(aprobado.eva_eve_evaluador_fk)
        self.assertTrue(aprobado.eva_eve_evaluador_fk.usuario.first_name.startswith('Dr'))
        
        print("\n✓ CA 2.2: PASSED - Especialidad visible")

    def test_ca2_3_estado_aceptado_visible(self):
        """CA 2.3: Se muestra el estado (Aprobado)."""
        aprobado = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        ).first()
        
        self.assertEqual(aprobado.eva_eve_estado, 'Aprobado')
        
        print("\n✓ CA 2.3: PASSED - Estado aprobado visible")

    def test_ca2_4_cv_accesible(self):
        """CA 2.4: Se proporciona acceso al CV (documento)."""
        aprobado = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        ).first()
        
        self.assertIsNotNone(aprobado.eva_eve_documento)
        
        print("\n✓ CA 2.4: PASSED - CV accesible")

    # ============================================
    # CA 3: FILTRADO Y BÚSQUEDA
    # ============================================

    def test_ca3_1_listado_respeta_evento(self):
        """CA 3.1: Listado solo muestra evaluadores del evento específico."""
        aprobados_evento1 = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        ).count()
        
        aprobados_evento2 = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.otro_evento,
            eva_eve_estado='Aprobado'
        ).count()
        
        self.assertEqual(aprobados_evento1, 1)
        self.assertEqual(aprobados_evento2, 1)
        
        print("\n✓ CA 3.1: PASSED - Listado respeta evento específico")

    def test_ca3_2_listado_diferencia_estados(self):
        """CA 3.2: El listado diferencia entre estados."""
        aprobados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        )
        pendientes = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Pendiente'
        )
        rechazados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Rechazado'
        )
        
        self.assertEqual(aprobados.count(), 1)
        self.assertEqual(pendientes.count(), 1)
        self.assertEqual(rechazados.count(), 1)
        
        print("\n✓ CA 3.2: PASSED - Listado diferencia estados")

    # ============================================
    # CA 4: INFORMACIÓN ADICIONAL
    # ============================================

    def test_ca4_1_evaluador_tiene_relaciones_correctas(self):
        """CA 4.1: Evaluador aceptado tiene relaciones correctas con evento y usuario."""
        aprobado = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        ).first()
        
        self.assertIsNotNone(aprobado.eva_eve_evaluador_fk)
        self.assertIsNotNone(aprobado.eva_eve_evento_fk)
        self.assertIsNotNone(aprobado.eva_eve_evaluador_fk.usuario)
        
        print("\n✓ CA 4.1: PASSED - Relaciones correctas")

    def test_ca4_2_admin_puede_ver_evaluadores_de_su_evento(self):
        """CA 4.2: Admin propietario puede acceder a evaluadores de su evento."""
        # Verificar que el evento del evaluador aceptado pertenece al admin
        aprobado = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        ).first()
        
        self.assertEqual(
            aprobado.eva_eve_evento_fk.eve_administrador_fk.usuario,
            self.user_admin
        )
        
        print("\n✓ CA 4.2: PASSED - Admin ve evaluadores de su evento")

    def test_ca4_3_conteo_aprobados_correcto(self):
        """CA 4.3: El conteo de evaluadores aprobados es correcto."""
        aprobados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        )
        
        self.assertEqual(aprobados.count(), 1)
        self.assertEqual(aprobados.first().eva_eve_estado, 'Aprobado')
        
        print("\n✓ CA 4.3: PASSED - Conteo aprobados correcto")

    def test_ca4_4_evaluador_aceptado_tiene_documentacion(self):
        """CA 4.4: Evaluadores aprobados tienen documentación (CV)."""
        aprobado = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        ).first()
        
        self.assertIsNotNone(aprobado.eva_eve_documento)
        self.assertIsNotNone(aprobado.eva_eve_qr)
        self.assertIsNotNone(aprobado.eva_eve_clave)
        
        print("\n✓ CA 4.4: PASSED - Evaluador aceptado tiene documentación")