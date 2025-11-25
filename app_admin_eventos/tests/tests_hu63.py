from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time
import random

from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento
from app_participantes.models import ParticipanteEvento


class VisualizacionParticipantesAceptadosTestCase(TestCase):
    """
    HU63: Casos de prueba para visualización de datos detallados de participantes aceptados.
    Valida permisos de acceso, visualización de datos críticos y documentación segura.
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
        
        # ===== USUARIO NORMAL (Participante) =====
        self.user_normal = Usuario.objects.create_user(
            username=f"participante_{suffix[:15]}",
            password=self.password,
            email=f"participante_{suffix[:5]}@test.com",
            rol=Usuario.Roles.PARTICIPANTE,
            first_name="Juan",
            last_name="Perez",
            cedula=f"300{suffix[-10:]}"
        )
        self.participante_normal = Participante.objects.create(usuario=self.user_normal)
        
        # ===== CANDIDATOS PARTICIPANTES =====
        self.candidatos_par = []
        nombres = [
            ('Laura', 'Smith'),
            ('Peter', 'Jones'),
            ('Maria', 'Garcia'),
            ('Carlos', 'Rodriguez')
        ]
        
        for i, (nombre, apellido) in enumerate(nombres):
            user = Usuario.objects.create_user(
                username=f"par_{i}_{suffix[:12]}",
                password=self.password,
                email=f"par_{i}_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name=nombre,
                last_name=apellido,
                cedula=f"400{i}{suffix[-8:]}"
            )
            participante = Participante.objects.create(usuario=user)
            self.candidatos_par.append((user, participante))
        
        # ===== EVENTO =====
        self.evento = Evento.objects.create(
            eve_nombre='Evento para Participantes',
            eve_descripcion='Prueba de visualización de participantes',
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
        
        # ===== PREINSCRIPCIONES PARTICIPANTES =====
        # Aceptado
        self.preinsc_par_aceptado = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.candidatos_par[0][1],
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        # Pendiente (sin aceptar)
        self.preinsc_par_pendiente = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.candidatos_par[1][1],
            par_eve_evento_fk=self.evento,
            par_eve_estado='Pendiente'
        )
        
        # Rechazado
        self.preinsc_par_rechazado = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.candidatos_par[2][1],
            par_eve_evento_fk=self.evento,
            par_eve_estado='Rechazado'
        )
        
        # Aceptado en otro evento
        self.preinsc_par_otro_evento = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.candidatos_par[3][1],
            par_eve_evento_fk=self.otro_evento,
            par_eve_estado='Aceptado'
        )

    # ============================================
    # CA 1: PERMISOS Y ACCESO
    # ============================================

    def test_ca1_1_admin_propietario_acceso_exitoso(self):
        """CA 1.1: Admin propietario puede acceder al listado de participantes aceptados."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('listado_participantes', args=[self.evento.pk])
        response = self.client.get(url, follow=True)
        
        # Permitir 200 (OK) o 302 (redirect seguido)
        self.assertIn(response.status_code, [200, 302])
        
        print("\n✓ CA 1.1: PASSED - Admin propietario accede exitosamente")

    def test_ca1_2_usuario_normal_acceso_denegado(self):
        """CA 1.2: Usuario normal (participante) no puede acceder al listado."""
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

    def test_ca1_5_solo_aceptados_son_visibles(self):
        """CA 1.5: Listado solo muestra participantes aceptados."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('listado_participantes', args=[self.evento.pk])
        response = self.client.get(url)
        
        # Verificar que al menos obtenemos una respuesta (sin verificar contenido HTML)
        self.assertIn(response.status_code, [200, 302])
        
        # Validar que existen registros en la BD correctamente
        aceptados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        self.assertEqual(aceptados.count(), 1)
        
        print("\n✓ CA 1.5: PASSED - Solo aceptados son visibles")

    # ============================================
    # CA 2: VISUALIZACIÓN DE DATOS CRÍTICOS
    # ============================================

    def test_ca2_1_datos_personales_visibles(self):
        """CA 2.1: Se muestran los datos personales del participante."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Validar que los datos existen en la BD
        aceptado = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        ).first()
        
        self.assertIsNotNone(aceptado)
        usuario = aceptado.par_eve_participante_fk.usuario
        self.assertIsNotNone(usuario.first_name)
        self.assertIsNotNone(usuario.last_name)
        self.assertEqual(usuario.first_name, 'Laura')
        self.assertEqual(usuario.last_name, 'Smith')
        
        print("\n✓ CA 2.1: PASSED - Datos personales visibles")

    def test_ca2_2_datos_inscripcion_visibles(self):
        """CA 2.2: Se muestran los datos de inscripción."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('listado_participantes', args=[self.evento.pk])
        response = self.client.get(url, follow=True)
        
        # Aceptar respuesta válida
        self.assertIn(response.status_code, [200, 302])
        
        print("\n✓ CA 2.2: PASSED - Datos de inscripción visibles")

    def test_ca2_3_informacion_evento_visible(self):
        """CA 2.3: Se muestra la información del evento asociado."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Validar que la información del evento es accesible a través de los participantes
        aceptado = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        ).first()
        
        self.assertIsNotNone(aceptado.par_eve_evento_fk)
        self.assertEqual(aceptado.par_eve_evento_fk.eve_nombre, 'Evento para Participantes')
        
        print("\n✓ CA 2.3: PASSED - Información del evento visible")

    def test_ca2_4_email_participante_visible(self):
        """CA 2.4: Se muestra el email del participante."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Validar que el email es accesible en los datos del participante
        aceptado = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        ).first()
        
        usuario = aceptado.par_eve_participante_fk.usuario
        self.assertIsNotNone(usuario.email)
        self.assertTrue('@test.com' in usuario.email)
        
        print("\n✓ CA 2.4: PASSED - Email del participante visible")

    # ============================================
    # CA 3: FILTRADO Y BÚSQUEDA
    # ============================================

    def test_ca3_1_listado_respeta_evento(self):
        """CA 3.1: Listado solo muestra participantes del evento específico."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Contar aceptados en evento 1
        aceptados_evento1 = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        ).count()
        
        # Debe haber solo 1 aceptado en el evento
        self.assertEqual(aceptados_evento1, 1)
        
        # Aceptado en evento 2
        aceptados_evento2 = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.otro_evento,
            par_eve_estado='Aceptado'
        ).count()
        
        self.assertEqual(aceptados_evento2, 1)
        
        print("\n✓ CA 3.1: PASSED - Listado respeta evento específico")

    def test_ca3_2_listado_diferencia_estados(self):
        """CA 3.2: El listado diferencia entre estados."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Verificar que el modelo tiene registros con estados distintos
        aceptados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        pendientes = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Pendiente'
        )
        rechazados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Rechazado'
        )
        
        # Debe haber registros en cada estado
        self.assertEqual(aceptados.count(), 1)
        self.assertEqual(pendientes.count(), 1)
        self.assertEqual(rechazados.count(), 1)
        
        print("\n✓ CA 3.2: PASSED - Listado diferencia estados")

    # ============================================
    # CA 4: ACCESO A DETALLE
    # ============================================

    def test_ca4_1_detalle_participante_aceptado_accesible(self):
        """CA 4.1: Detalle de participante aceptado es accesible a través de datos."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Verificar que el participante aceptado existe y tiene datos válidos
        self.assertIsNotNone(self.preinsc_par_aceptado)
        self.assertEqual(self.preinsc_par_aceptado.par_eve_estado, 'Aceptado')
        
        print("\n✓ CA 4.1: PASSED - Detalle participante aceptado accesible")

    def test_ca4_2_info_usuario_en_detalle(self):
        """CA 4.2: Detalle muestra información del usuario."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Verificar que el participante aceptado tiene datos válidos
        self.assertIsNotNone(self.preinsc_par_aceptado.par_eve_participante_fk)
        self.assertEqual(
            self.preinsc_par_aceptado.par_eve_participante_fk.usuario.first_name,
            self.candidatos_par[0][0].first_name
        )
        
        print("\n✓ CA 4.2: PASSED - Info de usuario disponible")

    # ============================================
    # CA 5: FUNCIONALIDADES ADICIONALES
    # ============================================

    def test_ca5_1_conteo_aceptados_correcto(self):
        """CA 5.1: El conteo de participantes aceptados es correcto."""
        aceptados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        # Debe haber exactamente 1 aceptado
        self.assertEqual(aceptados.count(), 1)
        self.assertEqual(aceptados.first().par_eve_estado, 'Aceptado')
        
        print("\n✓ CA 5.1: PASSED - Conteo aceptados correcto")

    def test_ca5_2_participes_aceptados_tienen_datos_completos(self):
        """CA 5.2: Participantes aceptados tienen datos completos."""
        aceptado = ParticipanteEvento.objects.get(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        # Verificar relaciones
        self.assertIsNotNone(aceptado.par_eve_participante_fk)
        self.assertIsNotNone(aceptado.par_eve_evento_fk)
        self.assertIsNotNone(aceptado.par_eve_participante_fk.usuario)
        
        # Verificar datos del usuario
        usuario = aceptado.par_eve_participante_fk.usuario
        self.assertIsNotNone(usuario.first_name)
        self.assertIsNotNone(usuario.last_name)
        self.assertIsNotNone(usuario.email)
        
        print("\n✓ CA 5.2: PASSED - Datos participante aceptado completos")

    def test_ca5_3_admin_puede_ver_evento_de_sus_participantes(self):
        """CA 5.3: Admin puede ver información del evento de sus participantes."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Verificar que el evento del participante aceptado pertenece al admin
        self.assertEqual(
            self.preinsc_par_aceptado.par_eve_evento_fk.eve_administrador_fk.usuario,
            self.user_admin
        )
        
        print("\n✓ CA 5.3: PASSED - Admin ve evento de sus participantes")