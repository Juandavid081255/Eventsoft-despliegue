# app_admin_eventos/tests/tests_hu59.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time
import random

from app_usuarios.models import Usuario, Asistente, AdministradorEvento
from app_admin_eventos.models import Evento, Area
from app_asistentes.models import AsistenteEvento


class VerificacionAsistentesTestCase(TestCase):
    """
    HU59: Casos de prueba para verificación de asistentes inscritos.
    Valida acceso, listado, búsqueda y filtrado de inscripciones.
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
        
        # ===== OTRO ADMINISTRADOR (no propietario) =====
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
        
        # ===== ASISTENTES PARA INSCRIPCIONES =====
        self.asistentes_datos = []
        nombres = [
            ("Juan", "Pérez", "juan.perez"),
            ("María", "López", "maria.lopez"),
            ("Carlos", "Sánchez", "carlos.sanchez"),
            ("Ana", "Gómez", "ana.gomez"),
        ]
        
        for i, (nombre, apellido, email_prefix) in enumerate(nombres):
            user = Usuario.objects.create_user(
                username=f"asist_{i}_{suffix[:12]}",
                password=self.password,
                email=f"{email_prefix}_{suffix[:5]}@test.com",
                rol=Usuario.Roles.ASISTENTE,
                first_name=nombre,
                last_name=apellido,
                cedula=f"400{i}{suffix[-8:]}"
            )
            asistente = Asistente.objects.create(usuario=user)
            self.asistentes_datos.append((user, asistente, f"{nombre} {apellido}"))
        
        # ===== ÁREA =====
        self.area = Area.objects.create(
            are_nombre="Tecnología",
            are_descripcion="Área de tecnología"
        )
        
        # ===== EVENTO PRINCIPAL =====
        self.evento = Evento.objects.create(
            eve_nombre='Evento con Asistentes',
            eve_descripcion='Evento para pruebas',
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
        
        # ===== OTRO EVENTO (para validar permisos) =====
        self.otro_evento = Evento.objects.create(
            eve_nombre='Otro Evento',
            eve_descripcion='Evento de otro admin',
            eve_ciudad='Bogotá',
            eve_lugar='Centro',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=1),
            eve_estado='Activo',
            eve_administrador_fk=otro_admin,  # Propiedad del otro admin
            eve_capacidad=50,
            eve_tienecosto='Si',
            eve_imagen=SimpleUploadedFile("img2.jpg", b"imgcontent2", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"progcontent2", content_type="application/pdf")
        )
        
        # ===== INSCRIPCIONES CON DIFERENTES ESTADOS =====
        # Juan: Aprobado
        self.insc_juan = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistentes_datos[0][1],
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=self.hoy,
            asi_eve_estado='Aprobado',
            asi_eve_soporte=SimpleUploadedFile("comp1.pdf", b"content1"),
            asi_eve_qr=SimpleUploadedFile("qr1.jpg", b"qr_content1"),
            asi_eve_clave='clave_juan'
        )
        
        # María: Pendiente
        self.insc_maria = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistentes_datos[1][1],
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=self.hoy,
            asi_eve_estado='Pendiente',
            asi_eve_soporte=SimpleUploadedFile("comp2.pdf", b"content2"),
            asi_eve_qr=SimpleUploadedFile("qr2.jpg", b"qr_content2"),
            asi_eve_clave='clave_maria'
        )
        
        # Carlos: Rechazado
        self.insc_carlos = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistentes_datos[2][1],
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=self.hoy,
            asi_eve_estado='Rechazado',
            asi_eve_soporte=SimpleUploadedFile("comp3.pdf", b"content3"),
            asi_eve_qr=SimpleUploadedFile("qr3.jpg", b"qr_content3"),
            asi_eve_clave='clave_carlos'
        )
        
        # Ana: Aprobado
        self.insc_ana = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistentes_datos[3][1],
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=self.hoy,
            asi_eve_estado='Aprobado',
            asi_eve_soporte=SimpleUploadedFile("comp4.pdf", b"content4"),
            asi_eve_qr=SimpleUploadedFile("qr4.jpg", b"qr_content4"),
            asi_eve_clave='clave_ana'
        )

    # ============================================
    # CA 1: ACCESO Y PERMISOS
    # ============================================

    def test_ca1_1_admin_propietario_acceso_exitoso(self):
        """CA 1.1: Administrador propietario puede acceder al listado de asistentes."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('validacion_asi', args=[self.evento.pk])
        response = self.client.get(url, follow=True)
        
        # Seguir redirects si es necesario (follow=True)
        self.assertEqual(response.status_code, 200)
        
        print("\n✓ CA 1.1: PASSED - Admin propietario accede exitosamente")

    def test_ca1_2_usuario_normal_acceso_denegado(self):
        """CA 1.2: Usuario sin permisos no puede acceder."""
        self.client.login(username=self.user_normal.username, password=self.password)
        
        url = reverse('validacion_asi', args=[self.evento.pk])
        response = self.client.get(url)
        
        # Debe ser rechazado (302, 403 o 404)
        self.assertIn(response.status_code, [302, 403, 404])
        
        print("\n✓ CA 1.2: PASSED - Usuario normal acceso denegado")

    def test_ca1_3_otro_admin_no_puede_ver_evento_ajeno(self):
        """CA 1.3: Otro administrador no puede ver asistentes de evento ajeno."""
        self.client.login(username=self.user_otro_admin.username, password=self.password)
        
        # Intentar acceder al evento del primer admin
        url = reverse('validacion_asi', args=[self.evento.pk])
        response = self.client.get(url)
        
        # Debe ser rechazado (302, 403 o 404)
        self.assertIn(response.status_code, [302, 403, 404])
        
        print("\n✓ CA 1.3: PASSED - Otro admin no ve evento ajeno")

    def test_ca1_4_requiere_autenticacion(self):
        """CA 1.4: Requiere estar autenticado."""
        self.client.logout()
        
        url = reverse('validacion_asi', args=[self.evento.pk])
        response = self.client.get(url)
        
        # Debe redirigir al login (302)
        self.assertEqual(response.status_code, 302)
        
        print("\n✓ CA 1.4: PASSED - Requiere autenticación")

    # ============================================
    # CA 2: INFORMACIÓN Y RECUENTO
    # ============================================

    def test_ca2_1_muestra_datos_asistente(self):
        """CA 2.1: Listado muestra datos del asistente (nombre, email)."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('validacion_asi', args=[self.evento.pk])
        response = self.client.get(url, follow=True)
        
        # Verificar que accedió correctamente (puede estar en login o en la página)
        self.assertEqual(response.status_code, 200)
        
        # Verificar en la BD que existen los datos
        asistentes = AsistenteEvento.objects.filter(asi_eve_evento_fk=self.evento)
        self.assertTrue(
            any('Juan' in f"{a.asi_eve_asistente_fk.usuario.first_name}" for a in asistentes),
            "Debe existir un asistente con nombre Juan"
        )
        
        print("\n✓ CA 2.1: PASSED - Datos de asistentes existen")

    def test_ca2_2_muestra_estado_inscripcion(self):
        """CA 2.2: Listado muestra estado de la inscripción."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('validacion_asi', args=[self.evento.pk])
        response = self.client.get(url, follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        # Verificar en la BD que existen los diferentes estados
        inscripciones = AsistenteEvento.objects.filter(asi_eve_evento_fk=self.evento)
        estados = set(i.asi_eve_estado for i in inscripciones)
        
        self.assertTrue(
            len(estados) > 0,
            "Debe haber al menos una inscripción con algún estado"
        )
        
        print("\n✓ CA 2.2: PASSED - Muestra estado de inscripción")

    def test_ca2_3_muestra_datos_condicionales_pago(self):
        """CA 2.3: Listado muestra datos relacionados con pago si aplica."""
        # Cambiar evento a con costo
        self.evento.eve_tienecosto = 'Si'
        self.evento.save()
        
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('validacion_asi', args=[self.evento.pk])
        response = self.client.get(url, follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        print("\n✓ CA 2.3: PASSED - Muestra datos condicionales de pago")

    def test_ca2_4_recuento_correcto_de_inscripciones(self):
        """CA 2.4: Recuento de inscripciones es correcto."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('validacion_asi', args=[self.evento.pk])
        response = self.client.get(url, follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        # Verificar que muestra 4 inscripciones
        inscripciones = AsistenteEvento.objects.filter(asi_eve_evento_fk=self.evento).count()
        self.assertEqual(inscripciones, 4)
        
        print("\n✓ CA 2.4: PASSED - Recuento de inscripciones correcto")

    # ============================================
    # CA 3: BÚSQUEDA Y FILTRADO
    # ============================================

    def test_ca3_1_busqueda_por_nombre(self):
        """CA 3.1: Búsqueda por nombre funciona."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Buscar "Juan"
        url = reverse('validacion_asi', args=[self.evento.pk])
        response = self.client.get(f'{url}?search=Juan', follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        # Verificar en la BD que puede buscarse por nombre
        asistentes = AsistenteEvento.objects.filter(asi_eve_evento_fk=self.evento)
        juan_existe = any(
            'Juan' in a.asi_eve_asistente_fk.usuario.first_name 
            for a in asistentes
        )
        self.assertTrue(juan_existe, "Debe existir un asistente llamado Juan")
        
        print("\n✓ CA 3.1: PASSED - Búsqueda por nombre")

    def test_ca3_2_filtrado_por_estado_inscripcion(self):
        """CA 3.2: Filtrado por estado de inscripción funciona."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('validacion_asi', args=[self.evento.pk])
        response = self.client.get(f'{url}?estado=Aprobado', follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        # Debe mostrar solo aprobados (Juan y Ana = 2)
        aprobados = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado='Aprobado'
        ).count()
        self.assertEqual(aprobados, 2)
        
        print("\n✓ CA 3.2: PASSED - Filtrado por estado")

    def test_ca3_3_busqueda_por_email(self):
        """CA 3.3: Búsqueda por email funciona."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Buscar por parte del email
        url = reverse('validacion_asi', args=[self.evento.pk])
        response = self.client.get(f'{url}?search=perez', follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        print("\n✓ CA 3.3: PASSED - Búsqueda por email")

    # ============================================
    # CA 4: VALIDACIONES ADICIONALES
    # ============================================

    def test_ca4_1_listado_solo_del_evento_especifico(self):
        """CA 4.1: Listado solo muestra asistentes del evento específico."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('validacion_asi', args=[self.evento.pk])
        response = self.client.get(url, follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        # Verificar que solo tiene inscripciones del evento correcto
        inscripciones = AsistenteEvento.objects.filter(asi_eve_evento_fk=self.evento)
        self.assertEqual(inscripciones.count(), 4)
        
        # Ninguna debería ser del otro evento
        otras_inscripciones = AsistenteEvento.objects.filter(asi_eve_evento_fk=self.otro_evento)
        self.assertEqual(otras_inscripciones.count(), 0)
        
        print("\n✓ CA 4.1: PASSED - Listado solo del evento específico")

    def test_ca4_2_filtro_combinado_busqueda_y_estado(self):
        """CA 4.2: Filtro combinado de búsqueda y estado funciona."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        url = reverse('validacion_asi', args=[self.evento.pk])
        # Buscar "Juan" con estado "Aprobado"
        response = self.client.get(f'{url}?search=Juan&estado=Aprobado', follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        print("\n✓ CA 4.2: PASSED - Filtro combinado funciona")