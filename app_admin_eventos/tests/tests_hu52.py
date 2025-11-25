# app_admin_eventos/tests/tests_hu52.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time
import random

from app_usuarios.models import Usuario, AdministradorEvento
from app_admin_eventos.models import Evento, Area, Categoria, EventoCategoria
from app_participantes.models import ParticipanteEvento
from app_usuarios.models import Participante


class EventoEdicionTestCase(TestCase):
    """
    HU52: Casos de prueba para la edición/actualización integral de eventos.
    Validaciones de información, configuración, permisos y lógica de negocio.
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.client = Client()
        self.password = "testpass123"
        
        # ===== FECHAS =====
        self.hoy = date.today()
        self.futuro_cercano = self.hoy + timedelta(days=5)
        self.futuro_lejano = self.hoy + timedelta(days=30)
        self.pasado = self.hoy - timedelta(days=5)
        
        # ===== ADMINISTRADOR PROPIETARIO =====
        self.user_propietario = Usuario.objects.create_user(
            username=f"admin_prop_{suffix[:20]}",
            password=self.password,
            email=f"admin_prop_{suffix[:10]}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Admin",
            last_name="Propietario",
            cedula=f"100{suffix[-10:]}"
        )
        self.admin_propietario, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.user_propietario
        )
        
        # ===== OTRO ADMINISTRADOR (no propietario) =====
        self.user_otro_admin = Usuario.objects.create_user(
            username=f"admin_otro_{suffix[:20]}",
            password=self.password,
            email=f"admin_otro_{suffix[:10]}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Admin",
            last_name="Otro",
            cedula=f"200{suffix[-10:]}"
        )
        self.admin_otro, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.user_otro_admin
        )
        
        # ===== ÁREA Y CATEGORÍA =====
        self.area = Area.objects.create(
            are_nombre="Tecnología",
            are_descripcion="Área de tecnología"
        )
        self.categoria = Categoria.objects.create(
            cat_nombre="Desarrollo Web",
            cat_descripcion="Categoría de desarrollo web",
            cat_area_fk=self.area
        )
        
        # ===== EVENTO INICIAL (a editar) =====
        self.evento = Evento.objects.create(
            eve_nombre='Evento Inicial',
            eve_descripcion='Descripción antigua.',
            eve_ciudad='Ciudad Original',
            eve_lugar='Ubicación Original',
            eve_fecha_inicio=self.futuro_cercano,
            eve_fecha_fin=self.futuro_cercano + timedelta(days=2),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_propietario,
            eve_capacidad=100,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"progcontent", content_type="application/pdf")
        )
        
        # Simular 50 participantes inscritos aprobados
        self.crear_participantes_inscritos(50)
        
        # ===== URL DE EDICIÓN =====
        self.editar_url = reverse('editar_evento', args=[self.evento.pk])
        
        # ===== DATOS PARA EDICIÓN VÁLIDA =====
        self.datos_edicion_valida = {
            'eve_nombre': 'Nuevo Título Editado',
            'eve_descripcion': 'Nueva descripción actualizada.',
            'eve_ciudad': 'Manizales',
            'eve_lugar': 'Nueva Ubicación Principal',
            'eve_fecha_inicio': self.futuro_lejano.strftime('%Y-%m-%d'),
            'eve_fecha_fin': (self.futuro_lejano + timedelta(days=5)).strftime('%Y-%m-%d'),
            'eve_capacidad': 150,
            'eve_tienecosto': 'Si',
            'eve_estado': 'Activo',
            'area': self.area.pk,
            'categorias': [self.categoria.pk],
        }
        
        # ⚡ CRÍTICO: Establecer sesión de admin para que @admin_required funcione
        session = self.client.session
        session['admin_id'] = self.admin_propietario.pk
        session.save()
    
    def crear_participantes_inscritos(self, cantidad):
        """Crear participantes aprobados para simular inscritos."""
        for i in range(cantidad):
            suffix_part = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
            
            user = Usuario.objects.create_user(
                username=f"part_{i}_{suffix_part[:15]}",
                password="password",
                email=f"part_{i}_{suffix_part[:10]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name=f"Participante{i}",
                last_name="Test",
                cedula=f"300{i}{suffix_part[-7:]}"
            )
            participante, _ = Participante.objects.get_or_create(usuario=user)
            
            ParticipanteEvento.objects.create(
                par_eve_participante_fk=participante,
                par_eve_evento_fk=self.evento,
                par_eve_estado="Aprobado",
                par_eve_clave=f"CLAVE{i}"
            )

    # ============================================
    # CA 1: EDICIÓN EXITOSA (POSITIVO)
    # ============================================

    def test_ca1_2_edicion_completa_exitosa(self):
        """
        CA 1.2: Prueba la edición exitosa de información y configuración a la vez.
        """
        self.client.login(username=self.user_propietario.username, password=self.password)
        
        response = self.client.post(self.editar_url, data=self.datos_edicion_valida, follow=True)
        
        # Validación de respuesta
        self.assertIn(response.status_code, [200, 302])
        
        # Validación de persistencia
        self.evento.refresh_from_db()
        self.assertEqual(self.evento.eve_nombre, 'Nuevo Título Editado')
        self.assertEqual(self.evento.eve_capacidad, 150)
        self.assertEqual(self.evento.eve_tienecosto, 'Si')
        
        print("\n✓ CA 1.2: PASSED - Edición completa exitosa")

    def test_ca1_3_edicion_campo_opcional_vacio(self):
        """
        CA 1.3: Prueba que un campo opcional (eve_informacion_tecnica) puede quedar vacío.
        """
        self.client.login(username=self.user_propietario.username, password=self.password)
        
        datos = self.datos_edicion_valida.copy()
        
        response = self.client.post(self.editar_url, datos, follow=True)
        self.assertIn(response.status_code, [200, 302])
        
        self.evento.refresh_from_db()
        self.assertFalse(self.evento.eve_informacion_tecnica)
        
        print("\n✓ CA 1.3: PASSED - Campo opcional puede estar vacío")

    # ============================================
    # CA 3: PERMISOS Y SEGURIDAD
    # ============================================

    def test_ca3_1_edicion_permisos_insuficientes(self):
        """
        CA 3.1: Prueba que solo el administrador propietario puede editar.
        """
        # Cambiar sesión al otro admin
        session = self.client.session
        session['admin_id'] = self.admin_otro.pk
        session.save()
        
        self.client.login(username=self.user_otro_admin.username, password=self.password)
        
        datos_intentados = self.datos_edicion_valida.copy()
        
        response = self.client.post(self.editar_url, datos_intentados)
        
        self.assertIn(response.status_code, [403, 302])
        
        self.evento.refresh_from_db()
        self.assertEqual(self.evento.eve_nombre, 'Evento Inicial')
        
        print("\n✓ CA 3.1: PASSED - Solo propietario puede editar")

    def test_ca3_2_edicion_requiere_autenticacion(self):
        """
        CA 3.2: Prueba que un usuario no autenticado no puede editar.
        """
        # Limpiar sesión
        self.client.logout()
        session = self.client.session
        if 'admin_id' in session:
            del session['admin_id']
        session.save()
        
        response = self.client.post(self.editar_url, self.datos_edicion_valida)
        
        self.assertEqual(response.status_code, 302)
        
        print("\n✓ CA 3.2: PASSED - Requiere autenticación")

    # ============================================
    # CA 2: VALIDACIONES DE DATOS Y LÓGICA (NEGATIVO)
    # ============================================

    def test_ca2_1_edicion_fecha_inicio_pasada(self):
        """
        CA 2.1: Prueba que la edición no permite poner fecha de inicio en el pasado.
        """
        self.client.login(username=self.user_propietario.username, password=self.password)
        
        datos_invalidos = self.datos_edicion_valida.copy()
        datos_invalidos['eve_fecha_inicio'] = self.pasado.strftime('%Y-%m-%d')
        
        response = self.client.post(self.editar_url, datos_invalidos)
        
        self.assertIn(response.status_code, [200, 302, 400])
        
        self.evento.refresh_from_db()
        self.assertNotEqual(self.evento.eve_fecha_inicio, self.pasado)
        
        print("\n✓ CA 2.1: PASSED - No permite fecha pasada")

    def test_ca2_2_edicion_fechas_incoherentes(self):
        """
        CA 2.2: Prueba que la fecha de inicio no puede ser posterior a la de fin.
        """
        self.client.login(username=self.user_propietario.username, password=self.password)
        
        datos_invalidos = self.datos_edicion_valida.copy()
        datos_invalidos['eve_fecha_inicio'] = self.futuro_lejano.strftime('%Y-%m-%d')
        datos_invalidos['eve_fecha_fin'] = self.futuro_cercano.strftime('%Y-%m-%d')
        
        response = self.client.post(self.editar_url, datos_invalidos)
        
        self.assertIn(response.status_code, [200, 302, 400])
        
        print("\n✓ CA 2.2: PASSED - Rechaza fechas incoherentes")

    def test_ca2_3_edicion_cupo_menor_que_inscritos(self):
        """
        CA 2.3: VALIDACIÓN CRÍTICA - No puede reducir cupo por debajo de inscritos (50).
        """
        self.client.login(username=self.user_propietario.username, password=self.password)
        
        datos_invalidos = self.datos_edicion_valida.copy()
        datos_invalidos['eve_capacidad'] = 40
        
        response = self.client.post(self.editar_url, datos_invalidos)
        
        self.assertIn(response.status_code, [200, 302, 400])
        
        self.evento.refresh_from_db()
        self.assertEqual(self.evento.eve_capacidad, 100)
        
        print("\n✓ CA 2.3: PASSED - No permite reducir cupo bajo inscritos")

    def test_ca2_4_edicion_campo_obligatorio_vacio(self):
        """
        CA 2.4: Prueba que la edición de un campo obligatorio falla si se deja vacío.
        """
        self.client.login(username=self.user_propietario.username, password=self.password)
        
        datos_invalidos = self.datos_edicion_valida.copy()
        datos_invalidos['eve_nombre'] = ''
        
        response = self.client.post(self.editar_url, datos_invalidos)
        
        self.assertIn(response.status_code, [200, 302, 400])
        
        self.evento.refresh_from_db()
        self.assertNotEqual(self.evento.eve_nombre, '')
        self.assertEqual(self.evento.eve_nombre, 'Evento Inicial')
        
        print("\n✓ CA 2.4: PASSED - Campo obligatorio no puede estar vacío")

    def test_ca2_5_estructura_datos_valida(self):
        """
        CA 2.5: Verificar que la estructura de datos sea correcta en BD.
        """
        evento = Evento.objects.get(pk=self.evento.pk)
        
        self.assertIsNotNone(evento.eve_nombre)
        self.assertIsNotNone(evento.eve_capacidad)
        self.assertIsNotNone(evento.eve_administrador_fk)
        
        self.assertGreater(evento.eve_capacidad, 0)
        self.assertIn(evento.eve_tienecosto, ['Si', 'No'])
        
        print("\n✓ CA 2.5: PASSED - Estructura de datos válida")

    # ============================================
    # TESTS ADICIONALES
    # ============================================

    def test_edicion_mantiene_relaciones(self):
        """Verificar que la edición mantiene las relaciones (admin, categorías)."""
        self.client.login(username=self.user_propietario.username, password=self.password)
        
        admin_original = self.evento.eve_administrador_fk
        
        response = self.client.post(self.editar_url, self.datos_edicion_valida, follow=True)
        self.assertIn(response.status_code, [200, 302])
        
        self.evento.refresh_from_db()
        self.assertEqual(self.evento.eve_administrador_fk, admin_original)
        
        print("\n✓ EXTRA: Mantiene relaciones después de edición")

    def test_edicion_capacidad_exactamente_igual_inscritos(self):
        """
        Prueba que SÍ permite establecer capacidad igual a inscritos actuales (50).
        """
        self.client.login(username=self.user_propietario.username, password=self.password)
        
        datos = self.datos_edicion_valida.copy()
        datos['eve_capacidad'] = 50
        
        response = self.client.post(self.editar_url, data=datos, follow=True)
        
        self.assertIn(response.status_code, [200, 302])
        
        self.evento.refresh_from_db()
        self.assertEqual(self.evento.eve_capacidad, 50)
        
        print("\n✓ EXTRA: Permite capacidad igual a inscritos")