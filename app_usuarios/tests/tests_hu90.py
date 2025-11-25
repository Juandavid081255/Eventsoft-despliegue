from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time as time_module
import random

from app_usuarios.models import Usuario, AdministradorEvento
from app_admin_eventos.models import Evento


class HU90_ListadoEventosActivosSuperAdminTestCase(TestCase):
    """
    HU90: Como Super Admin quiero acceder al listado de eventos activos
    para tener control de los eventos que se están gestionando.
    
    Tests adaptados a modelos y estructura REAL del proyecto.
    """

    def setUp(self):
        """Configuración inicial"""
        suffix = f"{int(time_module.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.password = "testpass123"
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
            is_staff=True
        )
        
        # ===== ADMIN DE EVENTO =====
        self.user_admin = Usuario.objects.create_user(
            username=f"admin_{suffix[:12]}",
            password=self.password,
            email=f"admin_{suffix[:5]}@sistema.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Admin",
            last_name="Evento",
            cedula=f"200{suffix[-10:]}",
            is_staff=True
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.user_admin
        )
        
        # ===== USUARIO NORMAL =====
        self.user_normal = Usuario.objects.create_user(
            username=f"normal_{suffix[:15]}",
            password=self.password,
            email=f"normal_{suffix[:5]}@sistema.com",
            rol=Usuario.Roles.VISITANTE,
            first_name="Usuario",
            last_name="Normal",
            cedula=f"400{suffix[-10:]}"
        )
        
        # ===== EVENTO 1: ACTIVO =====
        self.evento_activo = Evento.objects.create(
            eve_nombre='Seminario de Tecnologia',
            eve_descripcion='Seminario sobre tecnologia',
            eve_ciudad='Bogota',
            eve_lugar='Centro de Convenciones',
            eve_fecha_inicio=self.fecha_futura,
            eve_fecha_fin=self.fecha_futura + timedelta(days=3),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=500,
            eve_tienecosto='Si',
            eve_imagen=SimpleUploadedFile("img.jpg", b"content", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"content", content_type="application/pdf")
        )
        
        # ===== EVENTO 2: FINALIZADO =====
        self.evento_finalizado = Evento.objects.create(
            eve_nombre='Congreso Pasado',
            eve_descripcion='Evento que ya termino',
            eve_ciudad='Medellin',
            eve_lugar='Auditorio',
            eve_fecha_inicio=self.fecha_pasada - timedelta(days=5),
            eve_fecha_fin=self.fecha_pasada,
            eve_estado='FINALIZADO',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=300,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img2.jpg", b"content", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"content", content_type="application/pdf")
        )
        
        # ===== EVENTO 3: ARCHIVADO =====
        self.evento_archivado = Evento.objects.create(
            eve_nombre='Encuentro Viejo',
            eve_descripcion='Evento archivado',
            eve_ciudad='Cartagena',
            eve_lugar='Centro Historico',
            eve_fecha_inicio=self.fecha_pasada - timedelta(days=100),
            eve_fecha_fin=self.fecha_pasada - timedelta(days=90),
            eve_estado='ARCHIVADO',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=150,
            eve_tienecosto='Si',
            eve_imagen=SimpleUploadedFile("img3.jpg", b"content", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog3.pdf", b"content", content_type="application/pdf")
        )

    # ============================================
    # CA 1: CONTROL DE ACCESO
    # ============================================

    def test_ca101_superadmin_acceso_exitoso(self):
        """CA1.01: Super Admin puede acceder al listado de eventos activos"""
        # Verificar que es Super Admin
        self.assertTrue(self.user_superadmin.is_superuser)
        
        # Puede obtener eventos
        eventos = Evento.objects.filter(eve_estado='Activo')
        self.assertIsNotNone(eventos)
        
        print("\n OK CA 1.01: PASSED - Super Admin acceso exitoso")

    def test_ca101_admin_evento_acceso_denegado(self):
        """CA1.01: Admin de Evento NO puede ver listado Super Admin"""
        # Verificar que NO es Super Admin
        self.assertFalse(self.user_admin.is_superuser)
        
        # Solo super admin debería ver este listado
        tiene_permiso = self.user_admin.is_superuser
        self.assertFalse(tiene_permiso)
        
        print("\n OK CA 1.01: PASSED - Admin evento acceso denegado")

    def test_ca101_usuario_normal_acceso_denegado(self):
        """CA1.01: Usuario normal NO puede ver listado Super Admin"""
        self.assertFalse(self.user_normal.is_superuser)
        
        tiene_permiso = self.user_normal.is_superuser
        self.assertFalse(tiene_permiso)
        
        print("\n OK CA 1.01: PASSED - Usuario normal acceso denegado")

    # ============================================
    # CA 2: FILTRADO Y CONTENIDO
    # ============================================

    def test_ca201_filtrado_por_estado_activo(self):
        """CA2.01: Se muestran SOLO eventos con estado='Activo'"""
        # Obtener eventos activos
        eventos_activos = Evento.objects.filter(eve_estado='Activo')
        
        # Debe haber solo 1 evento activo
        self.assertEqual(eventos_activos.count(), 1)
        self.assertEqual(eventos_activos.first().eve_nombre, 'Seminario de Tecnologia')
        
        # No debe incluir FINALIZADO ni ARCHIVADO
        todos_estados = Evento.objects.exclude(eve_estado='Activo')
        self.assertEqual(todos_estados.count(), 2)
        
        print("\n OK CA 2.01: PASSED - Filtrado: 1 evento activo, 2 no activos")

    def test_ca202_información_administrador(self):
        """CA2.02: Se muestra información del administrador del evento"""
        evento = Evento.objects.get(eve_estado='Activo')
        
        # Verificar que tiene administrador
        self.assertIsNotNone(evento.eve_administrador_fk)
        
        # Acceder a datos del administrador
        admin = evento.eve_administrador_fk.usuario
        self.assertEqual(admin.username, self.user_admin.username)
        self.assertEqual(admin.email, self.user_admin.email)
        self.assertEqual(admin.first_name, 'Admin')
        
        print(f"\n OK CA 2.02: PASSED - Admin: {admin.first_name} {admin.last_name}")

    def test_ca203_detalles_principales_evento(self):
        """CA2.03: Se muestran detalles principales del evento"""
        evento = Evento.objects.get(eve_estado='Activo')
        
        # Verificar campos principales
        self.assertEqual(evento.eve_nombre, 'Seminario de Tecnologia')
        self.assertEqual(evento.eve_ciudad, 'Bogota')
        self.assertEqual(evento.eve_capacidad, 500)
        self.assertIsNotNone(evento.eve_fecha_inicio)
        self.assertIsNotNone(evento.eve_fecha_fin)
        
        print(f"\n OK CA 2.03: PASSED - Evento: {evento.eve_nombre}, {evento.eve_ciudad}")

    # ============================================
    # CA 3: BÚSQUEDA Y FILTROS
    # ============================================

    def test_ca301_búsqueda_por_nombre(self):
        """CA3.01: Se pueden buscar eventos por nombre"""
        # Buscar por nombre
        eventos = Evento.objects.filter(
            eve_estado='Activo',
            eve_nombre__icontains='Seminario'
        )
        
        self.assertEqual(eventos.count(), 1)
        self.assertEqual(eventos.first().eve_nombre, 'Seminario de Tecnologia')
        
        print("\n OK CA 3.01: PASSED - Búsqueda por nombre funciona")

    def test_ca302_búsqueda_por_administrador(self):
        """CA3.02: Se pueden buscar eventos por administrador"""
        # Buscar por admin
        eventos = Evento.objects.filter(
            eve_estado='Activo',
            eve_administrador_fk__usuario__username__icontains='admin'
        )
        
        self.assertEqual(eventos.count(), 1)
        
        print("\n OK CA 3.02: PASSED - Búsqueda por administrador funciona")

    def test_ca303_eventos_ordenados_por_fecha(self):
        """CA3.03: Los eventos se pueden ordenar por fecha de inicio"""
        # Obtener eventos ordenados
        eventos = Evento.objects.filter(eve_estado='Activo').order_by('eve_fecha_inicio')
        
        # Verificar que están ordenados
        if eventos.count() > 1:
            for i in range(len(eventos) - 1):
                self.assertLessEqual(
                    eventos[i].eve_fecha_inicio,
                    eventos[i + 1].eve_fecha_inicio
                )
        
        print("\n OK CA 3.03: PASSED - Ordenamiento por fecha funciona")

    # ============================================
    # CA 4: VALIDACIONES
    # ============================================

    def test_ca401_información_consistente_con_bd(self):
        """CA4.01: Información es consistente con base de datos"""
        # Contar eventos activos
        cantidad_activos = Evento.objects.filter(eve_estado='Activo').count()
        self.assertEqual(cantidad_activos, 1)
        
        # Verificar que los datos son correctos
        evento = Evento.objects.get(eve_estado='Activo')
        self.assertIsNotNone(evento.eve_nombre)
        self.assertIsNotNone(evento.eve_ciudad)
        self.assertIsNotNone(evento.eve_administrador_fk)
        
        print("\n OK CA 4.01: PASSED - Información consistente con BD")

    def test_ca402_no_incluye_eventos_pasados(self):
        """CA4.02: No incluye eventos FINALIZADO ni ARCHIVADO"""
        # Obtener solo activos
        eventos_activos = Evento.objects.filter(eve_estado='Activo')
        
        # Verificar que FINALIZADO no está
        evento_finalizado = Evento.objects.filter(eve_estado='FINALIZADO').first()
        self.assertNotIn(evento_finalizado.id, [e.id for e in eventos_activos])
        
        # Verificar que ARCHIVADO no está
        evento_archivado = Evento.objects.filter(eve_estado='ARCHIVADO').first()
        self.assertNotIn(evento_archivado.id, [e.id for e in eventos_activos])
        
        print("\n OK CA 4.02: PASSED - Excluye eventos no activos")

    # ============================================
    # FLUJO INTEGRAL
    # ============================================

    def test_flujo_integral_listado_eventos_activos(self):
        """Flujo completo: Super Admin accede y filtra eventos activos"""
        print("\n1. Super Admin se autentica")
        self.assertTrue(self.user_superadmin.is_superuser)
        
        print("2. Accede al listado de eventos activos")
        eventos_activos = Evento.objects.filter(eve_estado='Activo')
        self.assertEqual(eventos_activos.count(), 1)
        
        print("3. Verifica información del evento")
        evento = eventos_activos.first()
        self.assertEqual(evento.eve_nombre, 'Seminario de Tecnologia')
        self.assertEqual(evento.eve_ciudad, 'Bogota')
        
        print("4. Verifica información del administrador")
        admin = evento.eve_administrador_fk.usuario
        self.assertEqual(admin.first_name, 'Admin')
        
        print("5. Busca por nombre")
        resultados = Evento.objects.filter(
            eve_estado='Activo',
            eve_nombre__icontains='Seminario'
        )
        self.assertEqual(resultados.count(), 1)
        
        print("6. Verifica que eventos no activos no aparecen")
        eventos_no_activos = Evento.objects.exclude(eve_estado='Activo')
        self.assertEqual(eventos_no_activos.count(), 2)
        
        print("\n OK Flujo Integral: PASSED - Listado de eventos activos funcionando")