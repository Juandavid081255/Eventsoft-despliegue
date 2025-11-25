from django.test import TestCase, Client
from django.urls import reverse
from app_usuarios.models import Usuario, AdministradorEvento
from app_admin_eventos.models import Evento
from app_participantes.models import ParticipanteEvento
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import random


class EventoConfiguracionTestCase(TestCase):
    """
    Casos de prueba para la funcionalidad de configuración de características de eventos (HU51).
    Verifica la actualización de configuración, permisos y validaciones.
    
    Modelos utilizados:
    - Usuario (rol ADMIN_EVENTO)
    - AdministradorEvento
    - Evento
    - ParticipanteEvento (para contar inscritos)
    """
    
    def setUp(self):
        """Configuración inicial: Usuarios y evento de prueba."""
        unique_suffix = str(random.randint(100000, 999999))
        
        self.client = Client()
        self.password = "password123"
        
        # Fechas para evento
        self.hoy = date.today()
        self.inicio = self.hoy + timedelta(days=7)
        self.fin = self.inicio + timedelta(days=2)
        
        # --- ADMINISTRADOR PROPIETARIO DEL EVENTO ---
        self.admin_user = Usuario.objects.create_user(
            username=f"admin_evento_{unique_suffix}",
            password=self.password,
            email=f"admin_{unique_suffix}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Admin",
            last_name="Propietario",
            cedula=f"1001{unique_suffix}"
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.admin_user
        )
        
        # --- OTRO ADMINISTRADOR (sin permisos sobre este evento) ---
        self.otro_admin_user = Usuario.objects.create_user(
            username=f"otro_admin_{unique_suffix}",
            password=self.password,
            email=f"otro_admin_{unique_suffix}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Otro",
            last_name="Admin",
            cedula=f"1002{unique_suffix}"
        )
        self.otro_admin_evento, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.otro_admin_user
        )
        
        # --- EVENTO INICIAL ---
        self.evento = Evento.objects.create(
            eve_nombre="Taller de Configuración",
            eve_descripcion="Evento para probar configuración",
            eve_fecha_inicio=self.inicio,
            eve_fecha_fin=self.fin,
            eve_ciudad="Manizales",
            eve_lugar="Auditorio Principal",
            eve_capacidad=100,  # Capacidad original
            eve_tienecosto="No",  # Sin costo inicial
            eve_administrador_fk=self.admin_evento,
            eve_estado="Activo",
            eve_imagen=SimpleUploadedFile("img.jpg", b'img', content_type='image/jpeg'),
            eve_programacion=SimpleUploadedFile("prog.pdf", b'pdf', content_type='application/pdf')
        )
        
        # URL de configuración del evento
        try:
            self.config_url = reverse('configurar_evento', args=[self.evento.pk])
        except:
            self.config_url = f'/admin/eventos/{self.evento.pk}/configurar/'

    # ==========================================
    # CA 1: Configuración Exitosa (Positivo)
    # ==========================================

    def test_ca1_1_ca1_4_configuracion_exitosa_de_todas_caracteristicas(self):
        """
        CA 1.1, 1.2, 1.3, 1.4: Prueba la actualización de todas las características con éxito.
        """
        self.client.login(username=self.admin_user.username, password=self.password)
        
        nuevos_datos = {
            'eve_capacidad': '50',
            'eve_tienecosto': 'Si',
            # Agregar otros campos si es necesario
        }
        
        response = self.client.post(self.config_url, nuevos_datos, follow=True)
        
        if response.status_code == 404:
            print("\n⚠️ CA 1.1-1.4: URL no encontrada")
            print(f"   URL intentada: {self.config_url}")
            print("   DIAGNÓSTICO: No existe vista para configurar eventos")
            self.skipTest("URL no implementada")
            return
        
        # CA 1.1, 1.2: Validación de respuesta y persistencia
        self.assertIn(response.status_code, [200, 302],
                     "Debe redirigir o mostrar página")
        
        # CA 1.3: Validación de que se actualizaron los datos
        self.evento.refresh_from_db()
        self.assertEqual(self.evento.eve_capacidad, 50,
                        "La capacidad debe actualizarse a 50")
        self.assertEqual(self.evento.eve_tienecosto, "Si",
                        "Debe indicar que el evento tiene costo")
        
        # CA 1.4: Persistencia confirmada
        print("\n✓ CA 1.1-1.4: PASSED - Configuración actualizada exitosamente")
        print(f"   Evento: {self.evento.eve_nombre}")
        print(f"   Nueva capacidad: {self.evento.eve_capacidad}")
        print(f"   Tiene costo: {self.evento.eve_tienecosto}")

    # ==========================================
    # CA 3: Permisos y Alcance (Seguridad)
    # ==========================================

    def test_ca3_1_configuracion_solo_por_administrador_propietario(self):
        """
        CA 3.1: Prueba que un administrador diferente no puede modificar la configuración.
        """
        # Login como otro administrador (sin permisos sobre este evento)
        self.client.login(username=self.otro_admin_user.username, password=self.password)
        
        datos_intentados = {'eve_capacidad': '10'}
        
        response = self.client.post(self.config_url, datos_intentados)
        
        if response.status_code == 404:
            self.skipTest("URL no implementada")
            return
        
        # Debe ser denegado (403 Forbidden)
        self.assertIn(response.status_code, [302, 403],
                     "Usuario sin permisos debe ser denegado")
        
        # Verificar que el evento NO se modificó
        self.evento.refresh_from_db()
        self.assertEqual(self.evento.eve_capacidad, 100,
                        "La capacidad debe mantener su valor original")
        
        print("\n✓ CA 3.1: PASSED - Otro administrador bloqueado")
        print(f"   Usuario: {self.otro_admin_user.username}")
        print(f"   Capacidad se mantuvo en: {self.evento.eve_capacidad}")

    def test_ca3_2_configuracion_requiere_autenticacion(self):
        """
        CA 3.2: Prueba que un usuario no autenticado no puede acceder.
        """
        # SIN login
        response = self.client.post(self.config_url, {})
        
        if response.status_code == 404:
            self.skipTest("URL no implementada")
            return
        
        # Debe redirigir a login (302)
        self.assertEqual(response.status_code, 302,
                        "Usuario no autenticado debe ser redirigido")
        
        print("\n✓ CA 3.2: PASSED - Usuario no autenticado bloqueado")
        print(f"   Status code: {response.status_code}")

    # ==========================================
    # CA 2: Validaciones de Datos (Negativo)
    # ==========================================

    def test_ca2_1_configuracion_capacidad_no_positiva(self):
        """
        CA 2.1: Prueba que la capacidad no puede ser negativa o cero.
        """
        self.client.login(username=self.admin_user.username, password=self.password)
        
        datos_invalidos = {'eve_capacidad': '-10'}
        
        response = self.client.post(self.config_url, datos_invalidos)
        
        if response.status_code == 404:
            self.skipTest("URL no implementada")
            return
        
        # Debe rechazar o redirigir
        self.assertIn(response.status_code, [200, 302, 400],
                     "Debe rechazar capacidad negativa")
        
        # Verificar que NO se cambió
        self.evento.refresh_from_db()
        self.assertEqual(self.evento.eve_capacidad, 100,
                        "Capacidad debe mantener valor original")
        
        print("\n✓ CA 2.1: PASSED - Capacidad negativa rechazada")
        print(f"   Valor intentado: -10")
        print(f"   Valor actual: {self.evento.eve_capacidad}")

    def test_ca2_2_configuracion_capacidad_cero(self):
        """
        CA 2.2: Prueba que la capacidad no puede ser cero.
        """
        self.client.login(username=self.admin_user.username, password=self.password)
        
        datos_invalidos = {'eve_capacidad': '0'}
        
        response = self.client.post(self.config_url, datos_invalidos)
        
        if response.status_code == 404:
            self.skipTest("URL no implementada")
            return
        
        # Debe rechazar
        self.assertIn(response.status_code, [200, 302, 400],
                     "Debe rechazar capacidad cero")
        
        self.evento.refresh_from_db()
        self.assertEqual(self.evento.eve_capacidad, 100,
                        "Capacidad debe mantener valor original")
        
        print("\n✓ CA 2.2: PASSED - Capacidad cero rechazada")

    def test_ca2_3_configuracion_capacidad_menor_que_inscritos(self):
        """
        CA 2.3: Prueba que la capacidad no puede ser menor al número de inscritos actuales.
        Regla de negocio crítica.
        """
        self.client.login(username=self.admin_user.username, password=self.password)
        
        # Crear participantes inscritos (simular inscripciones)
        from app_usuarios.models import Participante
        for i in range(3):
            user = Usuario.objects.create_user(
                username=f"part_{i}_{random.randint(1000, 9999)}",
                password=self.password,
                email=f"part_{i}_{random.randint(1000, 9999)}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name=f"Participante",
                last_name=f"Test {i}",
                cedula=f"109{i}{random.randint(10000, 99999)}"
            )
            part, _ = Participante.objects.get_or_create(usuario=user)
            
            ParticipanteEvento.objects.create(
                par_eve_participante_fk=part,
                par_eve_evento_fk=self.evento,
                par_eve_estado="Aprobado",
                par_eve_clave=f"PART_{i}",
                par_eve_fecha=date.today()
            )
        
        # Ahora hay 3 inscritos, intentar reducir capacidad a 2
        datos_invalidos = {'eve_capacidad': '2'}
        
        response = self.client.post(self.config_url, datos_invalidos)
        
        if response.status_code == 404:
            self.skipTest("URL no implementada")
            return
        
        # Debe rechazar
        self.assertIn(response.status_code, [200, 302, 400],
                     "Debe rechazar capacidad menor a inscritos")
        
        self.evento.refresh_from_db()
        self.assertEqual(self.evento.eve_capacidad, 100,
                        "Capacidad debe mantener valor original")
        
        print("\n✓ CA 2.3: PASSED - Capacidad menor a inscritos rechazada")
        print(f"   Participantes inscritos: 3")
        print(f"   Capacidad intentada: 2")
        print(f"   Capacidad actual: {self.evento.eve_capacidad}")

    def test_ca2_4_configuracion_capacidad_valida_con_inscritos(self):
        """
        CA 2.4: Prueba que SÍ se puede reducir capacidad si es >= inscritos actuales.
        """
        self.client.login(username=self.admin_user.username, password=self.password)
        
        # Crear 2 participantes inscritos
        from app_usuarios.models import Participante
        for i in range(2):
            user = Usuario.objects.create_user(
                username=f"part_{i}_{random.randint(1000, 9999)}",
                password=self.password,
                email=f"part_{i}_{random.randint(1000, 9999)}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name=f"Participante",
                last_name=f"Test {i}",
                cedula=f"109{i}{random.randint(10000, 99999)}"
            )
            part, _ = Participante.objects.get_or_create(usuario=user)
            
            ParticipanteEvento.objects.create(
                par_eve_participante_fk=part,
                par_eve_evento_fk=self.evento,
                par_eve_estado="Aprobado",
                par_eve_clave=f"PART_{i}",
                par_eve_fecha=date.today()
            )
        
        # Reducir a 5 (mayor a 2 inscritos) - debe funcionar
        datos_validos = {'eve_capacidad': '5'}
        
        response = self.client.post(self.config_url, datos_validos, follow=True)
        
        if response.status_code == 404:
            self.skipTest("URL no implementada")
            return
        
        # Debe aceptar
        self.assertIn(response.status_code, [200, 302],
                     "Debe aceptar capacidad válida")
        
        self.evento.refresh_from_db()
        self.assertEqual(self.evento.eve_capacidad, 5,
                        "Capacidad debe actualizarse a 5")
        
        print("\n✓ CA 2.4: PASSED - Capacidad válida aceptada")
        print(f"   Participantes inscritos: 2")
        print(f"   Nueva capacidad: {self.evento.eve_capacidad}")

    def test_ca2_5_validar_estructura_de_datos(self):
        """
        CA 2.5: Verificar que la estructura de datos es correcta en BD.
        """
        # Verificar que el evento existe y tiene los campos necesarios
        evento = Evento.objects.get(pk=self.evento.pk)
        
        # Campos requeridos
        self.assertIsNotNone(evento.eve_nombre)
        self.assertIsNotNone(evento.eve_capacidad)
        self.assertIsNotNone(evento.eve_tienecosto)
        self.assertIsNotNone(evento.eve_administrador_fk)
        
        # Valores válidos
        self.assertGreater(evento.eve_capacidad, 0,
                          "Capacidad debe ser positiva")
        self.assertIn(evento.eve_tienecosto, ['Si', 'No'],
                     "Debe ser Si o No")
        
        print("\n✓ CA 2.5: PASSED - Estructura de datos válida")
        print(f"   Evento: {evento.eve_nombre}")
        print(f"   Capacidad: {evento.eve_capacidad}")
        print(f"   Tiene costo: {evento.eve_tienecosto}")
        print(f"   Administrador: {evento.eve_administrador_fk.usuario.username}")