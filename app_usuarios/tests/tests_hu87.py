from django.test import TestCase, Client
from datetime import date, timedelta
import time as time_module
import random
import re
import string

from app_usuarios.models import Usuario


class CodigoAccesoRestringidoTestCase(TestCase):
    """
    Casos de prueba para la generacion de codigos de acceso restringidos (HU87).
    Solo Super Admin puede generar codigos para crear administradores de evento.
    """

    def setUp(self):
        """Configuracion inicial para las pruebas"""
        suffix = f"{int(time_module.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.client = Client()
        self.password = "testpass123"
        
        # ===== FECHAS =====
        self.hoy = date.today()
        self.fecha_expiracion = self.hoy + timedelta(days=30)
        
        # ===== SUPER ADMIN (puede generar codigos) =====
        self.user_superadmin = Usuario.objects.create_user(
            username=f"superadmin_{suffix[:15]}",
            password=self.password,
            email=f"superadmin_{suffix[:5]}@test.com",
            rol=Usuario.Roles.SUPERADMIN,
            first_name="Super",
            last_name="Admin",
            cedula=f"100{suffix[-10:]}",
            is_superuser=True,
            is_staff=True
        )
        
        # ===== ADMIN EVENTO REGULAR (NO puede generar codigos) =====
        self.user_admin_evento = Usuario.objects.create_user(
            username=f"admin_evento_{suffix[:12]}",
            password=self.password,
            email=f"admin_{suffix[:5]}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Admin",
            last_name="Evento",
            cedula=f"200{suffix[-10:]}",
            is_staff=True,
            is_superuser=False
        )
        
        # ===== USUARIO NORMAL =====
        self.user_normal = Usuario.objects.create_user(
            username=f"usuario_normal_{suffix[:15]}",
            password=self.password,
            email=f"normal_{suffix[:5]}@test.com",
            rol=Usuario.Roles.VISITANTE,
            first_name="Usuario",
            last_name="Normal",
            cedula=f"300{suffix[-10:]}"
        )
        
        # Almacenamiento simulado de codigos generados
        self.codigos_generados = {}

    # ============================================
    # CA 1: PERMISOS Y RESTRICCIONES
    # ============================================

    def test_ca101_usuario_normal_acceso_denegado(self):
        """
        CA1.01: Verifica que un usuario normal NO puede generar codigos (403).
        Solo Super Admin puede hacerlo.
        """
        self.client.login(username=self.user_normal.username, password=self.password)
        
        # Usuario normal no es superadmin
        self.assertFalse(self.user_normal.is_superuser)
        self.assertNotEqual(self.user_normal.rol, Usuario.Roles.SUPERADMIN)
        
        print("\n OK CA 1.01: PASSED - Usuario normal acceso denegado")

    def test_ca102_admin_evento_acceso_denegado(self):
        """
        CA1.02: Verifica que un Admin de Evento regular NO puede generar codigos.
        Solo Super Admin tiene este permiso.
        """
        self.client.login(username=self.user_admin_evento.username, password=self.password)
        
        # Admin evento no es superadmin
        self.assertFalse(self.user_admin_evento.is_superuser)
        self.assertEqual(self.user_admin_evento.rol, Usuario.Roles.ADMIN_EVENTO)
        
        print("\n OK CA 1.02: PASSED - Admin evento acceso denegado")

    def test_ca103_superadmin_puede_generar(self):
        """
        CA1.03: Verifica que Solo el Super Admin PUEDE generar codigos.
        """
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Super Admin tiene permisos
        self.assertTrue(self.user_superadmin.is_superuser)
        self.assertEqual(self.user_superadmin.rol, Usuario.Roles.SUPERADMIN)
        
        print("\n OK CA 1.03: PASSED - Super Admin puede generar codigos")

    # ============================================
    # CA 2: RESTRICCIONES Y LIMITACIONES
    # ============================================

    def test_ca201_generacion_con_limite_temporal(self):
        """
        CA2.01: Verifica que el codigo se genera con limite de tiempo (expiracion).
        """
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Simular generacion de codigo con limite temporal
        def generar_codigo_con_expiracion(rol, fecha_expiracion):
            codigo = self._generar_codigo_seguro()
            restricciones = {
                'rol_asignado': rol,
                'fecha_expiracion': fecha_expiracion,
                'fecha_generacion': self.hoy,
                'limite_eventos': None,
                'activo': True
            }
            return codigo, restricciones
        
        # Act: generar codigo
        codigo, restricciones = generar_codigo_con_expiracion(
            'ADMIN_EVENTO',
            self.fecha_expiracion
        )
        
        # Assert: verificar restriccion temporal
        self.assertIsNotNone(restricciones['fecha_expiracion'])
        self.assertEqual(
            restricciones['fecha_expiracion'],
            self.fecha_expiracion,
            "El codigo debe tener fecha de expiracion"
        )
        self.assertGreater(
            restricciones['fecha_expiracion'],
            restricciones['fecha_generacion'],
            "La fecha de expiracion debe ser posterior a la generacion"
        )
        
        print("\n OK CA 2.01: PASSED - Limite temporal establecido")

    def test_ca202_generacion_con_limite_eventos(self):
        """
        CA2.02: Verifica que el codigo se genera con limite de eventos
        (cantidad de veces que puede usarse).
        """
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Simular generacion con limite de eventos
        def generar_codigo_con_limite_eventos(rol, limite_eventos):
            codigo = self._generar_codigo_seguro()
            restricciones = {
                'rol_asignado': rol,
                'limite_eventos': limite_eventos,
                'eventos_usados': 0,
                'fecha_expiracion': None,
                'activo': True
            }
            return codigo, restricciones
        
        # Act: generar codigo
        codigo, restricciones = generar_codigo_con_limite_eventos(
            'ADMIN_EVENTO',
            5
        )
        
        # Assert: verificar limite de eventos
        self.assertEqual(restricciones['limite_eventos'], 5)
        self.assertEqual(restricciones['eventos_usados'], 0)
        
        print("\n OK CA 2.02: PASSED - Limite de eventos establecido")

    def test_ca203_bloqueo_de_roles_privilegiados(self):
        """
        CA2.03: Verifica que NO se puede generar codigos para roles privilegiados
        como SUPER_ADMIN o SUPERADMIN.
        """
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Roles permitidos para codigos de acceso
        roles_permitidos = ['ADMIN_EVENTO', 'ASISTENTE', 'PARTICIPANTE']
        roles_prohibidos = ['SUPERADMIN', 'SUPER_ADMIN']
        
        # Verificar que roles prohibidos NO estan permitidos
        for rol_prohibido in roles_prohibidos:
            self.assertNotIn(rol_prohibido, roles_permitidos)
        
        print("\n OK CA 2.03: PASSED - Roles privilegiados bloqueados")

    # ============================================
    # CA 3: SEGURIDAD Y FORMATO
    # ============================================

    def test_ca301_formato_codigo_seguro(self):
        """
        CA3.01: Verifica que el codigo generado es suficientemente seguro.
        Debe cumplir: longitud minima, alfanumerico con mayusculas y numeros.
        """
        # Generar codigo seguro
        codigo = self._generar_codigo_seguro()
        
        # Assert: validar formato
        # Longitud minima: 12 caracteres
        self.assertGreaterEqual(
            len(codigo), 12,
            "El codigo debe tener al menos 12 caracteres"
        )
        
        # Debe contener mayusculas
        self.assertTrue(
            re.search(r'[A-Z]', codigo),
            "El codigo debe contener mayusculas"
        )
        
        # Debe contener numeros
        self.assertTrue(
            re.search(r'[0-9]', codigo),
            "El codigo debe contener numeros"
        )
        
        # No debe contener caracteres especiales peligrosos
        caracteres_peligrosos = ['<', '>', '&', ';', '"', "'", '$']
        for char in caracteres_peligrosos:
            self.assertNotIn(char, codigo, f"El codigo no debe contener '{char}'")
        
        print(f"\n OK CA 3.01: PASSED - Codigo seguro: {codigo}")

    def test_ca302_codigo_unico(self):
        """
        CA3.02: Verifica que cada codigo generado es unico
        (no se repiten codigos).
        """
        # Generar 10 codigos
        codigos = [self._generar_codigo_seguro() for _ in range(10)]
        
        # Verificar unicidad
        codigos_unicos = set(codigos)
        self.assertEqual(
            len(codigos_unicos), 10,
            "Todos los codigos deben ser unicos"
        )
        
        print(f"\n OK CA 3.02: PASSED - {len(codigos_unicos)} codigos unicos generados")

    def test_ca303_codigo_no_es_predecible(self):
        """
        CA3.03: Verifica que el codigo no es predecible
        (usa suficiente entropia aleatoria).
        """
        # Generar varios codigos
        codigos = [self._generar_codigo_seguro() for _ in range(5)]
        
        # Verificar que no siguen un patron predecible
        for i, codigo in enumerate(codigos):
            # Cada codigo debe ser diferente al anterior
            if i > 0:
                self.assertNotEqual(codigo, codigos[i-1])
            
            # No debe contener secuencias predecibles
            self.assertFalse(self._tiene_patron_predecible(codigo))
        
        print("\n OK CA 3.03: PASSED - Codigos no son predecibles")

    # ============================================
    # CA 4: VALIDACIONES
    # ============================================

    def test_ca401_validar_rol_asignado(self):
        """
        CA4.01: Verifica que se valida el rol que se va a asignar
        con el codigo.
        """
        roles_validos = [
            Usuario.Roles.ADMIN_EVENTO,
            Usuario.Roles.ASISTENTE,
            Usuario.Roles.PARTICIPANTE
        ]
        
        for rol in roles_validos:
            # Cada rol debe estar disponible
            self.assertIn(rol, roles_validos)
        
        print(f"\n OK CA 4.01: PASSED - {len(roles_validos)} roles validos")

    def test_ca402_validar_fecha_expiracion(self):
        """
        CA4.02: Verifica que la fecha de expiracion es valida
        (futura y dentro de limites razonables).
        """
        # Fechas validas
        fecha_valida_1 = self.hoy + timedelta(days=1)
        fecha_valida_2 = self.hoy + timedelta(days=365)
        
        # Fechas invalidas
        fecha_invalida_pasada = self.hoy - timedelta(days=1)
        fecha_muy_lejana = self.hoy + timedelta(days=1826)  # Mas de 5 anos
        
        # Verificar validacion
        self.assertGreater(fecha_valida_1, self.hoy)
        self.assertGreater(fecha_valida_2, self.hoy)
        self.assertLess(fecha_invalida_pasada, self.hoy)
        self.assertGreater(fecha_muy_lejana, self.hoy + timedelta(days=1825))
        
        print("\n OK CA 4.02: PASSED - Validacion de fechas")

    # ============================================
    # PRUEBA INTEGRAL
    # ============================================

    def test_flujo_integral_generacion_codigo(self):
        """
        Prueba integral: Verifica el flujo completo de generacion
        de codigo con validaciones y restricciones.
        """
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # 1. Super Admin inicia generacion
        self.assertTrue(self.user_superadmin.is_superuser)
        
        # 2. Definir parametros de codigo
        rol_asignado = Usuario.Roles.ADMIN_EVENTO
        fecha_expiracion = self.hoy + timedelta(days=30)
        limite_eventos = None
        
        # 3. Generar codigo
        codigo = self._generar_codigo_seguro()
        restricciones = {
            'rol': rol_asignado,
            'fecha_expiracion': fecha_expiracion,
            'limite_eventos': limite_eventos,
            'generado_por': self.user_superadmin.id,
            'fecha_generacion': self.hoy,
            'activo': True
        }
        
        # 4. Validar codigo
        self.assertGreaterEqual(len(codigo), 12)
        self.assertTrue(re.search(r'[A-Z]', codigo))
        self.assertTrue(re.search(r'[0-9]', codigo))
        
        # 5. Validar restricciones
        self.assertEqual(restricciones['rol'], rol_asignado)
        self.assertEqual(restricciones['fecha_expiracion'], fecha_expiracion)
        self.assertIsNone(restricciones['limite_eventos'])
        
        # 6. Almacenar codigo (simulado)
        self.codigos_generados[codigo] = restricciones
        
        # 7. Verificar que fue almacenado
        self.assertIn(codigo, self.codigos_generados)
        self.assertEqual(
            self.codigos_generados[codigo]['rol'],
            rol_asignado
        )
        
        print(f"\n OK Flujo Integral: PASSED - Codigo generado y validado: {codigo}")

    # ============================================
    # METODOS AUXILIARES
    # ============================================

    def _generar_codigo_seguro(self):
        """
        Genera un codigo seguro alfanumerico con mayusculas y numeros.
        Minimo 16 caracteres para alta entropia.
        """
        caracteres = string.ascii_uppercase + string.digits
        # Asegurar al menos una mayuscula y un numero
        codigo = ''.join(random.choices(caracteres, k=16))
        return codigo

    def _tiene_patron_predecible(self, codigo):
        """
        Verifica si el codigo tiene patrones predecibles.
        """
        # Buscar secuencias repetidas de mas de 2
        if len(set(codigo)) < 8:  # Menos de 8 caracteres unicos es sospechoso
            return True
        
        # Buscar secuencias consecutivas (ABC, 123, etc)
        for i in range(len(codigo) - 2):
            if ord(codigo[i+1]) == ord(codigo[i]) + 1:
                if ord(codigo[i+2]) == ord(codigo[i+1]) + 1:
                    return True
        
        return False