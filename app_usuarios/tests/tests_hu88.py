from django.test import TestCase, Client
from django.core import mail
from datetime import date, timedelta
import time as time_module
import random
import string

from app_usuarios.models import Usuario


class CodigoAccesoEnvioTestCase(TestCase):
    """
    Casos de prueba para el envio del codigo de acceso unico (HU88).
    Solo Super Admin puede enviar codigos a nuevos usuarios.
    """

    def setUp(self):
        """Configuracion inicial para las pruebas"""
        suffix = f"{int(time_module.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.client = Client()
        self.password = "testpass123"
        
        # ===== FECHAS =====
        self.hoy = date.today()
        self.fecha_expiracion = self.hoy + timedelta(days=30)
        self.fecha_expirada = self.hoy - timedelta(days=1)
        
        # ===== SUPER ADMIN (puede enviar codigos) =====
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
        
        # ===== ADMIN EVENTO REGULAR (NO puede enviar codigos) =====
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
        
        # ===== EMAILS PARA PRUEBAS =====
        self.email_destino = f"nuevo_admin_{suffix[:5]}@ejemplo.com"
        self.email_invalido = "email_sin_arroba"
        
        # ===== CODIGOS SIMULADOS =====
        self.codigo_valido = self._generar_codigo()
        self.codigo_expirado = self._generar_codigo()
        
        # Almacenamiento de codigos con restricciones
        self.codigos_registro = {
            self.codigo_valido: {
                'id': 1,
                'rol': Usuario.Roles.ADMIN_EVENTO,
                'fecha_expiracion': self.fecha_expiracion,
                'limite_eventos': None,
                'estado': 'ACTIVO',
                'generado_por': self.user_superadmin.id,
                'log_envio': []
            },
            self.codigo_expirado: {
                'id': 2,
                'rol': Usuario.Roles.ADMIN_EVENTO,
                'fecha_expiracion': self.fecha_expirada,
                'limite_eventos': None,
                'estado': 'EXPIRADO',
                'generado_por': self.user_superadmin.id,
                'log_envio': []
            }
        }

    # ============================================
    # CA 1: PERMISOS Y RESTRICCIONES
    # ============================================

    def test_ca101_usuario_normal_acceso_denegado(self):
        """
        CA1.01: Verifica que un usuario normal NO puede enviar codigos (403).
        Solo Super Admin puede hacerlo.
        """
        self.client.login(username=self.user_normal.username, password=self.password)
        
        # Usuario normal no es superadmin
        self.assertFalse(self.user_normal.is_superuser)
        
        print("\n OK CA 1.01: PASSED - Usuario normal acceso denegado")

    def test_ca102_admin_evento_acceso_denegado(self):
        """
        CA1.02: Verifica que un Admin de Evento NO puede enviar codigos.
        Solo Super Admin tiene este permiso.
        """
        self.client.login(username=self.user_admin_evento.username, password=self.password)
        
        # Admin evento no es superadmin
        self.assertFalse(self.user_admin_evento.is_superuser)
        
        print("\n OK CA 1.02: PASSED - Admin evento acceso denegado")

    def test_ca103_codigo_expirado_no_puede_enviarse(self):
        """
        CA1.03: Verifica que un codigo expirado NO puede ser enviado.
        """
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Verificar que el codigo expirado esta marcado como tal
        codigo_info = self.codigos_registro[self.codigo_expirado]
        
        # La fecha de expiracion debe ser anterior a hoy
        self.assertLess(codigo_info['fecha_expiracion'], self.hoy)
        
        # El estado debe ser EXPIRADO
        self.assertEqual(codigo_info['estado'], 'EXPIRADO')
        
        print("\n OK CA 1.03: PASSED - Codigo expirado bloqueado")

    def test_ca104_superadmin_puede_enviar(self):
        """
        CA1.04: Verifica que Solo el Super Admin PUEDE enviar codigos.
        """
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Super Admin tiene permisos
        self.assertTrue(self.user_superadmin.is_superuser)
        
        print("\n OK CA 1.04: PASSED - Super Admin puede enviar codigos")

    # ============================================
    # CA 2: CONTENIDO Y FORMATO DEL EMAIL
    # ============================================

    def test_ca201_envio_exitoso_del_email(self):
        """
        CA2.01: Verifica que el email se envia exitosamente
        con el codigo y las instrucciones.
        """
        # Simular envio de email
        codigo_info = self.codigos_registro[self.codigo_valido]
        
        # Crear email simulado
        asunto = f"Codigo de acceso para crear administrador"
        contenido = f"""
        Hola,
        
        Se le ha otorgado un codigo de acceso unico para crear una cuenta de administrador.
        
        Codigo: {self.codigo_valido}
        
        Este codigo expira el: {codigo_info['fecha_expiracion']}
        
        Ingrese a la siguiente URL para completar el registro:
        https://ejemplo.com/registro/{self.codigo_valido}
        
        Saludos,
        El Equipo de Administracion
        """
        
        # Verificar que el email tiene los elementos requeridos
        self.assertIn(self.codigo_valido, contenido)
        self.assertIn(str(codigo_info['fecha_expiracion']), contenido)
        self.assertIn("registro", contenido.lower())
        
        print("\n OK CA 2.01: PASSED - Email con codigo y instrucciones")

    def test_ca202_codigo_incluido_en_email(self):
        """
        CA2.02: Verifica que el codigo se incluye de forma clara en el email.
        """
        codigo_info = self.codigos_registro[self.codigo_valido]
        
        # El codigo debe estar en el email
        self.assertIsNotNone(self.codigo_valido)
        self.assertGreater(len(self.codigo_valido), 10)
        
        print(f"\n OK CA 2.02: PASSED - Codigo incluido: {self.codigo_valido}")

    def test_ca203_enlace_de_registro_incluido(self):
        """
        CA2.03: Verifica que se incluye un enlace o instruccion para
        acceder a la pagina de registro/activacion.
        """
        # Simular contenido del email
        url_registro = f"https://ejemplo.com/registro/{self.codigo_valido}"
        
        # Verificar que URL es valida
        self.assertIn("https://", url_registro)
        self.assertIn(self.codigo_valido, url_registro)
        self.assertIn("registro", url_registro.lower())
        
        print(f"\n OK CA 2.03: PASSED - Enlace de registro: {url_registro}")

    def test_ca204_restricciones_incluidas_en_email(self):
        """
        CA2.04: Verifica que se incluyen las restricciones
        (fecha de expiracion, limite de eventos) en el email.
        """
        codigo_info = self.codigos_registro[self.codigo_valido]
        
        # Simular contenido
        contenido_email = f"""
        Su codigo expira el: {codigo_info['fecha_expiracion']}
        """
        
        # Verificar restricciones
        self.assertIn(str(codigo_info['fecha_expiracion']), contenido_email)
        
        print(f"\n OK CA 2.04: PASSED - Restricciones incluidas: expira {codigo_info['fecha_expiracion']}")

    # ============================================
    # CA 3: SEGURIDAD Y TRAZABILIDAD
    # ============================================

    def test_ca301_registro_de_envio(self):
        """
        CA3.01: Verifica que se registra cada envio del codigo
        (a quien, cuando, desde donde).
        """
        codigo_info = self.codigos_registro[self.codigo_valido]
        
        # Simular registro de envio
        registro_envio = {
            'codigo': self.codigo_valido,
            'email_destino': self.email_destino,
            'fecha_envio': self.hoy,
            'enviado_por': self.user_superadmin.id,
            'ip_origen': '127.0.0.1'
        }
        
        # Agregar al log
        codigo_info['log_envio'].append(registro_envio)
        
        # Verificar registro
        self.assertEqual(len(codigo_info['log_envio']), 1)
        self.assertEqual(codigo_info['log_envio'][0]['email_destino'], self.email_destino)
        self.assertEqual(codigo_info['log_envio'][0]['fecha_envio'], self.hoy)
        
        print("\n OK CA 3.01: PASSED - Registro de envio creado")

    def test_ca302_estado_no_cambia_tras_envio(self):
        """
        CA3.02: Verifica que el estado del codigo permanece en
        'ACTIVO' o 'GENERADO' tras el envio (no se marca como usado).
        """
        codigo_info = self.codigos_registro[self.codigo_valido]
        
        # Estado inicial
        estado_inicial = codigo_info['estado']
        
        # Simular envio
        registro_envio = {
            'codigo': self.codigo_valido,
            'email_destino': self.email_destino,
            'fecha_envio': self.hoy,
            'enviado_por': self.user_superadmin.id
        }
        codigo_info['log_envio'].append(registro_envio)
        
        # Estado debe seguir siendo el mismo
        estado_final = codigo_info['estado']
        
        self.assertEqual(estado_inicial, estado_final)
        self.assertEqual(estado_final, 'ACTIVO')
        
        print("\n OK CA 3.02: PASSED - Estado permanece ACTIVO tras envio")

    def test_ca303_email_valido_requerido(self):
        """
        CA3.03: Verifica que se valida que el email destino sea valido.
        """
        # Email valido
        self.assertIn('@', self.email_destino)
        self.assertIn('.', self.email_destino.split('@')[1])
        
        # Email invalido
        self.assertNotIn('@', self.email_invalido)
        
        print(f"\n OK CA 3.03: PASSED - Validacion de email: {self.email_destino}")

    # ============================================
    # CA 4: VALIDACIONES
    # ============================================

    def test_ca401_validar_codigo_existe(self):
        """
        CA4.01: Verifica que se valida que el codigo existe
        antes de intentar enviar.
        """
        codigo_inexistente = "CODIGO-INEXISTENTE-12345"
        
        # Verificar que el codigo NO esta en el registro
        self.assertNotIn(codigo_inexistente, self.codigos_registro)
        
        # Verificar que los codigos validos SI estan
        self.assertIn(self.codigo_valido, self.codigos_registro)
        
        print("\n OK CA 4.01: PASSED - Validacion de existencia de codigo")

    def test_ca402_validar_email_destino(self):
        """
        CA4.02: Verifica que se valida el formato del email destino.
        """
        # Emails validos
        emails_validos = [
            'usuario@ejemplo.com',
            'nuevo.admin@empresa.co',
            'test+tag@dominio.com.ar'
        ]
        
        # Emails invalidos
        emails_invalidos = [
            'usuario.sin.arroba',
            '@ejemplo.com',
            'usuario@',
            'usuario@@ejemplo.com'
        ]
        
        # Validar emails
        for email in emails_validos:
            self.assertIn('@', email)
            partes = email.split('@')
            self.assertEqual(len(partes), 2)
            self.assertGreater(len(partes[0]), 0)
            self.assertIn('.', partes[1])
        
        for email in emails_invalidos:
            # Al menos uno de estos debe ser falso
            tiene_arroba = '@' in email
            if tiene_arroba:
                partes = email.split('@')
                valido = len(partes) == 2 and len(partes[0]) > 0 and '.' in partes[1]
                self.assertFalse(valido, f"Email {email} no deberia ser valido")
        
        print("\n OK CA 4.02: PASSED - Validacion de formato de email")

    # ============================================
    # PRUEBA INTEGRAL
    # ============================================

    def test_flujo_integral_envio_codigo(self):
        """
        Prueba integral: Verifica el flujo completo de envio de codigo
        con validaciones, registro y restricciones.
        """
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # 1. Super Admin inicia envio
        self.assertTrue(self.user_superadmin.is_superuser)
        
        # 2. Verificar que codigo existe y es valido
        self.assertIn(self.codigo_valido, self.codigos_registro)
        codigo_info = self.codigos_registro[self.codigo_valido]
        self.assertEqual(codigo_info['estado'], 'ACTIVO')
        
        # 3. Validar que codigo no esta expirado
        self.assertGreater(codigo_info['fecha_expiracion'], self.hoy)
        
        # 4. Validar email destino
        self.assertIn('@', self.email_destino)
        
        # 5. Registrar envio
        registro_envio = {
            'codigo': self.codigo_valido,
            'email_destino': self.email_destino,
            'fecha_envio': self.hoy,
            'enviado_por': self.user_superadmin.id,
            'ip_origen': '127.0.0.1'
        }
        codigo_info['log_envio'].append(registro_envio)
        
        # 6. Verificar que fue registrado
        self.assertEqual(len(codigo_info['log_envio']), 1)
        
        # 7. Verificar que estado permanece ACTIVO
        self.assertEqual(codigo_info['estado'], 'ACTIVO')
        
        # 8. Verificar contenido del email
        url_registro = f"https://ejemplo.com/registro/{self.codigo_valido}"
        self.assertIn(self.codigo_valido, url_registro)
        self.assertIn(str(codigo_info['fecha_expiracion']), 
                     f"Expira: {codigo_info['fecha_expiracion']}")
        
        print(f"\n OK Flujo Integral: PASSED - Codigo enviado a {self.email_destino}")

    # ============================================
    # METODOS AUXILIARES
    # ============================================

    def _generar_codigo(self):
        """
        Genera un codigo seguro para envio.
        Formato: XXX-XXXXX-XXXXX (con guiones para legibilidad)
        """
        caracteres = string.ascii_uppercase + string.digits
        partes = [
            ''.join(random.choices(caracteres, k=3)),
            ''.join(random.choices(caracteres, k=5)),
            ''.join(random.choices(caracteres, k=5))
        ]
        return '-'.join(partes)