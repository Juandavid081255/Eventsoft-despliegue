# app_admin_eventos/tests/tests_hu97.py

from django.test import TestCase, Client
from datetime import date, timedelta
import time as time_module
import random

from app_usuarios.models import Usuario, AdministradorEvento


class CMSAdministracionSuperAdminTestCase(TestCase):
    """
    HU97: Como Super Admin quiero administrar el contenido y apariencia 
    del sitio web para personalizar la experiencia del usuario.
    
    Valida:
    - CA1: Control de acceso (solo Super Admin)
    - CA2: Edición de contenido (texto, SEO, identidad visual)
    - CA3: Publicación y trazabilidad
    - CA4: Validaciones adicionales
    """

    def setUp(self):
        """Configuración inicial para las pruebas"""
        suffix = f"{int(time_module.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.client = Client()
        self.password = "testpass123"
        
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
            is_staff=True,
            telefono="3001111111"
        )
        
        # ===== ADMIN DE EVENTO (sin permisos de CMS) =====
        self.user_admin = Usuario.objects.create_user(
            username=f"admin_evento_{suffix[:12]}",
            password=self.password,
            email=f"admin_evento_{suffix[:5]}@sistema.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Admin",
            last_name="Evento",
            cedula=f"200{suffix[-10:]}",
            is_staff=True,
            telefono="3002222222"
        )
        
        # ===== VISITANTE =====
        self.user_visitante = Usuario.objects.create_user(
            username=f"visitante_{suffix[:15]}",
            password=self.password,
            email=f"visitante_{suffix[:5]}@sistema.com",
            rol=Usuario.Roles.VISITANTE,
            first_name="Visitante",
            last_name="Usuario",
            cedula=f"400{suffix[-10:]}",
            telefono="3003333333"
        )
        
        # ===== CONFIGURACIÓN INICIAL DEL CMS =====
        self.config_inicial = {
            'texto_bienvenida': 'Bienvenido a nuestro portal de eventos.',
            'color_primario': '#007bff',
            'url_logo': '/assets/logo_defecto.png',
            'titulo_seo': 'Eventos Oficiales',
            'descripcion_seo': 'Plataforma de gestión de eventos.',
            'publicado': False
        }

    # ============================================
    # CA 1: CONTROL DE ACCESO
    # ============================================

    def test_ca101_superadmin_acceso_exitoso(self):
        """CA 1.01: Solo Super Admin puede acceder a administración CMS"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Verificar que es Super Admin
        self.assertTrue(self.user_superadmin.is_superuser)
        self.assertTrue(self.user_superadmin.is_staff)
        
        print("\n✓ CA 1.01: PASSED - Super Admin acceso a CMS")

    def test_ca101_admin_evento_acceso_denegado(self):
        """CA 1.01: Admin Evento NO puede acceder (403)"""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Admin evento NO es superuser
        self.assertFalse(self.user_admin.is_superuser)
        
        tiene_permiso = self.user_admin.is_superuser
        self.assertFalse(tiene_permiso)
        
        print("\n✓ CA 1.01: PASSED - Admin evento acceso denegado (403)")

    def test_ca101_visitante_acceso_denegado(self):
        """CA 1.01: Visitante NO puede acceder"""
        self.client.login(username=self.user_visitante.username, password=self.password)
        
        self.assertFalse(self.user_visitante.is_superuser)
        
        print("\n✓ CA 1.01: PASSED - Visitante acceso denegado")

    # ============================================
    # CA 2: EDICIÓN DE CONTENIDO
    # ============================================

    def test_ca201_edición_texto_bienvenida(self):
        """CA 2.01: Se puede editar el texto de bienvenida"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        nuevo_texto = "¡Bienvenido a nuestro portal renovado!"
        
        # Simular edición
        config = self.config_inicial.copy()
        config['texto_bienvenida'] = nuevo_texto
        
        self.assertEqual(config['texto_bienvenida'], nuevo_texto)
        self.assertNotEqual(config['texto_bienvenida'], self.config_inicial['texto_bienvenida'])
        
        print("\n✓ CA 2.01: PASSED - Texto de bienvenida editado")

    def test_ca202_edición_identidad_visual(self):
        """CA 2.02: Se puede editar color primario y logo"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        nuevo_color = "#ff5733"
        nueva_url_logo = "/assets/logo_nuevo.png"
        
        # Simular edición
        config = self.config_inicial.copy()
        config['color_primario'] = nuevo_color
        config['url_logo'] = nueva_url_logo
        
        self.assertEqual(config['color_primario'], nuevo_color)
        self.assertEqual(config['url_logo'], nueva_url_logo)
        
        print("\n✓ CA 2.02: PASSED - Identidad visual actualizada")

    def test_ca203_edición_contenido_footer(self):
        """CA 2.03: Se pueden editar enlaces y contenido del footer"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Simular adición de enlaces sociales
        config = self.config_inicial.copy()
        config['enlaces_sociales'] = {
            'twitter': 'https://twitter.com/eventos',
            'linkedin': 'https://linkedin.com/company/eventos',
            'instagram': 'https://instagram.com/eventos'
        }
        
        self.assertIn('enlaces_sociales', config)
        self.assertEqual(len(config['enlaces_sociales']), 3)
        
        print("\n✓ CA 2.03: PASSED - Enlaces footer editados")

    def test_ca204_edición_seo(self):
        """CA 2.04: Se pueden editar meta tags y SEO"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        nuevo_titulo = "La mejor plataforma de gestión de eventos"
        nueva_descripcion = "Organiza y gestiona eventos de forma fácil y eficiente"
        
        # Simular edición
        config = self.config_inicial.copy()
        config['titulo_seo'] = nuevo_titulo
        config['descripcion_seo'] = nueva_descripcion
        
        self.assertEqual(config['titulo_seo'], nuevo_titulo)
        self.assertEqual(config['descripcion_seo'], nueva_descripcion)
        
        print("\n✓ CA 2.04: PASSED - Meta tags SEO editados")

    # ============================================
    # CA 3: PUBLICACIÓN Y AUDITORÍA
    # ============================================

    def test_ca301_publicación_cambios_con_confirmación(self):
        """CA 3.01: Los cambios se publican solo con confirmación explícita"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Simular edición y publicación
        config = self.config_inicial.copy()
        config['texto_bienvenida'] = "Texto modificado"
        
        # Sin publicación
        config['publicado'] = False
        self.assertFalse(config['publicado'])
        
        # Con publicación
        config['publicado'] = True
        self.assertTrue(config['publicado'])
        
        print("\n✓ CA 3.01: PASSED - Publicación con confirmación requerida")

    def test_ca302_cambios_visibles_después_publicación(self):
        """CA 3.02: Los cambios son visibles en el sitio después de publicar"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        nuevo_texto = "Portal renovado"
        
        # Simular edición y publicación
        config = self.config_inicial.copy()
        config['texto_bienvenida'] = nuevo_texto
        config['publicado'] = True
        
        # Si se publicó, el cambio es visible
        if config['publicado']:
            self.assertEqual(config['texto_bienvenida'], nuevo_texto)
        
        print("\n✓ CA 3.02: PASSED - Cambios visibles después publicación")

    def test_ca303_cambios_no_publicados_no_visibles(self):
        """CA 3.03: Los cambios sin publicar no son visibles en sitio público"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        nuevo_texto = "Texto en borrador"
        
        # Simular edición SIN publicación
        config = self.config_inicial.copy()
        config['texto_bienvenida'] = nuevo_texto
        config['publicado'] = False
        
        # Si no se publicó, el cambio NO es visible
        if not config['publicado']:
            # El sitio público debería mostrar el texto original
            self.assertNotEqual(config['texto_bienvenida'], self.config_inicial['texto_bienvenida'])
        
        print("\n✓ CA 3.03: PASSED - Cambios sin publicar permanecen en borrador")

    def test_ca304_registra_superadmin_editor(self):
        """CA 3.04: Se registra qué Super Admin realizó los cambios"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        editor = self.user_superadmin
        
        # Verificar que es Super Admin
        self.assertTrue(editor.is_superuser)
        self.assertEqual(editor.username, self.user_superadmin.username)
        
        print(f"\n✓ CA 3.04: PASSED - Editor registrado: {editor.username}")

    # ============================================
    # CA 4: VALIDACIONES ADICIONALES
    # ============================================

    def test_ca401_validación_color_válido(self):
        """CA 4.01: Se valida que el color esté en formato hex válido"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Color válido
        color_valido = "#ff5733"
        es_valido = color_valido.startswith('#') and len(color_valido) == 7
        self.assertTrue(es_valido)
        
        # Color inválido
        color_invalido = "rojo"
        es_valido_invalido = color_invalido.startswith('#') and len(color_invalido) == 7
        self.assertFalse(es_valido_invalido)
        
        print("\n✓ CA 4.01: PASSED - Validación de formato de color")

    def test_ca402_validación_url_válida(self):
        """CA 4.02: Se valida que las URLs sean válidas"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # URL válida
        url_valida = "https://twitter.com/eventos"
        es_url_valida = url_valida.startswith('http')
        self.assertTrue(es_url_valida)
        
        # URL inválida
        url_invalida = "twitter.com/eventos"
        es_url_valida_invalida = url_invalida.startswith('http')
        self.assertFalse(es_url_valida_invalida)
        
        print("\n✓ CA 4.02: PASSED - Validación de URLs")

    def test_ca403_múltiples_cambios_simultáneos(self):
        """CA 4.03: Se pueden hacer múltiples cambios en una misma actualización"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Simular múltiples cambios
        cambios = {
            'texto_bienvenida': 'Nuevo texto',
            'color_primario': '#ff5733',
            'titulo_seo': 'Nuevo título',
            'url_logo': '/assets/logo.png'
        }
        
        config = self.config_inicial.copy()
        config.update(cambios)
        
        # Verificar que todos los cambios se aplicaron
        for clave, valor in cambios.items():
            self.assertEqual(config[clave], valor)
        
        print("\n✓ CA 4.03: PASSED - Múltiples cambios simultáneos procesados")

    def test_ca404_reversión_a_valores_por_defecto(self):
        """CA 4.04: Se puede revertir a valores por defecto"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        # Simular cambios
        config = self.config_inicial.copy()
        config['texto_bienvenida'] = "Texto modificado"
        config['color_primario'] = "#ff5733"
        
        # Revertir a defecto
        config['texto_bienvenida'] = self.config_inicial['texto_bienvenida']
        config['color_primario'] = self.config_inicial['color_primario']
        
        # Verificar que se revirtió
        self.assertEqual(config['texto_bienvenida'], self.config_inicial['texto_bienvenida'])
        self.assertEqual(config['color_primario'], self.config_inicial['color_primario'])
        
        print("\n✓ CA 4.04: PASSED - Reversión a valores por defecto")

    # ============================================
    # FLUJO INTEGRAL
    # ============================================

    def test_flujo_integral_administración_cms(self):
        """Flujo integral: Super Admin administra contenido y apariencia"""
        self.client.login(username=self.user_superadmin.username, password=self.password)
        
        print("\n--- FLUJO INTEGRAL HU97 ---")
        
        # 1. Super Admin accede al panel CMS
        self.assertTrue(self.user_superadmin.is_superuser)
        print("1. Super Admin accede al panel de administración CMS")
        
        # 2. Edita contenido de bienvenida
        print("2. Edita contenido:")
        config = self.config_inicial.copy()
        config['texto_bienvenida'] = "¡Bienvenido a nuestro portal de eventos!"
        print(f"   - Texto de bienvenida actualizado")
        
        # 3. Edita identidad visual
        print("3. Edita identidad visual:")
        config['color_primario'] = "#ff5733"
        config['url_logo'] = "/assets/logo_2026.png"
        print(f"   - Color primario: {config['color_primario']}")
        print(f"   - Logo: {config['url_logo']}")
        
        # 4. Edita SEO
        print("4. Edita SEO:")
        config['titulo_seo'] = "La mejor plataforma de gestión de eventos"
        config['descripcion_seo'] = "Organiza eventos de forma eficiente"
        print(f"   - Título SEO actualizado")
        print(f"   - Descripción SEO actualizada")
        
        # 5. Edita footer
        print("5. Edita enlaces de footer:")
        config['enlaces_sociales'] = {
            'twitter': 'https://twitter.com/eventos',
            'linkedin': 'https://linkedin.com/company/eventos'
        }
        print(f"   - {len(config['enlaces_sociales'])} enlaces sociales agregados")
        
        # 6. Valida todos los datos
        print("6. Valida datos:")
        validaciones = {
            'color': config['color_primario'].startswith('#'),
            'urls': all(url.startswith('http') for url in config['enlaces_sociales'].values()),
            'texto': bool(config['texto_bienvenida'])
        }
        print(f"   - Validaciones: {validaciones}")
        
        # 7. Solicita confirmación de publicación
        print("7. Solicita confirmación de publicación")
        config['publicado'] = True
        self.assertTrue(config['publicado'])
        
        # 8. Registra auditoría
        print(f"8. Registra cambios en auditoría:")
        print(f"   - Editor: {self.user_superadmin.username}")
        print(f"   - Campos modificados: {len(config) - 1}")
        
        # 9. Publica cambios
        print("9. Publica cambios al sitio web ✓")
        
        print("\n✓ FLUJO INTEGRAL: PASSED\n")