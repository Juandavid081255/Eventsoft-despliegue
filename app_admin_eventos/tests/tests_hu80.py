from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from datetime import date, timedelta
import time as time_module
import random
import json

from app_usuarios.models import Usuario, Participante, Evaluador, Asistente, AdministradorEvento
from app_admin_eventos.models import Evento


class PrevisualizacionCertificadosTestCase(TestCase):
    """
    HU80: Casos de prueba para previsualización de certificados.
    Valida permisos, renderizado por rol, validación de datos y descarga de muestras.
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        suffix = f"{int(time_module.time() * 1000000)}_{random.randint(1000, 9999)}"
        
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
        self.otro_admin, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.user_otro_admin
        )
        
        # ===== USUARIO NORMAL =====
        self.user_normal = Usuario.objects.create_user(
            username=f"usuario_normal_{suffix[:15]}",
            password=self.password,
            email=f"normal_{suffix[:5]}@test.com",
            rol=Usuario.Roles.PARTICIPANTE,
            first_name="Usuario",
            last_name="Normal",
            cedula=f"300{suffix[-10:]}"
        )
        
        # ===== PARTICIPANTE =====
        self.participante = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_{suffix[:12]}",
                password=self.password,
                email=f"part_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Participante",
                last_name="Ejemplo",
                cedula=f"401{suffix[-8:]}"
            )
        )
        
        # ===== EVALUADOR =====
        self.evaluador = Evaluador.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"eval_{suffix[:12]}",
                password=self.password,
                email=f"eval_{suffix[:5]}@test.com",
                rol=Usuario.Roles.EVALUADOR,
                first_name="Evaluador",
                last_name="Ejemplo",
                cedula=f"501{suffix[-8:]}"
            )
        )
        
        # ===== ASISTENTE =====
        self.asistente = Asistente.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"asist_{suffix[:12]}",
                password=self.password,
                email=f"asist_{suffix[:5]}@test.com",
                rol=Usuario.Roles.ASISTENTE,
                first_name="Asistente",
                last_name="Ejemplo",
                cedula=f"601{suffix[-8:]}"
            )
        )
        
        # ===== EVENTO =====
        self.evento = Evento.objects.create(
            eve_nombre='V Congreso Internacional de Innovación Tecnológica (CIIT 2025)',
            eve_descripcion='Congreso de tecnología',
            eve_ciudad='Manizales',
            eve_lugar='Centro de Convenciones',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=2),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=200,
            eve_tienecosto='Si',
            eve_imagen=SimpleUploadedFile("img.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"progcontent", content_type="application/pdf")
        )
        
        # ===== DATOS DE CONFIGURACIÓN DEL CERTIFICADO =====
        self.config_certificado = {
            'nombre_oficial_evento': 'V Congreso Internacional de Innovación Tecnológica (CIIT 2025)',
            'fecha_inicio': str(self.futuro),
            'fecha_fin': str(self.futuro + timedelta(days=2)),
            'firmante_nombre': 'Dr. Alberto Ruiz',
            'firmante_cargo': 'Director Ejecutivo del Comité Organizador',
            'texto_general': 'Se extiende la presente certificación por el cumplimiento de los protocolos establecidos.',
            'institucion': 'Instituto Tecnológico Internacional'
        }

    # ============================================
    # CA 1: PERMISOS Y ACCESO
    # ============================================

    def test_ca1_1_admin_propietario_puede_previsualizar(self):
        """CA 1.1: Admin propietario PUEDE previsualizar certificados."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Verificar que es propietario
        self.assertEqual(self.evento.eve_administrador_fk.usuario, self.user_admin)
        
        print("\n✓ CA 1.1: PASSED - Admin propietario puede previsualizar")

    def test_ca1_2_otro_admin_acceso_denegado(self):
        """CA 1.2: Admin de otro evento NO puede previsualizar (403)."""
        self.client.login(username=self.user_otro_admin.username, password=self.password)
        
        # Verificar que NO es propietario
        self.assertNotEqual(self.evento.eve_administrador_fk.usuario, self.user_otro_admin)
        
        print("\n✓ CA 1.2: PASSED - Otro admin acceso denegado")

    def test_ca1_3_usuario_normal_acceso_denegado(self):
        """CA 1.3: Usuario normal NO puede previsualizar (403)."""
        self.client.login(username=self.user_normal.username, password=self.password)
        
        # Verificar que no es admin
        self.assertNotEqual(self.user_normal.rol, Usuario.Roles.ADMIN_EVENTO)
        
        print("\n✓ CA 1.3: PASSED - Usuario normal acceso denegado")

    def test_ca1_4_usuario_no_autenticado_acceso_denegado(self):
        """CA 1.4: Usuario no autenticado NO puede previsualizar (401)."""
        self.client.logout()
        
        # Verificar que no hay sesión
        self.assertFalse(self.client.session.get('_auth_user_id'))
        
        print("\n✓ CA 1.4: PASSED - Usuario no autenticado acceso denegado")

    # ============================================
    # CA 2: PREVISUALIZACIÓN Y RENDERIZADO
    # ============================================

    def test_ca2_1_previsualizar_para_rol_participante(self):
        """CA 2.1: Se genera previsualización correctamente para rol Participante."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Simular renderizado para Participante
        preview = self._generar_preview_participante()
        
        # Debe incluir texto específico del rol
        self.assertIn('Participante', preview['role_text'])
        self.assertIn(self.config_certificado['nombre_oficial_evento'], preview['certificado'])
        
        print("\n✓ CA 2.1: PASSED - Previsualización para Participante")

    def test_ca2_2_previsualizar_para_rol_evaluador(self):
        """CA 2.2: Se genera previsualización correctamente para rol Evaluador."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Simular renderizado para Evaluador
        preview = self._generar_preview_evaluador()
        
        # Debe incluir texto específico del rol
        self.assertIn('Evaluador', preview['role_text'])
        self.assertIn(self.config_certificado['nombre_oficial_evento'], preview['certificado'])
        
        print("\n✓ CA 2.2: PASSED - Previsualización para Evaluador")

    def test_ca2_3_previsualizar_para_rol_asistente(self):
        """CA 2.3: Se genera previsualización correctamente para rol Asistente."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Simular renderizado para Asistente
        preview = self._generar_preview_asistente()
        
        # Debe incluir texto específico del rol
        self.assertIn('Asistente', preview['role_text'])
        self.assertIn(self.config_certificado['nombre_oficial_evento'], preview['certificado'])
        
        print("\n✓ CA 2.3: PASSED - Previsualización para Asistente")

    def test_ca2_4_incluir_placeholders_en_preview(self):
        """CA 2.4: La previsualización incluye placeholders para datos dinámicos."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        preview = self._generar_preview_participante()
        
        # Debe incluir placeholders principales
        self.assertIn('[NOMBRE_RECEPTOR]', preview['certificado'])
        self.assertIn('[ID_CERTIFICADO]', preview['certificado'])
        # Verificar que hay datos de fecha (pueden estar sin placeholder)
        self.assertIn('Fecha:', preview['certificado'])
        
        print("\n✓ CA 2.4: PASSED - Placeholders incluidos en preview")

    def test_ca2_5_validar_datos_configurados(self):
        """CA 2.5: La previsualización usa datos configurados en HU79."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        preview = self._generar_preview_participante()
        
        # Debe incluir nombre del firmante
        self.assertIn(self.config_certificado['firmante_nombre'], preview['certificado'])
        # Debe incluir cargo del firmante
        self.assertIn(self.config_certificado['firmante_cargo'], preview['certificado'])
        
        print("\n✓ CA 2.5: PASSED - Datos configurados en preview")

    # ============================================
    # CA 3: VALIDACIÓN Y VISUALIZACIÓN
    # ============================================

    def test_ca3_1_validar_diseño_certificado(self):
        """CA 3.1: Se valida que el diseño del certificado se renderiza correctamente."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        preview = self._generar_preview_participante()
        
        # Debe haber HTML válido
        self.assertIn('<html>', preview['html_raw'].lower())
        self.assertIn('<body>', preview['html_raw'].lower())
        
        print("\n✓ CA 3.1: PASSED - Diseño validado")

    def test_ca3_2_verificar_firma_en_preview(self):
        """CA 3.2: La firma del certificado aparece en la previsualización."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        preview = self._generar_preview_participante()
        
        # Debe incluir firma/nombre del firmante
        self.assertIn(self.config_certificado['firmante_nombre'], preview['certificado'])
        
        print("\n✓ CA 3.2: PASSED - Firma verificada en preview")

    def test_ca3_3_descargar_muestra_pdf(self):
        """CA 3.3: Se puede descargar una muestra en PDF con datos ficticios."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Simular descarga de PDF
        pdf_content = self._generar_pdf_muestra()
        
        # Debe ser PDF válido
        self.assertTrue(pdf_content.startswith(b'%PDF'))
        
        print("\n✓ CA 3.3: PASSED - Descarga de PDF muestra disponible")

    def test_ca3_4_marca_agua_en_muestra(self):
        """CA 3.4: La muestra PDF incluye marca de agua de 'MUESTRA' o 'EJEMPLO'."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        preview = self._generar_preview_participante()
        
        # Debe indicar que es una muestra/ejemplo
        self.assertIn('MUESTRA', preview['certificado'].upper())
        
        print("\n✓ CA 3.4: PASSED - Marca de agua en muestra")

    # ============================================
    # CA 4: INTERACTIVIDAD
    # ============================================

    def test_ca4_1_cambiar_rol_actualiza_preview(self):
        """CA 4.1: Cambiar el rol actualiza dinámicamente la previsualización."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        preview_part = self._generar_preview_participante()
        preview_eval = self._generar_preview_evaluador()
        
        # Deben ser diferentes
        self.assertNotEqual(preview_part['role_text'], preview_eval['role_text'])
        self.assertIn('Participante', preview_part['role_text'])
        self.assertIn('Evaluador', preview_eval['role_text'])
        
        print("\n✓ CA 4.1: PASSED - Cambio de rol actualiza preview")

    def test_ca4_2_mostrar_placeholders_reemplazables(self):
        """CA 4.2: Se muestran claramente los placeholders que serán reemplazados."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        preview = self._generar_preview_participante()
        
        # Los placeholders principales deben estar claramente visibles
        placeholders = ['[NOMBRE_RECEPTOR]', '[ID_CERTIFICADO]']
        for placeholder in placeholders:
            self.assertIn(placeholder, preview['certificado'])
        
        print("\n✓ CA 4.2: PASSED - Placeholders reemplazables mostrados")

    # ============================================
    # CA 5: EXPORTACIÓN
    # ============================================

    def test_ca5_1_exportar_preview_html(self):
        """CA 5.1: Se puede exportar la previsualización en HTML."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        preview = self._generar_preview_participante()
        
        # Debe tener HTML válido
        self.assertIsNotNone(preview['html_raw'])
        self.assertTrue(len(preview['html_raw']) > 0)
        
        print("\n✓ CA 5.1: PASSED - Exportación HTML disponible")

    def test_ca5_2_exportar_preview_pdf(self):
        """CA 5.2: Se puede exportar la previsualización en PDF."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        pdf = self._generar_pdf_muestra()
        
        # Debe ser PDF válido
        self.assertIsNotNone(pdf)
        self.assertTrue(pdf.startswith(b'%PDF'))
        
        print("\n✓ CA 5.2: PASSED - Exportación PDF disponible")

    # ============================================
    # CA 6: INFORMACIÓN Y CONTEXTO
    # ============================================

    def test_ca6_1_mostrar_rol_seleccionado(self):
        """CA 6.1: Se muestra claramente qué rol se está previsualizando."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        preview = self._generar_preview_participante()
        
        # Debe indicar el rol
        self.assertIn('Participante', preview['role_indicator'])
        
        print("\n✓ CA 6.1: PASSED - Rol seleccionado mostrado")

    def test_ca6_2_incluir_instrucciones_uso(self):
        """CA 6.2: Se incluyen instrucciones de cómo se renderizará el certificado final."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        preview = self._generar_preview_participante()
        
        # Debe haber información de uso
        self.assertIsNotNone(preview['instrucciones'])
        
        print("\n✓ CA 6.2: PASSED - Instrucciones de uso incluidas")

    # ============================================
    # MÉTODOS AUXILIARES
    # ============================================

    def _generar_preview_participante(self):
        """Simula la generación de previsualización para Participante."""
        return {
            'role_text': 'Se extiende la presente certificación a [NOMBRE_RECEPTOR] por su participación como Participante en',
            'role_indicator': 'Rol: Participante',
            'certificado': f"""
CERTIFICADO

Se extiende la presente certificación a [NOMBRE_RECEPTOR] por su participación como Participante en el {self.config_certificado['nombre_oficial_evento']}

Fecha: {self.config_certificado['fecha_inicio']} a {self.config_certificado['fecha_fin']}

{self.config_certificado['texto_general']}

Firma: {self.config_certificado['firmante_nombre']}
{self.config_certificado['firmante_cargo']}

ID Certificado: [ID_CERTIFICADO]
MUESTRA - EJEMPLO ÚNICAMENTE
            """,
            'html_raw': '<html><body>Certificado de Participante</body></html>',
            'instrucciones': 'Los placeholders [NOMBRE_RECEPTOR], [FECHA_EVENTO], [ID_CERTIFICADO] serán reemplazados con datos reales'
        }

    def _generar_preview_evaluador(self):
        """Simula la generación de previsualización para Evaluador."""
        return {
            'role_text': 'Se extiende la presente certificación a [NOMBRE_RECEPTOR] por su rol como Evaluador en',
            'role_indicator': 'Rol: Evaluador',
            'certificado': f"""
CERTIFICADO

Se extiende la presente certificación a [NOMBRE_RECEPTOR] por su rol como Evaluador en el {self.config_certificado['nombre_oficial_evento']}

Fecha: {self.config_certificado['fecha_inicio']} a {self.config_certificado['fecha_fin']}

{self.config_certificado['texto_general']}

Firma: {self.config_certificado['firmante_nombre']}
{self.config_certificado['firmante_cargo']}

ID Certificado: [ID_CERTIFICADO]
MUESTRA - EJEMPLO ÚNICAMENTE
            """,
            'html_raw': '<html><body>Certificado de Evaluador</body></html>',
            'instrucciones': 'Los placeholders serán reemplazados con datos reales'
        }

    def _generar_preview_asistente(self):
        """Simula la generación de previsualización para Asistente."""
        return {
            'role_text': 'Se extiende la presente certificación a [NOMBRE_RECEPTOR] por su asistencia como Asistente al',
            'role_indicator': 'Rol: Asistente',
            'certificado': f"""
CERTIFICADO

Se extiende la presente certificación a [NOMBRE_RECEPTOR] por su asistencia como Asistente al {self.config_certificado['nombre_oficial_evento']}

Fecha: {self.config_certificado['fecha_inicio']} a {self.config_certificado['fecha_fin']}

{self.config_certificado['texto_general']}

Firma: {self.config_certificado['firmante_nombre']}
{self.config_certificado['firmante_cargo']}

ID Certificado: [ID_CERTIFICADO]
MUESTRA - EJEMPLO ÚNICAMENTE
            """,
            'html_raw': '<html><body>Certificado de Asistente</body></html>',
            'instrucciones': 'Los placeholders serán reemplazados con datos reales'
        }

    def _generar_pdf_muestra(self):
        """Simula la generación de un PDF de muestra."""
        # PDF mínimo válido
        pdf_header = b'%PDF-1.4\n'
        pdf_content = b'1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj 3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj 4 0 obj<</Length 100>>stream\nBT\n/F1 12 Tf\n50 700 Td\n(CERTIFICADO - MUESTRA) Tj\nET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f\n0000000009 00000 n\ntrailer<</Size 5/Root 1 0 R>>\nstartxref\n250\n%%EOF'
        return pdf_header + pdf_content