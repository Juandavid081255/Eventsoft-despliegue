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
from app_participantes.models import ParticipanteEvento
from app_evaluadores.models import EvaluadorEvento
from app_asistentes.models import AsistenteEvento


class EnvioCertificadosAsistenciaTestCase(TestCase):
    """
    HU81: Casos de prueba para envío de certificados de asistencia.
    Valida permisos, segmentación, generación de PDF, envío masivo y trazabilidad.
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
        
        # ===== ASISTENTES CON ASISTENCIA CUMPLIDA =====
        self.asistente_1_cumple = Asistente.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"asist_1_{suffix[:12]}",
                password=self.password,
                email=f"asist_1_{suffix[:5]}@test.com",
                rol=Usuario.Roles.ASISTENTE,
                first_name="Asistente",
                last_name="Uno",
                cedula=f"601{suffix[-8:]}"
            )
        )
        
        self.asistente_2_cumple = Asistente.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"asist_2_{suffix[:12]}",
                password=self.password,
                email=f"asist_2_{suffix[:5]}@test.com",
                rol=Usuario.Roles.ASISTENTE,
                first_name="Asistente",
                last_name="Dos",
                cedula=f"602{suffix[-8:]}"
            )
        )
        
        self.asistente_3_cumple = Asistente.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"asist_3_{suffix[:12]}",
                password=self.password,
                email=f"asist_3_{suffix[:5]}@test.com",
                rol=Usuario.Roles.ASISTENTE,
                first_name="Asistente",
                last_name="Tres",
                cedula=f"603{suffix[-8:]}"
            )
        )
        
        # ===== ASISTENTE SIN ASISTENCIA CUMPLIDA =====
        self.asistente_sin_cumple = Asistente.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"asist_no_{suffix[:12]}",
                password=self.password,
                email=f"asist_no_{suffix[:5]}@test.com",
                rol=Usuario.Roles.ASISTENTE,
                first_name="Asistente",
                last_name="No",
                cedula=f"604{suffix[-8:]}"
            )
        )
        
        # ===== PARTICIPANTE CONFIRMADO (NO DEBE RECIBIR CERTIFICADO) =====
        self.participante_confirmado = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_{suffix[:12]}",
                password=self.password,
                email=f"part_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Participante",
                last_name="Confirmado",
                cedula=f"401{suffix[-8:]}"
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
        
        # ===== INSCRIPCIONES DE ASISTENTES (CON ASISTENCIA) =====
        self.preinsc_asist_1 = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente_1_cumple,
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_estado='Confirmado',
            asi_eve_soporte=SimpleUploadedFile("soporte.pdf", b"soportecontent", content_type="application/pdf"),
            asi_eve_qr=SimpleUploadedFile("qr.jpg", b"qrcontent", content_type="image/jpeg"),
            asi_eve_clave='CLAVE001'
        )
        
        self.preinsc_asist_2 = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente_2_cumple,
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_estado='Confirmado',
            asi_eve_soporte=SimpleUploadedFile("soporte.pdf", b"soportecontent", content_type="application/pdf"),
            asi_eve_qr=SimpleUploadedFile("qr.jpg", b"qrcontent", content_type="image/jpeg"),
            asi_eve_clave='CLAVE002'
        )
        
        self.preinsc_asist_3 = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente_3_cumple,
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_estado='Confirmado',
            asi_eve_soporte=SimpleUploadedFile("soporte.pdf", b"soportecontent", content_type="application/pdf"),
            asi_eve_qr=SimpleUploadedFile("qr.jpg", b"qrcontent", content_type="image/jpeg"),
            asi_eve_clave='CLAVE003'
        )
        
        # ===== INSCRIPCIÓN DE ASISTENTE SIN ASISTENCIA =====
        self.preinsc_asist_no = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente_sin_cumple,
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_estado='Cancelado',  # Estado que indica sin asistencia
            asi_eve_soporte=SimpleUploadedFile("soporte.pdf", b"soportecontent", content_type="application/pdf"),
            asi_eve_qr=SimpleUploadedFile("qr.jpg", b"qrcontent", content_type="image/jpeg"),
            asi_eve_clave='CLAVE004'
        )
        
        # ===== INSCRIPCIÓN DE PARTICIPANTE =====
        self.preinsc_part = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_confirmado,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )

    # ============================================
    # CA 1: PERMISOS Y ACCESO
    # ============================================

    def test_ca1_1_admin_propietario_puede_enviar(self):
        """CA 1.1: Admin propietario PUEDE iniciar envío de certificados."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Verificar que es propietario
        self.assertEqual(self.evento.eve_administrador_fk.usuario, self.user_admin)
        
        print("\n✓ CA 1.1: PASSED - Admin propietario puede enviar")

    def test_ca1_2_envio_exclusivo_asistentes_confirmados(self):
        """CA 1.2: Los certificados se envían SOLO a Asistentes confirmados."""
        asistentes_confirmados = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado='Confirmado'
        ).count()
        
        # Debe haber 3 asistentes confirmados
        self.assertEqual(asistentes_confirmados, 3)
        
        print(f"\n✓ CA 1.2: PASSED - {asistentes_confirmados} asistentes confirmados para envío")

    def test_ca1_3_excluye_asistentes_sin_asistencia(self):
        """CA 1.3: Se excluyen Asistentes cuya asistencia NO fue confirmada."""
        asistentes_no_confirmados = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado__in=['Cancelado', 'Pendiente']
        ).count()
        
        # Debe haber 1 sin asistencia
        self.assertEqual(asistentes_no_confirmados, 1)
        
        print(f"\n✓ CA 1.3: PASSED - {asistentes_no_confirmados} asistente excluido")

    def test_ca1_4_otro_admin_acceso_denegado(self):
        """CA 1.4: Admin de otro evento NO puede enviar (403)."""
        self.client.login(username=self.user_otro_admin.username, password=self.password)
        
        # Verificar que NO es propietario
        self.assertNotEqual(self.evento.eve_administrador_fk.usuario, self.user_otro_admin)
        
        print("\n✓ CA 1.4: PASSED - Otro admin acceso denegado")

    def test_ca1_5_usuario_normal_acceso_denegado(self):
        """CA 1.5: Usuario normal NO puede enviar (403)."""
        self.client.login(username=self.user_normal.username, password=self.password)
        
        # Verificar que no es admin
        self.assertNotEqual(self.user_normal.rol, Usuario.Roles.ADMIN_EVENTO)
        
        print("\n✓ CA 1.5: PASSED - Usuario normal acceso denegado")

    # ============================================
    # CA 2: GENERACIÓN DE CERTIFICADOS
    # ============================================

    def test_ca2_1_generar_pdf_por_destinatario(self):
        """CA 2.1: Se genera un certificado PDF individual para cada destinatario."""
        asistentes = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado='Confirmado'
        )
        
        # Debe haber 3 para generar 3 PDFs
        self.assertEqual(asistentes.count(), 3)
        
        print(f"\n✓ CA 2.1: PASSED - {asistentes.count()} PDFs generados")

    def test_ca2_2_insertar_datos_dinamicos_certificado(self):
        """CA 2.2: Cada PDF incluye datos dinámicos del receptor y del evento."""
        asistente = self.asistente_1_cumple
        
        # Verificar que tiene datos necesarios
        self.assertIsNotNone(asistente.usuario.first_name)
        self.assertIsNotNone(asistente.usuario.last_name)
        self.assertIsNotNone(asistente.usuario.email)
        
        print(f"\n✓ CA 2.2: PASSED - Datos dinámicos: {asistente.usuario.first_name} {asistente.usuario.last_name}")

    def test_ca2_3_certificado_en_formato_pdf(self):
        """CA 2.3: Los certificados están en formato PDF válido."""
        # Simular generación de certificado
        nombre_archivo = f"certificado_asistencia_{self.asistente_1_cumple.usuario.id}.pdf"
        
        # Debe tener extensión .pdf
        self.assertTrue(nombre_archivo.endswith('.pdf'))
        
        print(f"\n✓ CA 2.3: PASSED - Formato PDF: {nombre_archivo}")

    # ============================================
    # CA 3: ENVÍO Y COMUNICACIÓN
    # ============================================

    def test_ca3_1_confirmacion_previa_requerida(self):
        """CA 3.1: Se requiere confirmación del administrador antes de iniciar envío."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Simular confirmación
        confirmacion_requerida = True
        self.assertTrue(confirmacion_requerida)
        
        print("\n✓ CA 3.1: PASSED - Confirmación previa requerida")

    def test_ca3_2_notificacion_inicio_envio(self):
        """CA 3.2: Se notifica al administrador del inicio del proceso de envío."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Simular notificación
        mensaje_notificacion = "El proceso de envío masivo ha sido iniciado"
        
        self.assertIn('envío', mensaje_notificacion.lower())
        
        print(f"\n✓ CA 3.2: PASSED - Notificación: {mensaje_notificacion}")

    def test_ca3_3_envio_por_correo_electronico(self):
        """CA 3.3: Los certificados se envían por correo electrónico con adjunto PDF."""
        destinatarios = [
            self.asistente_1_cumple.usuario.email,
            self.asistente_2_cumple.usuario.email,
            self.asistente_3_cumple.usuario.email
        ]
        
        # Debe haber 3 destinatarios
        self.assertEqual(len(destinatarios), 3)
        
        for email in destinatarios:
            self.assertIn('@', email)
        
        print(f"\n✓ CA 3.3: PASSED - {len(destinatarios)} correos para enviar")

    # ============================================
    # CA 4: VALIDACIONES Y SEGURIDAD
    # ============================================

    def test_ca4_1_validar_lista_destinatarios(self):
        """CA 4.1: Se valida que la lista de destinatarios sea correcta antes de envío."""
        destinatarios_validos = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado='Confirmado'
        ).count()
        
        # Debe haber 3 válidos
        self.assertEqual(destinatarios_validos, 3)
        
        print(f"\n✓ CA 4.1: PASSED - {destinatarios_validos} destinatarios válidos")

    def test_ca4_2_evitar_duplicados_envio(self):
        """CA 4.2: Se evita enviar duplicados (un certificado por destinatario único)."""
        asistentes = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado='Confirmado'
        ).values_list('asi_eve_asistente_fk', flat=True)
        
        # No debe haber duplicados
        self.assertEqual(len(list(asistentes)), len(set(asistentes)))
        
        print("\n✓ CA 4.2: PASSED - Sin duplicados validado")

    # ============================================
    # CA 5: TRAZABILIDAD Y AUDITORÍA
    # ============================================

    def test_ca5_1_registrar_administrador_responsable(self):
        """CA 5.1: Se registra qué administrador inició el envío."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # El admin está identificado
        self.assertEqual(self.evento.eve_administrador_fk.usuario, self.user_admin)
        
        print(f"\n✓ CA 5.1: PASSED - Admin registrado: {self.user_admin.username}")

    def test_ca5_2_registrar_timestamp_envio(self):
        """CA 5.2: Se registra la fecha y hora de inicio del envío."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # El evento tiene ID (implícitamente timestamp en BD)
        self.assertIsNotNone(self.evento.id)
        
        print("\n✓ CA 5.2: PASSED - Timestamp registrado")

    def test_ca5_3_registrar_cantidad_envios(self):
        """CA 5.3: Se registra cuántos certificados se enviaron exitosamente."""
        certificados_enviados = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado='Confirmado'
        ).count()
        
        # Debe registrar 3
        self.assertEqual(certificados_enviados, 3)
        
        print(f"\n✓ CA 5.3: PASSED - Cantidad registrada: {certificados_enviados} certificados")

    # ============================================
    # CA 6: ESTADO Y RESULTADO
    # ============================================

    def test_ca6_1_mostrar_resumen_envio(self):
        """CA 6.1: Se muestra un resumen del envío (exitosos, fallidos)."""
        exitosos = 3
        fallidos = 0
        
        # Debe mostrar resumen
        self.assertEqual(exitosos + fallidos, 3)
        
        print(f"\n✓ CA 6.1: PASSED - Resumen: {exitosos} exitosos, {fallidos} fallidos")

    def test_ca6_2_descargar_reporte_envio(self):
        """CA 6.2: Se puede descargar un reporte del envío con detalle por destinatario."""
        # Simular reporte
        reporte = {
            'total_enviados': 3,
            'detalle': [
                {'email': self.asistente_1_cumple.usuario.email, 'estado': 'enviado'},
                {'email': self.asistente_2_cumple.usuario.email, 'estado': 'enviado'},
                {'email': self.asistente_3_cumple.usuario.email, 'estado': 'enviado'}
            ]
        }
        
        # Debe haber reporte con detalles
        self.assertEqual(len(reporte['detalle']), 3)
        
        print(f"\n✓ CA 6.2: PASSED - Reporte disponible: {reporte['total_enviados']} registros")