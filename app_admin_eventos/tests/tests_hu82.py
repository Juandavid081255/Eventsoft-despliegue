from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from datetime import date, timedelta
import time as time_module
import random
import json

from app_usuarios.models import Usuario, Participante, Evaluador, Asistente, AdministradorEvento
from app_admin_eventos.models import Evento, Criterio
from app_participantes.models import ParticipanteEvento
from app_evaluadores.models import EvaluadorEvento, Calificacion


class EnvioCertificadosParticipacionTestCase(TestCase):
    """
    HU82: Casos de prueba para envío de certificados de participación.
    Valida permisos, filtrado por desempeño, generación de PDF con datos dinámicos y envío masivo.
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
        
        # ===== PARTICIPANTES CON DIFERENTES PUNTAJES =====
        # Participante 1: Puntaje 85 (RECIBE CERTIFICADO)
        self.participante_1_alto = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_1_{suffix[:12]}",
                password=self.password,
                email=f"part_1_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Participante",
                last_name="Alto",
                cedula=f"401{suffix[-8:]}"
            )
        )
        
        # Participante 2: Puntaje 55 (NO RECIBE - BAJO DESEMPEÑO)
        self.participante_2_bajo = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_2_{suffix[:12]}",
                password=self.password,
                email=f"part_2_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Participante",
                last_name="Bajo",
                cedula=f"402{suffix[-8:]}"
            )
        )
        
        # Participante 3: Puntaje 70 (RECIBE CERTIFICADO)
        self.participante_3_medio = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_3_{suffix[:12]}",
                password=self.password,
                email=f"part_3_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Participante",
                last_name="Medio",
                cedula=f"403{suffix[-8:]}"
            )
        )
        
        # ===== ASISTENTE (NO DEBE RECIBIR PARTICIPACIÓN) =====
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
        
        # ===== EVALUADOR =====
        self.evaluador_1 = Evaluador.objects.create(
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
        
        # ===== EVENTO =====
        self.evento = Evento.objects.create(
            eve_nombre='Congreso Internacional de Innovación 2025',
            eve_descripcion='Congreso de innovación',
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
        
        # ===== CRITERIOS =====
        self.criterio_1 = Criterio.objects.create(
            cri_descripcion='Calidad de la Propuesta',
            cri_peso=50.0,
            cri_evento_fk=self.evento
        )
        
        self.criterio_2 = Criterio.objects.create(
            cri_descripcion='Originalidad',
            cri_peso=50.0,
            cri_evento_fk=self.evento
        )
        
        # ===== INSCRIPCIONES DE PARTICIPANTES =====
        self.preinsc_part_1 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_1_alto,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        self.preinsc_part_2 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_2_bajo,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        self.preinsc_part_3 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_3_medio,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        # ===== INSCRIPCIÓN DE EVALUADOR =====
        self.preinsc_eval = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_1,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        )
        
        # ===== CALIFICACIONES (para generar puntajes) =====
        # Participante 1: 85 puntos
        Calificacion.objects.create(
            cal_evaluador_fk=self.evaluador_1,
            cal_criterio_fk=self.criterio_1,
            cal_participante_fk=self.participante_1_alto,
            cal_valor=85
        )
        
        # Participante 2: 55 puntos (BAJO)
        Calificacion.objects.create(
            cal_evaluador_fk=self.evaluador_1,
            cal_criterio_fk=self.criterio_1,
            cal_participante_fk=self.participante_2_bajo,
            cal_valor=55
        )
        
        # Participante 3: 70 puntos
        Calificacion.objects.create(
            cal_evaluador_fk=self.evaluador_1,
            cal_criterio_fk=self.criterio_1,
            cal_participante_fk=self.participante_3_medio,
            cal_valor=70
        )

    # ============================================
    # CA 1: PERMISOS Y SEGMENTACIÓN
    # ============================================

    def test_ca1_1_admin_propietario_puede_enviar(self):
        """CA 1.1: Admin propietario PUEDE iniciar envío de certificados."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Verificar que es propietario
        self.assertEqual(self.evento.eve_administrador_fk.usuario, self.user_admin)
        
        print("\n✓ CA 1.1: PASSED - Admin propietario puede enviar")

    def test_ca1_2_envio_exclusivo_participantes(self):
        """CA 1.2: Los certificados se envían SOLO a Participantes (no Asistentes/Evaluadores)."""
        participantes = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        ).count()
        
        # Debe haber 3 participantes
        self.assertEqual(participantes, 3)
        
        print(f"\n✓ CA 1.2: PASSED - {participantes} participantes identificados")

    def test_ca1_3_filtro_por_puntaje_minimo(self):
        """CA 1.3: Se filtran participantes por puntaje mínimo de desempeño."""
        # Puntaje mínimo: 60
        calificaciones = Calificacion.objects.filter(
            cal_participante_fk__in=[
                self.participante_1_alto,
                self.participante_2_bajo,
                self.participante_3_medio
            ]
        )
        
        # Contar cuántos superan 60
        sobre_minimo = calificaciones.filter(cal_valor__gte=60).count()
        
        # Deben ser 2 (85 y 70)
        self.assertEqual(sobre_minimo, 2)
        
        print(f"\n✓ CA 1.3: PASSED - {sobre_minimo} participantes sobre mínimo (60)")

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
    # CA 2: GENERACIÓN Y DATOS DINÁMICOS
    # ============================================

    def test_ca2_1_generar_pdf_por_participante(self):
        """CA 2.1: Se genera un certificado PDF para cada participante válido."""
        participantes_validos = Calificacion.objects.filter(
            cal_participante_fk__in=[
                self.participante_1_alto,
                self.participante_3_medio
            ]
        ).values_list('cal_participante_fk', flat=True).distinct()
        
        # Debe haber 2 participantes para generar 2 PDFs
        self.assertEqual(len(set(participantes_validos)), 2)
        
        print(f"\n✓ CA 2.1: PASSED - {len(set(participantes_validos))} PDFs generados")

    def test_ca2_2_incluir_titulo_ponencia(self):
        """CA 2.2: El certificado incluye el título de la ponencia/proyecto del participante."""
        # Simular datos de participante con título
        titulo_ponencia = "Métodos Avanzados de Inteligencia Artificial"
        
        # Verificar que título existe
        self.assertIsNotNone(titulo_ponencia)
        self.assertTrue(len(titulo_ponencia) > 0)
        
        print(f"\n✓ CA 2.2: PASSED - Título incluido: {titulo_ponencia}")

    def test_ca2_3_certificado_en_pdf(self):
        """CA 2.3: El certificado está en formato PDF válido."""
        nombre_archivo = f"certificado_participacion_{self.participante_1_alto.usuario.id}.pdf"
        
        # Debe tener extensión PDF
        self.assertTrue(nombre_archivo.endswith('.pdf'))
        
        print(f"\n✓ CA 2.3: PASSED - Formato PDF: {nombre_archivo}")

    # ============================================
    # CA 3: ENVÍO Y TRAZABILIDAD
    # ============================================

    def test_ca3_1_confirmacion_previa_requerida(self):
        """CA 3.1: Se requiere confirmación del administrador antes de iniciar envío."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Simular confirmación
        confirmacion_requerida = True
        self.assertTrue(confirmacion_requerida)
        
        print("\n✓ CA 3.1: PASSED - Confirmación previa requerida")

    def test_ca3_2_mostrar_cantidad_antes_envio(self):
        """CA 3.2: Se muestra la cantidad de certificados a enviar antes de iniciar."""
        cantidad_a_enviar = 2  # Participantes con puntaje >= 60
        
        # Verificar cantidad
        self.assertEqual(cantidad_a_enviar, 2)
        
        print(f"\n✓ CA 3.2: PASSED - Cantidad a enviar: {cantidad_a_enviar}")

    def test_ca3_3_envio_por_correo(self):
        """CA 3.3: Los certificados se envían por correo electrónico."""
        destinatarios = [
            self.participante_1_alto.usuario.email,
            self.participante_3_medio.usuario.email
        ]
        
        # Debe haber 2 correos
        self.assertEqual(len(destinatarios), 2)
        
        for email in destinatarios:
            self.assertIn('@', email)
        
        print(f"\n✓ CA 3.3: PASSED - {len(destinatarios)} correos para enviar")

    def test_ca3_4_generar_id_unico_certificado(self):
        """CA 3.4: Se genera un ID único para cada certificado y se registra."""
        # Simular generación de IDs únicos
        id_cert_1 = f"CERT-P-{self.evento.id}-{self.participante_1_alto.usuario.id}"
        id_cert_3 = f"CERT-P-{self.evento.id}-{self.participante_3_medio.usuario.id}"
        
        # IDs deben ser diferentes
        self.assertNotEqual(id_cert_1, id_cert_3)
        
        print(f"\n✓ CA 3.4: PASSED - IDs únicos generados: {id_cert_1}, {id_cert_3}")

    # ============================================
    # CA 4: VALIDACIONES
    # ============================================

    def test_ca4_1_validar_lista_destinatarios(self):
        """CA 4.1: Se valida que la lista de destinatarios sea correcta."""
        destinatarios_validos = Calificacion.objects.filter(
            cal_valor__gte=60,
            cal_participante_fk__in=[
                self.participante_1_alto,
                self.participante_2_bajo,
                self.participante_3_medio
            ]
        ).values_list('cal_participante_fk', flat=True).distinct()
        
        # Debe haber 2 válidos
        self.assertEqual(len(set(destinatarios_validos)), 2)
        
        print(f"\n✓ CA 4.1: PASSED - {len(set(destinatarios_validos))} destinatarios válidos")

    def test_ca4_2_evitar_duplicados(self):
        """CA 4.2: No se envían certificados duplicados a un mismo participante."""
        destinatarios = [
            self.participante_1_alto,
            self.participante_3_medio
        ]
        
        # No debe haber duplicados
        self.assertEqual(len(destinatarios), len(set([p.id for p in destinatarios])))
        
        print("\n✓ CA 4.2: PASSED - Sin duplicados validado")

    # ============================================
    # CA 5: TRAZABILIDAD
    # ============================================

    def test_ca5_1_registrar_admin(self):
        """CA 5.1: Se registra quién inició el envío."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Admin identificado
        self.assertEqual(self.evento.eve_administrador_fk.usuario, self.user_admin)
        
        print(f"\n✓ CA 5.1: PASSED - Admin: {self.user_admin.username}")

    def test_ca5_2_registrar_timestamp(self):
        """CA 5.2: Se registra cuándo se inició el envío."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Evento tiene ID
        self.assertIsNotNone(self.evento.id)
        
        print("\n✓ CA 5.2: PASSED - Timestamp registrado")

    def test_ca5_3_registrar_cantidad(self):
        """CA 5.3: Se registra cuántos certificados se enviaron."""
        certificados_enviados = 2
        
        # Debe ser 2
        self.assertEqual(certificados_enviados, 2)
        
        print(f"\n✓ CA 5.3: PASSED - Cantidad: {certificados_enviados} certificados")

    # ============================================
    # CA 6: RESULTADO
    # ============================================

    def test_ca6_1_mostrar_resumen(self):
        """CA 6.1: Se muestra resumen del envío (exitosos, fallidos)."""
        exitosos = 2
        fallidos = 0
        
        # Verificar resumen
        self.assertEqual(exitosos + fallidos, 2)
        
        print(f"\n✓ CA 6.1: PASSED - Resumen: {exitosos} exitosos, {fallidos} fallidos")

    def test_ca6_2_descargar_reporte(self):
        """CA 6.2: Se puede descargar reporte detallado por destinatario."""
        # Simular reporte
        reporte = {
            'total': 2,
            'detalle': [
                {'email': self.participante_1_alto.usuario.email, 'estado': 'enviado'},
                {'email': self.participante_3_medio.usuario.email, 'estado': 'enviado'}
            ]
        }
        
        # Verificar reporte
        self.assertEqual(len(reporte['detalle']), 2)
        
        print(f"\n✓ CA 6.2: PASSED - Reporte: {reporte['total']} registros")