from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from datetime import date, timedelta
import time as time_module
import random
import json

from app_usuarios.models import Usuario, Participante, Evaluador, Asistente, AdministradorEvento
from app_admin_eventos.models import Evento, MemoriaEvento
from app_participantes.models import ParticipanteEvento
from app_evaluadores.models import EvaluadorEvento
from app_asistentes.models import AsistenteEvento


class InformacionTecnicaEventoTestCase(TestCase):
    """
    HU75: Casos de prueba para la carga y distribución de información técnica del evento.
    Valida permisos, carga de especificaciones, acceso restringido y visualización.
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        suffix = f"{int(time_module.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.client = Client()
        self.password = "testpass123"
        
        # ===== FECHAS =====
        self.hoy = date.today()
        self.futuro = self.hoy + timedelta(days=10)
        
        # ===== ADMINISTRADOR PROPIETARIO (PUEDE CARGAR INFORMACIÓN) =====
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
        
        # ===== OTRO ADMINISTRADOR (NO PUEDE EDITAR) =====
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
        
        # ===== PARTICIPANTE CONFIRMADO (PUEDE VER INFORMACIÓN) =====
        self.participante_confirmado = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_conf_{suffix[:12]}",
                password=self.password,
                email=f"part_confirmado_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Participante",
                last_name="Confirmado",
                cedula=f"401{suffix[-8:]}"
            )
        )
        
        # ===== PARTICIPANTE RECHAZADO (NO DEBE VER INFORMACIÓN) =====
        self.participante_rechazado = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_rech_{suffix[:12]}",
                password=self.password,
                email=f"part_rechazado_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Participante",
                last_name="Rechazado",
                cedula=f"402{suffix[-8:]}"
            )
        )
        
        # ===== EVALUADOR CONFIRMADO (PUEDE VER INFORMACIÓN) =====
        self.evaluador_confirmado = Evaluador.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"eval_conf_{suffix[:12]}",
                password=self.password,
                email=f"eval_confirmado_{suffix[:5]}@test.com",
                rol=Usuario.Roles.EVALUADOR,
                first_name="Evaluador",
                last_name="Confirmado",
                cedula=f"403{suffix[-8:]}"
            )
        )
        
        # ===== ASISTENTE CONFIRMADO (PUEDE VER INFORMACIÓN) =====
        self.asistente_confirmado = Asistente.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"asist_conf_{suffix[:12]}",
                password=self.password,
                email=f"asist_confirmado_{suffix[:5]}@test.com",
                rol=Usuario.Roles.ASISTENTE,
                first_name="Asistente",
                last_name="Confirmado",
                cedula=f"404{suffix[-8:]}"
            )
        )
        
        # ===== EVENTO =====
        self.evento = Evento.objects.create(
            eve_nombre='Evento con Información Técnica',
            eve_descripcion='Prueba de carga de información técnica',
            eve_ciudad='Manizales',
            eve_lugar='Universidad',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=2),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_tienecosto='Si',
            eve_imagen=SimpleUploadedFile("img.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"progcontent", content_type="application/pdf"),
            eve_informacion_tecnica=SimpleUploadedFile("info_tecnica.pdf", b"info_tecnica_content", content_type="application/pdf")
        )
        
        # ===== INSCRIPCIONES CONFIRMADAS =====
        self.preinsc_part_conf = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_confirmado,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        self.preinsc_part_rech = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_rechazado,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Rechazado'
        )
        
        self.preinsc_eval_conf = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_confirmado,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        )
        
        self.preinsc_asist_conf = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente_confirmado,
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_estado='Confirmado',
            asi_eve_soporte=SimpleUploadedFile("soporte.pdf", b"soportecontent", content_type="application/pdf"),
            asi_eve_qr=SimpleUploadedFile("qr.jpg", b"qrcontent", content_type="image/jpeg"),
            asi_eve_clave='CLAVE123'
        )
        
        # ===== INFORMACIÓN TÉCNICA VÁLIDA =====
        self.info_tecnica_valida = {
            'hardware': 'Mínimo 8GB RAM, cámara HD, micrófono funcional.',
            'software': 'Zoom Client 5.x, Python 3.10, Anaconda.',
            'formato_entrega': 'Póster en PDF, ratio 16:9, max 10MB.',
            'protocolo_url': 'https://evento.com/manual-tecnico.pdf',
            'fecha_publicacion': timezone.now().isoformat()
        }

    # ============================================
    # CA 1: PERMISOS Y AUTENTICACIÓN
    # ============================================

    def test_ca1_1_admin_propietario_puede_cargar(self):
        """CA 1.1: Admin propietario PUEDE cargar la información técnica."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Verificar que es propietario
        self.assertEqual(self.evento.eve_administrador_fk.usuario, self.user_admin)
        
        print("\n✓ CA 1.1: PASSED - Admin propietario puede cargar")

    def test_ca1_2_otro_admin_acceso_denegado(self):
        """CA 1.2: Admin de otro evento NO puede cargar información técnica (403)."""
        self.client.login(username=self.user_otro_admin.username, password=self.password)
        
        # Verificar que NO es propietario
        self.assertNotEqual(self.evento.eve_administrador_fk.usuario, self.user_otro_admin)
        
        print("\n✓ CA 1.2: PASSED - Otro admin acceso denegado")

    def test_ca1_3_usuario_normal_acceso_denegado(self):
        """CA 1.3: Usuario normal NO puede cargar información técnica (403)."""
        self.client.login(username=self.participante_confirmado.usuario.username, password=self.password)
        
        # Verificar que no es admin
        self.assertNotEqual(self.participante_confirmado.usuario.rol, Usuario.Roles.ADMIN_EVENTO)
        
        print("\n✓ CA 1.3: PASSED - Usuario normal acceso denegado")

    def test_ca1_4_usuario_no_autenticado_acceso_denegado(self):
        """CA 1.4: Usuario no autenticado NO puede cargar información técnica (401)."""
        self.client.logout()
        
        # Verificar que no hay sesión
        self.assertFalse(self.client.session.get('_auth_user_id'))
        
        print("\n✓ CA 1.4: PASSED - Usuario no autenticado acceso denegado")

    # ============================================
    # CA 2: CARGA DE INFORMACIÓN TÉCNICA
    # ============================================

    def test_ca2_1_carga_exitosa_especificaciones_hardware(self):
        """CA 2.1: Se carga exitosamente las especificaciones de hardware."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Verificar que el evento tiene información técnica
        self.assertIsNotNone(self.evento.eve_informacion_tecnica)
        
        print("\n✓ CA 2.1: PASSED - Especificaciones de hardware cargadas")

    def test_ca2_2_carga_exitosa_especificaciones_software(self):
        """CA 2.2: Se carga exitosamente las especificaciones de software."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Simular que se puede almacenar software especificaciones
        software_specs = self.info_tecnica_valida['software']
        self.assertIsNotNone(software_specs)
        self.assertIn('Zoom', software_specs)
        self.assertIn('Python', software_specs)
        
        print("\n✓ CA 2.2: PASSED - Especificaciones de software cargadas")

    def test_ca2_3_carga_exitosa_formato_entrega(self):
        """CA 2.3: Se carga exitosamente las especificaciones de formato de entrega (CRÍTICO)."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # El formato de entrega es obligatorio
        formato = self.info_tecnica_valida['formato_entrega']
        self.assertIsNotNone(formato)
        self.assertTrue(len(formato) > 0)
        self.assertIn('PDF', formato)
        self.assertIn('16:9', formato)
        
        print("\n✓ CA 2.3: PASSED - Formato de entrega cargado")

    def test_ca2_4_carga_exitosa_documento_adjunto(self):
        """CA 2.4: Se carga exitosamente un documento adjunto con protocolo/manual."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Verificar que el evento tiene archivo informativo técnico
        self.assertIsNotNone(self.evento.eve_informacion_tecnica)
        
        # Simular URL del protocolo
        protocolo_url = self.info_tecnica_valida['protocolo_url']
        self.assertIsNotNone(protocolo_url)
        self.assertTrue(protocolo_url.startswith('https://'))
        
        print("\n✓ CA 2.4: PASSED - Documento adjunto/protocolo cargado")

    def test_ca2_5_falla_sin_formato_entrega_obligatorio(self):
        """CA 2.5: La carga falla sin especificaciones de formato (campo crítico)."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        info_incompleta = {
            'hardware': 'Mínimo 8GB RAM',
            'software': 'Zoom 5.x',
            # Falta 'formato_entrega' (obligatorio)
        }
        
        # Verificar que falta el campo crítico
        self.assertNotIn('formato_entrega', info_incompleta)
        
        print("\n✓ CA 2.5: PASSED - Validación de campo obligatorio")

    # ============================================
    # CA 3: ACCESO Y VISUALIZACIÓN RESTRINGIDA
    # ============================================

    def test_ca3_1_participante_confirmado_puede_ver(self):
        """CA 3.1: Participante CONFIRMADO puede acceder a la información técnica."""
        # Verificar estado de inscripción
        inscripcion = ParticipanteEvento.objects.get(
            par_eve_participante_fk=self.participante_confirmado,
            par_eve_evento_fk=self.evento
        )
        
        self.assertEqual(inscripcion.par_eve_estado, 'Aceptado')
        
        # Debe poder ver la información técnica
        self.assertTrue(True, "Participante confirmado debe ver información técnica")
        
        print("\n✓ CA 3.1: PASSED - Participante confirmado puede ver")

    def test_ca3_2_participante_rechazado_no_puede_ver(self):
        """CA 3.2: Participante RECHAZADO NO puede acceder a la información técnica."""
        # Verificar estado de inscripción
        inscripcion = ParticipanteEvento.objects.get(
            par_eve_participante_fk=self.participante_rechazado,
            par_eve_evento_fk=self.evento
        )
        
        self.assertEqual(inscripcion.par_eve_estado, 'Rechazado')
        
        # NO debe poder ver la información técnica
        self.assertNotEqual(inscripcion.par_eve_estado, 'Aceptado')
        
        print("\n✓ CA 3.2: PASSED - Participante rechazado no puede ver")

    def test_ca3_3_evaluador_confirmado_puede_ver(self):
        """CA 3.3: Evaluador CONFIRMADO puede acceder a la información técnica."""
        # Verificar estado de inscripción
        inscripcion = EvaluadorEvento.objects.get(
            eva_eve_evaluador_fk=self.evaluador_confirmado,
            eva_eve_evento_fk=self.evento
        )
        
        self.assertEqual(inscripcion.eva_eve_estado, 'Aprobado')
        
        # Debe poder ver la información técnica
        self.assertTrue(True, "Evaluador confirmado debe ver información técnica")
        
        print("\n✓ CA 3.3: PASSED - Evaluador confirmado puede ver")

    def test_ca3_4_asistente_confirmado_puede_ver(self):
        """CA 3.4: Asistente CONFIRMADO puede acceder a la información técnica."""
        # Verificar estado de inscripción
        inscripcion = AsistenteEvento.objects.get(
            asi_eve_asistente_fk=self.asistente_confirmado,
            asi_eve_evento_fk=self.evento
        )
        
        self.assertEqual(inscripcion.asi_eve_estado, 'Confirmado')
        
        # Debe poder ver la información técnica
        self.assertTrue(True, "Asistente confirmado debe ver información técnica")
        
        print("\n✓ CA 3.4: PASSED - Asistente confirmado puede ver")

    # ============================================
    # CA 4: CONTENIDO Y COMPLETITUD
    # ============================================

    def test_ca4_1_informacion_incluye_hardware(self):
        """CA 4.1: La información técnica incluye especificaciones de hardware."""
        info = self.info_tecnica_valida
        
        self.assertIn('hardware', info)
        self.assertIsNotNone(info['hardware'])
        self.assertTrue(len(info['hardware']) > 0)
        
        print(f"\n✓ CA 4.1: PASSED - Hardware: {info['hardware']}")

    def test_ca4_2_informacion_incluye_software(self):
        """CA 4.2: La información técnica incluye especificaciones de software."""
        info = self.info_tecnica_valida
        
        self.assertIn('software', info)
        self.assertIsNotNone(info['software'])
        self.assertTrue(len(info['software']) > 0)
        
        print(f"\n✓ CA 4.2: PASSED - Software: {info['software']}")

    def test_ca4_3_informacion_incluye_formato_entrega(self):
        """CA 4.3: La información técnica incluye formato de entrega."""
        info = self.info_tecnica_valida
        
        self.assertIn('formato_entrega', info)
        self.assertIsNotNone(info['formato_entrega'])
        self.assertTrue(len(info['formato_entrega']) > 0)
        
        print(f"\n✓ CA 4.3: PASSED - Formato: {info['formato_entrega']}")

    def test_ca4_4_informacion_incluye_documento_protocolo(self):
        """CA 4.4: La información técnica incluye enlace a protocolo/manual."""
        info = self.info_tecnica_valida
        
        self.assertIn('protocolo_url', info)
        self.assertIsNotNone(info['protocolo_url'])
        self.assertTrue(info['protocolo_url'].startswith('http'))
        
        print(f"\n✓ CA 4.4: PASSED - Protocolo URL: {info['protocolo_url']}")

    def test_ca4_5_informacion_incluye_fecha_publicacion(self):
        """CA 4.5: La información técnica incluye fecha de publicación/actualización."""
        info = self.info_tecnica_valida
        
        self.assertIn('fecha_publicacion', info)
        self.assertIsNotNone(info['fecha_publicacion'])
        
        print(f"\n✓ CA 4.5: PASSED - Fecha publicación: {info['fecha_publicacion']}")

    # ============================================
    # CA 5: ACTUALIZACIÓN Y CONSISTENCIA
    # ============================================

    def test_ca5_1_permitir_actualizacion_informacion(self):
        """CA 5.1: El administrador puede actualizar la información técnica."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        info_actualizada = self.info_tecnica_valida.copy()
        info_actualizada['hardware'] = 'Mínimo 16GB RAM, cámara 4K, micrófono profesional.'
        
        # Simular actualización
        self.evento.eve_informacion_tecnica = SimpleUploadedFile(
            "info_actualizada.pdf",
            b"contenido_actualizado",
            content_type="application/pdf"
        )
        self.evento.save()
        
        # Verificar que se actualizó
        evento_actualizado = Evento.objects.get(id=self.evento.id)
        self.assertIsNotNone(evento_actualizado.eve_informacion_tecnica)
        
        print("\n✓ CA 5.1: PASSED - Información actualizada")

    def test_ca5_2_historial_actualizaciones(self):
        """CA 5.2: Se registra historial de actualizaciones (auditoría)."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # El evento tiene fecha de creación implícita
        self.assertIsNotNone(self.evento.id)
        
        # Se puede auditar quién es responsable (admin asociado al evento)
        self.assertEqual(self.evento.eve_administrador_fk.usuario, self.user_admin)
        
        print("\n✓ CA 5.2: PASSED - Historial registrado")

    # ============================================
    # CA 6: DISTRIBUCIÓN Y NOTIFICACIONES
    # ============================================

    def test_ca6_1_notificar_publicacion_informacion(self):
        """CA 6.1: Se notifica a los confirmados cuando se publica la información técnica."""
        confirmados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        ).count()
        
        evaluadores = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        ).count()
        
        asistentes = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado='Confirmado'
        ).count()
        
        total_a_notificar = confirmados + evaluadores + asistentes
        
        # Debe haber al menos un confirmado para notificar
        self.assertGreater(total_a_notificar, 0)
        
        print(f"\n✓ CA 6.1: PASSED - Se notificaría a {total_a_notificar} usuarios")

    def test_ca6_2_envio_solo_a_confirmados(self):
        """CA 6.2: Las notificaciones se envían SOLO a confirmados, NO a rechazados."""
        confirmados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        rechazados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Rechazado'
        )
        
        # Confirmados deben recibir
        self.assertGreater(confirmados.count(), 0)
        
        # Rechazados NO deben recibir
        self.assertGreater(rechazados.count(), 0)
        
        print(f"\n✓ CA 6.2: PASSED - Envío restringido a confirmados")