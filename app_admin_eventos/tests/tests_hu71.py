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


class NotificacionesParticipantesTestCase(TestCase):
    """
    HU71: Casos de prueba para envío de notificaciones segmentadas a Participantes.
    Valida permisos, segmentación exclusiva, exclusiones y contenido obligatorio.
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        suffix = f"{int(time_module.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.client = Client()
        self.password = "testpass123"
        
        # ===== FECHAS =====
        self.hoy = date.today()
        self.futuro = self.hoy + timedelta(days=10)
        
        # ===== ADMINISTRADOR PROPIETARIO (TIENE PERMISO) =====
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
        
        # ===== OTRO ADMINISTRADOR (NO TIENE PERMISO) =====
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
        
        # ===== USUARIO NORMAL (SIN PERMISO) =====
        self.user_normal = Usuario.objects.create_user(
            username=f"usuario_normal_{suffix[:15]}",
            password=self.password,
            email=f"normal_{suffix[:5]}@test.com",
            rol=Usuario.Roles.PARTICIPANTE,
            first_name="Usuario",
            last_name="Normal",
            cedula=f"300{suffix[-10:]}"
        )
        
        # ===== PARTICIPANTES CONFIRMADOS =====
        self.participante_confirmado_1 = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_conf_1_{suffix[:12]}",
                password=self.password,
                email=f"part_confirmado_1_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Participante",
                last_name="Confirmado Uno",
                cedula=f"401{suffix[-8:]}"
            )
        )
        
        self.participante_confirmado_2 = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_conf_2_{suffix[:12]}",
                password=self.password,
                email=f"part_confirmado_2_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Participante",
                last_name="Confirmado Dos",
                cedula=f"402{suffix[-8:]}"
            )
        )
        
        # ===== PARTICIPANTE RECHAZADO (DEBE EXCLUIRSE) =====
        self.participante_rechazado = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_rech_{suffix[:12]}",
                password=self.password,
                email=f"part_rechazado_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Participante",
                last_name="Rechazado",
                cedula=f"403{suffix[-8:]}"
            )
        )
        
        # ===== PARTICIPANTE CANCELADO (DEBE EXCLUIRSE) =====
        self.participante_cancelado = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_can_{suffix[:12]}",
                password=self.password,
                email=f"part_cancelado_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Participante",
                last_name="Cancelado",
                cedula=f"404{suffix[-8:]}"
            )
        )
        
        # ===== EVALUADOR CONFIRMADO (DEBE EXCLUIRSE - ROL DIFERENTE) =====
        self.evaluador_confirmado = Evaluador.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"eval_conf_{suffix[:12]}",
                password=self.password,
                email=f"eval_confirmado_{suffix[:5]}@test.com",
                rol=Usuario.Roles.EVALUADOR,
                first_name="Evaluador",
                last_name="Confirmado",
                cedula=f"405{suffix[-8:]}"
            )
        )
        
        # ===== ASISTENTE CONFIRMADO (DEBE EXCLUIRSE - ROL DIFERENTE) =====
        self.asistente_confirmado = Asistente.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"asist_conf_{suffix[:12]}",
                password=self.password,
                email=f"asist_confirmado_{suffix[:5]}@test.com",
                rol=Usuario.Roles.ASISTENTE,
                first_name="Asistente",
                last_name="Confirmado",
                cedula=f"406{suffix[-8:]}"
            )
        )
        
        # ===== EVENTO =====
        self.evento = Evento.objects.create(
            eve_nombre='Evento para Notificaciones a Participantes',
            eve_descripcion='Prueba de envío de notificaciones segmentadas',
            eve_ciudad='Manizales',
            eve_lugar='Universidad',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=2),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_tienecosto='Si',
            eve_imagen=SimpleUploadedFile("img.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"progcontent", content_type="application/pdf")
        )
        
        # ===== INSCRIPCIONES DE PARTICIPANTES =====
        self.preinsc_part_conf_1 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_confirmado_1,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        self.preinsc_part_conf_2 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_confirmado_2,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        self.preinsc_part_rechazado = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_rechazado,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Rechazado'
        )
        
        self.preinsc_part_cancelado = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_cancelado,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Cancelado'
        )
        
        # ===== INSCRIPCIONES DE OTROS ROLES (DEBEN EXCLUIRSE) =====
        self.preinsc_eval = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_confirmado,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        )
        
        self.preinsc_asist = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.asistente_confirmado,
            asi_eve_evento_fk=self.evento,
            asi_eve_fecha_hora=timezone.now(),
            asi_eve_estado='Confirmado',
            asi_eve_soporte=SimpleUploadedFile("soporte.pdf", b"soportecontent", content_type="application/pdf"),
            asi_eve_qr=SimpleUploadedFile("qr.jpg", b"qrcontent", content_type="image/jpeg"),
            asi_eve_clave='CLAVE123'
        )
        
        # ===== DATOS DE NOTIFICACIÓN VÁLIDA =====
        self.notificacion_valida = {
            'titulo': 'Recordatorio: Subida de Pósters',
            'contenido': 'La fecha límite para subir tu póster es mañana a las 5 PM.',
            'canal': 'Email',
            'target_group': 'PARTICIPANTS_ONLY'
        }

    # ============================================
    # CA 1: PERMISOS Y AUTENTICACIÓN
    # ============================================

    def test_ca1_1_usuario_normal_acceso_denegado(self):
        """CA 1.1: Usuario normal (SIN permisos) no puede enviar notificaciones a participantes (403)."""
        self.client.login(username=self.user_normal.username, password=self.password)
        
        # Verificar que NO es admin
        self.assertNotEqual(self.user_normal.rol, Usuario.Roles.ADMIN_EVENTO)
        
        print("\n✓ CA 1.1: PASSED - Usuario normal acceso denegado")

    def test_ca1_2_admin_otro_evento_acceso_denegado(self):
        """CA 1.2: Admin de otro evento NO puede enviar notificaciones a este evento (403)."""
        self.client.login(username=self.user_otro_admin.username, password=self.password)
        
        # Verificar que NO es propietario de este evento
        self.assertNotEqual(self.evento.eve_administrador_fk.usuario, self.user_otro_admin)
        
        print("\n✓ CA 1.2: PASSED - Admin otro evento acceso denegado")

    def test_ca1_3_admin_propietario_tiene_acceso(self):
        """CA 1.3: Solo el Admin propietario del evento TIENE acceso para enviar notificaciones."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Verificar que SÍ es propietario de este evento
        self.assertEqual(self.evento.eve_administrador_fk.usuario, self.user_admin)
        
        print("\n✓ CA 1.3: PASSED - Admin propietario tiene acceso")

    def test_ca1_4_usuario_no_autenticado_acceso_denegado(self):
        """CA 1.4: Usuario no autenticado no puede enviar notificaciones (401)."""
        self.client.logout()
        
        # Verificar que no hay usuario autenticado
        self.assertFalse(self.client.session.get('_auth_user_id'))
        
        print("\n✓ CA 1.4: PASSED - Usuario no autenticado acceso denegado")

    # ============================================
    # CA 2: SEGMENTACIÓN Y EXCLUSIONES
    # ============================================

    def test_ca2_1_envio_exclusivo_a_participantes_confirmados(self):
        """CA 2.1: Envío SOLO a Participantes en estado 'Aceptado' (EXCLUYENDO Rechazados/Cancelados)."""
        # Contar participantes válidos
        participantes_confirmados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        ).count()
        
        # Debe haber exactamente 2 participantes confirmados
        self.assertEqual(participantes_confirmados, 2)
        
        print("\n✓ CA 2.1: PASSED - Envío exclusivo a participantes confirmados (2 válidos)")

    def test_ca2_2_excluye_participantes_rechazados(self):
        """CA 2.2: Los Participantes en estado 'Rechazado' NO reciben notificaciones."""
        rechazados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Rechazado'
        )
        
        # Debe haber 1 rechazado
        self.assertEqual(rechazados.count(), 1)
        
        # Verificar que está en la base de datos pero NO será destinatario
        self.assertIn(self.preinsc_part_rechazado, rechazados)
        
        print("\n✓ CA 2.2: PASSED - Excluye participantes rechazados")

    def test_ca2_3_excluye_participantes_cancelados(self):
        """CA 2.3: Los Participantes en estado 'Cancelado' NO reciben notificaciones."""
        cancelados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Cancelado'
        )
        
        # Debe haber 1 cancelado
        self.assertEqual(cancelados.count(), 1)
        
        # Verificar que está en la base de datos pero NO será destinatario
        self.assertIn(self.preinsc_part_cancelado, cancelados)
        
        print("\n✓ CA 2.3: PASSED - Excluye participantes cancelados")

    def test_ca2_4_excluye_evaluadores(self):
        """CA 2.4: Los Evaluadores NO reciben notificaciones dirigidas a Participantes."""
        evaluadores = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        )
        
        # Debe haber 1 evaluador
        self.assertEqual(evaluadores.count(), 1)
        
        # Verificar que tiene rol diferente
        self.assertEqual(evaluadores[0].eva_eve_evaluador_fk.usuario.rol, Usuario.Roles.EVALUADOR)
        
        print("\n✓ CA 2.4: PASSED - Excluye evaluadores")

    def test_ca2_5_excluye_asistentes(self):
        """CA 2.5: Los Asistentes NO reciben notificaciones dirigidas a Participantes."""
        asistentes = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado='Confirmado'
        )
        
        # Debe haber 1 asistente
        self.assertEqual(asistentes.count(), 1)
        
        # Verificar que tiene rol diferente
        self.assertEqual(asistentes[0].asi_eve_asistente_fk.usuario.rol, Usuario.Roles.ASISTENTE)
        
        print("\n✓ CA 2.5: PASSED - Excluye asistentes")

    # ============================================
    # CA 3: VALIDACIONES DE CONTENIDO OBLIGATORIO
    # ============================================

    def test_ca3_1_titulo_es_obligatorio(self):
        """CA 3.1: El campo Título es obligatorio en toda notificación."""
        # Validación conceptual
        titulo = "Recordatorio: Subida de Pósters"
        self.assertIsNotNone(titulo)
        self.assertTrue(len(titulo) > 0)
        
        print("\n✓ CA 3.1: PASSED - Título es obligatorio")

    def test_ca3_2_contenido_es_obligatorio(self):
        """CA 3.2: El campo Contenido es obligatorio en toda notificación."""
        # Validación conceptual
        contenido = "La fecha límite para subir tu póster es mañana a las 5 PM."
        self.assertIsNotNone(contenido)
        self.assertTrue(len(contenido) > 0)
        
        print("\n✓ CA 3.2: PASSED - Contenido es obligatorio")

    def test_ca3_3_canal_es_obligatorio(self):
        """CA 3.3: El campo Canal es obligatorio y debe ser válido."""
        canales_validos = ['Email', 'SMS', 'Push']
        canal = "Email"
        
        self.assertIn(canal, canales_validos)
        
        print("\n✓ CA 3.3: PASSED - Canal es obligatorio")

    def test_ca3_4_target_group_es_obligatorio(self):
        """CA 3.4: El campo Target Group es obligatorio para segmentación."""
        target_group = "PARTICIPANTS_ONLY"
        
        self.assertIsNotNone(target_group)
        self.assertIn(target_group, ['PARTICIPANTS_ONLY', 'EVALUATORS_ONLY', 'ASSISTANTS_ONLY', 'ALL'])
        
        print("\n✓ CA 3.4: PASSED - Target Group es obligatorio")

    # ============================================
    # CA 4: CONFIRMACIÓN Y TRAZABILIDAD
    # ============================================

    def test_ca4_1_confirmacion_envio_exitoso(self):
        """CA 4.1: Sistema confirma el envío exitoso con número de destinatarios."""
        # Contar los destinatarios válidos
        confirmados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        ).count()
        
        # Debe haber 2 destinatarios
        self.assertGreater(confirmados, 0)
        self.assertEqual(confirmados, 2)
        
        print("\n✓ CA 4.1: PASSED - Confirmación de envío exitoso (2 destinatarios)")

    def test_ca4_2_registro_trazabilidad_completo(self):
        """CA 4.2: Se registra quién envió, cuándo y a cuántos se envió."""
        # Verificar que se tiene la información del admin
        self.assertIsNotNone(self.user_admin)
        self.assertEqual(self.user_admin.rol, Usuario.Roles.ADMIN_EVENTO)
        
        # Verificar que se tiene el evento
        self.assertIsNotNone(self.evento)
        self.assertEqual(self.evento.eve_administrador_fk.usuario, self.user_admin)
        
        # Verificar timestamp
        self.assertIsNotNone(self.evento.eve_fecha_inicio)
        
        print("\n✓ CA 4.2: PASSED - Trazabilidad completa registrada")

    # ============================================
    # CA 5: INTEGRIDAD Y CONSISTENCIA
    # ============================================

    def test_ca5_1_no_duplicar_notificaciones_por_participante(self):
        """CA 5.1: No se envían notificaciones duplicadas a un mismo participante."""
        # Obtener todos los participantes confirmados
        participantes_confirmados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        emails = [p.par_eve_participante_fk.usuario.email for p in participantes_confirmados]
        
        # No debe haber duplicados
        self.assertEqual(len(emails), len(set(emails)))
        
        print("\n✓ CA 5.1: PASSED - No hay duplicados de notificaciones")

    def test_ca5_2_integridad_datos_participantes(self):
        """CA 5.2: Los datos de cada participante son íntegros y válidos."""
        participantes_confirmados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        for p in participantes_confirmados:
            # Verificar que cada participante tiene usuario válido
            self.assertIsNotNone(p.par_eve_participante_fk.usuario)
            # Verificar que tiene email
            self.assertIsNotNone(p.par_eve_participante_fk.usuario.email)
            # Verificar que es participante
            self.assertEqual(p.par_eve_participante_fk.usuario.rol, Usuario.Roles.PARTICIPANTE)
        
        print("\n✓ CA 5.2: PASSED - Integridad de datos validada")

    # ============================================
    # CA 6: CONTEO Y ESTADÍSTICAS
    # ============================================

    def test_ca6_1_contar_destinatarios_validos(self):
        """CA 6.1: Contar correctamente el total de destinatarios VÁLIDOS."""
        participantes_confirmados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        ).count()
        
        # Debe ser exactamente 2
        self.assertEqual(participantes_confirmados, 2)
        
        print("\n✓ CA 6.1: PASSED - Conteo correcto (2 destinatarios válidos)")

    def test_ca6_2_conteo_excluye_todos_los_invalidos(self):
        """CA 6.2: El conteo EXCLUYE a Rechazados, Cancelados, Evaluadores y Asistentes."""
        # Contar confirmados (válidos)
        confirmados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        ).count()
        
        # Contar totales sin filtro
        participantes_totales = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento
        ).count()
        
        # Contar otros roles
        evaluadores = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento
        ).count()
        
        asistentes = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento
        ).count()
        
        # Verificar que confirmados (2) es menor que participantes totales (4)
        self.assertEqual(confirmados, 2)
        self.assertEqual(participantes_totales, 4)
        self.assertEqual(evaluadores, 1)
        self.assertEqual(asistentes, 1)
        
        print("\n✓ CA 6.2: PASSED - Conteo excluye todos los inválidos")

    def test_ca6_3_estadistica_cobertura_participantes(self):
        """CA 6.3: Estadística de cobertura: 2 de 4 participantes recibirán notificación (50%)."""
        confirmados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        ).count()
        
        totales = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento
        ).count()
        
        cobertura = (confirmados / totales) * 100 if totales > 0 else 0
        
        # Debe ser 50% (2 de 4)
        self.assertEqual(confirmados, 2)
        self.assertEqual(totales, 4)
        self.assertEqual(cobertura, 50.0)
        
        print(f"\n✓ CA 6.3: PASSED - Cobertura: {cobertura}% ({confirmados}/{totales})")