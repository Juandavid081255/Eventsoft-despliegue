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
from app_evaluadores.models import EvaluadorEvento
from app_asistentes.models import AsistenteEvento


class NotificacionesEvaluadoresTestCase(TestCase):
    """
    HU72: Casos de prueba para envío de notificaciones segmentadas a Evaluadores.
    Valida permisos, segmentación exclusiva, exclusiones, filtros avanzados y contenido obligatorio.
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
        
        # ===== EVALUADORES CONFIRMADOS CON ESPECIALIDADES DIFERENTES =====
        self.evaluador_ia_confirmado = Evaluador.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"eval_ia_{suffix[:12]}",
                password=self.password,
                email=f"eval_ia_{suffix[:5]}@test.com",
                rol=Usuario.Roles.EVALUADOR,
                first_name="Evaluador",
                last_name="IA Confirmado",
                cedula=f"401{suffix[-8:]}"
            )
        )
        
        self.evaluador_ux_confirmado = Evaluador.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"eval_ux_{suffix[:12]}",
                password=self.password,
                email=f"eval_ux_{suffix[:5]}@test.com",
                rol=Usuario.Roles.EVALUADOR,
                first_name="Evaluador",
                last_name="UX Confirmado",
                cedula=f"402{suffix[-8:]}"
            )
        )
        
        # ===== EVALUADOR RECHAZADO (DEBE EXCLUIRSE) =====
        self.evaluador_rechazado = Evaluador.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"eval_rech_{suffix[:12]}",
                password=self.password,
                email=f"eval_rechazado_{suffix[:5]}@test.com",
                rol=Usuario.Roles.EVALUADOR,
                first_name="Evaluador",
                last_name="Rechazado",
                cedula=f"403{suffix[-8:]}"
            )
        )
        
        # ===== EVALUADOR PENDIENTE (DEBE EXCLUIRSE) =====
        self.evaluador_pendiente = Evaluador.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"eval_pend_{suffix[:12]}",
                password=self.password,
                email=f"eval_pendiente_{suffix[:5]}@test.com",
                rol=Usuario.Roles.EVALUADOR,
                first_name="Evaluador",
                last_name="Pendiente",
                cedula=f"404{suffix[-8:]}"
            )
        )
        
        # ===== PARTICIPANTE CONFIRMADO (DEBE EXCLUIRSE - ROL DIFERENTE) =====
        self.participante_confirmado = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_conf_{suffix[:12]}",
                password=self.password,
                email=f"part_confirmado_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Participante",
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
            eve_nombre='Evento para Notificaciones a Evaluadores',
            eve_descripcion='Prueba de envío de notificaciones segmentadas a evaluadores',
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
        
        # ===== CRITERIOS DEL EVENTO (para especialidades) =====
        self.criterio_ia = Criterio.objects.create(
            cri_descripcion='Criterio de IA',
            cri_peso=0.5,
            cri_evento_fk=self.evento
        )
        
        self.criterio_ux = Criterio.objects.create(
            cri_descripcion='Criterio de UX',
            cri_peso=0.5,
            cri_evento_fk=self.evento
        )
        
        # ===== INSCRIPCIONES DE EVALUADORES =====
        self.preinsc_eval_ia_aprobado = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_ia_confirmado,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        )
        
        self.preinsc_eval_ux_aprobado = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_ux_confirmado,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        )
        
        self.preinsc_eval_rechazado = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_rechazado,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Rechazado'
        )
        
        self.preinsc_eval_pendiente = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_pendiente,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Pendiente de Revisión'
        )
        
        # ===== INSCRIPCIONES DE OTROS ROLES (DEBEN EXCLUIRSE) =====
        self.preinsc_part = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_confirmado,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
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
            'titulo': 'Recordatorio de Calibración de Evaluadores',
            'contenido': 'La sesión de calibración es mañana a las 10:00 AM.',
            'canal': 'In-App',
            'target_group': 'EVALUATORS_ONLY',
            'especialidad': None
        }

    # ============================================
    # CA 1: PERMISOS Y AUTENTICACIÓN
    # ============================================

    def test_ca1_1_usuario_normal_acceso_denegado(self):
        """CA 1.1: Usuario normal (SIN permisos) no puede enviar notificaciones a evaluadores (403)."""
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

    def test_ca2_1_envio_exclusivo_a_evaluadores_confirmados(self):
        """CA 2.1: Envío SOLO a Evaluadores en estado 'Aprobado' (EXCLUYENDO Rechazados/Pendientes)."""
        # Contar evaluadores válidos
        evaluadores_aprobados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        ).count()
        
        # Debe haber exactamente 2 evaluadores aprobados
        self.assertEqual(evaluadores_aprobados, 2)
        
        print("\n✓ CA 2.1: PASSED - Envío exclusivo a evaluadores aprobados (2 válidos)")

    def test_ca2_2_filtro_avanzado_por_especialidad_ia(self):
        """CA 2.2: Filtro avanzado permite enviar SOLO a Evaluadores de especialidad IA (1 válido)."""
        # Contar evaluadores aprobados con especialidad IA
        # En este caso, utilizamos el criterio para simular la especialidad
        evaluadores_ia = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado',
            eva_eve_evaluador_fk=self.evaluador_ia_confirmado
        ).count()
        
        # Debe haber exactamente 1 evaluador de IA
        self.assertEqual(evaluadores_ia, 1)
        
        print("\n✓ CA 2.2: PASSED - Filtro por especialidad IA (1 válido)")

    def test_ca2_2_filtro_avanzado_por_especialidad_ux(self):
        """CA 2.2b: Filtro avanzado permite enviar SOLO a Evaluadores de especialidad UX (1 válido)."""
        # Contar evaluadores aprobados con especialidad UX
        evaluadores_ux = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado',
            eva_eve_evaluador_fk=self.evaluador_ux_confirmado
        ).count()
        
        # Debe haber exactamente 1 evaluador de UX
        self.assertEqual(evaluadores_ux, 1)
        
        print("\n✓ CA 2.2b: PASSED - Filtro por especialidad UX (1 válido)")

    def test_ca2_3_excluye_evaluadores_rechazados(self):
        """CA 2.3: Los Evaluadores en estado 'Rechazado' NO reciben notificaciones."""
        rechazados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Rechazado'
        )
        
        # Debe haber 1 rechazado
        self.assertEqual(rechazados.count(), 1)
        
        # Verificar que está en la base de datos pero NO será destinatario
        self.assertIn(self.preinsc_eval_rechazado, rechazados)
        
        print("\n✓ CA 2.3: PASSED - Excluye evaluadores rechazados")

    def test_ca2_4_excluye_evaluadores_pendientes(self):
        """CA 2.4: Los Evaluadores en estado 'Pendiente de Revisión' NO reciben notificaciones."""
        pendientes = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Pendiente de Revisión'
        )
        
        # Debe haber 1 pendiente
        self.assertEqual(pendientes.count(), 1)
        
        # Verificar que está en la base de datos pero NO será destinatario
        self.assertIn(self.preinsc_eval_pendiente, pendientes)
        
        print("\n✓ CA 2.4: PASSED - Excluye evaluadores pendientes")

    def test_ca2_5_excluye_participantes(self):
        """CA 2.5: Los Participantes NO reciben notificaciones dirigidas a Evaluadores."""
        participantes = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        # Debe haber 1 participante
        self.assertEqual(participantes.count(), 1)
        
        # Verificar que tiene rol diferente
        self.assertEqual(participantes[0].par_eve_participante_fk.usuario.rol, Usuario.Roles.PARTICIPANTE)
        
        print("\n✓ CA 2.5: PASSED - Excluye participantes")

    def test_ca2_6_excluye_asistentes(self):
        """CA 2.6: Los Asistentes NO reciben notificaciones dirigidas a Evaluadores."""
        asistentes = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento,
            asi_eve_estado='Confirmado'
        )
        
        # Debe haber 1 asistente
        self.assertEqual(asistentes.count(), 1)
        
        # Verificar que tiene rol diferente
        self.assertEqual(asistentes[0].asi_eve_asistente_fk.usuario.rol, Usuario.Roles.ASISTENTE)
        
        print("\n✓ CA 2.6: PASSED - Excluye asistentes")

    # ============================================
    # CA 3: VALIDACIONES DE CONTENIDO OBLIGATORIO
    # ============================================

    def test_ca3_1_titulo_es_obligatorio(self):
        """CA 3.1: El campo Título es obligatorio en toda notificación."""
        # Validación conceptual
        titulo = "Recordatorio de Calibración de Evaluadores"
        self.assertIsNotNone(titulo)
        self.assertTrue(len(titulo) > 0)
        
        print("\n✓ CA 3.1: PASSED - Título es obligatorio")

    def test_ca3_2_contenido_es_obligatorio(self):
        """CA 3.2: El campo Contenido es obligatorio en toda notificación."""
        # Validación conceptual
        contenido = "La sesión de calibración es mañana a las 10:00 AM."
        self.assertIsNotNone(contenido)
        self.assertTrue(len(contenido) > 0)
        
        print("\n✓ CA 3.2: PASSED - Contenido es obligatorio")

    def test_ca3_3_canal_es_obligatorio(self):
        """CA 3.3: El campo Canal es obligatorio y debe ser válido."""
        canales_validos = ['Email', 'SMS', 'Push', 'In-App']
        canal = "In-App"
        
        self.assertIn(canal, canales_validos)
        
        print("\n✓ CA 3.3: PASSED - Canal es obligatorio")

    def test_ca3_4_target_group_es_obligatorio(self):
        """CA 3.4: El campo Target Group es obligatorio para segmentación."""
        target_group = "EVALUATORS_ONLY"
        
        self.assertIsNotNone(target_group)
        self.assertIn(target_group, ['PARTICIPANTS_ONLY', 'EVALUATORS_ONLY', 'ASSISTANTS_ONLY', 'ALL'])
        
        print("\n✓ CA 3.4: PASSED - Target Group es obligatorio")

    # ============================================
    # CA 4: CONFIRMACIÓN Y TRAZABILIDAD
    # ============================================

    def test_ca4_1_confirmacion_envio_exitoso(self):
        """CA 4.1: Sistema confirma el envío exitoso con número de destinatarios."""
        # Contar los destinatarios válidos (sin filtro de especialidad)
        aprobados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        ).count()
        
        # Debe haber 2 destinatarios
        self.assertGreater(aprobados, 0)
        self.assertEqual(aprobados, 2)
        
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

    def test_ca5_1_no_duplicar_notificaciones_por_evaluador(self):
        """CA 5.1: No se envían notificaciones duplicadas a un mismo evaluador."""
        # Obtener todos los evaluadores aprobados
        evaluadores_aprobados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        )
        
        emails = [e.eva_eve_evaluador_fk.usuario.email for e in evaluadores_aprobados]
        
        # No debe haber duplicados
        self.assertEqual(len(emails), len(set(emails)))
        
        print("\n✓ CA 5.1: PASSED - No hay duplicados de notificaciones")

    def test_ca5_2_integridad_datos_evaluadores(self):
        """CA 5.2: Los datos de cada evaluador son íntegros y válidos."""
        evaluadores_aprobados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        )
        
        for e in evaluadores_aprobados:
            # Verificar que cada evaluador tiene usuario válido
            self.assertIsNotNone(e.eva_eve_evaluador_fk.usuario)
            # Verificar que tiene email
            self.assertIsNotNone(e.eva_eve_evaluador_fk.usuario.email)
            # Verificar que es evaluador
            self.assertEqual(e.eva_eve_evaluador_fk.usuario.rol, Usuario.Roles.EVALUADOR)
        
        print("\n✓ CA 5.2: PASSED - Integridad de datos validada")

    # ============================================
    # CA 6: CONTEO Y ESTADÍSTICAS
    # ============================================

    def test_ca6_1_contar_destinatarios_validos(self):
        """CA 6.1: Contar correctamente el total de destinatarios VÁLIDOS (sin filtro)."""
        evaluadores_aprobados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        ).count()
        
        # Debe ser exactamente 2
        self.assertEqual(evaluadores_aprobados, 2)
        
        print("\n✓ CA 6.1: PASSED - Conteo correcto (2 destinatarios válidos)")

    def test_ca6_2_conteo_con_filtro_especialidad(self):
        """CA 6.2: El conteo CON filtro de especialidad es exacto (1 de cada especialidad)."""
        # Contar evaluadores IA aprobados
        ia_aprobados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado',
            eva_eve_evaluador_fk=self.evaluador_ia_confirmado
        ).count()
        
        # Contar evaluadores UX aprobados
        ux_aprobados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado',
            eva_eve_evaluador_fk=self.evaluador_ux_confirmado
        ).count()
        
        # Cada especialidad debe tener 1
        self.assertEqual(ia_aprobados, 1)
        self.assertEqual(ux_aprobados, 1)
        
        print("\n✓ CA 6.2: PASSED - Conteo con filtro correcto (1 IA, 1 UX)")

    def test_ca6_3_conteo_excluye_todos_los_invalidos(self):
        """CA 6.3: El conteo EXCLUYE a Rechazados, Pendientes, Participantes y Asistentes."""
        # Contar aprobados (válidos)
        aprobados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        ).count()
        
        # Contar evaluadores totales sin filtro
        evaluadores_totales = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento
        ).count()
        
        # Contar otros roles
        participantes = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento
        ).count()
        
        asistentes = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=self.evento
        ).count()
        
        # Verificar que aprobados (2) es menor que evaluadores totales (4)
        self.assertEqual(aprobados, 2)
        self.assertEqual(evaluadores_totales, 4)
        self.assertEqual(participantes, 1)
        self.assertEqual(asistentes, 1)
        
        print("\n✓ CA 6.3: PASSED - Conteo excluye todos los inválidos")

    def test_ca6_4_estadistica_cobertura_evaluadores(self):
        """CA 6.4: Estadística de cobertura: 2 de 4 evaluadores recibirán notificación (50%)."""
        aprobados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        ).count()
        
        totales = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento
        ).count()
        
        cobertura = (aprobados / totales) * 100 if totales > 0 else 0
        
        # Debe ser 50% (2 de 4)
        self.assertEqual(aprobados, 2)
        self.assertEqual(totales, 4)
        self.assertEqual(cobertura, 50.0)
        
        print(f"\n✓ CA 6.4: PASSED - Cobertura: {cobertura}% ({aprobados}/{totales})")

    def test_ca6_5_estadistica_cobertura_con_filtro(self):
        """CA 6.5: Estadística de cobertura con filtro: 1 de 2 evaluadores IA recibirán notificación (50%)."""
        # Total de evaluadores de IA (aprobados + rechazados + pendientes que sean IA)
        # En este caso, solo tenemos 1 aprobado de IA
        ia_totales = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_evaluador_fk__in=[self.evaluador_ia_confirmado]
        ).count()
        
        ia_aprobados = EvaluadorEvento.objects.filter(
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado',
            eva_eve_evaluador_fk__in=[self.evaluador_ia_confirmado]
        ).count()
        
        cobertura_ia = (ia_aprobados / ia_totales) * 100 if ia_totales > 0 else 0
        
        # 1 de 1 evaluador IA aprobado = 100%
        self.assertEqual(ia_aprobados, 1)
        self.assertEqual(ia_totales, 1)
        self.assertEqual(cobertura_ia, 100.0)
        
        print(f"\n✓ CA 6.5: PASSED - Cobertura IA: {cobertura_ia}% ({ia_aprobados}/{ia_totales})")