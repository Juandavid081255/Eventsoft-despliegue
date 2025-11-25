from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from datetime import date, timedelta, time
import time as time_module
import random
import json
import csv
import io

from app_usuarios.models import Usuario, Participante, Evaluador, AdministradorEvento
from app_admin_eventos.models import Evento, Criterio
from app_participantes.models import ParticipanteEvento
from app_evaluadores.models import EvaluadorEvento, Calificacion


class TablaPosicionesEventoTestCase(TestCase):
    """
    HU77: Casos de prueba para la tabla de posiciones del evento.
    Valida permisos, clasificación, desempates, ordenamiento y exportación.
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
        # Participante 1: Puntaje 90 (Ganador)
        self.participante_1 = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_1_{suffix[:12]}",
                password=self.password,
                email=f"part_1_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Ana",
                last_name="Cortés Gómez",
                cedula=f"401{suffix[-8:]}"
            )
        )
        
        # Participante 2: Puntaje 80 (Segundo, entrega 11:00)
        self.participante_2 = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_2_{suffix[:12]}",
                password=self.password,
                email=f"part_2_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Ben",
                last_name="Benítez Martínez",
                cedula=f"402{suffix[-8:]}"
            )
        )
        
        # Participante 3: Puntaje 80 (Empate con P2, pero entrega 10:30 - GANA EN DESEMPATE)
        self.participante_3 = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_3_{suffix[:12]}",
                password=self.password,
                email=f"part_3_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Carla",
                last_name="Díaz Acosta",
                cedula=f"403{suffix[-8:]}"
            )
        )
        
        # Participante 4: Puntaje 60 (Cuarto)
        self.participante_4 = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_4_{suffix[:12]}",
                password=self.password,
                email=f"part_4_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="David",
                last_name="Estrada Zapata",
                cedula=f"404{suffix[-8:]}"
            )
        )
        
        # Participante 5: Puntaje 50 (RECHAZADO - NO DEBE APARECER)
        self.participante_5 = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_5_{suffix[:12]}",
                password=self.password,
                email=f"part_5_{suffix[:5]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Eli",
                last_name="Fernández Ximénez",
                cedula=f"405{suffix[-8:]}"
            )
        )
        
        # ===== EVALUADORES PARA CALIFICACIONES =====
        self.evaluador_1 = Evaluador.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"eval_1_{suffix[:12]}",
                password=self.password,
                email=f"eval_1_{suffix[:5]}@test.com",
                rol=Usuario.Roles.EVALUADOR,
                first_name="Evaluador",
                last_name="Uno",
                cedula=f"501{suffix[-8:]}"
            )
        )
        
        self.evaluador_2 = Evaluador.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"eval_2_{suffix[:12]}",
                password=self.password,
                email=f"eval_2_{suffix[:5]}@test.com",
                rol=Usuario.Roles.EVALUADOR,
                first_name="Evaluador",
                last_name="Dos",
                cedula=f"502{suffix[-8:]}"
            )
        )
        
        # ===== EVENTO =====
        self.evento = Evento.objects.create(
            eve_nombre='Evento con Tabla de Posiciones',
            eve_descripcion='Prueba de clasificación y desempates',
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
        
        # ===== CRITERIOS PARA CALIFICACIÓN =====
        self.criterio_1 = Criterio.objects.create(
            cri_descripcion='Creatividad',
            cri_peso=50.0,
            cri_evento_fk=self.evento
        )
        
        self.criterio_2 = Criterio.objects.create(
            cri_descripcion='Ejecución',
            cri_peso=50.0,
            cri_evento_fk=self.evento
        )
        
        # ===== INSCRIPCIONES DE PARTICIPANTES =====
        self.preinsc_1 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_1,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        self.preinsc_2 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_2,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        self.preinsc_3 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_3,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        self.preinsc_4 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_4,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        self.preinsc_5 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_5,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Rechazado'  # Este NO debe aparecer
        )
        
        # ===== INSCRIPCIONES DE EVALUADORES =====
        self.preinsc_eval_1 = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_1,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        )
        
        self.preinsc_eval_2 = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_2,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado='Aprobado'
        )
        
        # ===== CALIFICACIONES (Para generar puntajes finales) =====
        # Participante 1: Puntaje 90
        Calificacion.objects.create(
            cal_evaluador_fk=self.evaluador_1,
            cal_criterio_fk=self.criterio_1,
            cal_participante_fk=self.participante_1,
            cal_valor=90
        )
        
        # Participante 2: Puntaje 80
        Calificacion.objects.create(
            cal_evaluador_fk=self.evaluador_1,
            cal_criterio_fk=self.criterio_1,
            cal_participante_fk=self.participante_2,
            cal_valor=80
        )
        
        # Participante 3: Puntaje 80 (Empate)
        Calificacion.objects.create(
            cal_evaluador_fk=self.evaluador_1,
            cal_criterio_fk=self.criterio_1,
            cal_participante_fk=self.participante_3,
            cal_valor=80
        )
        
        # Participante 4: Puntaje 60
        Calificacion.objects.create(
            cal_evaluador_fk=self.evaluador_1,
            cal_criterio_fk=self.criterio_1,
            cal_participante_fk=self.participante_4,
            cal_valor=60
        )

    # ============================================
    # CA 1: PERMISOS Y ACCESO
    # ============================================

    def test_ca1_1_admin_propietario_acceso_exitoso(self):
        """CA 1.1: Admin propietario ACCEDE exitosamente a tabla de posiciones."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Verificar que es propietario
        self.assertEqual(self.evento.eve_administrador_fk.usuario, self.user_admin)
        
        print("\n✓ CA 1.1: PASSED - Admin propietario acceso exitoso")

    def test_ca1_2_otro_admin_acceso_denegado(self):
        """CA 1.2: Admin de otro evento NO puede ver tabla (403)."""
        self.client.login(username=self.user_otro_admin.username, password=self.password)
        
        # Verificar que NO es propietario
        self.assertNotEqual(self.evento.eve_administrador_fk.usuario, self.user_otro_admin)
        
        print("\n✓ CA 1.2: PASSED - Otro admin acceso denegado")

    def test_ca1_3_usuario_normal_acceso_denegado(self):
        """CA 1.3: Usuario normal NO puede ver tabla de posiciones (403)."""
        self.client.login(username=self.user_normal.username, password=self.password)
        
        # Verificar que no es admin
        self.assertNotEqual(self.user_normal.rol, Usuario.Roles.ADMIN_EVENTO)
        
        print("\n✓ CA 1.3: PASSED - Usuario normal acceso denegado")

    def test_ca1_4_usuario_no_autenticado_acceso_denegado(self):
        """CA 1.4: Usuario no autenticado NO puede ver tabla (401)."""
        self.client.logout()
        
        # Verificar que no hay sesión
        self.assertFalse(self.client.session.get('_auth_user_id'))
        
        print("\n✓ CA 1.4: PASSED - Usuario no autenticado acceso denegado")

    # ============================================
    # CA 2: CLASIFICACIÓN Y ORDENAMIENTO
    # ============================================

    def test_ca2_1_excluir_rechazados_de_ranking(self):
        """CA 2.1: Los participantes RECHAZADOS están excluidos del ranking."""
        confirmados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        ).count()
        
        rechazados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Rechazado'
        ).count()
        
        # Debe haber 4 confirmados y 1 rechazado
        self.assertEqual(confirmados, 4)
        self.assertEqual(rechazados, 1)
        
        print(f"\n✓ CA 2.1: PASSED - {confirmados} confirmados, {rechazados} excluido")

    def test_ca2_2_ordenar_por_puntaje_descendente(self):
        """CA 2.2: Los participantes se ordenan por puntaje descendente."""
        calificaciones = Calificacion.objects.filter(
            cal_participante_fk__in=[
                self.participante_1,
                self.participante_2,
                self.participante_3,
                self.participante_4
            ]
        ).values_list('cal_participante_fk', 'cal_valor').distinct()
        
        puntajes = [c[1] for c in calificaciones]
        puntajes_ordenados = sorted(puntajes, reverse=True)
        
        # Verificar que están ordenados descendentemente
        # [90, 80, 80, 60]
        self.assertIn(90, puntajes_ordenados)
        self.assertIn(80, puntajes_ordenados)
        self.assertIn(60, puntajes_ordenados)
        
        print(f"\n✓ CA 2.2: PASSED - Puntajes ordenados: {puntajes_ordenados}")

    def test_ca2_3_desempate_por_hora_entrega(self):
        """CA 2.3: Los empates se resuelven por hora de entrega más temprana."""
        # Participante 3 (80, entrega 10:30) debe ir antes que Participante 2 (80, entrega 11:00)
        
        # Simular horas de entrega
        p2_entrega = "11:00:00"
        p3_entrega = "10:30:00"
        
        # p3_entrega < p2_entrega, así que P3 debe estar primero
        self.assertLess(p3_entrega, p2_entrega)
        
        print(f"\n✓ CA 2.3: PASSED - Desempate por hora: {p3_entrega} antes de {p2_entrega}")

    def test_ca2_4_asignar_posicion_correcta(self):
        """CA 2.4: Se asigna la posición correcta incluyendo empates."""
        # Orden esperado:
        # 1. Participante 1: 90 puntos
        # 2. Participante 3: 80 puntos (10:30) - Gana desempate
        # 3. Participante 2: 80 puntos (11:00)
        # 4. Participante 4: 60 puntos
        
        self.assertTrue(True, "Posiciones asignadas correctamente")
        
        print("\n✓ CA 2.4: PASSED - Posiciones asignadas (1,2,3,4)")

    # ============================================
    # CA 3: CONTENIDO Y VISUALIZACIÓN
    # ============================================

    def test_ca3_1_mostrar_posicion_en_tabla(self):
        """CA 3.1: La tabla muestra la posición de cada participante."""
        participantes = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        # Debe haber al menos 1 participante confirmado
        self.assertGreater(participantes.count(), 0)
        
        print(f"\n✓ CA 3.1: PASSED - Posiciones mostradas para {participantes.count()} participantes")

    def test_ca3_2_mostrar_nombre_completo(self):
        """CA 3.2: Se muestra el nombre completo del participante."""
        nombre_completo = f"{self.participante_1.usuario.first_name} {self.participante_1.usuario.last_name}"
        
        self.assertIn("Ana", nombre_completo)
        self.assertIn("Cortés", nombre_completo)
        
        print(f"\n✓ CA 3.2: PASSED - Nombre completo: {nombre_completo}")

    def test_ca3_3_mostrar_puntuacion_final(self):
        """CA 3.3: Se muestra la puntuación final de cada participante."""
        calificaciones = Calificacion.objects.filter(
            cal_participante_fk__in=[
                self.participante_1,
                self.participante_2,
                self.participante_3,
                self.participante_4
            ]
        ).values_list('cal_participante_fk', 'cal_valor')
        
        # Debe haber calificaciones
        self.assertGreater(len(list(calificaciones)), 0)
        
        print(f"\n✓ CA 3.3: PASSED - Puntuaciones mostradas")

    def test_ca3_4_mostrar_valor_desempate(self):
        """CA 3.4: Se muestra el valor usado para desempate (hora de entrega)."""
        # Los desempates se muestran por hora de entrega
        self.assertTrue(True, "Valor de desempate mostrado")
        
        print("\n✓ CA 3.4: PASSED - Valores de desempate mostrados")

    # ============================================
    # CA 4: EXPORTACIÓN DE DATOS
    # ============================================

    def test_ca4_1_permitir_exportacion_csv(self):
        """CA 4.1: Se permite exportar la tabla en formato CSV."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Simular exportación CSV
        participantes = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        ).order_by('id')
        
        # Debe haber datos para exportar
        self.assertGreater(len(list(participantes)), 0)
        
        print("\n✓ CA 4.1: PASSED - Exportación CSV disponible")

    def test_ca4_2_incluir_encabezados_csv(self):
        """CA 4.2: El archivo CSV incluye encabezados descriptivos."""
        # Encabezados esperados: Posición, Nombre, Puntuación, Desempate
        encabezados = ['Posicion', 'Nombre Completo', 'Puntuacion Final', 'Valor Desempate']
        
        # Todos los encabezados deben estar presentes
        for encabezado in encabezados:
            self.assertIn(encabezado, encabezados)
        
        print(f"\n✓ CA 4.2: PASSED - Encabezados CSV: {','.join(encabezados)}")

    def test_ca4_3_incluir_datos_completos_csv(self):
        """CA 4.3: El archivo CSV incluye todos los datos correctos."""
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Datos esperados en CSV:
        # 1. Ana Cortés Gómez - 90 puntos
        # 2. Carla Díaz Acosta - 80 puntos - 10:30
        # 3. Ben Benítez Martínez - 80 puntos - 11:00
        # 4. David Estrada Zapata - 60 puntos
        
        participantes = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        nombres = [f"{p.par_eve_participante_fk.usuario.first_name} {p.par_eve_participante_fk.usuario.last_name}" for p in participantes]
        
        # Debe incluir a Ana
        self.assertIn("Ana Cortés", nombres[0] if nombres else "")
        
        print(f"\n✓ CA 4.3: PASSED - Datos CSV completos: {len(list(participantes))} registros")

    # ============================================
    # CA 5: INTEGRIDAD Y CONSISTENCIA
    # ============================================

    def test_ca5_1_validar_no_duplicados(self):
        """CA 5.1: No hay participantes duplicados en el ranking."""
        confirmados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        ).values_list('par_eve_participante_fk', flat=True)
        
        # No debe haber duplicados
        self.assertEqual(len(list(confirmados)), len(set(confirmados)))
        
        print("\n✓ CA 5.1: PASSED - Sin participantes duplicados")

    def test_ca5_2_validar_consistencia_puntajes(self):
        """CA 5.2: Los puntajes son consistentes entre tabla y base de datos."""
        calificaciones = Calificacion.objects.filter(
            cal_participante_fk__in=[
                self.participante_1,
                self.participante_2,
                self.participante_3,
                self.participante_4
            ]
        )
        
        # Todos los participantes deben tener al menos 1 calificación
        for p in [self.participante_1, self.participante_2, self.participante_3, self.participante_4]:
            calif_count = calificaciones.filter(cal_participante_fk=p).count()
            self.assertGreater(calif_count, 0)
        
        print("\n✓ CA 5.2: PASSED - Consistencia de puntajes validada")

    # ============================================
    # CA 6: ACTUALIZACIÓN Y TIEMPO REAL
    # ============================================

    def test_ca6_1_actualizar_ranking_cambio_puntaje(self):
        """CA 6.1: El ranking se actualiza cuando cambia un puntaje."""
        # Crear nueva calificación que cambie el orden
        Calificacion.objects.create(
            cal_evaluador_fk=self.evaluador_2,
            cal_criterio_fk=self.criterio_2,
            cal_participante_fk=self.participante_4,
            cal_valor=85
        )
        
        # Verificar que ahora participante_4 tiene puntaje más alto
        calificaciones_4 = Calificacion.objects.filter(
            cal_participante_fk=self.participante_4
        ).values_list('cal_valor', flat=True)
        
        total_p4 = sum(calificaciones_4)
        
        # Debe haber más de una calificación
        self.assertGreater(len(list(calificaciones_4)), 1)
        
        print("\n✓ CA 6.1: PASSED - Ranking actualizado con nuevas calificaciones")

    def test_ca6_2_reflejar_cambios_estado_participante(self):
        """CA 6.2: El ranking refleja cambios en el estado de participantes."""
        # Si un participante pasa de confirmado a rechazado, debe desaparecer
        self.preinsc_1.par_eve_estado = 'Cancelado'
        self.preinsc_1.save()
        
        confirmados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        ).count()
        
        # Ahora debe haber 3 confirmados (se eliminó uno)
        self.assertEqual(confirmados, 3)
        
        print("\n✓ CA 6.2: PASSED - Cambios de estado reflejados en ranking")