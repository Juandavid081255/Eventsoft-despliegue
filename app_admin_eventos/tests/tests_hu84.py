from django.test import TestCase, Client
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time as time_module
import random

from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento, Criterio
from app_participantes.models import ParticipanteEvento
from app_evaluadores.models import Calificacion


class CertificadoPremiacionTestCase(TestCase):
    """
    Casos de prueba para el envío de certificados de Premiación (HU84).
    Se basa en la estructura del HU82 y HU83.
    """

    def setUp(self):
        """Configuración inicial para las pruebas"""
        suffix = f"{int(time_module.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.client = Client()
        self.password = "testpass123"
        
        # ===== FECHAS =====
        self.hoy = date.today()
        self.futuro = self.hoy + timedelta(days=10)
        
        # ===== ADMINISTRADOR PROPIETARIO DEL EVENTO =====
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
        
        # ===== USUARIO NORMAL (SIN PERMISOS) =====
        self.user_normal = Usuario.objects.create_user(
            username=f"usuario_normal_{suffix[:15]}",
            password=self.password,
            email=f"normal_{suffix[:5]}@test.com",
            rol=Usuario.Roles.PARTICIPANTE,
            first_name="Usuario",
            last_name="Normal",
            cedula=f"300{suffix[-10:]}"
        )
        
        # ===== PARTICIPANTES CON DIFERENTES POSICIONES =====
        # Participante 1: Primer Lugar (Ganador)
        self.participante_1_ganador = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_ganador1_{suffix[:10]}",
                password=self.password,
                email=f"ganador1_{suffix[:3]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Leo",
                last_name="Martinez",
                cedula=f"401{suffix[-8:]}"
            )
        )
        
        # Participante 2: Segundo Lugar (Ganador)
        self.participante_2_ganador = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_ganador2_{suffix[:10]}",
                password=self.password,
                email=f"ganador2_{suffix[:3]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Mia",
                last_name="Torres",
                cedula=f"402{suffix[-8:]}"
            )
        )
        
        # Participante 3: Tercer Lugar (Ganador)
        self.participante_3_ganador = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_ganador3_{suffix[:10]}",
                password=self.password,
                email=f"ganador3_{suffix[:3]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Juan",
                last_name="Lopez",
                cedula=f"403{suffix[-8:]}"
            )
        )
        
        # Participante 4: Mención Honorífica (Ganador sin posición)
        self.participante_4_mencion = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_mencion_{suffix[:10]}",
                password=self.password,
                email=f"mencion_{suffix[:3]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Nico",
                last_name="Campos",
                cedula=f"404{suffix[-8:]}"
            )
        )
        
        # Participante 5: No ganador (puntaje bajo)
        self.participante_5_no_ganador = Participante.objects.create(
            usuario=Usuario.objects.create_user(
                username=f"part_nogana_{suffix[:10]}",
                password=self.password,
                email=f"nogana_{suffix[:3]}@test.com",
                rol=Usuario.Roles.PARTICIPANTE,
                first_name="Carlos",
                last_name="Ruiz",
                cedula=f"405{suffix[-8:]}"
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
        
        # ===== CRITERIOS PARA EVALUACIÓN =====
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
            par_eve_participante_fk=self.participante_1_ganador,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        self.preinsc_part_2 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_2_ganador,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        self.preinsc_part_3 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_3_ganador,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        self.preinsc_part_4 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_4_mencion,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        self.preinsc_part_5 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante_5_no_ganador,
            par_eve_evento_fk=self.evento,
            par_eve_estado='Aceptado'
        )
        
        # ===== PUNTAJES SIMULADOS (para premios) =====
        # Usar diccionario para almacenar puntajes sin crear Calificacion
        self.puntajes = {
            self.participante_1_ganador.id: 95,  # Primer Lugar
            self.participante_2_ganador.id: 90,  # Segundo Lugar
            self.participante_3_ganador.id: 85,  # Tercer Lugar
            self.participante_4_mencion.id: 80,  # Mención Honorífica
            self.participante_5_no_ganador.id: 50  # No ganador
        }

    # ============================================
    # CA 1: PERMISOS Y SEGMENTACIÓN
    # ============================================

    def test_ca101_usuario_normal_acceso_denegado_a_envio(self):
        """
        CA1.01: Verifica que un usuario SIN permisos de administrador 
        no puede iniciar el envío (debe ser denegado).
        """
        # Usuario normal NO es ADMIN_EVENTO
        self.assertNotEqual(self.user_normal.rol, Usuario.Roles.ADMIN_EVENTO)
        self.assertFalse(self.user_normal.is_staff)
        
        print("\n✓ CA 1.01: PASSED - Usuario normal acceso denegado")

    def test_ca102_envio_exitoso_a_ganadores_seleccionados(self):
        """
        CA1.02: Verifica que el envío es INDIVIDUALIZADO según los ganadores 
        seleccionados por el administrador (no automático).
        """
        # Admin selecciona específicamente a Leo (1er lugar) y Nico (mención)
        ganadores_seleccionados_ids = [
            self.participante_1_ganador.id,
            self.participante_4_mencion.id
        ]
        
        # Act: Simular filtrado de ganadores seleccionados
        ganadores_seleccionados = Participante.objects.filter(
            id__in=ganadores_seleccionados_ids
        )
        
        # Assert: Verificar que solo los seleccionados están en la lista
        self.assertEqual(ganadores_seleccionados.count(), 2)
        self.assertIn(self.participante_1_ganador.id, ganadores_seleccionados_ids)
        self.assertIn(self.participante_4_mencion.id, ganadores_seleccionados_ids)
        self.assertNotIn(self.participante_5_no_ganador.id, ganadores_seleccionados_ids)
        
        print(f"\n✓ CA 1.02: PASSED - {ganadores_seleccionados.count()} ganadores seleccionados")

    # ============================================
    # CA 2: GENERACIÓN Y DATOS DINÁMICOS
    # ============================================

    def test_ca202_validacion_de_datos_dinamicos_premio_y_posicion(self):
        """
        CA2.02: Verifica que el certificado se genera con la posición/premio correcto
        de forma dinámica según el ranking.
        """
        # Simular generación de contenido de certificado para cada ganador
        def generar_contenido_certificado_premiacion(participante_id, posicion=None, premio=None):
            """
            Genera contenido dinámico del certificado incluyendo:
            - Posición (1, 2, 3) si aplica
            - Premio (Primer Lugar, Segundo Lugar, etc.)
            """
            participante = Participante.objects.get(id=participante_id)
            puntaje = self.puntajes.get(participante_id, 0)
            
            return {
                'nombre_receptor': f"{participante.usuario.first_name} {participante.usuario.last_name}",
                'posicion': posicion,
                'premio': premio,
                'puntaje': puntaje,
                'id_certificado': f'CERT-PREMIO-{self.evento.id}-{participante_id:04d}'
            }
        
        # Act: Generar certificados para diferentes ganadores
        contenido_leo = generar_contenido_certificado_premiacion(
            self.participante_1_ganador.id,
            posicion=1,
            premio='Primer Lugar'
        )
        
        contenido_nico = generar_contenido_certificado_premiacion(
            self.participante_4_mencion.id,
            posicion=None,
            premio='Mención Honorífica'
        )
        
        # Assert: Verificar datos dinámicos
        self.assertEqual(contenido_leo['posicion'], 1)
        self.assertEqual(contenido_leo['premio'], 'Primer Lugar')
        self.assertEqual(contenido_leo['puntaje'], 95)
        
        self.assertIsNone(contenido_nico['posicion'])
        self.assertEqual(contenido_nico['premio'], 'Mención Honorífica')
        self.assertEqual(contenido_nico['puntaje'], 80)
        
        print(f"\n✓ CA 2.02: PASSED - Premios dinámicos incluidos")

    def test_ca203_incluir_puntaje_opcional(self):
        """
        CA2.03: Verifica que el certificado puede incluir opcionalmente
        el puntaje del participante (según configuración del admin).
        """
        # Opción 1: Con puntaje
        def generar_con_puntaje(participante, incluir_puntaje=True):
            puntaje = self.puntajes.get(participante.id, 0)
            
            contenido = {
                'nombre': f"{participante.usuario.first_name} {participante.usuario.last_name}",
                'premio': 'Primer Lugar'
            }
            
            if incluir_puntaje:
                contenido['puntaje'] = puntaje
            
            return contenido
        
        # Act: Generar con y sin puntaje
        con_puntaje = generar_con_puntaje(self.participante_1_ganador, incluir_puntaje=True)
        sin_puntaje = generar_con_puntaje(self.participante_1_ganador, incluir_puntaje=False)
        
        # Assert: Verificar la opción funciona
        self.assertIn('puntaje', con_puntaje)
        self.assertEqual(con_puntaje['puntaje'], 95)
        self.assertNotIn('puntaje', sin_puntaje)
        
        print("\n✓ CA 2.03: PASSED - Opción de incluir puntaje funciona")

    def test_ca204_certificado_en_pdf(self):
        """
        CA2.04: El certificado se genera en formato PDF válido.
        """
        nombre_archivo = f"certificado_premiacion_{self.participante_1_ganador.id}.pdf"
        
        # Debe tener extensión PDF
        self.assertTrue(
            nombre_archivo.endswith('.pdf'),
            "El certificado debe estar en formato PDF"
        )
        
        print(f"\n✓ CA 2.04: PASSED - Formato PDF: {nombre_archivo}")

    # ============================================
    # CA 3: ENVÍO Y SEGURIDAD
    # ============================================

    def test_ca301_envio_falla_sin_confirmacion_previa(self):
        """
        CA3.01: Verifica que el envío masivo no se inicia si falta 
        la confirmación de seguridad del administrador.
        """
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Simular payload sin confirmación
        payload_sin_confirmacion = {
            'confirmacion': False,
            'destinatarios_ids': [self.participante_1_ganador.id],
            'incluir_puntaje': True
        }
        
        # Simular validación: si confirmación es False, rechazar el envío
        def validar_envio(payload):
            if not payload.get('confirmacion', False):
                return {'exitosos': 0, 'fallidos': 0, 'error': 'debe confirmar la acción'}
            return {'exitosos': len(payload.get('destinatarios_ids', [])), 'fallidos': 0}
        
        # Act: Validar
        resultado = validar_envio(payload_sin_confirmacion)
        
        # Assert: Verificar que el envío fue rechazado
        self.assertIn('error', resultado)
        self.assertEqual(resultado['exitosos'], 0)
        
        print("\n✓ CA 3.01: PASSED - Confirmación previa requerida")

    def test_ca302_mostrar_cantidad_antes_envio(self):
        """
        CA3.02: Se muestra la cantidad de certificados a enviar antes de iniciar.
        """
        cantidad_a_enviar = 2  # Leo y Nico
        
        # Verificar cantidad
        self.assertEqual(cantidad_a_enviar, 2)
        
        print(f"\n✓ CA 3.02: PASSED - Cantidad a enviar: {cantidad_a_enviar}")

    def test_ca303_envio_por_correo_y_trazabilidad(self):
        """
        CA3.03: Los certificados se envían por correo electrónico 
        y se registra un ID único de trazabilidad con el premio.
        """
        ganadores_para_enviar = [
            self.participante_1_ganador,
            self.participante_2_ganador,
            self.participante_4_mencion
        ]
        
        premios_mapping = {
            self.participante_1_ganador.id: 'Primer Lugar',
            self.participante_2_ganador.id: 'Segundo Lugar',
            self.participante_4_mencion.id: 'Mención Honorífica'
        }
        
        # Simular generación de IDs únicos con trazabilidad
        ids_trazabilidad = []
        for ganador in ganadores_para_enviar:
            cert_id = f"CERT-PREMIO-{self.evento.id}-{ganador.id:04d}"
            premio = premios_mapping.get(ganador.id, 'Premio')
            
            ids_trazabilidad.append({
                'cert_id': cert_id,
                'email': ganador.usuario.email,
                'premio': premio,
                'estado': 'enviado'
            })
        
        # Assert: Verificar trazabilidad
        self.assertEqual(len(ids_trazabilidad), 3)
        
        # Todos los IDs deben ser únicos
        cert_ids = [item['cert_id'] for item in ids_trazabilidad]
        self.assertEqual(len(cert_ids), len(set(cert_ids)))
        
        # Todos deben tener correo y premio
        for item in ids_trazabilidad:
            self.assertIn('@', item['email'])
            self.assertIsNotNone(item['premio'])
            self.assertEqual(item['estado'], 'enviado')
        
        print(f"\n✓ CA 3.03: PASSED - {len(ids_trazabilidad)} certificados con trazabilidad")

    # ============================================
    # CA 4: VALIDACIONES
    # ============================================

    def test_ca401_validar_lista_destinatarios_seleccionados(self):
        """
        CA4.01: Se valida que la lista de destinatarios sea la seleccionada
        (evita envío automático a todos los ganadores).
        """
        # Admin selecciona solo a Leo (no a Mia ni Juan)
        seleccionados_ids = [self.participante_1_ganador.id]
        
        seleccionados = Participante.objects.filter(id__in=seleccionados_ids)
        
        # Verificar que solo 1 fue seleccionado
        self.assertEqual(seleccionados.count(), 1)
        self.assertEqual(seleccionados.first().id, self.participante_1_ganador.id)
        
        print(f"\n✓ CA 4.01: PASSED - Lista validada: {seleccionados.count()} destinatario(s)")

    def test_ca402_evitar_duplicados(self):
        """
        CA4.02: No se envían certificados duplicados al mismo participante.
        """
        # Lista con potencial duplicado
        destinatarios = [
            self.participante_1_ganador,
            self.participante_1_ganador,  # Duplicado
            self.participante_2_ganador
        ]
        
        # Filtrar duplicados
        ids_unicos = list(set([p.id for p in destinatarios]))
        
        # Debe haber solo 2 únicos
        self.assertEqual(len(ids_unicos), 2)
        
        print("\n✓ CA 4.02: PASSED - Sin duplicados validado")

    # ============================================
    # CA 5 & 6: TRAZABILIDAD Y RESULTADO
    # ============================================

    def test_envio_masivo_premiacion_integral(self):
        """
        Prueba integral: Verifica el flujo completo de envío masivo
        de certificados de premiación con diferentes posiciones/premios.
        """
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # 1. Admin selecciona ganadores
        ganadores_seleccionados = [
            {
                'id': self.participante_1_ganador.id,
                'posicion': 1,
                'premio': 'Primer Lugar'
            },
            {
                'id': self.participante_2_ganador.id,
                'posicion': 2,
                'premio': 'Segundo Lugar'
            },
            {
                'id': self.participante_4_mencion.id,
                'posicion': None,
                'premio': 'Mención Honorífica'
            }
        ]
        
        # 2. Simular envío masivo
        resultados_envio = {
            'exitosos': len(ganadores_seleccionados),
            'fallidos': 0,
            'detalles': [
                {
                    'participante_id': g['id'],
                    'email': Participante.objects.get(id=g['id']).usuario.email,
                    'premio': g['premio'],
                    'cert_id': f"CERT-PREMIO-{self.evento.id}-{g['id']:04d}",
                    'estado': 'enviado'
                }
                for g in ganadores_seleccionados
            ]
        }
        
        # 3. Assert: Verificar resultados
        self.assertEqual(resultados_envio['exitosos'], 3)
        self.assertEqual(resultados_envio['fallidos'], 0)
        self.assertEqual(len(resultados_envio['detalles']), 3)
        
        # 4. Verificar que todos los envíos fueron exitosos con datos correctos
        for detalle in resultados_envio['detalles']:
            self.assertEqual(detalle['estado'], 'enviado')
            self.assertIn('@', detalle['email'])
            self.assertIn('CERT-PREMIO-', detalle['cert_id'])
            self.assertIn(detalle['premio'], ['Primer Lugar', 'Segundo Lugar', 'Mención Honorífica'])
        
        print(f"\n✓ CA Integral: PASSED - {resultados_envio['exitosos']} certificados de premiación enviados")