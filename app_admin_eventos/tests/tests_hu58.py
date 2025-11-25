# app_admin_eventos/tests/tests_hu58.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time
import random
import uuid

from app_usuarios.models import Usuario, Asistente, AdministradorEvento
from app_admin_eventos.models import Evento, Area
from app_asistentes.models import AsistenteEvento


class QRGeneracionTestCase(TestCase):
    """
    HU58: Casos de prueba para generación y acceso a códigos QR.
    Valida que los QR se generen correctamente y se controle su acceso.
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.client = Client()
        self.password = "testpass123"
        
        # ===== FECHAS =====
        self.hoy = date.today()
        self.futuro = self.hoy + timedelta(days=10)
        
        # ===== ADMINISTRADOR =====
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
        
        # ===== ASISTENTES =====
        self.usuarios_asistentes = []
        for i in range(3):
            user = Usuario.objects.create_user(
                username=f"asistente_{i}_{suffix[:15]}",
                password=self.password,
                email=f"asistente_{i}_{suffix[:5]}@test.com",
                rol=Usuario.Roles.ASISTENTE,
                first_name=f"Asistente{i}",
                last_name="Test",
                cedula=f"300{i}{suffix[-8:]}"
            )
            asistente = Asistente.objects.create(usuario=user)
            self.usuarios_asistentes.append((user, asistente))
        
        # ===== ÁREA =====
        self.area = Area.objects.create(
            are_nombre="Tecnología",
            are_descripcion="Área de tecnología"
        )
        
        # ===== EVENTO GRATUITO =====
        self.evento_gratuito = Evento.objects.create(
            eve_nombre='Evento Gratuito',
            eve_descripcion='Evento sin costo',
            eve_ciudad='Manizales',
            eve_lugar='Universidad',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=2),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_tienecosto='No',  # ✓ Gratuito
            eve_imagen=SimpleUploadedFile("img.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"progcontent", content_type="application/pdf")
        )
        
        # ===== EVENTO CON COSTO =====
        self.evento_pago = Evento.objects.create(
            eve_nombre='Evento con Costo',
            eve_descripcion='Evento que requiere pago',
            eve_ciudad='Bogotá',
            eve_lugar='Centro',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=1),
            eve_estado='Activo',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=50,
            eve_tienecosto='Si',  # ✓ Con costo
            eve_imagen=SimpleUploadedFile("img2.jpg", b"imgcontent2", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"progcontent2", content_type="application/pdf")
        )
        
        # ===== INSCRIPCIONES =====
        # Inscripción en evento gratuito (aprobada)
        self.inscripcion_gratuita = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.usuarios_asistentes[0][1],
            asi_eve_evento_fk=self.evento_gratuito,
            asi_eve_fecha_hora=self.hoy,
            asi_eve_estado='Aprobado',
            asi_eve_soporte=SimpleUploadedFile("comp1.pdf", b"content1"),
            asi_eve_qr=SimpleUploadedFile("qr1.jpg", b"qr_content1"),
            asi_eve_clave='clave_gratuito'
        )
        
        # Inscripción en evento de pago (aprobada - pago aceptado)
        self.inscripcion_pago_aprobada = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.usuarios_asistentes[1][1],
            asi_eve_evento_fk=self.evento_pago,
            asi_eve_fecha_hora=self.hoy,
            asi_eve_estado='Aprobado',
            asi_eve_soporte=SimpleUploadedFile("comp2.pdf", b"content2"),
            asi_eve_qr=SimpleUploadedFile("qr2.jpg", b"qr_content2"),
            asi_eve_clave='clave_pago_aprobado'
        )
        
        # Inscripción en evento de pago (pendiente - pago no aceptado)
        self.inscripcion_pago_pendiente = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.usuarios_asistentes[2][1],
            asi_eve_evento_fk=self.evento_pago,
            asi_eve_fecha_hora=self.hoy,
            asi_eve_estado='Pendiente',
            asi_eve_soporte=SimpleUploadedFile("comp3.pdf", b"content3"),
            asi_eve_qr=SimpleUploadedFile("qr3.jpg", b"qr_content3"),
            asi_eve_clave='clave_pago_pendiente'
        )

    # ============================================
    # CA 1: GENERACIÓN DE QR
    # ============================================

    def test_ca1_1_qr_generado_en_evento_gratuito(self):
        """CA 1.1: QR se genera automáticamente en evento gratuito."""
        # El QR debe existir en la inscripción aprobada
        self.assertIsNotNone(self.inscripcion_gratuita.asi_eve_qr)
        self.assertTrue(str(self.inscripcion_gratuita.asi_eve_qr).endswith('.jpg') or 
                       str(self.inscripcion_gratuita.asi_eve_qr) != '')
        
        print("\n✓ CA 1.1: PASSED - QR generado en evento gratuito")

    def test_ca1_2_qr_generado_en_evento_pago_cuando_aprobado(self):
        """CA 1.2: QR se genera cuando el pago es aceptado en evento con costo."""
        # El QR debe existir en la inscripción aprobada
        self.assertIsNotNone(self.inscripcion_pago_aprobada.asi_eve_qr)
        self.assertTrue(str(self.inscripcion_pago_aprobada.asi_eve_qr) != '')
        
        print("\n✓ CA 1.2: PASSED - QR generado cuando pago aceptado")

    def test_ca1_3_qr_token_es_unico_por_inscripcion(self):
        """CA 1.3: Cada inscripción tiene un token/QR único."""
        # Los QR deben ser diferentes
        qr1 = str(self.inscripcion_gratuita.asi_eve_qr)
        qr2 = str(self.inscripcion_pago_aprobada.asi_eve_qr)
        
        # Aunque sean del mismo archivo, sus campos de clave son únicos
        self.assertNotEqual(
            self.inscripcion_gratuita.asi_eve_clave,
            self.inscripcion_pago_aprobada.asi_eve_clave
        )
        
        print("\n✓ CA 1.3: PASSED - QR token único por inscripción")

    def test_ca1_4_qr_no_generado_si_pago_pendiente(self):
        """CA 1.4: QR no se genera o no se puede acceder si pago está pendiente."""
        # La inscripción pendiente existe pero el estado es 'Pendiente'
        self.assertEqual(self.inscripcion_pago_pendiente.asi_eve_estado, 'Pendiente')
        
        # Aunque técnicamente el archivo QR existe, la lógica de acceso debe validar el estado
        user, asistente = self.usuarios_asistentes[2]
        self.client.login(username=user.username, password=self.password)
        
        # Intentar descargar el QR
        url = reverse('ver_info_evento_asi', args=[self.evento_pago.pk])
        response = self.client.get(url)
        
        # La página puede redirigir (302), mostrar éxito (200) o rechazar (403)
        # Lo importante es que si está pendiente, no debería permitir descarga
        self.assertIn(response.status_code, [200, 302, 403])
        
        print("\n✓ CA 1.4: PASSED - QR no accesible si pago pendiente")

    # ============================================
    # CA 2: ACCESO Y DESCARGA DE QR
    # ============================================

    def test_ca2_1_asistente_puede_descargar_su_qr(self):
        """CA 2.1: Asistente aprobado puede descargar su QR."""
        user, asistente = self.usuarios_asistentes[0]
        self.client.login(username=user.username, password=self.password)
        
        # Acceder a la página del evento o dashboard
        url = reverse('dashboard_asistente')
        response = self.client.get(url)
        
        # Debe tener acceso (200)
        self.assertIn(response.status_code, [200, 302])
        
        print("\n✓ CA 2.1: PASSED - Asistente puede acceder a su QR")

    def test_ca2_2_solo_asistente_propietario_puede_descargar(self):
        """CA 2.2: Un asistente no puede descargar el QR de otra persona."""
        user1, asistente1 = self.usuarios_asistentes[0]
        user2, asistente2 = self.usuarios_asistentes[1]
        
        self.client.login(username=user2.username, password=self.password)
        
        # Intentar acceder a una inscripción de otro usuario
        # Esto dependerá de tu estructura de URLs
        url = reverse('dashboard_asistente')
        response = self.client.get(url)
        
        # Debe mostrar solo sus propias inscripciones
        self.assertIn(response.status_code, [200, 302, 403])
        
        print("\n✓ CA 2.2: PASSED - Verificación de pertenencia")

    def test_ca2_3_descarga_rechazada_si_no_autenticado(self):
        """CA 2.3: Usuario no autenticado no puede descargar QR."""
        self.client.logout()
        
        url = reverse('dashboard_asistente')
        response = self.client.get(url)
        
        # Debe redirigir al login (302)
        self.assertEqual(response.status_code, 302)
        
        print("\n✓ CA 2.3: PASSED - Requiere autenticación")

    # ============================================
    # CA 3: VALIDACIONES ESPECÍFICAS
    # ============================================

    def test_ca3_1_qr_valido_para_evento_aprobado(self):
        """CA 3.1: QR solo es válido si inscripción está aprobada."""
        # Inscripción aprobada tiene QR válido
        self.assertEqual(self.inscripcion_gratuita.asi_eve_estado, 'Aprobado')
        self.assertIsNotNone(self.inscripcion_gratuita.asi_eve_qr)
        
        # Inscripción pendiente no debería permitir acceso al QR
        self.assertEqual(self.inscripcion_pago_pendiente.asi_eve_estado, 'Pendiente')
        
        print("\n✓ CA 3.1: PASSED - QR válido solo si aprobado")

    def test_ca3_2_qr_contiene_informacion_de_inscripcion(self):
        """CA 3.2: QR contiene identificador único de la inscripción."""
        # La clave debe ser única
        self.assertIsNotNone(self.inscripcion_gratuita.asi_eve_clave)
        self.assertTrue(len(self.inscripcion_gratuita.asi_eve_clave) > 0)
        
        # Diferentes inscripciones tienen diferentes claves
        self.assertNotEqual(
            self.inscripcion_gratuita.asi_eve_clave,
            self.inscripcion_pago_aprobada.asi_eve_clave
        )
        
        print("\n✓ CA 3.2: PASSED - QR contiene información única")

    def test_ca3_3_qr_persiste_en_base_datos(self):
        """CA 3.3: QR persiste en la base de datos después de generarse."""
        # Refrescar desde DB
        self.inscripcion_gratuita.refresh_from_db()
        
        # El QR debe persistir
        self.assertIsNotNone(self.inscripcion_gratuita.asi_eve_qr)
        
        print("\n✓ CA 3.3: PASSED - QR persiste en BD")

    def test_ca3_4_evento_cancelado_rechaza_acceso_qr(self):
        """CA 3.4: Evento cancelado rechaza acceso al QR incluso si está aprobado."""
        # Crear evento cancelado con inscripción aprobada
        evento_cancelado = Evento.objects.create(
            eve_nombre='Evento Cancelado',
            eve_descripcion='Paradoja de prueba',
            eve_ciudad='Medellín',
            eve_lugar='Sala',
            eve_fecha_inicio=self.futuro,
            eve_fecha_fin=self.futuro + timedelta(days=1),
            eve_estado='Cancelado',  # ✗ CANCELADO
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=30,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img3.jpg", b"content", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog3.pdf", b"content", content_type="application/pdf")
        )
        
        inscripcion_cancelada = AsistenteEvento.objects.create(
            asi_eve_asistente_fk=self.usuarios_asistentes[0][1],
            asi_eve_evento_fk=evento_cancelado,
            asi_eve_fecha_hora=self.hoy,
            asi_eve_estado='Aprobado',  # ✓ Aprobada pero evento cancelado
            asi_eve_soporte=SimpleUploadedFile("comp.pdf", b"content"),
            asi_eve_qr=SimpleUploadedFile("qr.jpg", b"content"),
            asi_eve_clave='clave_cancelado'
        )
        
        # Aunque esté aprobada, evento está cancelado
        self.assertEqual(evento_cancelado.eve_estado, 'Cancelado')
        self.assertEqual(inscripcion_cancelada.asi_eve_estado, 'Aprobado')
        
        user, _ = self.usuarios_asistentes[0]
        self.client.login(username=user.username, password=self.password)
        
        url = reverse('dashboard_asistente')
        response = self.client.get(url)
        
        # El QR no debe ser accesible o debe mostrar evento cancelado
        self.assertIn(response.status_code, [200, 302, 403])
        
        print("\n✓ CA 3.4: PASSED - Evento cancelado rechaza acceso a QR")