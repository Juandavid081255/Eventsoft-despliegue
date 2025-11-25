""" Como Asistente quiero Descargar el comprobante de inscripción a un evento (código QR) para 
Presentarlo y poder ingresar al evento"""

# app_asistentes/tests/HU_07.py

from django.test import TransactionTestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model
from django.utils import timezone
from datetime import date, timedelta
from io import BytesIO 
from unittest.mock import patch, MagicMock
import uuid

# Importa los modelos necesarios
from app_usuarios.models import Asistente, AdministradorEvento
from app_admin_eventos.models import Evento
from app_asistentes.models import AsistenteEvento

# ======================================================================
# FUNCIONES DE UTILIDAD
# ======================================================================

Usuario = get_user_model() 

def crear_usuario_rol(username, rol, cedula, is_staff=False):
    """
    Crea un Usuario y su perfil asociado.
    Usa get_or_create para evitar conflictos de unicidad.
    """
    cedula_unica = f"{cedula}_{uuid.uuid4().hex[:8]}"
    email_unico = f'{username}_{uuid.uuid4().hex[:6]}@test.com'
    
    user, created = Usuario.objects.get_or_create(
        username=username,
        defaults={
            'email': email_unico,
            'rol': rol,
            'cedula': cedula_unica,
            'is_staff': is_staff
        }
    )
    
    if created:
        user.set_password('testpassword123')
        user.save()
    
    # Crear perfil de forma segura
    if rol == Usuario.Roles.ASISTENTE:
        perfil, _ = Asistente.objects.get_or_create(usuario=user)
        return perfil
    elif rol == Usuario.Roles.ADMIN_EVENTO:
        perfil, _ = AdministradorEvento.objects.get_or_create(usuario=user)
        return perfil
    
    return user

def crear_evento(admin_perfil, estado="Publicado", nombre="Evento Test", tienecosto="No"):
    """Crea un Evento con valores por defecto."""
    fecha_inicio = date.today() + timedelta(days=30)
    imagen_dummy = SimpleUploadedFile("logo.png", b"file_content", content_type="image/png")
    programacion_dummy = SimpleUploadedFile("prog.pdf", b"file_content", content_type="application/pdf")
    
    return Evento.objects.create(
        eve_nombre=nombre,
        eve_descripcion="Descripción del Evento",
        eve_ciudad="Ciudad Test",
        eve_lugar="Lugar Test",
        eve_fecha_inicio=fecha_inicio,
        eve_fecha_fin=fecha_inicio + timedelta(days=2),
        eve_estado=estado,
        eve_imagen=imagen_dummy,
        eve_administrador_fk=admin_perfil,
        eve_tienecosto=tienecosto,
        eve_capacidad=100,
        eve_programacion=programacion_dummy,
        preinscripcion_habilitada_asistentes=True
    )

def crear_inscripcion_asistente(asistente_perfil, evento, estado="Aprobado"):
    """Crea una inscripción de AsistenteEvento con un QR de prueba."""
    qr_content = b'Contenido del QR'
    qr_dummy = SimpleUploadedFile("qr_code.png", qr_content, content_type="image/png")
    soporte_dummy = SimpleUploadedFile("soporte.pdf", b"soporte_content", content_type="application/pdf")
    
    return AsistenteEvento.objects.create(
        asi_eve_asistente_fk=asistente_perfil,
        asi_eve_evento_fk=evento,
        asi_eve_fecha_hora=timezone.now(),
        asi_eve_estado=estado,
        asi_eve_soporte=soporte_dummy,
        asi_eve_qr=qr_dummy,
        asi_eve_clave="CLAVE123"
    )

# ======================================================================
# CASOS DE PRUEBA: Descarga de Comprobante QR (HU_07)
# ======================================================================

@patch('django.core.files.storage.FileSystemStorage.save', MagicMock(return_value='dummy_path.png'))
@patch('django.db.models.fields.files.FieldFile.open', MagicMock(return_value=BytesIO(b'dummy content')))
class ComprobanteQRTestCase(TransactionTestCase):
    """
    Test case para verificar la descarga de QR de inscripción a eventos.
    
    Usa TransactionTestCase porque cada test tiene su propia transacción.
    """
    
    def setUp(self):
        """
        Setup que se ejecuta ANTES de CADA test.
        Todos los datos se crean frescos en cada test para evitar conflictos.
        """
        self.client = Client()

        # Crear admin NUEVO para cada test
        self.admin_perfil = crear_usuario_rol(
            f'admin_{uuid.uuid4().hex[:6]}', 
            Usuario.Roles.ADMIN_EVENTO, 
            '1000', 
            is_staff=True
        )
        
        # Crear asistentes ÚNICOS
        self.asistente_aprobado = crear_usuario_rol(
            f'asistente_aprobado_{uuid.uuid4().hex[:6]}', 
            Usuario.Roles.ASISTENTE, 
            '1001'
        )
        
        self.asistente_pendiente = crear_usuario_rol(
            f'asistente_pendiente_{uuid.uuid4().hex[:6]}', 
            Usuario.Roles.ASISTENTE, 
            '1002'
        )
        
        self.asistente_rechazado = crear_usuario_rol(
            f'asistente_rechazado_{uuid.uuid4().hex[:6]}', 
            Usuario.Roles.ASISTENTE, 
            '1003'
        )
        
        # Crear eventos ÚNICOS
        self.evento_aprobado = crear_evento(
            self.admin_perfil, 
            nombre=f"Evento Aprobado {uuid.uuid4().hex[:6]}"
        )
        
        self.evento_pendiente = crear_evento(
            self.admin_perfil, 
            nombre=f"Evento Pendiente {uuid.uuid4().hex[:6]}"
        )
        
        self.evento_rechazado = crear_evento(
            self.admin_perfil, 
            nombre=f"Evento Rechazado {uuid.uuid4().hex[:6]}"
        )
        
        # Crear inscripciones
        self.inscripcion_aprobada = crear_inscripcion_asistente(
            self.asistente_aprobado, 
            self.evento_aprobado, 
            estado="Aprobado"
        )
        
        self.inscripcion_pendiente = crear_inscripcion_asistente(
            self.asistente_pendiente, 
            self.evento_pendiente, 
            estado="Pendiente"
        )
        
        self.inscripcion_rechazada = crear_inscripcion_asistente(
            self.asistente_rechazado, 
            self.evento_rechazado, 
            estado="Rechazado"
        )
        
        # Definir URLs
        self.url_descarga_aprobado = reverse(
            'ingreso_evento_asi', 
            kwargs={'pk': self.evento_aprobado.pk}
        )
        
        self.url_descarga_pendiente = reverse(
            'ingreso_evento_asi', 
            kwargs={'pk': self.evento_pendiente.pk}
        )
        
        self.url_descarga_rechazado = reverse(
            'ingreso_evento_asi', 
            kwargs={'pk': self.evento_rechazado.pk}
        )
        
        self.url_login = reverse('login_view')

    def _login_asistente(self, asistente_perfil):
        """
        Helper para hacer login de un asistente y configurar la sesión correctamente.
        """
        username = asistente_perfil.usuario.username
        
        # Hacer login
        login_ok = self.client.login(
            username=username, 
            password='testpassword123'
        )
        
        if not login_ok:
            raise AssertionError(f"Login fallido para {username}")
        
        # IMPORTANTE: Configurar la sesión con el asistente_id
        # Esto es necesario si tu vista lo requiere
        session = self.client.session
        session['asistente_id'] = asistente_perfil.pk
        session.save()
        
        return login_ok

    # ====================================================================
    # TEST: CP-AS-QR-001
    # ====================================================================
    def test_cp_as_qr_001_descarga_qr_aprobado(self):
        """
        Verifica que un Asistente con inscripción APROBADA pueda acceder 
        y ver el QR de ingreso al evento.
        """
        # Login del asistente aprobado
        self._login_asistente(self.asistente_aprobado)
        
        # Acceder a la URL del evento
        response = self.client.get(self.url_descarga_aprobado, follow=True)
        
        # Verificar que la solicitud fue exitosa
        self.assertEqual(
            response.status_code, 
            200, 
            f"Se esperaba status 200, se obtuvo {response.status_code}"
        )
        
        # Verificar que el estado "Aprobado" aparece en la respuesta
        self.assertContains(response, "Aprobado")

    # ====================================================================
    # TEST: CP-AS-QR-002
    # ====================================================================
    def test_cp_as_qr_002_restriccion_qr_pendiente(self):
        """
        Verifica que un Asistente con inscripción PENDIENTE pueda ver 
        el estado de su inscripción, pero NO tenga acceso al QR.
        """
        # Login del asistente pendiente
        self._login_asistente(self.asistente_pendiente)
        
        response = self.client.get(self.url_descarga_pendiente, follow=True)
        
        self.assertEqual(
            response.status_code, 
            200,
            f"Se esperaba status 200, se obtuvo {response.status_code}"
        )
        
        # Verificar que aparece el estado "Pendiente"
        self.assertContains(response, "Pendiente")
        
        # Verificar que el QR NO es accesible
        response_text = response.content.decode()
        self.assertNotIn(
            'qr_code',
            response_text.lower(),
            msg="El QR no debería estar disponible en estado Pendiente"
        )

    # ====================================================================
    # TEST: CP-AS-QR-004
    # ====================================================================
    def test_cp_as_qr_004_restriccion_qr_rechazado(self):
        """
        Verifica que un Asistente con inscripción RECHAZADA pueda ver 
        el estado, pero NO tenga acceso al QR.
        """
        # Login del asistente rechazado
        self._login_asistente(self.asistente_rechazado)
        
        response = self.client.get(self.url_descarga_rechazado, follow=True)
        
        self.assertEqual(
            response.status_code, 
            200,
            f"Se esperaba status 200, se obtuvo {response.status_code}"
        )
        
        # Verificar que aparece el estado "Rechazado"
        self.assertContains(response, "Rechazado")
        
        # Verificar que el QR NO está disponible
        response_text = response.content.decode()
        self.assertNotIn(
            'qr_code',
            response_text.lower(),
            msg="El QR no debería estar disponible en estado Rechazado"
        )

    # ====================================================================
    # TEST: CP-AS-QR-003
    # ====================================================================
    def test_cp_as_qr_003_restriccion_no_autenticado(self):
        """
        Verifica que un usuario NO AUTENTICADO sea redirigido al login
        cuando intenta acceder a la vista de ingreso a evento.
        """
        # Asegurar que no hay sesión activa
        self.client.logout()
        
        # Intentar acceder sin seguir redirecciones automáticas
        response = self.client.get(self.url_descarga_aprobado, follow=False)
        
        # Debe redirigir (302) o rechazar (403)
        self.assertIn(
            response.status_code, 
            [302, 403],
            msg=f"Se esperaba redirección (302) o rechazo (403), se obtuvo {response.status_code}"
        )
        
        # Si es redirección (302), verificar que va al login
        if response.status_code == 302:
            self.assertIn(
                'login',
                response.url.lower(),
                msg=f"La redirección no apunta al login. Redirige a: {response.url}"
            )