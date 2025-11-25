""" Como visitante web (asistente) Anexar soporte(s) del pago requerido para la asistencia a eventos con cobro de ingreso para 
Asegurar mi asistencia y cupo en el evento"""





from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth.hashers import make_password
from django.core import mail
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch

# Importar Modelos (Asegúrate de que las importaciones son correctas)
from app_admin_eventos.models import Evento 
from app_asistentes.models import AsistenteEvento
from app_usuarios.models import Usuario, AdministradorEvento, Asistente, Participante, Evaluador 
from app_participantes.models import ParticipanteEvento
from app_evaluadores.models import EvaluadorEvento
from django.db.models.fields.files import FieldFile 
from django.core.files.base import ContentFile
from django.conf import settings
from django.contrib.messages import get_messages # Necesario para leer mensajes de sesión


# --- Setup General y Casos de Prueba ---
class AsistenteSoporteTest(TestCase):
    
    @classmethod
    def setUpTestData(cls): # Usar setUpTestData para objetos que no cambian
        
        # 1. Setup de Administrador para Eventos
        ADMIN_USER_ID = 9999
        
        # FIX E1: Añadir 'cedula' al objeto Usuario para evitar IntegrityError (1062)
        cls.user_admin, _ = Usuario.objects.update_or_create(
            pk=ADMIN_USER_ID,
            defaults={
                'username': 'admin_test_9999', 
                'email': 'admin_9999@test.com', 
                'password': make_password('password123'), 
                'rol': Usuario.Roles.ADMIN_EVENTO, 
                'is_staff': True,
                'cedula': '111110000', # <<< CORRECCIÓN
            }
        )

        cls.admin, _ = AdministradorEvento.objects.update_or_create(
            usuario=cls.user_admin,
            defaults={'cedula': '11111'}
        )
        
        cls.fecha_proxima = timezone.now().date() + timedelta(days=7)

        # 2. Evento 1: Sin Costo (Aprobación Automática)
        cls.evento_gratis = Evento.objects.create(
            eve_nombre="Conferencia Gratuita", eve_descripcion="Gratuito", eve_estado="Publicado",
            eve_administrador_fk=cls.admin, eve_tienecosto='Sin costo', eve_capacidad=100, 
            eve_fecha_inicio=cls.fecha_proxima, eve_fecha_fin=cls.fecha_proxima + timedelta(days=1), 
            eve_ciudad='Ciudad', eve_lugar='Lugar', 
            eve_programacion=SimpleUploadedFile("prog.pdf", b"pdf"), 
            eve_imagen=SimpleUploadedFile("img.png", b"file")
        )

        # 3. Evento 2: De Pago (Aprobación Pendiente)
        cls.evento_pago = Evento.objects.create(
            eve_nombre="Taller de Pago", eve_descripcion="Con Costo", eve_estado="Publicado",
            eve_administrador_fk=cls.admin, eve_tienecosto='De pago', eve_capacidad=50,
            eve_fecha_inicio=cls.fecha_proxima, eve_fecha_fin=cls.fecha_proxima + timedelta(days=1), 
            eve_ciudad='Ciudad', eve_lugar='Lugar', 
            eve_programacion=SimpleUploadedFile("prog.pdf", b"pdf"), 
            eve_imagen=SimpleUploadedFile("img.png", b"file")
        )
        
        # 4. Evento 3: Capacidad Agotada
        cls.evento_lleno = Evento.objects.create(
            eve_nombre="Capacidad Max", eve_descripcion="Lleno", eve_estado="Publicado",
            eve_administrador_fk=cls.admin, eve_tienecosto='Sin costo', eve_capacidad=0, 
            eve_fecha_inicio=cls.fecha_proxima, eve_fecha_fin=cls.fecha_proxima + timedelta(days=1), 
            eve_ciudad='Ciudad', eve_lugar='Lugar', 
            eve_programacion=SimpleUploadedFile("prog.pdf", b"pdf"), 
            eve_imagen=SimpleUploadedFile("img.png", b"file")
        )
        
        # 5. URLs
        cls.url_gratis = reverse('crear_asistente', kwargs={'pk': cls.evento_gratis.pk})
        cls.url_pago = reverse('crear_asistente', kwargs={'pk': cls.evento_pago.pk})
        cls.url_lleno = reverse('crear_asistente', kwargs={'pk': cls.evento_lleno.pk})
        

    def setUp(self):
        self.client = Client()
        mail.outbox = [] # Limpiar bandeja de salida de correos

        # Datos base de un nuevo asistente 
        self.new_user_data = {
            'cedula': 123456789,
            'username': 'nuevoasistente',
            'email': 'nuevo@example.com',
            'telefono': '3001234567',
            'first_name': 'Juan',
            'last_name': 'Perez',
        }
        
        # ✅ CORRECCIÓN CRÍTICA: Cambiar self.dummy_file de PDF a PNG para pasar la validación del formulario.
        self.dummy_file = SimpleUploadedFile(
            "soporte_pago.png", 
            b"soporte_pago_content", 
            content_type="image/png" # Tipo de contenido de imagen
        )
        
        # FIX: Patching para simular el guardado de archivos (QR)
        self.qr_patch = patch('django.db.models.fields.files.FieldFile.save')
        self.mock_qr = self.qr_patch.start()
        self.mock_qr.return_value = None 


    def tearDown(self):
        # Asegúrate de detener el patch después de cada prueba
        self.qr_patch.stop()



    def test_cp_1_2_registro_pago_exitoso_con_soporte(self):
        """Valida registro exitoso, estado 'Pendiente' y que el soporte de pago fue cargado."""
        
        # 0. Preparación de datos
        initial_capacidad = self.evento_pago.eve_capacidad
        
        post_data = self.new_user_data.copy()
        
        # Datos únicos y válidos
        UNIQUE_ID = 9999
        
        post_data.update({
            'email': f'pago_test_{UNIQUE_ID}@unique.com',
            'cedula': 98765432, 
            'username': f'asistente{UNIQUE_ID}', 
            'asi_eve_soporte': self.dummy_file # Archivo de imagen (PNG)
        })

        # 1. Ejecución del POST (SIN seguir la redirección: follow=False)
        response_redirect = self.client.post(self.url_pago, post_data)

        # 1A. Validación del POST inicial (Redirección 302)
        # Esto DEBE pasar ahora que el archivo es PNG.
        self.assertEqual(response_redirect.status_code, 302, 
                         f"FALLO: La vista devolvió 200. El formulario debe estar fallando la validación. Datos: {post_data}")
        self.assertEqual(response_redirect['Location'], reverse('pagina_principal'))

        # 1B. Validación del Mensaje de Éxito en la Sesión
        session_messages = [str(msg) for msg in list(get_messages(response_redirect.wsgi_request))]
        
        self.assertTrue(
            any('Te has inscrito correctamente' in msg for msg in session_messages),
            "FALLO: El mensaje de éxito 'Te has inscrito correctamente' no se guardó en la sesión."
        )

        # 1C. Ejecución del GET (Seguir la redirección manualmente)
        response = self.client.get(response_redirect['Location'])
        
        # 1D. Validación de que el mensaje se renderiza en la página final
        self.assertContains(response, 'Te has inscrito correctamente', status_code=200, 
                             msg_prefix="FALLO: El mensaje de éxito no se renderizó en la página principal.")
        
        # ----------------------------------------------------------------------
        
        # 2. Validación de Estado, Soporte y Capacidad (CA-1.2)
        try:
            user = Usuario.objects.get(email=post_data['email'])
            asistente_evento = AsistenteEvento.objects.get(asi_eve_asistente_fk__usuario=user, asi_eve_evento_fk=self.evento_pago)
        except (Usuario.DoesNotExist, AsistenteEvento.DoesNotExist):
            self.fail("FALLO CRÍTICO: No se creó el usuario o el asistente de evento.")


        self.assertEqual(asistente_evento.asi_eve_estado, "Pendiente", "CA-1.2 FALLO: Estado incorrecto.")
        # ✅ Aserción ajustada para esperar la extensión PNG
        self.assertTrue(asistente_evento.asi_eve_soporte.name.endswith('png'), 
                        "CA-1.2 FALLO: Soporte de pago no fue cargado o tiene extensión incorrecta (debe ser .png).")
        
        self.evento_pago.refresh_from_db()
        self.assertEqual(self.evento_pago.eve_capacidad, initial_capacidad - 1, "CA-1.2 FALLO: Capacidad no disminuyó.")
        
        # 3. Validación de Correo (Sin QR adjunto)
        self.assertEqual(len(mail.outbox), 1, "FALLO: No se envió el correo de confirmación.")
        self.assertEqual(len(mail.outbox[0].attachments), 0, "FALLO: QR adjunto a evento de pago Pendiente.")


    # ----------------------------------------------------------------------
    # CP-1.3: Registro Fallido en Evento 'De Pago' por Falta de Soporte (CA-1.2)
    # ----------------------------------------------------------------------
    def test_cp_1_3_registro_pago_fallido_sin_soporte(self):
        """Valida que un evento 'De Pago' requiere soporte obligatoriamente."""
        
        initial_count = AsistenteEvento.objects.count()
        post_data = self.new_user_data.copy()
        post_data.update({'email': 'sin_soporte@test.com', 'cedula': 3000})

        response = self.client.post(self.url_pago, post_data, follow=False)

        # 1. Validación de Respuesta (Renderiza formulario con error)
        self.assertEqual(response.status_code, 200, "CA-1.2 FALLO: Debería renderizar el formulario con errores (Status 200).")
        self.assertContains(response, "Debe cargar una imagen del comprobante de pago para este evento.") 
        
        # 2. Validación de No Creación de Objetos
        self.assertEqual(AsistenteEvento.objects.count(), initial_count, "CA-1.2 FALLO: Se creó un AsistenteEvento sin soporte de pago.")