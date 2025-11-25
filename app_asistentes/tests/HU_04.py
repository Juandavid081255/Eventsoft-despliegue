""" Como visitante web (asistente) quiero Compartir la información de eventos con mis contactos para 
Darlos a conocer a personas posiblemente interesadas en asistir"""





from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from app_admin_eventos.models import Evento
from app_usuarios.models import Usuario, AdministradorEvento
from django.core.files.uploadedfile import SimpleUploadedFile
# Importamos quote de urllib.parse, aunque lo usaremos con cuidado
from urllib.parse import quote 
import time 

# Asumiendo que 'ver_info_evento' es el nombre de la URL para EventoDetailView
class EventoComparticionTest(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        # Setup básico de usuarios y archivos
        unique_id = int(time.time() * 1000)

        cls.user_admin, _ = Usuario.objects.get_or_create(
            username=f'admin_comp_{unique_id}', 
            defaults={
                'email': f'admin_comp{unique_id}@event.com', 
                'password': 'password123', 
                'rol': Usuario.Roles.ADMIN_EVENTO,
                'is_staff': True
            }
        )
        cls.admin, _ = AdministradorEvento.objects.get_or_create(usuario=cls.user_admin)

        cls.manana = timezone.now().date() + timedelta(days=1)
        
        # Evento 1: Publicado y apto para compartir
        cls.evento_publicado = Evento.objects.create(
            eve_nombre="Congreso de Bioinformática", 
            eve_descripcion="Evento para compartir",
            eve_ciudad="Medellín",
            eve_lugar="UNAL",
            eve_fecha_inicio=cls.manana,
            eve_fecha_fin=cls.manana + timedelta(days=2),
            eve_estado="Publicado",
            eve_administrador_fk=cls.admin,
            eve_tienecosto='De pago',
            eve_capacidad=150,
            # Se usan SimpleUploadedFile para simular la existencia de los archivos
            eve_programacion=SimpleUploadedFile("prog.pdf", b"pdf", content_type="application/pdf"),
            eve_imagen=SimpleUploadedFile("img.png", b"file", content_type="image/png")
        )
        
        # Evento 2: Editando (No debe permitir compartir/acceder)
        cls.evento_editando = Evento.objects.create(
            eve_nombre="Taller Interno", 
            eve_descripcion="Solo para admins.",
            eve_ciudad="Cali",
            eve_lugar="Sede Central",
            eve_fecha_inicio=cls.manana,
            eve_fecha_fin=cls.manana + timedelta(days=1),
            eve_estado="Editando",
            eve_administrador_fk=cls.admin,
            eve_tienecosto='Sin costo',
            eve_capacidad=10,
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"pdf", content_type="application/pdf"),
            eve_imagen=SimpleUploadedFile("img2.png", b"file", content_type="image/png")
        )

    def setUp(self):
        self.client = Client()
        self.pk_publicado = self.evento_publicado.pk
        # Nota: La URL es '/ver_info/1/' porque es el primer evento creado y el HTML lo confirma
        self.url_publicado = reverse('ver_info_evento', kwargs={'pk': self.pk_publicado}) 
        self.url_editando = reverse('ver_info_evento', kwargs={'pk': self.evento_editando.pk})
        
        # URL ABSOLUTA esperada del evento
        self.evento_url_base = f'http://testserver{self.url_publicado}'
        
        # APLICAMOS LA CORRECCIÓN: Generamos el fragmento codificado manualmente 
        # para emular *exactamente* lo que hace el filtro |urlencode del template (solo codifica el ':')
        self.url_codificada_fragmento = self.evento_url_base.replace(':', '%3A')


    # --- CP-3.1: Visibilidad del Botón de Compartir y Enlace Base Correcto (CA-3.1, CA-3.2, CA-3.4) ---
    def test_cp_3_1_visibilidad_y_enlace_base_correcto(self):
        """
        Valida la unicidad del botón de activación y la exactitud de la URL base en el input de copia.
        """
        
        response = self.client.get(self.url_publicado)
        
        self.assertEqual(response.status_code, 200)
        
        # 1. Verificar la existencia del BOTÓN DE ACTIVACIÓN del modal (CA-3.1)
        self.assertContains(
            response, 
            'data-bs-target="#modalCompartir"', 
            count=1,
            msg_prefix="CA-3.1 FALLO: El botón de activación del modal de Compartir no se encontró o no es único."
        )
        
        # 2. Verificar que la URL base del evento esté disponible en el input del modal (CA-3.2, CA-3.4)
        self.assertContains(
            response, 
            f'value="{self.evento_url_base}"', 
            count=1,
            msg_prefix="CA-3.2/CA-3.4 FALLO: El enlace directo del evento no se encontró o es incorrecto en el input de copia."
        )


    # --- CP-3.2: Enlaces a Redes Sociales Codificados (CA-3.3) ---
    def test_cp_3_2_enlaces_redes_sociales_codificados_correctamente(self):
        """
        CORREGIDO: Valida que los enlaces de WhatsApp y Facebook contienen la URL del evento 
        absoluta y codificada según el estándar de Django (solo el ':' codificado).
        """
        
        response = self.client.get(self.url_publicado)
        
        # Fragmento de URL codificado (ej: http%3A//testserver/ver_info/1/)
        url_fragmento = self.url_codificada_fragmento 
        
        # 1. Enlace de WhatsApp
        whatsapp_path = f'https://wa.me/?text={url_fragmento}'
        self.assertContains(
            response, 
            whatsapp_path, 
            count=1, 
            msg_prefix="CA-3.3 FALLO: El enlace completo de WhatsApp no contiene la URL del evento codificada, o no es único."
        )
        
        # 2. Enlace de Facebook
        facebook_path = f'https://www.facebook.com/sharer/sharer.php?u={url_fragmento}'
        self.assertContains(
            response, 
            facebook_path, 
            count=1,
            msg_prefix="CA-3.3 FALLO: El enlace completo de Facebook no contiene la URL del evento codificada, o no es único."
        )


    # --- CP-3.3: Restricción de Acceso a Evento No Público (CA-3.5) ---
    def test_cp_3_3_acceso_negado_a_evento_editando_sin_compartir(self):
        """Valida que no se puede acceder ni, por ende, compartir un evento en estado 'Editando'."""
        
        response = self.client.get(self.url_editando)
        
        # Esperamos 404, validando que el evento 'Editando' no es accesible para un Visitante.
        self.assertEqual(response.status_code, 404,
                         "CA-3.5 FALLO: Un evento en estado 'Editando' no debería ser accesible (se esperaba 404).")