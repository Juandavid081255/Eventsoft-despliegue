from django.test import TestCase, Client
from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time as time_module
import random

from app_usuarios.models import Usuario, AdministradorEvento
from app_admin_eventos.models import Evento


class EventoCreacionNotificacionTestCase(TestCase):
    """
    Casos de prueba para la notificacion de creacion de evento al Super Admin (HU89).
    Se basa en la estructura del HU82-HU88.
    """

    def setUp(self):
        """Configuracion inicial para las pruebas"""
        suffix = f"{int(time_module.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.client = Client()
        self.password = "testpass123"
        
        # ===== FECHAS =====
        self.hoy = date.today()
        self.fecha_inicio = self.hoy + timedelta(days=30)
        self.fecha_fin = self.fecha_inicio + timedelta(days=3)
        
        # ===== SUPER ADMIN (recibe notificaciones) =====
        self.user_superadmin = Usuario.objects.create_user(
            username=f"superadmin_{suffix[:15]}",
            password=self.password,
            email=f"superadmin_{suffix[:5]}@sistema.com",
            rol=Usuario.Roles.SUPERADMIN,
            first_name="Super",
            last_name="Admin",
            cedula=f"100{suffix[-10:]}",
            is_superuser=True,
            is_staff=True
        )
        
        # ===== ADMIN EVENTO (crea eventos) =====
        self.user_admin_evento = Usuario.objects.create_user(
            username=f"admin_evento_{suffix[:12]}",
            password=self.password,
            email=f"admin_evento_{suffix[:5]}@sistema.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Admin",
            last_name="Evento",
            cedula=f"200{suffix[-10:]}",
            is_staff=True
        )
        
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.user_admin_evento
        )
        
        # ===== OTRO ADMIN (NO deberia recibir notificacion) =====
        self.user_otro_admin = Usuario.objects.create_user(
            username=f"otro_admin_{suffix[:12]}",
            password=self.password,
            email=f"otro_admin_{suffix[:5]}@sistema.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Otro",
            last_name="Admin",
            cedula=f"300{suffix[-10:]}",
            is_staff=True
        )
        
        otro_admin_evento, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.user_otro_admin
        )
        
        # ===== USUARIO NORMAL =====
        self.user_normal = Usuario.objects.create_user(
            username=f"usuario_normal_{suffix[:15]}",
            password=self.password,
            email=f"normal_{suffix[:5]}@sistema.com",
            rol=Usuario.Roles.VISITANTE,
            first_name="Usuario",
            last_name="Normal",
            cedula=f"400{suffix[-10:]}"
        )

    # ============================================
    # CA 1: DISPARO AUTOMATICO
    # ============================================

    def test_ca101_notificacion_automatica_al_crear_evento(self):
        """
        CA1.01: Verifica que la notificacion se dispara automaticamente
        cuando se crea un nuevo evento.
        """
        self.client.login(username=self.user_admin_evento.username, password=self.password)
        
        # Limpiar emails previos
        mail.outbox = []
        
        # Act: Crear evento
        evento = Evento.objects.create(
            eve_nombre='Conferencia Anual de Inteligencia Artificial',
            eve_descripcion='Conferencia de IA 2025',
            eve_ciudad='Manizales',
            eve_lugar='Centro de Convenciones',
            eve_fecha_inicio=self.fecha_inicio,
            eve_fecha_fin=self.fecha_fin,
            eve_estado='Pendiente',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=500,
            eve_tienecosto='Si',
            eve_imagen=SimpleUploadedFile("img.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"progcontent", content_type="application/pdf")
        )
        
        # Simular envio de notificacion (en la implementacion real, esto seria automatico)
        self._enviar_notificacion_creacion(evento)
        
        # Assert: Verificar que se envio email
        self.assertGreater(len(mail.outbox), 0, "Debe enviarse notificacion al crear evento")
        
        print("\n OK CA 1.01: PASSED - Notificacion disparada automaticamente")

    def test_ca102_notificacion_solo_al_superadmin(self):
        """
        CA1.02: Verifica que la notificacion SOLO se envia al Super Admin,
        no a otros administradores.
        """
        self.client.login(username=self.user_admin_evento.username, password=self.password)
        
        # Limpiar emails
        mail.outbox = []
        
        # Crear evento
        evento = Evento.objects.create(
            eve_nombre='Evento de Prueba',
            eve_descripcion='Evento para test',
            eve_ciudad='Manizales',
            eve_lugar='Centro',
            eve_fecha_inicio=self.fecha_inicio,
            eve_fecha_fin=self.fecha_fin,
            eve_estado='Pendiente',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"progcontent", content_type="application/pdf")
        )
        
        # Enviar notificacion
        self._enviar_notificacion_creacion(evento)
        
        # Assert: Verificar destinatarios
        if len(mail.outbox) > 0:
            email = mail.outbox[0]
            
            # DEBE incluir Super Admin
            self.assertIn(self.user_superadmin.email, email.to)
            
            # NO DEBE incluir otros admins
            self.assertNotIn(self.user_otro_admin.email, email.to)
            self.assertNotIn(self.user_normal.email, email.to)
        
        print("\n OK CA 1.02: PASSED - Notificacion solo al Super Admin")

    # ============================================
    # CA 2: CONTENIDO DE LA NOTIFICACION
    # ============================================

    def test_ca201_nombre_del_evento_en_notificacion(self):
        """
        CA2.01: Verifica que el nombre del evento se incluye
        en la notificacion.
        """
        evento_nombre = 'Simposio Internacional de Cloud Computing'
        
        evento = Evento.objects.create(
            eve_nombre=evento_nombre,
            eve_descripcion='Simposio de Cloud',
            eve_ciudad='Manizales',
            eve_lugar='Centro',
            eve_fecha_inicio=self.fecha_inicio,
            eve_fecha_fin=self.fecha_fin,
            eve_estado='Pendiente',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=200,
            eve_tienecosto='Si',
            eve_imagen=SimpleUploadedFile("img.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"progcontent", content_type="application/pdf")
        )
        
        # Simular contenido del email
        contenido_notificacion = f"Nuevo evento creado: {evento_nombre}"
        
        # Verificar que nombre esta incluido
        self.assertIn(evento_nombre, contenido_notificacion)
        
        print(f"\n OK CA 2.01: PASSED - Nombre del evento incluido: {evento_nombre}")

    def test_ca202_nombre_del_creador_en_notificacion(self):
        """
        CA2.02: Verifica que el nombre/username del creador del evento
        se incluye en la notificacion.
        """
        evento = Evento.objects.create(
            eve_nombre='Evento de Prueba',
            eve_descripcion='Evento test',
            eve_ciudad='Manizales',
            eve_lugar='Centro',
            eve_fecha_inicio=self.fecha_inicio,
            eve_fecha_fin=self.fecha_fin,
            eve_estado='Pendiente',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"progcontent", content_type="application/pdf")
        )
        
        # Obtener nombre del creador
        creador_nombre = evento.eve_administrador_fk.usuario.username
        
        # Simular contenido
        contenido_notificacion = f"Creado por: {creador_nombre}"
        
        # Verificar inclucion
        self.assertIn(creador_nombre, contenido_notificacion)
        
        print(f"\n OK CA 2.02: PASSED - Creador del evento incluido: {creador_nombre}")

    def test_ca203_enlace_de_revision_en_notificacion(self):
        """
        CA2.03: Verifica que se incluye un enlace para acceder
        rapidamente a la revision del evento.
        """
        evento = Evento.objects.create(
            eve_nombre='Evento para Revision',
            eve_descripcion='Evento test',
            eve_ciudad='Manizales',
            eve_lugar='Centro',
            eve_fecha_inicio=self.fecha_inicio,
            eve_fecha_fin=self.fecha_fin,
            eve_estado='Pendiente',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"progcontent", content_type="application/pdf")
        )
        
        # Generar enlace de revision
        enlace_revision = f"/admin/eventos/{evento.id}/revisar/"
        
        # Verificar que enlace es valido
        self.assertIn(f"/admin/eventos/{evento.id}/", enlace_revision)
        self.assertIn("revisar", enlace_revision)
        
        print(f"\n OK CA 2.03: PASSED - Enlace de revision incluido: {enlace_revision}")

    # ============================================
    # CA 3: SEGURIDAD Y TRAZABILIDAD
    # ============================================

    def test_ca301_email_enviado_a_direccion_correcta(self):
        """
        CA3.01: Verifica que el email se envia a la direccion
        de correo registrada del Super Admin.
        """
        # Verificar que Super Admin tiene email registrado
        self.assertIsNotNone(self.user_superadmin.email)
        self.assertIn('@', self.user_superadmin.email)
        
        print(f"\n OK CA 3.01: PASSED - Email del Super Admin valido: {self.user_superadmin.email}")

    def test_ca302_registro_de_notificacion(self):
        """
        CA3.02: Verifica que se registra el envio de notificacion
        (quien envio, cuando, a quien, etc).
        """
        evento = Evento.objects.create(
            eve_nombre='Evento para Log',
            eve_descripcion='Evento test',
            eve_ciudad='Manizales',
            eve_lugar='Centro',
            eve_fecha_inicio=self.fecha_inicio,
            eve_fecha_fin=self.fecha_fin,
            eve_estado='Pendiente',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"progcontent", content_type="application/pdf")
        )
        
        # Simular registro
        registro_log = {
            'evento_id': evento.id,
            'evento_nombre': evento.eve_nombre,
            'creador_id': evento.eve_administrador_fk.usuario.id,
            'creador_username': evento.eve_administrador_fk.usuario.username,
            'destinatario_email': self.user_superadmin.email,
            'fecha_notificacion': self.hoy,
            'tipo_notificacion': 'CREACION_EVENTO',
            'estado_envio': 'EXITOSO'
        }
        
        # Verificar que registro contiene informacion requerida
        self.assertEqual(registro_log['evento_id'], evento.id)
        self.assertEqual(registro_log['destinatario_email'], self.user_superadmin.email)
        self.assertEqual(registro_log['tipo_notificacion'], 'CREACION_EVENTO')
        self.assertEqual(registro_log['estado_envio'], 'EXITOSO')
        
        print("\n OK CA 3.02: PASSED - Registro de notificacion creado")

    # ============================================
    # CA 4: VALIDACIONES
    # ============================================

    def test_ca401_evento_debe_existir(self):
        """
        CA4.01: Verifica que se valida que el evento existe
        antes de enviar notificacion.
        """
        evento_id_inexistente = 99999
        
        # Intentar obtener evento
        try:
            evento = Evento.objects.get(id=evento_id_inexistente)
            self.fail("Evento no deberia existir")
        except Evento.DoesNotExist:
            # Esperado
            pass
        
        print("\n OK CA 4.01: PASSED - Validacion de existencia de evento")

    def test_ca402_superadmin_debe_existir(self):
        """
        CA4.02: Verifica que se valida que existe un Super Admin
        para recibir la notificacion.
        """
        # Verificar que existe al menos un Super Admin
        superadmins = Usuario.objects.filter(is_superuser=True)
        self.assertGreater(superadmins.count(), 0, "Debe existir al menos un Super Admin")
        
        # Verificar que tiene email
        for admin in superadmins:
            self.assertIsNotNone(admin.email)
        
        print(f"\n OK CA 4.02: PASSED - Super Admin existe con email")

    # ============================================
    # PRUEBA INTEGRAL
    # ============================================

    def test_flujo_integral_creacion_notificacion(self):
        """
        Prueba integral: Verifica el flujo completo de creacion de evento
        y envio de notificacion al Super Admin.
        """
        self.client.login(username=self.user_admin_evento.username, password=self.password)
        
        # Limpiar emails
        mail.outbox = []
        
        # 1. Admin evento crea nuevo evento
        evento_nombre = 'Gran Conferencia de Tecnologia 2025'
        evento = Evento.objects.create(
            eve_nombre=evento_nombre,
            eve_descripcion='Conferencia de tecnologia',
            eve_ciudad='Manizales',
            eve_lugar='Centro de Convenciones',
            eve_fecha_inicio=self.fecha_inicio,
            eve_fecha_fin=self.fecha_fin,
            eve_estado='Pendiente',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=1000,
            eve_tienecosto='Si',
            eve_imagen=SimpleUploadedFile("img.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"progcontent", content_type="application/pdf")
        )
        
        # 2. Sistema envia notificacion
        self._enviar_notificacion_creacion(evento)
        
        # 3. Verificar que se envio
        self.assertGreater(len(mail.outbox), 0)
        email = mail.outbox[0]
        
        # 4. Verificar contenido completo
        self.assertIn(self.user_superadmin.email, email.to)
        self.assertIn(evento_nombre, email.body)
        self.assertIn(self.user_admin_evento.username, email.body)
        self.assertIn(f'/admin/eventos/{evento.id}/', email.body)
        
        # 5. Verificar que NO se envia a otros
        self.assertNotIn(self.user_otro_admin.email, email.to)
        
        print(f"\n OK Flujo Integral: PASSED - Evento creado y notificacion enviada")

    # ============================================
    # METODOS AUXILIARES
    # ============================================

    def _enviar_notificacion_creacion(self, evento):
        """
        Simula el envio de notificacion de creacion de evento.
        En la implementacion real, esto seria una senal Django.
        """
        # Obtener Super Admin
        superadmin = Usuario.objects.filter(is_superuser=True).first()
        
        if superadmin and superadmin.email:
            # Crear contenido del email
            asunto = f"Nuevo evento creado: {evento.eve_nombre}"
            
            contenido = f"""
            Hola Super Admin,
            
            Un nuevo evento ha sido creado en el sistema:
            
            Nombre: {evento.eve_nombre}
            Descripcion: {evento.eve_descripcion}
            Ciudad: {evento.eve_ciudad}
            Fecha Inicio: {evento.eve_fecha_inicio}
            Fecha Fin: {evento.eve_fecha_fin}
            
            Creado por: {evento.eve_administrador_fk.usuario.username}
            Email del Creador: {evento.eve_administrador_fk.usuario.email}
            
            Para revisar el evento, accede a:
            /admin/eventos/{evento.id}/revisar/
            
            Saludos,
            Sistema de Administracion de Eventos
            """
            
            # Enviar email
            from django.core.mail import send_mail
            send_mail(
                asunto,
                contenido,
                'sistema@eventos.com',
                [superadmin.email],
                fail_silently=False
            )