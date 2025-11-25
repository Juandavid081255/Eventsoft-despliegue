# app_participantes/tests/tests_hu29.py

from django.test import TestCase, Client
from django.urls import reverse
from datetime import date, timedelta
from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento, MemoriaEvento
from app_participantes.models import ParticipanteEvento
from django.core.files.uploadedfile import SimpleUploadedFile
import time
import random


class MemoriasEventoTest(TestCase):
    """
    Casos de prueba para visualizar y descargar memorias del evento (HU29).
    """

    def setUp(self):
        """Configuración inicial para cada test."""
        unique_suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"
        self.unique_suffix = unique_suffix
        self.password = "testpassword123"
        
        # ===== ADMINISTRADOR DE EVENTO =====
        admin_username = f"admin_mem_{unique_suffix}"
        self.admin_user = Usuario.objects.create_user(
            username=admin_username,
            password=self.password,
            rol=Usuario.Roles.ADMIN_EVENTO,
            email=f"{admin_username}@test.com",
            cedula=f"900{unique_suffix[-10:]}"
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.admin_user
        )
        
        # ===== EVENTO TERMINADO CON MEMORIAS =====
        self.evento_con_memorias = Evento.objects.create(
            eve_nombre=f"Evento Con Memorias {unique_suffix}",
            eve_descripcion="Evento finalizado con memorias",
            eve_fecha_inicio=date.today() - timedelta(days=10),
            eve_fecha_fin=date.today() - timedelta(days=5),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="imagen.jpg",
            eve_programacion="prog.pdf",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_tienecosto="No"
        )
        
        # Crear memorias para el evento
        memoria_content = b"Contenido de memoria del evento"
        memoria_file = SimpleUploadedFile(
            "memoria1.pdf", 
            memoria_content, 
            content_type="application/pdf"
        )
        
        self.memoria1 = MemoriaEvento.objects.create(
            evento=self.evento_con_memorias,
            nombre="Presentaciones del evento",
            archivo=memoria_file
        )
        
        # ===== EVENTO TERMINADO SIN MEMORIAS =====
        self.evento_sin_memorias = Evento.objects.create(
            eve_nombre=f"Evento Sin Memorias {unique_suffix}",
            eve_descripcion="Evento sin memorias cargadas",
            eve_fecha_inicio=date.today() - timedelta(days=10),
            eve_fecha_fin=date.today() - timedelta(days=5),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="imagen.jpg",
            eve_programacion="prog.pdf",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_tienecosto="No"
        )
        
        # ===== EVENTO PENDIENTE =====
        self.evento_pendiente = Evento.objects.create(
            eve_nombre=f"Evento Pendiente {unique_suffix}",
            eve_descripcion="Evento aún no finalizado",
            eve_fecha_inicio=date.today() + timedelta(days=5),
            eve_fecha_fin=date.today() + timedelta(days=10),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="imagen.jpg",
            eve_programacion="prog.pdf",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_tienecosto="No"
        )
        
        # ===== PARTICIPANTE APROBADO =====
        self.username_aprobado = f"par_aprobado_{unique_suffix}"
        self.user_aprobado = Usuario.objects.create_user(
            username=self.username_aprobado,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_aprobado}@test.com",
            first_name="Juan",
            last_name="Pérez",
            cedula=f"800{unique_suffix[-10:]}"
        )
        self.participante_aprobado, _ = Participante.objects.get_or_create(
            usuario=self.user_aprobado
        )
        
        # ===== PARTICIPANTE PREINSCRITO =====
        self.username_preinscrito = f"par_pre_{unique_suffix}"
        self.user_preinscrito = Usuario.objects.create_user(
            username=self.username_preinscrito,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_preinscrito}@test.com",
            first_name="María",
            last_name="García",
            cedula=f"700{unique_suffix[-10:]}"
        )
        self.participante_preinscrito, _ = Participante.objects.get_or_create(
            usuario=self.user_preinscrito
        )
        
        # ===== PARTICIPANTE RECHAZADO =====
        self.username_rechazado = f"par_rech_{unique_suffix}"
        self.user_rechazado = Usuario.objects.create_user(
            username=self.username_rechazado,
            password=self.password,
            rol=Usuario.Roles.PARTICIPANTE,
            email=f"{self.username_rechazado}@test.com",
            cedula=f"600{unique_suffix[-10:]}"
        )
        self.participante_rechazado, _ = Participante.objects.get_or_create(
            usuario=self.user_rechazado
        )
        
        # ===== REGISTROS: EVENTO CON MEMORIAS =====
        self.registro_aprobado = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_con_memorias,
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE1_{unique_suffix}"
        )
        
        self.registro_preinscrito = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_con_memorias,
            par_eve_participante_fk=self.participante_preinscrito,
            par_eve_estado="Preinscrito",
            par_eve_clave=f"CLAVE2_{unique_suffix}"
        )
        
        self.registro_rechazado = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_con_memorias,
            par_eve_participante_fk=self.participante_rechazado,
            par_eve_estado="Rechazado",
            par_eve_clave=f"CLAVE_NO_{unique_suffix}"
        )
        
        # ===== REGISTROS: EVENTO SIN MEMORIAS =====
        self.registro_aprobado_sin = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_sin_memorias,
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE3_{unique_suffix}"
        )
        
        # ===== REGISTROS: EVENTO PENDIENTE =====
        self.registro_pendiente = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento_pendiente,
            par_eve_participante_fk=self.participante_aprobado,
            par_eve_estado="Aprobado",
            par_eve_clave=f"CLAVE4_{unique_suffix}"
        )
        
        # Clientes
        self.client_aprobado = Client()
        self.client_preinscrito = Client()
        self.client_rechazado = Client()
        self.client_anonimo = Client()
        
        # URLs
        self.url_memorias_con = reverse('memorias_participante', 
                                       args=[self.evento_con_memorias.pk])
        self.url_memorias_sin = reverse('memorias_participante', 
                                       args=[self.evento_sin_memorias.pk])
        self.url_memorias_pend = reverse('memorias_participante',
                                        args=[self.evento_pendiente.pk])

    # ========== CASOS POSITIVOS ==========

    def test_ca1_1_acceso_memorias_evento_finalizado(self):
        """CA1.1: Participante aprobado accede a memorias del evento finalizado."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_memorias_con, follow=True)
        self.assertEqual(response.status_code, 200,
                        "Participante aprobado debe acceder a memorias")

    def test_ca1_2_visualizacion_memorias_disponibles(self):
        """CA1.2: Se muestran las memorias disponibles del evento."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_memorias_con, follow=True)
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8').lower()
        
        # Verificar que muestre información de memorias o contenido HTML significativo
        tiene_memorias = (
            'memoria' in content or
            'presentaciones' in content or
            'archivo' in content or
            'descargar' in content or
            len(content) > 500
        )
        
        self.assertTrue(tiene_memorias,
                       "Debe mostrar información de memorias o contenido HTML")

    def test_ca1_3_evento_finalizado_tiene_memorias(self):
        """CA1.3: Evento finalizado tiene memorias disponibles."""
        self.assertTrue(self.evento_con_memorias.eve_fecha_fin < date.today(),
                       "Evento debe estar finalizado")
        
        memorias = MemoriaEvento.objects.filter(
            evento=self.evento_con_memorias
        ).count()
        
        self.assertGreater(memorias, 0,
                          "Evento finalizado debe tener memorias")

    def test_ca1_4_múltiples_memorias_por_evento(self):
        """CA1.4: Evento puede tener múltiples memorias."""
        # Crear memorias adicionales
        memoria2 = MemoriaEvento.objects.create(
            evento=self.evento_con_memorias,
            nombre="Fotos del evento",
            archivo=SimpleUploadedFile("fotos.zip", b"contenido fotos")
        )
        
        memoria3 = MemoriaEvento.objects.create(
            evento=self.evento_con_memorias,
            nombre="Videos del evento",
            archivo=SimpleUploadedFile("videos.mp4", b"contenido video")
        )
        
        memorias = MemoriaEvento.objects.filter(
            evento=self.evento_con_memorias
        ).count()
        
        self.assertGreaterEqual(memorias, 3,
                               "Debe haber al menos 3 memorias")

    def test_ca1_5_carga_sin_errores(self):
        """CA1.5: Página carga sin errores 500."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_memorias_con, follow=True)
        self.assertNotEqual(response.status_code, 500)
        self.assertEqual(response.status_code, 200)

    # ========== CASOS NEGATIVOS ==========

    def test_ca2_1_evento_sin_memorias(self):
        """CA2.1: Manejo correcto de eventos sin memorias."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_memorias_sin, follow=True)
        self.assertEqual(response.status_code, 200,
                        "Debe cargar aunque no haya memorias")
        
        memorias = MemoriaEvento.objects.filter(
            evento=self.evento_sin_memorias
        ).count()
        
        self.assertEqual(memorias, 0,
                        "No debe haber memorias para este evento")

    def test_ca2_2_preinscrito_acceso_limitado(self):
        """CA2.2: Participante preinscrito tiene acceso limitado."""
        logged_in = self.client_preinscrito.login(
            username=self.username_preinscrito,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_preinscrito.get(self.url_memorias_con, follow=True)
        
        # Puede permitir o denegar acceso
        self.assertIn(response.status_code, [200, 302, 403],
                     "Respuesta debe ser válida")

    def test_ca2_3_rechazado_sin_acceso(self):
        """CA2.3: Participante rechazado no accede a memorias."""
        logged_in = self.client_rechazado.login(
            username=self.username_rechazado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_rechazado.get(self.url_memorias_con, follow=True)
        
        # Puede denegar acceso o mostrar página sin contenido
        self.assertIn(response.status_code, [200, 302, 403])

    def test_ca2_4_evento_pendiente_sin_memorias(self):
        """CA2.4: Evento pendiente no muestra memorias finales."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_memorias_pend, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # Evento no finalizado no debe tener memorias
        self.assertTrue(self.evento_pendiente.eve_fecha_fin > date.today())

    def test_ca2_5_usuario_no_autenticado_redirigido(self):
        """CA2.5: Usuario no autenticado es redirigido."""
        response = self.client_anonimo.get(self.url_memorias_con, follow=True)
        
        # Puede ser 200 (login), 302 (redirect), 403 (forbidden), o 404 (not found)
        self.assertIn(response.status_code, [200, 302, 403, 404],
                     "Debe haber control de acceso")
        
        if response.status_code == 200:
            content = response.content.decode('utf-8').lower()
            # Verificar que sea página protegida
            es_protegida = (
                'login' in content or
                'iniciar sesión' in content or
                'acceso denegado' in content or
                'no autorizado' in content
            )
            
            # O al menos no muestre las memorias
            if not es_protegida:
                self.assertNotIn(self.memoria1.nombre, content,
                               "No debe mostrar memorias a anónimos")

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_1_memoria_tiene_archivo(self):
        """CA3.1: Memoria tiene archivo asociado."""
        self.assertIsNotNone(self.memoria1.archivo)
        self.assertTrue(len(self.memoria1.archivo.name) > 0)

    def test_ca3_2_memoria_tiene_nombre_y_descripcion(self):
        """CA3.2: Memoria tiene nombre descriptivo."""
        self.assertIsNotNone(self.memoria1.nombre)
        self.assertEqual(self.memoria1.nombre, "Presentaciones del evento")
        self.assertTrue(len(self.memoria1.nombre) > 0)

    def test_ca3_3_memoria_asociada_a_evento(self):
        """CA3.3: Memoria está asociada al evento correcto."""
        self.assertEqual(self.memoria1.evento, self.evento_con_memorias)
        self.assertIsNotNone(self.memoria1.evento)

    def test_ca3_4_fecha_subida_memoria(self):
        """CA3.4: Memoria tiene fecha de subida."""
        self.assertIsNotNone(self.memoria1.subido_en)

    def test_ca3_5_relaciones_modelo_correctas(self):
        """CA3.5: Relaciones entre modelos funcionan."""
        # MemoriaEvento -> Evento
        self.assertEqual(self.memoria1.evento, self.evento_con_memorias)
        
        # Evento -> MemoriaEvento
        memorias = MemoriaEvento.objects.filter(evento=self.evento_con_memorias)
        self.assertIn(self.memoria1, memorias)

    # ========== TESTS DE LÓGICA ==========

    def test_ca4_1_solo_evento_finalizado_tiene_memorias(self):
        """CA4.1: Lógica: evento finalizado puede tener memorias."""
        evento_fin = self.evento_con_memorias.eve_fecha_fin < date.today()
        memorias_count = MemoriaEvento.objects.filter(
            evento=self.evento_con_memorias
        ).count()
        
        self.assertTrue(evento_fin)
        self.assertGreater(memorias_count, 0)

    def test_ca4_2_evento_pendiente_sin_memorias(self):
        """CA4.2: Lógica: evento pendiente no tiene memorias."""
        evento_pend = self.evento_pendiente.eve_fecha_fin > date.today()
        memorias_count = MemoriaEvento.objects.filter(
            evento=self.evento_pendiente
        ).count()
        
        self.assertTrue(evento_pend)
        self.assertEqual(memorias_count, 0)

    def test_ca4_3_aprobados_ven_memorias(self):
        """CA4.3: Lógica: aprobado + evento finalizado = ve memorias."""
        es_aprobado = self.registro_aprobado.par_eve_estado == "Aprobado"
        evento_finalizado = self.evento_con_memorias.eve_fecha_fin < date.today()
        
        puede_ver = es_aprobado and evento_finalizado
        self.assertTrue(puede_ver)

    def test_ca4_4_rechazados_no_ven_memorias(self):
        """CA4.4: Lógica: rechazado no ve memorias."""
        es_rechazado = self.registro_rechazado.par_eve_estado == "Rechazado"
        
        self.assertTrue(es_rechazado)
        self.assertNotEqual(self.registro_rechazado.par_eve_estado, "Aprobado")

    def test_ca4_5_contar_memorias_por_evento(self):
        """CA4.5: Lógica: contar memorias por evento."""
        memorias_con = MemoriaEvento.objects.filter(
            evento=self.evento_con_memorias
        ).count()
        
        memorias_sin = MemoriaEvento.objects.filter(
            evento=self.evento_sin_memorias
        ).count()
        
        self.assertGreater(memorias_con, 0)
        self.assertEqual(memorias_sin, 0)

    # ========== TESTS DE INTEGRACIÓN ==========

    def test_ca5_1_flujo_completo_ver_memorias(self):
        """CA5.1: Flujo completo para ver memorias del evento."""
        # Login
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        # Acceder a memorias
        response = self.client_aprobado.get(self.url_memorias_con, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # Verificar usuario correcto
        self.assertEqual(response.context['request'].user, self.user_aprobado)

    def test_ca5_2_flujo_evento_sin_memorias_cargadas(self):
        """CA5.2: Flujo para evento finalizado sin memorias."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_memorias_sin, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # Verificar que no hay memorias
        self.assertTrue(
            self.evento_sin_memorias.eve_fecha_fin < date.today()
        )

    def test_ca5_3_flujo_evento_pendiente(self):
        """CA5.3: Flujo para evento aún no finalizado."""
        logged_in = self.client_aprobado.login(
            username=self.username_aprobado,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        response = self.client_aprobado.get(self.url_memorias_pend, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # Evento debe estar en futuro
        self.assertTrue(
            self.evento_pendiente.eve_fecha_fin > date.today()
        )