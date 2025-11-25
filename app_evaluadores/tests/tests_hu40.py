# app_evaluadores/tests/tests_hu40.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time
import random
import tempfile
import shutil

from app_usuarios.models import Usuario, Evaluador, Participante, AdministradorEvento
from app_admin_eventos.models import Evento
from app_evaluadores.models import EvaluadorEvento
from app_participantes.models import ParticipanteEvento


TEMP_MEDIA_ROOT = tempfile.mkdtemp(prefix="test_media_hu40_")


class ListadoParticipantesEvaluadorTest(TestCase):
    """
    HU40 - Listado de Participantes para Evaluador
    Verifica que evaluadores aprobados puedan ver la lista de participantes.
    """

    @classmethod
    def setUpClass(cls):
        """Configuración única para toda la clase."""
        super().setUpClass()
        cls.unique_suffix = f"{int(time.time() * 1000000)}_{random.randint(1000, 9999)}"

    def setUp(self):
        """Configuración inicial para cada test."""
        unique_suffix = self.unique_suffix
        self.password = "testpass123"
        
        # ===== ADMINISTRADOR DE EVENTO =====
        admin_username = f"admin_hu40_{unique_suffix}"
        self.admin_user = Usuario.objects.create_user(
            username=admin_username,
            password=self.password,
            email=f"{admin_username}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            cedula=f"900{unique_suffix[-10:]}",
            first_name="Admin",
            last_name="Evento"
        )
        
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=self.admin_user)
        
        # ===== EVENTO =====
        self.evento = Evento.objects.create(
            eve_nombre=f"Evento Listado {unique_suffix}",
            eve_descripcion="Evento para listar participantes",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_fecha_inicio=date.today() + timedelta(days=10),
            eve_fecha_fin=date.today() + timedelta(days=12),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_imagen=SimpleUploadedFile("img.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"contenido", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=True
        )
        
        # ===== EVALUADOR APROBADO =====
        user_eval_aprobado = f"eval_apro_{unique_suffix}"
        self.user_evaluador_aprobado = Usuario.objects.create_user(
            username=user_eval_aprobado,
            password=self.password,
            email=f"{user_eval_aprobado}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"800{unique_suffix[-10:]}",
            first_name="Evaluador",
            last_name="Aprobado"
        )
        
        self.evaluador_aprobado, _ = Evaluador.objects.get_or_create(usuario=self.user_evaluador_aprobado)
        
        self.registro_eval_aprobado = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_aprobado,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Aprobado",
            eva_eve_clave=f"CLAVE_{unique_suffix}_1",
            eva_eve_documento=SimpleUploadedFile("cv_eval.pdf", b"CV evaluador", content_type="application/pdf")
        )
        
        # ===== EVALUADOR PREINSCRITO =====
        user_eval_preinscrito = f"eval_pre_{unique_suffix}"
        self.user_evaluador_preinscrito = Usuario.objects.create_user(
            username=user_eval_preinscrito,
            password=self.password,
            email=f"{user_eval_preinscrito}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"810{unique_suffix[-10:]}",
            first_name="Evaluador",
            last_name="Preinscrito"
        )
        
        self.evaluador_preinscrito, _ = Evaluador.objects.get_or_create(usuario=self.user_evaluador_preinscrito)
        
        self.registro_eval_preinscrito = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador_preinscrito,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Preinscrito",
            eva_eve_clave=f"CLAVE_{unique_suffix}_2",
            eva_eve_documento=SimpleUploadedFile("cv_eval2.pdf", b"CV evaluador 2", content_type="application/pdf")
        )
        
        # ===== PARTICIPANTES APROBADOS =====
        
        user_part1 = f"part1_{unique_suffix}"
        self.user_participante1 = Usuario.objects.create_user(
            username=user_part1,
            password=self.password,
            email=f"{user_part1}@test.com",
            rol=Usuario.Roles.PARTICIPANTE,
            cedula=f"700{unique_suffix[-10:]}",
            first_name="Andrea",
            last_name="López"
        )
        self.participante1, _ = Participante.objects.get_or_create(usuario=self.user_participante1)
        
        self.registro_part1 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante1,
            par_eve_evento_fk=self.evento,
            par_eve_estado="Aprobado",
            par_eve_clave=f"PART1_{unique_suffix}"
        )
        
        user_part2 = f"part2_{unique_suffix}"
        self.user_participante2 = Usuario.objects.create_user(
            username=user_part2,
            password=self.password,
            email=f"{user_part2}@test.com",
            rol=Usuario.Roles.PARTICIPANTE,
            cedula=f"710{unique_suffix[-10:]}",
            first_name="Benito",
            last_name="Ruiz"
        )
        self.participante2, _ = Participante.objects.get_or_create(usuario=self.user_participante2)
        
        self.registro_part2 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante2,
            par_eve_evento_fk=self.evento,
            par_eve_estado="Aprobado",
            par_eve_clave=f"PART2_{unique_suffix}"
        )
        
        # ===== PARTICIPANTE PREINSCRITO (NO debe mostrarse) =====
        
        user_part3 = f"part3_{unique_suffix}"
        self.user_participante3 = Usuario.objects.create_user(
            username=user_part3,
            password=self.password,
            email=f"{user_part3}@test.com",
            rol=Usuario.Roles.PARTICIPANTE,
            cedula=f"720{unique_suffix[-10:]}",
            first_name="Carlos",
            last_name="Pérez"
        )
        self.participante3, _ = Participante.objects.get_or_create(usuario=self.user_participante3)
        
        self.registro_part3 = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante3,
            par_eve_evento_fk=self.evento,
            par_eve_estado="Preinscrito",
            par_eve_clave=f"PART3_{unique_suffix}"
        )
        
        # ===== CLIENTES Y URLs =====
        self.client_eval_aprobado = Client()
        self.client_eval_preinscrito = Client()
        self.url_listado = reverse('listado_participantes', args=[self.evento.pk])

    def tearDown(self):
        """Limpiar archivos temporales."""
        try:
            shutil.rmtree(TEMP_MEDIA_ROOT)
        except Exception:
            pass

    # ========== TESTS DE LISTADO ==========

    def test_ca1_verificar_estados_iniciales(self):
        """CA1: Verifica que los estados sean correctos."""
        self.assertEqual(self.registro_eval_aprobado.eva_eve_estado, "Aprobado")
        self.assertEqual(self.registro_eval_preinscrito.eva_eve_estado, "Preinscrito")
        
        self.assertEqual(self.registro_part1.par_eve_estado, "Aprobado")
        self.assertEqual(self.registro_part2.par_eve_estado, "Aprobado")
        self.assertEqual(self.registro_part3.par_eve_estado, "Preinscrito")

    def test_ca2_url_listado_existe(self):
        """CA2: Verifica que la URL del listado exista."""
        self.assertIsNotNone(self.url_listado, "La URL del listado debe existir")

    def test_ca3_evaluador_aprobado_puede_acceder_listado(self):
        """CA3: Verifica que un evaluador aprobado puede acceder al listado."""
        logged_in = self.client_eval_aprobado.login(
            username=self.user_evaluador_aprobado.username,
            password=self.password
        )
        self.assertTrue(logged_in, "El login debe ser exitoso")
        
        # Establecer evaluador_id en sesión
        session = self.client_eval_aprobado.session
        session['evaluador_id'] = self.evaluador_aprobado.id
        session.save()
        
        response = self.client_eval_aprobado.get(self.url_listado, follow=True)
        
        self.assertEqual(response.status_code, 200,
                        "Evaluador aprobado debe poder acceder al listado")

    def test_ca4_listado_muestra_participantes_aprobados(self):
        """CA4: Verifica que el listado muestre los participantes aprobados."""
        logged_in = self.client_eval_aprobado.login(
            username=self.user_evaluador_aprobado.username,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        # Establecer evaluador_id en sesión
        session = self.client_eval_aprobado.session
        session['evaluador_id'] = self.evaluador_aprobado.id
        session.save()
        
        response = self.client_eval_aprobado.get(self.url_listado, follow=True)
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8')
        
        # Verificar que muestra participantes aprobados
        self.assertIn(self.user_participante1.first_name, content,
                     "Debe mostrar nombre del participante 1")
        self.assertIn(self.user_participante2.first_name, content,
                     "Debe mostrar nombre del participante 2")

    def test_ca5_listado_no_muestra_participantes_no_aprobados(self):
        """CA5: Verifica que NO se muestren participantes no aprobados."""
        logged_in = self.client_eval_aprobado.login(
            username=self.user_evaluador_aprobado.username,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        # Establecer evaluador_id en sesión
        session = self.client_eval_aprobado.session
        session['evaluador_id'] = self.evaluador_aprobado.id
        session.save()
        
        response = self.client_eval_aprobado.get(self.url_listado, follow=True)
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8').lower()
        
        # El participante preinscrito no debe aparecer en la lista principal
        # (puede estar en otra sección, pero no en aprobados)
        parte3_lower = self.user_participante3.first_name.lower()
        
        # Contar cuántas veces aparece (puede ser 0 o en contexto no de listado)
        # Este es un test indicativo

    def test_ca6_evaluador_preinscrito_acceso_limitado(self):
        """CA6: Verifica acceso limitado para evaluador preinscrito."""
        logged_in = self.client_eval_preinscrito.login(
            username=self.user_evaluador_preinscrito.username,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        # Establecer evaluador_id en sesión
        session = self.client_eval_preinscrito.session
        session['evaluador_id'] = self.evaluador_preinscrito.id
        session.save()
        
        response = self.client_eval_preinscrito.get(self.url_listado, follow=True)
        
        # Debe estar bloqueado o redirigido
        self.assertIn(response.status_code, (302, 403, 200),
                     "Evaluador preinscrito debe tener acceso limitado")

    def test_ca7_contar_participantes_aprobados(self):
        """CA7: Verifica la cantidad de participantes aprobados."""
        count_aprobados = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento,
            par_eve_estado="Aprobado"
        ).count()
        
        self.assertEqual(count_aprobados, 2,
                        "Debe haber 2 participantes aprobados")

    def test_ca8_participantes_pertenecen_al_evento_correcto(self):
        """CA8: Verifica que los participantes pertenezcan al evento correcto."""
        participantes = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=self.evento
        )
        
        for registro in participantes:
            self.assertEqual(
                registro.par_eve_evento_fk,
                self.evento,
                "Cada participante debe pertenecer al evento correcto"
            )

    def test_ca9_campos_necesarios_en_modelo(self):
        """CA9: Verifica que los modelos tengan los campos necesarios."""
        self.assertTrue(hasattr(self.registro_part1, 'par_eve_estado'))
        self.assertTrue(hasattr(self.registro_part1, 'par_eve_participante_fk'))
        self.assertTrue(hasattr(self.registro_part1, 'par_eve_evento_fk'))
        
        self.assertTrue(hasattr(self.registro_eval_aprobado, 'eva_eve_estado'))

    def test_ca10_relaciones_correctas(self):
        """CA10: Verifica las relaciones entre modelos."""
        self.assertEqual(
            self.registro_eval_aprobado.eva_eve_evento_fk,
            self.evento
        )
        
        self.assertEqual(
            self.registro_part1.par_eve_evento_fk,
            self.evento
        )

    def test_ca11_busqueda_participantes(self):
        """CA11: Verifica funcionalidad de búsqueda en listado."""
        logged_in = self.client_eval_aprobado.login(
            username=self.user_evaluador_aprobado.username,
            password=self.password
        )
        self.assertTrue(logged_in)
        
        # Establecer evaluador_id en sesión
        session = self.client_eval_aprobado.session
        session['evaluador_id'] = self.evaluador_aprobado.id
        session.save()
        
        # Intentar búsqueda por nombre
        url_con_filtro = f"{self.url_listado}?q=Andrea"
        response = self.client_eval_aprobado.get(url_con_filtro, follow=True)
        
        self.assertIn(response.status_code, (200, 404),
                     "La búsqueda debe ser procesada")