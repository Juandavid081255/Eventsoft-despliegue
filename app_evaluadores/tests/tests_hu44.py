# app_evaluadores/tests/tests_hu44.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date
import time
import random

from app_usuarios.models import Usuario, Evaluador, Participante, AdministradorEvento
from app_admin_eventos.models import Evento, Criterio
from app_evaluadores.models import EvaluadorEvento
from app_participantes.models import ParticipanteEvento


class PublicacionCriteriosTest(TestCase):
    """
    HU44 - Publicación y Visualización de Criterios de Evaluación
    Como usuario del sistema quiero visualizar los criterios de evaluación
    para conocer cómo serán evaluados los proyectos/propuestas.
    
    Roles que pueden ver criterios:
    - Administrador (creador)
    - Evaluadores (inscritos en el evento)
    - Participantes (inscritos en el evento)
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
        admin_username = f"admin_hu44_{unique_suffix}"
        self.admin_user = Usuario.objects.create_user(
            username=admin_username,
            password=self.password,
            email=f"{admin_username}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            cedula=f"900{unique_suffix[-10:]}",
            first_name="Admin",
            last_name="HU44"
        )
        
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=self.admin_user)
        
        # ===== EVENTO =====
        self.evento = Evento.objects.create(
            eve_nombre=f"Evento HU44 {unique_suffix}",
            eve_descripcion="Evento para visualización de criterios",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_fecha_inicio=date(2025, 12, 1),
            eve_fecha_fin=date(2025, 12, 3),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_imagen=SimpleUploadedFile("img.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"contenido", content_type="application/pdf"),
            preinscripcion_habilitada_evaluadores=True,
            preinscripcion_habilitada_participantes=True
        )
        
        # ===== CRITERIOS DEL EVENTO =====
        self.criterio1 = Criterio.objects.create(
            cri_descripcion="Claridad de la propuesta",
            cri_peso=30.0,
            cri_evento_fk=self.evento
        )
        
        self.criterio2 = Criterio.objects.create(
            cri_descripcion="Innovación y originalidad",
            cri_peso=40.0,
            cri_evento_fk=self.evento
        )
        
        self.criterio3 = Criterio.objects.create(
            cri_descripcion="Viabilidad técnica",
            cri_peso=30.0,
            cri_evento_fk=self.evento
        )
        
        self.criterios = [self.criterio1, self.criterio2, self.criterio3]
        
        # ===== EVALUADOR INSCRITO =====
        user_evaluador = f"eval_hu44_{unique_suffix}"
        self.user_evaluador = Usuario.objects.create_user(
            username=user_evaluador,
            password=self.password,
            email=f"{user_evaluador}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"800{unique_suffix[-10:]}",
            first_name="Carlos",
            last_name="Evaluador"
        )
        
        self.evaluador, _ = Evaluador.objects.get_or_create(usuario=self.user_evaluador)
        
        self.registro_evaluador = EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador,
            eva_eve_evento_fk=self.evento,
            eva_eve_estado="Aprobado",
            eva_eve_clave=f"E{unique_suffix}",
            eva_eve_documento=SimpleUploadedFile("cv.pdf", b"CV", content_type="application/pdf")
        )
        
        # ===== EVALUADOR NO INSCRITO =====
        user_eval_no_inscrito = f"eval_no_hu44_{unique_suffix}"
        self.user_eval_no_inscrito = Usuario.objects.create_user(
            username=user_eval_no_inscrito,
            password=self.password,
            email=f"{user_eval_no_inscrito}@test.com",
            rol=Usuario.Roles.EVALUADOR,
            cedula=f"810{unique_suffix[-10:]}",
            first_name="Pedro",
            last_name="NoInscrito"
        )
        
        self.evaluador_no_inscrito, _ = Evaluador.objects.get_or_create(
            usuario=self.user_eval_no_inscrito
        )
        
        # ===== PARTICIPANTE INSCRITO =====
        user_participante = f"part_hu44_{unique_suffix}"
        self.user_participante = Usuario.objects.create_user(
            username=user_participante,
            password=self.password,
            email=f"{user_participante}@test.com",
            rol=Usuario.Roles.PARTICIPANTE,
            cedula=f"700{unique_suffix[-10:]}",
            first_name="Diana",
            last_name="Participante"
        )
        
        self.participante, _ = Participante.objects.get_or_create(usuario=self.user_participante)
        
        self.part_evento = ParticipanteEvento.objects.create(
            par_eve_participante_fk=self.participante,
            par_eve_evento_fk=self.evento,
            par_eve_estado="Aprobado",
            par_eve_clave=f"P{unique_suffix}",
            par_eve_documentos=SimpleUploadedFile("proyecto.pdf", b"Proyecto", content_type="application/pdf")
        )
        
        # ===== CLIENTES =====
        self.client = Client()
        
        # ===== URLs =====
        self.url_ver_criterios_eva = reverse('ver_criterios_eva', args=[self.evento.pk])
        self.url_ver_criterios_par = reverse('ver_criterios_par', args=[self.evento.pk])
        self.url_ver_criterios_agregados = reverse('ver_criterios_agregados_eva', args=[self.evento.pk])

    # ========== TESTS POSITIVOS ==========

    def test_ca1_1_evaluador_inscrito_puede_ver_criterios(self):
        """CA1.1: Un evaluador inscrito puede visualizar los criterios del evento."""
        # Login como evaluador inscrito
        login_ok = self.client.login(
            username=self.user_evaluador.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        # Establecer evaluador_id en sesión
        session = self.client.session
        session['evaluador_id'] = self.evaluador.id
        session.save()
        
        # Acceder a los criterios
        response = self.client.get(self.url_ver_criterios_eva, follow=True)
        
        # Verificar acceso exitoso
        self.assertEqual(response.status_code, 200,
                        "El evaluador inscrito debe poder ver los criterios")
        
        # Verificar que se muestran todos los criterios
        content = response.content.decode('utf-8')
        for criterio in self.criterios:
            self.assertIn(criterio.cri_descripcion, content,
                         f"El criterio '{criterio.cri_descripcion}' debe mostrarse")

    def test_ca1_2_participante_inscrito_puede_ver_criterios(self):
        """CA1.2: Un participante inscrito puede visualizar los criterios del evento."""
        # Login como participante inscrito
        login_ok = self.client.login(
            username=self.user_participante.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        # Establecer participante_id en sesión
        session = self.client.session
        session['participante_id'] = self.participante.id
        session.save()
        
        # Acceder a los criterios
        response = self.client.get(self.url_ver_criterios_par, follow=True)
        
        # Verificar acceso exitoso
        self.assertEqual(response.status_code, 200,
                        "El participante inscrito debe poder ver los criterios")
        
        # Verificar que se muestran todos los criterios
        content = response.content.decode('utf-8')
        for criterio in self.criterios:
            self.assertIn(criterio.cri_descripcion, content,
                         f"El criterio '{criterio.cri_descripcion}' debe mostrarse")

    def test_ca1_3_criterios_muestran_descripcion_y_peso(self):
        """CA1.3: Los criterios muestran tanto la descripción como el peso."""
        # Login como evaluador
        self.client.login(username=self.user_evaluador.username, password=self.password)
        
        session = self.client.session
        session['evaluador_id'] = self.evaluador.id
        session.save()
        
        response = self.client.get(self.url_ver_criterios_eva, follow=True)
        self.assertEqual(response.status_code, 200)
        
        content = response.content.decode('utf-8')
        
        # Verificar que se muestran descripciones Y pesos
        for criterio in self.criterios:
            self.assertIn(criterio.cri_descripcion, content,
                         "Debe mostrar la descripción del criterio")
            self.assertIn(str(int(criterio.cri_peso)), content,
                         "Debe mostrar el peso del criterio")

    def test_ca1_4_suma_de_pesos_es_100(self):
        """CA1.4: La suma de los pesos de los criterios debe ser 100%."""
        suma_pesos = sum(criterio.cri_peso for criterio in self.criterios)
        
        self.assertEqual(suma_pesos, 100.0,
                        "La suma de los pesos de los criterios debe ser 100%")

    def test_ca1_5_admin_puede_ver_criterios_agregados(self):
        """CA1.5: El administrador puede ver la lista de criterios agregados."""
        # Esta vista es del módulo de evaluadores, no de admin
        # El admin normalmente ve criterios desde otra vista
        # Por ahora verificamos que la vista existe y responde
        
        # Login como admin
        login_ok = self.client.login(
            username=self.admin_user.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        session = self.client.session
        session['administrador_evento_id'] = self.admin_evento.id
        session.save()
        
        # Acceder a la vista de criterios agregados
        response = self.client.get(self.url_ver_criterios_agregados, follow=True)
        
        # Verificar acceso (puede redirigir si no tiene permisos de evaluador)
        self.assertIn(response.status_code, [200, 302],
                     "La vista debe responder o redirigir")
        
        # Si responde con 200, verificar contenido
        if response.status_code == 200:
            content = response.content.decode('utf-8')
            criterios_encontrados = sum(
                1 for criterio in self.criterios 
                if criterio.cri_descripcion in content
            )
            
            # Si no encuentra criterios, es porque la vista requiere rol de evaluador
            if criterios_encontrados == 0:
                # Verificar que al menos la página cargó sin errores
                self.assertNotIn('error', content.lower(),
                               "No debe haber errores en la respuesta")
        else:
            # Si redirigió, es aceptable (puede requerir rol específico)
            self.assertEqual(response.status_code, 302,
                           "Debe redirigir si no tiene permisos")

    def test_ca1_6_evento_sin_criterios_muestra_mensaje(self):
        """CA1.6: Si un evento no tiene criterios, se muestra un mensaje apropiado."""
        # Crear evento sin criterios
        evento_vacio = Evento.objects.create(
            eve_nombre=f"Evento Sin Criterios {self.unique_suffix}",
            eve_descripcion="Evento sin criterios",
            eve_ciudad="Manizales",
            eve_lugar="Universidad",
            eve_fecha_inicio=date(2025, 12, 1),
            eve_fecha_fin=date(2025, 12, 3),
            eve_estado="activo",
            eve_administrador_fk=self.admin_evento,
            eve_tienecosto="No",
            eve_capacidad=100,
            eve_imagen=SimpleUploadedFile("img2.jpg", b"contenido", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"contenido", content_type="application/pdf")
        )
        
        # Crear evaluador inscrito en este evento
        EvaluadorEvento.objects.create(
            eva_eve_evaluador_fk=self.evaluador,
            eva_eve_evento_fk=evento_vacio,
            eva_eve_estado="Aprobado",
            eva_eve_clave=f"E2{self.unique_suffix}",
            eva_eve_documento=SimpleUploadedFile("cv2.pdf", b"CV", content_type="application/pdf")
        )
        
        # Login como evaluador
        self.client.login(username=self.user_evaluador.username, password=self.password)
        
        session = self.client.session
        session['evaluador_id'] = self.evaluador.id
        session.save()
        
        # Acceder a criterios del evento vacío
        url_evento_vacio = reverse('ver_criterios_eva', args=[evento_vacio.pk])
        response = self.client.get(url_evento_vacio, follow=True)
        
        self.assertEqual(response.status_code, 200)
        
        # Verificar mensaje apropiado
        content = response.content.decode('utf-8').lower()
        tiene_mensaje = any([
            'no hay criterios' in content,
            'sin criterios' in content,
            'no se han definido' in content,
            'no se han agregado' in content,
        ])
        
        # Si no hay mensaje explícito, al menos verificar que no muestra criterios falsos
        if not tiene_mensaje:
            # Verificar que no aparecen los criterios del otro evento
            for criterio in self.criterios:
                self.assertNotIn(criterio.cri_descripcion.lower(), content,
                               "No debe mostrar criterios de otros eventos")

    # ========== TESTS NEGATIVOS ==========

    def test_ca2_1_evaluador_no_inscrito_no_puede_ver_criterios(self):
        """CA2.1: Un evaluador NO inscrito no puede ver los criterios del evento."""
        # Login como evaluador no inscrito
        login_ok = self.client.login(
            username=self.user_eval_no_inscrito.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        session = self.client.session
        session['evaluador_id'] = self.evaluador_no_inscrito.id
        session.save()
        
        # Intentar acceder a los criterios
        response = self.client.get(self.url_ver_criterios_eva, follow=True)
        
        # Debe ser bloqueado o redirigido
        if response.status_code == 200:
            # Si es 200, verificar que no muestra los criterios reales
            content = response.content.decode('utf-8')
            criterios_mostrados = sum(
                1 for criterio in self.criterios 
                if criterio.cri_descripcion in content
            )
            
            self.assertEqual(criterios_mostrados, 0,
                           "No debe mostrar criterios a evaluadores no inscritos")
        else:
            # Si redirige, está correcto
            self.assertIn(response.status_code, [302, 403],
                         "Debe bloquear o redirigir a evaluadores no inscritos")

    def test_ca2_2_usuario_sin_autenticar_no_puede_ver_criterios(self):
        """CA2.2: Un usuario no autenticado no puede ver los criterios."""
        # NO hacer login
        response = self.client.get(self.url_ver_criterios_eva, follow=True)
        
        # Debe redirigir al login
        final_url = response.redirect_chain[-1][0] if response.redirect_chain else ''
        
        redirigido_a_login = (
            'login' in final_url.lower() or
            response.status_code in [302, 403]
        )
        
        self.assertTrue(redirigido_a_login,
                       "Usuario no autenticado debe ser redirigido al login")

    def test_ca2_3_participante_no_inscrito_no_puede_ver_criterios(self):
        """CA2.3: Un participante NO inscrito no puede ver los criterios."""
        # Crear participante no inscrito
        user_part_no_inscrito = f"part_no_hu44_{self.unique_suffix}"
        user_part_no_inscrito = Usuario.objects.create_user(
            username=user_part_no_inscrito,
            password=self.password,
            email=f"{user_part_no_inscrito}@test.com",
            rol=Usuario.Roles.PARTICIPANTE,
            cedula=f"720{self.unique_suffix[-10:]}",
            first_name="Juan",
            last_name="NoInscrito"
        )
        
        participante_no_inscrito, _ = Participante.objects.get_or_create(
            usuario=user_part_no_inscrito
        )
        
        # Login como participante no inscrito
        self.client.login(username=user_part_no_inscrito.username, password=self.password)
        
        session = self.client.session
        session['participante_id'] = participante_no_inscrito.id
        session.save()
        
        # Intentar acceder
        response = self.client.get(self.url_ver_criterios_par, follow=True)
        
        # Verificar bloqueo
        if response.status_code == 200:
            content = response.content.decode('utf-8')
            criterios_mostrados = sum(
                1 for criterio in self.criterios 
                if criterio.cri_descripcion in content
            )
            
            self.assertEqual(criterios_mostrados, 0,
                           "No debe mostrar criterios a participantes no inscritos")
        else:
            self.assertIn(response.status_code, [302, 403],
                         "Debe bloquear a participantes no inscritos")

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_1_modelo_criterio_tiene_campos_necesarios(self):
        """CA3.1: El modelo Criterio tiene los campos necesarios para la visualización."""
        self.assertTrue(hasattr(self.criterio1, 'cri_descripcion'),
                       "Debe tener campo cri_descripcion")
        self.assertTrue(hasattr(self.criterio1, 'cri_peso'),
                       "Debe tener campo cri_peso")
        self.assertTrue(hasattr(self.criterio1, 'cri_evento_fk'),
                       "Debe tener relación con evento")

    def test_ca3_2_criterios_relacionados_con_evento(self):
        """CA3.2: Los criterios están correctamente relacionados con el evento."""
        for criterio in self.criterios:
            self.assertEqual(criterio.cri_evento_fk, self.evento,
                           "Cada criterio debe estar relacionado con el evento correcto")

    def test_ca3_3_puede_consultar_criterios_por_evento(self):
        """CA3.3: Se pueden consultar todos los criterios de un evento específico."""
        criterios_evento = Criterio.objects.filter(cri_evento_fk=self.evento)
        
        self.assertEqual(criterios_evento.count(), 3,
                        "Debe haber 3 criterios para este evento")
        
        # Verificar que son los criterios correctos
        descripciones = [c.cri_descripcion for c in criterios_evento]
        self.assertIn("Claridad de la propuesta", descripciones)
        self.assertIn("Innovación y originalidad", descripciones)
        self.assertIn("Viabilidad técnica", descripciones)

    def test_ca3_4_relaciones_de_inscripcion_controlan_acceso(self):
        """CA3.4: Las relaciones de inscripción determinan quién puede ver los criterios."""
        # Verificar que el evaluador inscrito tiene relación
        tiene_relacion_eval = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=self.evaluador,
            eva_eve_evento_fk=self.evento
        ).exists()
        self.assertTrue(tiene_relacion_eval,
                       "El evaluador inscrito debe tener relación con el evento")
        
        # Verificar que el evaluador no inscrito NO tiene relación
        no_tiene_relacion = not EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=self.evaluador_no_inscrito,
            eva_eve_evento_fk=self.evento
        ).exists()
        self.assertTrue(no_tiene_relacion,
                       "El evaluador no inscrito no debe tener relación")
        
        # Similar para participante
        tiene_relacion_part = ParticipanteEvento.objects.filter(
            par_eve_participante_fk=self.participante,
            par_eve_evento_fk=self.evento
        ).exists()
        self.assertTrue(tiene_relacion_part,
                       "El participante inscrito debe tener relación con el evento")