# app_evaluadores/tests/tests_hu43.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date
import time
import random

from app_usuarios.models import Usuario, Evaluador, AdministradorEvento
from app_admin_eventos.models import Evento
from app_evaluadores.models import EvaluadorEvento


class GestionInformacionTecnicaTest(TestCase):
    """
    HU43 - Gestión de Información Técnica del Evento
    Como administrador quiero cargar información técnica del evento
    para que los evaluadores puedan consultarla.
    
    Adaptado a la estructura existente que usa eve_informacion_tecnica.
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
        admin_username = f"admin_hu43_{unique_suffix}"
        self.admin_user = Usuario.objects.create_user(
            username=admin_username,
            password=self.password,
            email=f"{admin_username}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            cedula=f"900{unique_suffix[-10:]}",
            first_name="Admin",
            last_name="HU43"
        )
        
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=self.admin_user)
        
        # ===== EVENTO SIN INFORMACIÓN TÉCNICA INICIAL =====
        self.evento = Evento.objects.create(
            eve_nombre=f"Evento HU43 {unique_suffix}",
            eve_descripcion="Evento para gestión de información técnica",
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
            preinscripcion_habilitada_evaluadores=True
            # eve_informacion_tecnica se deja NULL inicialmente
        )
        
        # ===== EVALUADOR APROBADO =====
        user_evaluador = f"eval_hu43_{unique_suffix}"
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
        user_eval_no_inscrito = f"eval_no_inscrito_hu43_{unique_suffix}"
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
        
        # ===== CLIENTES =====
        self.client = Client()
        
        # ===== URLs =====
        # URL para que el evaluador vea la info técnica
        self.url_ver_info_tecnica = reverse('ver_info_tecnica_evento', args=[self.evento.pk])

    # ========== TESTS POSITIVOS ==========

    def test_ca1_1_evento_puede_tener_informacion_tecnica(self):
        """CA1.1: El modelo Evento puede almacenar información técnica."""
        self.assertTrue(hasattr(self.evento, 'eve_informacion_tecnica'),
                       "El evento debe tener campo eve_informacion_tecnica")
        
        # Verificar que inicialmente está vacío
        self.assertFalse(bool(self.evento.eve_informacion_tecnica),
                        "Inicialmente no debe haber información técnica")

    def test_ca1_2_admin_puede_cargar_informacion_tecnica(self):
        """CA1.2: El administrador puede cargar información técnica."""
        # Crear archivo de información técnica
        archivo_tecnico = SimpleUploadedFile(
            "guia_evaluacion.pdf",
            b"Contenido de la guia de evaluacion",
            content_type="application/pdf"
        )
        
        # Asignar al evento
        self.evento.eve_informacion_tecnica = archivo_tecnico
        self.evento.save()
        
        # Recargar desde BD
        evento_actualizado = Evento.objects.get(pk=self.evento.pk)
        
        # Verificar que se guardó
        self.assertTrue(bool(evento_actualizado.eve_informacion_tecnica),
                       "El archivo de información técnica debe estar guardado")
        self.assertIn('guia_evaluacion',
                     evento_actualizado.eve_informacion_tecnica.name,
                     "El nombre del archivo debe contener 'guia_evaluacion'")

    def test_ca1_3_evaluador_aprobado_puede_visualizar_info_tecnica(self):
        """CA1.3: Un evaluador aprobado puede visualizar la información técnica."""
        # Primero cargar información técnica
        archivo_tecnico = SimpleUploadedFile(
            "manual_evaluacion.pdf",
            b"Manual de evaluacion para evaluadores",
            content_type="application/pdf"
        )
        self.evento.eve_informacion_tecnica = archivo_tecnico
        self.evento.save()
        
        # Login como evaluador aprobado
        login_ok = self.client.login(
            username=self.user_evaluador.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        # Establecer evaluador_id en sesión
        session = self.client.session
        session['evaluador_id'] = self.evaluador.id
        session.save()
        
        # Intentar acceder a la información técnica
        response = self.client.get(self.url_ver_info_tecnica, follow=True)
        
        # Verificar acceso exitoso
        self.assertEqual(response.status_code, 200,
                        "El evaluador aprobado debe poder acceder a la información técnica")
        
        # Verificar que se muestra la información del archivo
        content = response.content.decode('utf-8')
        tiene_referencia = any([
            'manual_evaluacion' in content.lower(),
            'información técnica' in content.lower(),
            'informacion tecnica' in content.lower(),
            'descargar' in content.lower(),
        ])
        self.assertTrue(tiene_referencia,
                       "Debe mostrar referencia al archivo de información técnica")

    def test_ca1_4_admin_puede_actualizar_informacion_tecnica(self):
        """CA1.4: El administrador puede actualizar/reemplazar la información técnica."""
        # Cargar archivo inicial
        archivo_v1 = SimpleUploadedFile(
            "version1.pdf",
            b"Version 1 del documento",
            content_type="application/pdf"
        )
        self.evento.eve_informacion_tecnica = archivo_v1
        self.evento.save()
        
        # Verificar versión inicial
        evento_v1 = Evento.objects.get(pk=self.evento.pk)
        nombre_v1 = evento_v1.eve_informacion_tecnica.name
        
        # Actualizar con nueva versión
        archivo_v2 = SimpleUploadedFile(
            "version2_actualizada.pdf",
            b"Version 2 del documento con mas informacion",
            content_type="application/pdf"
        )
        self.evento.eve_informacion_tecnica = archivo_v2
        self.evento.save()
        
        # Verificar actualización
        evento_v2 = Evento.objects.get(pk=self.evento.pk)
        nombre_v2 = evento_v2.eve_informacion_tecnica.name
        
        # Los nombres deben ser diferentes
        self.assertNotEqual(nombre_v1, nombre_v2,
                           "El archivo debe haberse actualizado")
        self.assertIn('version2',
                     nombre_v2.lower(),
                     "El nuevo archivo debe estar presente")

    def test_ca1_5_evento_sin_info_tecnica_es_valido(self):
        """CA1.5: Un evento puede existir sin información técnica (campo opcional)."""
        # Crear nuevo evento sin información técnica
        evento_sin_info = Evento.objects.create(
            eve_nombre=f"Evento sin info {self.unique_suffix}",
            eve_descripcion="Evento sin información técnica",
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
            # eve_informacion_tecnica NO se proporciona
        )
        
        # Verificar que se creó correctamente
        self.assertIsNotNone(evento_sin_info.pk,
                            "El evento debe crearse sin información técnica")
        self.assertFalse(bool(evento_sin_info.eve_informacion_tecnica),
                        "No debe tener información técnica")

    # ========== TESTS NEGATIVOS ==========

    def test_ca2_1_evaluador_no_inscrito_no_puede_ver_info(self):
        """CA2.1: Un evaluador no inscrito en el evento no puede ver la información técnica."""
        # Cargar información técnica
        archivo_tecnico = SimpleUploadedFile(
            "info_restringida.pdf",
            b"Informacion solo para inscritos",
            content_type="application/pdf"
        )
        self.evento.eve_informacion_tecnica = archivo_tecnico
        self.evento.save()
        
        # Login como evaluador NO inscrito
        login_ok = self.client.login(
            username=self.user_eval_no_inscrito.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        # Establecer evaluador_id en sesión
        session = self.client.session
        session['evaluador_id'] = self.evaluador_no_inscrito.id
        session.save()
        
        # Intentar acceder
        response = self.client.get(self.url_ver_info_tecnica, follow=True)
        
        # Debe ser bloqueado (302 redirige, 403 prohibido, o 404 no encontrado)
        # Si es 200, verificar que no muestra el contenido real
        if response.status_code == 200:
            content = response.content.decode('utf-8').lower()
            # No debe mostrar el archivo real
            no_muestra_archivo = 'info_restringida' not in content
            self.assertTrue(no_muestra_archivo,
                          "No debe mostrar información técnica a evaluadores no inscritos")
        else:
            # Si redirige o bloquea, está correcto
            self.assertIn(response.status_code, [302, 403, 404],
                         "Debe bloquear el acceso a evaluadores no inscritos")

    def test_ca2_2_evaluador_sin_autenticar_no_puede_acceder(self):
        """CA2.2: Un usuario no autenticado no puede acceder a la información técnica."""
        # Cargar información técnica
        archivo_tecnico = SimpleUploadedFile(
            "info_privada.pdf",
            b"Informacion privada del evento",
            content_type="application/pdf"
        )
        self.evento.eve_informacion_tecnica = archivo_tecnico
        self.evento.save()
        
        # NO hacer login
        response = self.client.get(self.url_ver_info_tecnica, follow=True)
        
        # Debe redirigir al login o mostrar error
        # Típicamente redirige a /login/
        final_url = response.redirect_chain[-1][0] if response.redirect_chain else ''
        
        redirigido_a_login = (
            'login' in final_url.lower() or
            response.status_code in [302, 403]
        )
        
        self.assertTrue(redirigido_a_login,
                       "Usuario no autenticado debe ser redirigido al login")

    def test_ca2_3_vista_maneja_evento_sin_info_tecnica(self):
        """CA2.3: La vista debe manejar correctamente eventos sin información técnica."""
        # Este evento no tiene eve_informacion_tecnica cargado
        self.assertFalse(bool(self.evento.eve_informacion_tecnica),
                        "El evento de prueba no debe tener info técnica inicialmente")
        
        # Login como evaluador
        login_ok = self.client.login(
            username=self.user_evaluador.username,
            password=self.password
        )
        self.assertTrue(login_ok)
        
        session = self.client.session
        session['evaluador_id'] = self.evaluador.id
        session.save()
        
        # Intentar acceder a la vista
        response = self.client.get(self.url_ver_info_tecnica, follow=True)
        
        # Debe responder sin errores
        self.assertEqual(response.status_code, 200,
                        "La vista debe responder incluso sin información técnica")
        
        # Debe mostrar mensaje apropiado
        content = response.content.decode('utf-8').lower()
        mensaje_apropiado = any([
            'no disponible' in content,
            'no se ha cargado' in content,
            'sin información' in content,
            'no hay' in content,
        ])
        
        # Es válido si muestra un mensaje apropiado O si simplemente no muestra el archivo
        if not mensaje_apropiado:
            # Verificar que al menos no intenta mostrar un archivo inexistente
            no_error = 'error' not in content and 'exception' not in content
            self.assertTrue(no_error,
                          "No debe mostrar errores cuando no hay información técnica")

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_1_campo_informacion_tecnica_en_modelo(self):
        """CA3.1: El modelo Evento tiene el campo eve_informacion_tecnica."""
        self.assertTrue(hasattr(Evento, 'eve_informacion_tecnica'),
                       "El modelo Evento debe tener campo eve_informacion_tecnica")

    def test_ca3_2_campo_permite_archivos(self):
        """CA3.2: El campo eve_informacion_tecnica puede almacenar archivos."""
        archivo = SimpleUploadedFile(
            "test.pdf",
            b"Contenido de prueba",
            content_type="application/pdf"
        )
        
        # Intentar asignar archivo
        try:
            self.evento.eve_informacion_tecnica = archivo
            self.evento.save()
            
            # Recargar y verificar
            evento_guardado = Evento.objects.get(pk=self.evento.pk)
            self.assertTrue(bool(evento_guardado.eve_informacion_tecnica),
                           "Debe poder guardar archivos")
        except Exception as e:
            self.fail(f"No se pudo guardar archivo: {e}")

    def test_ca3_3_puede_almacenar_pdfs(self):
        """CA3.3: El campo puede almacenar archivos PDF."""
        archivo_pdf = SimpleUploadedFile(
            "documento.pdf",
            b"%PDF-1.4 contenido simulado de PDF",
            content_type="application/pdf"
        )
        
        self.evento.eve_informacion_tecnica = archivo_pdf
        self.evento.save()
        
        evento_con_pdf = Evento.objects.get(pk=self.evento.pk)
        nombre_archivo = evento_con_pdf.eve_informacion_tecnica.name
        
        self.assertIn('.pdf', nombre_archivo.lower(),
                     "Debe poder almacenar archivos PDF")

    def test_ca3_4_relacion_evento_evaluador_permite_acceso(self):
        """CA3.4: La relación EvaluadorEvento determina el acceso a la información."""
        # Verificar que existe la relación
        relacion_existe = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=self.evaluador,
            eva_eve_evento_fk=self.evento
        ).exists()
        
        self.assertTrue(relacion_existe,
                       "Debe existir relación EvaluadorEvento para controlar acceso")
        
        # Verificar que el evaluador no inscrito NO tiene relación
        no_relacion = not EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=self.evaluador_no_inscrito,
            eva_eve_evento_fk=self.evento
        ).exists()
        
        self.assertTrue(no_relacion,
                       "El evaluador no inscrito no debe tener relación con el evento")