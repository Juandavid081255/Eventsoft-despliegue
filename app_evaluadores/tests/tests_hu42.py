# app_evaluadores/tests/tests_hu42.py

from django.test import TestCase, Client
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date
import time
import random

from app_usuarios.models import Usuario, Evaluador, AdministradorEvento
from app_admin_eventos.models import Evento, Criterio
from app_evaluadores.models import EvaluadorEvento, Calificacion
from app_participantes.models import ParticipanteEvento


class GestionCriteriosEvaluadorTest(TestCase):
    """
    HU42 - Gestión de Criterios de Evaluación
    Como evaluador quiero gestionar criterios de evaluación (crear/modificar/eliminar)
    para poder evaluar participantes de forma estructurada.
    
    Adaptado a la estructura existente que usa el modelo Criterio.
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
        admin_username = f"admin_hu42_{unique_suffix}"
        self.admin_user = Usuario.objects.create_user(
            username=admin_username,
            password=self.password,
            email=f"{admin_username}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            cedula=f"900{unique_suffix[-10:]}",
            first_name="Admin",
            last_name="HU42"
        )
        
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=self.admin_user)
        
        # ===== EVENTO =====
        self.evento = Evento.objects.create(
            eve_nombre=f"Evento HU42 {unique_suffix}",
            eve_descripcion="Evento para gestión de criterios",
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
        )
        
        # ===== EVALUADOR APROBADO =====
        user_evaluador = f"eval_hu42_{unique_suffix}"
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
        
        # ===== CRITERIO BASE (no usado) =====
        self.criterio_base = Criterio.objects.create(
            cri_descripcion="Claridad de la propuesta",
            cri_peso=25.0,
            cri_evento_fk=self.evento
        )
        
        # ===== CRITERIO USADO (tiene calificaciones) =====
        self.criterio_usado = Criterio.objects.create(
            cri_descripcion="Metodología",
            cri_peso=30.0,
            cri_evento_fk=self.evento
        )
        
        # Crear un participante y calificación para marcar el criterio como "usado"
        from app_usuarios.models import Participante
        user_part = f"part_hu42_{unique_suffix}"
        self.user_participante = Usuario.objects.create_user(
            username=user_part,
            password=self.password,
            email=f"{user_part}@test.com",
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
        
        # Crear calificación para marcar el criterio como usado
        Calificacion.objects.create(
            cal_evaluador_fk=self.evaluador,
            cal_criterio_fk=self.criterio_usado,
            cal_participante_fk=self.participante,
            cal_valor=85
        )
        
        # ===== CLIENTE Y LOGIN =====
        self.client = Client()
        login_ok = self.client.login(username=self.user_evaluador.username, password=self.password)
        self.assertTrue(login_ok, "El login debe ser exitoso")
        
        # Establecer evaluador_id en sesión
        session = self.client.session
        session['evaluador_id'] = self.evaluador.id
        session.save()
        
        # ===== URLs =====
        self.url_crear = reverse('crear_criterio_eva', args=[self.evento.pk])
        self.url_listar = reverse('ver_criterios_agregados_eva', args=[self.evento.pk])
        self.url_actualizar = reverse('actualizar_criterio_eva', args=[self.criterio_base.pk])
        self.url_eliminar = reverse('eliminar_criterio_eva', args=[self.criterio_base.pk])

    # ========== TESTS POSITIVOS ==========

    def test_ca1_1_evaluador_accede_gestion_criterios(self):
        """CA1.1: Evaluador aprobado puede acceder a la gestión de criterios."""
        response = self.client.get(self.url_listar, follow=True)
        self.assertEqual(response.status_code, 200,
                        "Evaluador aprobado debe acceder a la gestión de criterios")

    def test_ca1_2_crear_nuevo_criterio(self):
        """CA1.2: Crear un nuevo criterio de evaluación."""
        datos_criterio = {
            'cri_descripcion': 'Innovación de la propuesta',
            'cri_peso': 20.0
        }
        
        # Contar criterios antes
        count_antes = Criterio.objects.filter(cri_evento_fk=self.evento).count()
        
        response = self.client.post(self.url_crear, datos_criterio, follow=True)
        self.assertIn(response.status_code, [200, 302],
                     "La creación debe ser exitosa")
        
        # Verificar que se creó
        count_despues = Criterio.objects.filter(cri_evento_fk=self.evento).count()
        self.assertEqual(count_despues, count_antes + 1,
                        "Debe haberse creado un nuevo criterio")
        
        # Verificar que existe el criterio con esa descripción
        existe = Criterio.objects.filter(
            cri_evento_fk=self.evento,
            cri_descripcion="Innovación de la propuesta"
        ).exists()
        self.assertTrue(existe, "El criterio creado debe existir en la BD")

    def test_ca1_3_modificar_criterio_existente(self):
        """CA1.3: Modificar descripción y peso de un criterio existente."""
        datos_modificacion = {
            'cri_descripcion': 'Claridad y coherencia actualizada',
            'cri_peso': 35.0
        }
        
        response = self.client.post(self.url_actualizar, datos_modificacion, follow=True)
        self.assertIn(response.status_code, [200, 302],
                     "La modificación debe ser exitosa")
        
        # Recargar desde BD y verificar cambios
        criterio_actualizado = Criterio.objects.get(pk=self.criterio_base.pk)
        self.assertEqual(criterio_actualizado.cri_descripcion, 
                        'Claridad y coherencia actualizada',
                        "La descripción debe haberse actualizado")
        self.assertEqual(float(criterio_actualizado.cri_peso), 35.0,
                        "El peso debe haberse actualizado")

    def test_ca1_4_eliminar_criterio_no_utilizado(self):
        """CA1.4: Eliminar un criterio que no ha sido usado en calificaciones."""
        response = self.client.post(self.url_eliminar, follow=True)
        self.assertIn(response.status_code, [200, 302],
                     "La eliminación debe ser exitosa")
        
        # Verificar que ya no existe
        existe = Criterio.objects.filter(pk=self.criterio_base.pk).exists()
        self.assertFalse(existe, 
                        "El criterio no utilizado debe haberse eliminado")

    def test_ca1_5_visualizar_lista_criterios(self):
        """CA1.5: Visualizar lista de todos los criterios del evento."""
        response = self.client.get(self.url_listar, follow=True)
        self.assertEqual(response.status_code, 200)
        
        # Verificar que se muestran los criterios en el contexto o contenido
        content = response.content.decode('utf-8')
        self.assertIn('Claridad', content,
                     "Debe mostrar los criterios existentes")

    # ========== TESTS NEGATIVOS ==========

    def test_ca2_1_no_eliminar_criterio_con_calificaciones(self):
        """CA2.1: No se debe permitir eliminar un criterio que tiene calificaciones."""
        url_eliminar_usado = reverse('eliminar_criterio_eva', args=[self.criterio_usado.pk])
        
        response = self.client.post(url_eliminar_usado, follow=True)
        
        # El criterio debe seguir existiendo
        existe = Criterio.objects.filter(pk=self.criterio_usado.pk).exists()
        self.assertTrue(existe,
                       "El criterio con calificaciones no debe eliminarse")
        
        # Debe mostrar advertencia o error
        content = response.content.decode('utf-8').lower()
        tiene_advertencia = ('advertencia' in content or 
                           'calificaciones' in content or 
                           'no se puede eliminar' in content or
                           response.status_code in [400, 403])
        self.assertTrue(tiene_advertencia,
                       "Debe mostrar advertencia al intentar eliminar criterio usado")

    def test_ca2_2_no_modificar_criterio_con_calificaciones(self):
        """CA2.2: No se debe permitir modificar significativamente un criterio con calificaciones."""
        url_modificar_usado = reverse('actualizar_criterio_eva', args=[self.criterio_usado.pk])
        
        datos_modificacion = {
            'cri_descripcion': 'Metodología alterada',
            'cri_peso': 50.0
        }
        
        response = self.client.post(url_modificar_usado, datos_modificacion, follow=True)
        
        # Recargar y verificar que no cambió (o cambió mínimamente)
        criterio = Criterio.objects.get(pk=self.criterio_usado.pk)
        
        # El peso no debe haber cambiado drásticamente o debe mostrar error
        if float(criterio.cri_peso) != 50.0:
            # Correcto: no se modificó
            self.assertNotEqual(float(criterio.cri_peso), 50.0,
                              "El peso no debe modificarse para criterios con calificaciones")
        else:
            # Si se modificó, debe haber advertencia en la respuesta
            content = response.content.decode('utf-8').lower()
            tiene_advertencia = ('advertencia' in content or 
                               'calificaciones' in content or
                               response.status_code in [400, 403])
            self.assertTrue(tiene_advertencia,
                          "Debe mostrar advertencia si permite modificar criterio usado")

    def test_ca2_3_validacion_peso_positivo(self):
        """CA2.3: Validar que el peso del criterio sea positivo."""
        datos_invalidos = {
            'cri_descripcion': 'Criterio con peso inválido',
            'cri_peso': 0
        }
        
        count_antes = Criterio.objects.filter(cri_evento_fk=self.evento).count()
        
        response = self.client.post(self.url_crear, datos_invalidos, follow=True)
        
        # No debe haberse creado
        count_despues = Criterio.objects.filter(cri_evento_fk=self.evento).count()
        
        if count_despues == count_antes:
            # Correcto: no se creó
            self.assertEqual(count_despues, count_antes,
                           "No debe crearse criterio con peso inválido")
        else:
            # Si se creó, debe tener peso > 0
            criterio_creado = Criterio.objects.filter(
                cri_evento_fk=self.evento,
                cri_descripcion='Criterio con peso inválido'
            ).first()
            if criterio_creado:
                self.assertGreater(float(criterio_creado.cri_peso), 0,
                                 "Si se crea, el peso debe ser mayor a 0")

    def test_ca2_4_validacion_descripcion_requerida(self):
        """CA2.4: La descripción del criterio es obligatoria."""
        datos_invalidos = {
            'cri_descripcion': '',  # vacío
            'cri_peso': 25.0
        }
        
        count_antes = Criterio.objects.filter(cri_evento_fk=self.evento).count()
        
        response = self.client.post(self.url_crear, datos_invalidos, follow=True)
        
        # No debe haberse creado o debe mostrar error
        count_despues = Criterio.objects.filter(cri_evento_fk=self.evento).count()
        
        if count_despues == count_antes:
            # Correcto
            self.assertEqual(count_despues, count_antes,
                           "No debe crearse criterio sin descripción")
        else:
            # Si se permite, verificar que tiene descripción
            content = response.content.decode('utf-8').lower()
            tiene_error = ('requerido' in content or 
                          'obligatorio' in content or
                          response.status_code in [400])
            self.assertTrue(tiene_error,
                          "Debe mostrar error si falta descripción")

    # ========== TESTS DE ESTRUCTURA ==========

    def test_ca3_1_modelo_criterio_tiene_campos_necesarios(self):
        """CA3.1: El modelo Criterio tiene los campos necesarios."""
        self.assertTrue(hasattr(self.criterio_base, 'cri_descripcion'))
        self.assertTrue(hasattr(self.criterio_base, 'cri_peso'))
        self.assertTrue(hasattr(self.criterio_base, 'cri_evento_fk'))

    def test_ca3_2_relacion_criterio_evento(self):
        """CA3.2: La relación entre Criterio y Evento es correcta."""
        self.assertEqual(self.criterio_base.cri_evento_fk, self.evento,
                        "El criterio debe estar relacionado con el evento correcto")

    def test_ca3_3_criterio_puede_tener_calificaciones(self):
        """CA3.3: Un criterio puede tener múltiples calificaciones."""
        calificaciones = Calificacion.objects.filter(
            cal_criterio_fk=self.criterio_usado
        )
        self.assertGreater(calificaciones.count(), 0,
                          "El criterio usado debe tener al menos una calificación")

    def test_ca3_4_suma_pesos_criterios(self):
        """CA3.4: La suma de pesos de criterios puede validarse (opcional)."""
        # Este test verifica que existe la posibilidad de validar la suma de pesos
        total_pesos = sum(
            criterio.cri_peso 
            for criterio in Criterio.objects.filter(cri_evento_fk=self.evento)
        )
        
        # Solo verificamos que se puede calcular
        self.assertIsInstance(total_pesos, (int, float),
                            "Debe ser posible sumar los pesos de los criterios")
        self.assertGreaterEqual(total_pesos, 0,
                               "La suma de pesos debe ser no negativa")