# app_participantes/tests/tests_hu16.py

from django.test import TestCase, Client
from django.urls import reverse
from datetime import date, timedelta
from app_usuarios.models import Usuario, Participante, AdministradorEvento
from app_admin_eventos.models import Evento
from app_participantes.models import ParticipanteEvento


class ParticipanteEventoCancelacionViewTest(TestCase):
    """
    Tests HU16 - Cancelación de preinscripción de participante
    """

    def setUp(self):
        self.client = Client()
        
        # Administrador y evento
        admin_user = Usuario.objects.create_user(
            username="adminuser_hu16",
            password="password",
            rol=Usuario.Roles.ADMIN_EVENTO,
            cedula="1234567890"
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(usuario=admin_user)

        self.evento = Evento.objects.create(
            eve_nombre="Evento Cancelable",
            eve_descripcion="Descripcion",
            eve_fecha_inicio=date.today() + timedelta(days=30),
            eve_fecha_fin=date.today() + timedelta(days=31),
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=100,
            eve_imagen="f.jpg",
            eve_programacion="f.pdf",
            eve_ciudad="T",
            eve_lugar="T",
            eve_tienecosto="No",
        )
        
        # Usuario propietario (cancelador)
        self.user_owner = Usuario.objects.create_user(
            username="owner_hu16",
            password="password",
            rol=Usuario.Roles.PARTICIPANTE,
            cedula="1111111111"
        )
        self.participante_owner = Participante.objects.create(usuario=self.user_owner)
        
        # Agregar participante_id a sesión
        session = self.client.session
        session['participante_id'] = self.participante_owner.pk
        session.save()
        
        # Login inicial como owner
        self.client.force_login(self.user_owner)
        
        # Registro cancelable (propietario, estado Preinscrito)
        self.registro_cancelable = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento,
            par_eve_participante_fk=self.participante_owner,
            par_eve_estado="Preinscrito",
            par_eve_clave="CLAVE_CANC",
        )
        self.url_delete_cancelable = reverse('cancelar_inscripcion_participante', 
                                             kwargs={'evento_id': self.evento.pk})

        # Registro aprobado: otro participante
        self.user_owner2 = Usuario.objects.create_user(
            username="owner2_hu16",
            password="password2",
            rol=Usuario.Roles.PARTICIPANTE,
            cedula="2222222222"
        )
        self.participante_owner2 = Participante.objects.create(usuario=self.user_owner2)
        self.registro_aprobado = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento,
            par_eve_participante_fk=self.participante_owner2,
            par_eve_estado="Aprobado",
            par_eve_clave="CLAVE_APROB",
        )
        
        # Registro de otro usuario (stranger)
        self.user_stranger = Usuario.objects.create_user(
            username="stranger_hu16",
            password="password_s",
            rol=Usuario.Roles.PARTICIPANTE,
            cedula="3333333333"
        )
        self.participante_stranger = Participante.objects.create(usuario=self.user_stranger)
        self.registro_stranger = ParticipanteEvento.objects.create(
            par_eve_evento_fk=self.evento,
            par_eve_participante_fk=self.participante_stranger,
            par_eve_estado="Preinscrito",
            par_eve_clave="CLAVE_STRANGER",
        )

    # ========== CASOS POSITIVOS ==========

    def test_ca1_1_cancelacion_exitosa_preinscrito(self):
        """
        CA1.1: Participante con estado Preinscrito puede cancelar su inscripción
        """
        initial_count = ParticipanteEvento.objects.filter(
            par_eve_participante_fk=self.participante_owner,
            par_eve_evento_fk=self.evento
        ).count()
        self.assertEqual(initial_count, 1)
        
        response = self.client.post(self.url_delete_cancelable, follow=True)
        
        # La vista debe responder correctamente
        self.assertIn(response.status_code, (200, 302))
        
        # Verificar que el registro fue eliminado o marcado como cancelado
        after_registro = ParticipanteEvento.objects.filter(
            par_eve_participante_fk=self.participante_owner,
            par_eve_evento_fk=self.evento
        ).first()
        
        # El registro debe estar eliminado o en estado Cancelado
        if after_registro:
            self.assertEqual(after_registro.par_eve_estado, "Cancelado")
        else:
            # Si fue completamente eliminado, también es válido
            self.assertFalse(ParticipanteEvento.objects.filter(
                par_eve_participante_fk=self.participante_owner,
                par_eve_evento_fk=self.evento
            ).exists())

    # ========== CASOS NEGATIVOS ==========

    def test_ca2_1_cancelacion_falla_estado_aprobado(self):
        """
        CA2.1: No se puede cancelar un registro con estado Aprobado
        """
        # Login como owner2 (propietario del registro aprobado)
        self.client.force_login(self.user_owner2)
        session = self.client.session
        session['participante_id'] = self.participante_owner2.pk
        session.save()
        
        url_delete_aprobado = reverse('cancelar_inscripcion_participante',
                                       kwargs={'evento_id': self.evento.pk})
        
        response = self.client.post(url_delete_aprobado, follow=True)
        
        # La vista debe responder
        self.assertIn(response.status_code, (200, 302))
        
        # El registro DEBE seguir existiendo con estado Aprobado
        self.registro_aprobado.refresh_from_db()
        self.assertEqual(self.registro_aprobado.par_eve_estado, "Aprobado",
                        "No debe permitir cancelar un registro Aprobado")

    def test_ca2_2_cancelacion_falla_no_propiedad(self):
        """
        CA2.2: Usuario no propietario no puede cancelar registro ajeno
        """
        url_delete_stranger = reverse('cancelar_inscripcion_participante',
                                       kwargs={'evento_id': self.evento.pk})
        
        # self.user_owner intenta cancelar pero no tiene registro para este evento
        # (ya usó el suyo en el test anterior), así que no debería poder hacerlo
        response = self.client.post(url_delete_stranger, follow=True)
        
        # La vista debe responder
        self.assertIn(response.status_code, (200, 302, 403, 404))
        
        # El registro del stranger DEBE seguir existiendo
        self.assertTrue(ParticipanteEvento.objects.filter(
            pk=self.registro_stranger.pk
        ).exists(), "No debería permitir cancelar registro de otro usuario")