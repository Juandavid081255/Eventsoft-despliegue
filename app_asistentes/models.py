from django.db import models
from app_admin_eventos.models import Evento
from django.core.exceptions import ValidationError



class AsistenteEvento(models.Model):
    asi_eve_asistente_fk = models.ForeignKey('app_usuarios.Asistente', on_delete=models.CASCADE)
    asi_eve_evento_fk = models.ForeignKey(Evento, on_delete=models.CASCADE)
    asi_eve_fecha_hora = models.DateTimeField()
    asi_eve_estado = models.CharField(max_length=45)
    asi_eve_soporte = models.FileField(upload_to='upload/')
    asi_eve_qr = models.ImageField(upload_to='upload/')
    asi_eve_clave = models.CharField(max_length=45)

    def clean(self):
        
        from app_evaluadores.models import EvaluadorEvento
        from app_participantes.models import ParticipanteEvento
        """
        Realiza validaciones para asegurar que el usuario no esté ya inscrito 
        en el mismo evento con otro rol (Participante o Evaluador).
        La unicidad como Asistente se maneja en la clase Meta.
        """
        # Obtenemos el objeto Usuario base a través del perfil Asistente
        usuario = self.asi_eve_asistente_fk.usuario
        evento = self.asi_eve_evento_fk

        # 1. Validación Cruzada: El Usuario no puede ser Participante en este Evento
        if ParticipanteEvento.objects.filter(par_eve_participante_fk__usuario=usuario, par_eve_evento_fk=evento).exists():
            raise ValidationError(
                {'asi_eve_asistente_fk': "Este usuario ya está inscrito como Participante en este evento."}
            )
        
        # 2. Validación Cruzada: El Usuario no puede ser Evaluador en este Evento
        if EvaluadorEvento.objects.filter(eva_eve_evaluador_fk__usuario=usuario, eva_eve_evento_fk=evento).exists():
            raise ValidationError(
                {'asi_eve_asistente_fk': "Este usuario ya está inscrito como Evaluador en este evento."}
            )
            
        # Nota: La validación de unicidad propia (que no se inscriba dos veces como Asistente)
        # se manejará principalmente por unique_together en Meta, lo cual es más eficiente.
        # Eliminamos la línea explícita de unicidad propia del clean() para simplificar,
        # confiando en la restricción de base de datos.

    def save(self, *args, **kwargs):
        """
        Remueve la llamada explícita a self.clean() para seguir el flujo estándar de Django.
        """
        super().save(*args, **kwargs)

    class Meta:
        # **Clave de la Unicidad:** Esta restricción garantiza que un mismo
        # perfil de Asistente no pueda tener dos entradas para el mismo Evento
        unique_together = ('asi_eve_asistente_fk', 'asi_eve_evento_fk')
        verbose_name = "Inscripción de Asistente"
        verbose_name_plural = "Inscripciones de Asistentes"


