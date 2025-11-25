from django.db import models
from app_admin_eventos.models import Evento, Criterio
from app_usuarios.models import Participante
from django.core.exceptions import ValidationError



class Calificacion(models.Model):
    cal_evaluador_fk = models.ForeignKey('app_usuarios.Evaluador', on_delete=models.CASCADE)
    cal_criterio_fk = models.ForeignKey(Criterio, on_delete=models.CASCADE)
    cal_participante_fk = models.ForeignKey(Participante, on_delete=models.CASCADE)
    cal_valor = models.IntegerField()

    class Meta:
        unique_together = ('cal_evaluador_fk', 'cal_criterio_fk', 'cal_participante_fk')




class EvaluadorEvento(models.Model):
    eva_eve_evaluador_fk = models.ForeignKey('app_usuarios.Evaluador', on_delete=models.CASCADE)
    eva_eve_evento_fk = models.ForeignKey(Evento, on_delete=models.CASCADE)
    eva_eve_fecha_hora = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    eva_eve_estado = models.CharField(max_length=45, null=True, blank=True)
    eva_eve_qr = models.ImageField(upload_to='upload/', null=True, blank=True)
    eva_eve_clave = models.CharField(max_length=45, null=True, blank=True)
    eva_eve_documento = models.FileField(upload_to='upload/', null=True, blank=True)

    def clean(self):
        
        from app_asistentes.models import AsistenteEvento
        from app_participantes.models import ParticipanteEvento
        """
        Realiza validaciones para asegurar que el usuario no esté ya inscrito 
        en el mismo evento con otro rol (Asistente o Participante).
        """
        usuario = self.eva_eve_evaluador_fk.usuario
        evento = self.eva_eve_evento_fk

        # 1. Validación Cruzada: El Usuario no puede ser Participante en este Evento
        if ParticipanteEvento.objects.filter(par_eve_participante_fk__usuario=usuario, par_eve_evento_fk=evento).exists():
            raise ValidationError(
                {'eva_eve_evaluador_fk': "Este usuario ya está inscrito como Participante en este evento."}
            )
            
        # 2. Validación Cruzada: El Usuario no puede ser Asistente en este Evento
        if AsistenteEvento.objects.filter(asi_eve_asistente_fk__usuario=usuario, asi_eve_evento_fk=evento).exists():
            raise ValidationError(
                {'eva_eve_evaluador_fk': "Este usuario ya está inscrito como Asistente en este evento."}
            )
            
        # Nota: La validación de unicidad propia ya no es necesaria en clean() porque 
        # se utiliza `unique_together` en Meta, lo cual es más eficiente y obligatorio
        # a nivel de base de datos.

    def save(self, *args, **kwargs):
        """
        Se elimina la llamada a self.clean().
        Se asume que full_clean() se llama antes de save() en el flujo normal de Django.
        """
        super().save(*args, **kwargs)

    class Meta:
        # **Clave de la Unicidad:** Garantiza que un mismo evaluador 
        # no pueda tener dos entradas para el mismo evento.
        unique_together = ('eva_eve_evaluador_fk', 'eva_eve_evento_fk')
        verbose_name = "Inscripción de Evaluador"
        verbose_name_plural = "Inscripciones de Evaluadores"



