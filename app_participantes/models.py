from django.db import models
from app_admin_eventos.models import Evento
from django.core.exceptions import ValidationError
import random
import string



class ParticipanteEvento(models.Model):
    par_eve_evento_fk = models.ForeignKey(Evento, on_delete=models.CASCADE)
    par_eve_participante_fk = models.ForeignKey('app_usuarios.Participante', on_delete=models.CASCADE)
    par_eve_fecha = models.DateTimeField(auto_now_add=True)
    par_eve_estado = models.CharField(max_length=45)
    par_eve_documentos = models.FileField(upload_to='upload/', null=True, blank=True)
    par_eve_qr = models.ImageField(upload_to='upload/', null=True, blank=True)
    par_eve_clave = models.CharField(max_length=45)
    calificacion = models.IntegerField(null=True, blank=True)
    
    # Nuevos campos para manejo de grupos
    par_eve_es_grupo = models.BooleanField(default=False)
    par_eve_proyecto_principal = models.ForeignKey(
        'self',
        related_name='miembros_proyecto',
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    par_eve_codigo_proyecto = models.CharField(max_length=10, null=True, blank=True)

    def __str__(self):
        return f"{self.par_eve_participante_fk} - {self.par_eve_evento_fk}"

    def clean(self):

        from app_asistentes.models import AsistenteEvento
        from app_evaluadores.models import EvaluadorEvento
        """ 
        Validación: no permitir que el mismo usuario esté en el evento con otro rol.
        """
        usuario = self.par_eve_participante_fk.usuario
        evento = self.par_eve_evento_fk

        # 1. Validación Cruzada: No puede ser Asistente
        if AsistenteEvento.objects.filter(asi_eve_asistente_fk__usuario=usuario, asi_eve_evento_fk=evento).exists():
            raise ValidationError(
                {'par_eve_participante_fk': "Este usuario ya está inscrito como Asistente en este evento."}
            )
            
        # 2. Validación Cruzada: No puede ser Evaluador
        if EvaluadorEvento.objects.filter(eva_eve_evaluador_fk__usuario=usuario, eva_eve_evento_fk=evento).exists():
            raise ValidationError(
                {'par_eve_participante_fk': "Este usuario ya está inscrito como Evaluador en este evento."}
            )
            
        # 3. Validación de Unicidad Propia (Para evitar doble inscripción del mismo Participante)
        # Se mantiene en clean() como capa defensiva, pero confiamos en `unique_together` de Meta.
        if ParticipanteEvento.objects.filter(
            par_eve_participante_fk__usuario=usuario,
            par_eve_evento_fk=evento
        ).exclude(pk=self.pk).exists():
            raise ValidationError(
                {'par_eve_participante_fk': "Este usuario ya está inscrito como Participante en este evento."}
            )

    def save(self, *args, **kwargs):
        # 1. Lógica para generar código único de proyecto (NO TOCADA)
        # Solo se genera si no tiene un código y NO es miembro de otro proyecto
        if not self.par_eve_codigo_proyecto and not self.par_eve_proyecto_principal:
            # Usamos random y string importados en el ámbito del módulo
            self.par_eve_codigo_proyecto = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        
        # 2. Ejecutar validaciones ANTES de guardar (CORRECCIÓN CLAVE)
        # Se elimina la llamada a self.clean() que había aquí. 
        # Si llamas a .save() directamente, debes llamar a .full_clean() antes.
        
        super().save(*args, **kwargs)

    # NO SE TOCAN los métodos @property y get_todos_miembros_proyecto ya que manejan la lógica de grupos.
    @property
    def es_lider_proyecto(self):
        """Retorna True si este participante es el líder del proyecto (no tiene proyecto_principal)"""
        return self.par_eve_proyecto_principal is None and self.par_eve_es_grupo

    @property
    def proyecto_principal(self):
        """Retorna el proyecto principal (si es miembro) o self (si es líder)"""
        return self.par_eve_proyecto_principal if self.par_eve_proyecto_principal else self

    def get_todos_miembros_proyecto(self):
        """Retorna todos los miembros del proyecto incluyendo el líder"""
        if self.par_eve_proyecto_principal:
            # Si es miembro, obtener desde el proyecto principal
            return self.par_eve_proyecto_principal.get_todos_miembros_proyecto()
        else:
            # Si es líder, obtener todos los miembros + self
            miembros = list(self.miembros_proyecto.all())
            miembros.insert(0, self)  # Agregar el líder al inicio
            return miembros
            
    class Meta:
        # **Clave de la Unicidad:** Garantiza que un mismo participante 
        # no pueda tener dos entradas para el mismo evento.
        unique_together = ('par_eve_participante_fk', 'par_eve_evento_fk')
        verbose_name = "Inscripción de Participante"
        verbose_name_plural = "Inscripciones de Participantes"


