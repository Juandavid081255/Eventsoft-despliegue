from django.db import models


class Area(models.Model):
    are_nombre = models.CharField(max_length=45)
    are_descripcion = models.CharField(max_length=400)

    def __str__(self):
        return self.are_nombre

class Categoria(models.Model):
    cat_nombre = models.CharField(max_length=45)
    cat_descripcion = models.CharField(max_length=400)
    cat_area_fk = models.ForeignKey(Area, on_delete=models.CASCADE)

    def __str__(self):
        return self.cat_nombre

class Evento(models.Model):
    eve_nombre = models.CharField(max_length=100)
    eve_descripcion = models.CharField(max_length=520)
    eve_ciudad = models.CharField(max_length=45)
    eve_lugar = models.CharField(max_length=100)
    eve_fecha_inicio = models.DateField()
    eve_fecha_fin = models.DateField()
    eve_estado = models.CharField(max_length=45)
    eve_imagen = models.ImageField(upload_to='upload/', verbose_name="Imagen/Logo del Evento")
    eve_administrador_fk = models.ForeignKey('app_usuarios.AdministradorEvento', on_delete=models.CASCADE)
    eve_tienecosto = models.CharField(max_length=45)
    eve_capacidad = models.IntegerField()
    eve_programacion = models.FileField(upload_to='upload/', verbose_name="Archivo de Programación")
    eve_informacion_tecnica = models.FileField(upload_to='upload/', null=True, blank=True, verbose_name="Información Técnica Opcional")
    preinscripcion_habilitada_asistentes = models.BooleanField(default=False)
    preinscripcion_habilitada_participantes = models.BooleanField(default=False)
    preinscripcion_habilitada_evaluadores = models.BooleanField(default=False)
    categorias = models.ManyToManyField(Categoria, through='EventoCategoria')

    def __str__(self):
        return self.eve_nombre

class EventoCategoria(models.Model):
    eve_cat_evento_fk = models.ForeignKey(Evento, on_delete=models.CASCADE)
    eve_cat_categoria_fk = models.ForeignKey(Categoria, on_delete=models.CASCADE)

class Criterio(models.Model):
    cri_descripcion = models.CharField(max_length=150)
    cri_peso = models.FloatField()
    cri_evento_fk = models.ForeignKey(Evento, on_delete=models.CASCADE)

    def __str__(self):
        return self.cri_descripcion
    
class MemoriaEvento(models.Model):
    
    evento = models.ForeignKey(Evento, on_delete=models.CASCADE, related_name='memorias')
    nombre = models.CharField(max_length=100, help_text="Texto descriptivo para el archivo")
    archivo = models.FileField(upload_to='upload/')
    subido_en = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.nombre} ({self.evento.eve_nombre})"




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


from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid
from django.db import models
from django.utils import timezone



class Usuario(AbstractUser):
    class Roles(models.TextChoices):
        PARTICIPANTE = 'PARTICIPANTE', 'Participante'
        EVALUADOR = 'EVALUADOR', 'Evaluador'
        ADMIN_EVENTO = 'ADMIN_EVENTO', 'Administrador de Evento'
        ASISTENTE = 'ASISTENTE', 'Asistente'
        VISITANTE = 'VISITANTE', 'Visitante Web'
        SUPERADMIN = 'SUPERADMIN', 'Super Admin'

    telefono = models.CharField(max_length=15, blank=True, null=True)
    rol = models.CharField(max_length=30, choices=Roles.choices, default=Roles.ASISTENTE)
    cedula = models.CharField(max_length=20, unique=True)


    def __str__(self):
        return f"{self.username} ({self.rol})"


class Asistente(models.Model):
    usuario = models.OneToOneField(Usuario, on_delete=models.CASCADE, related_name='asistente')
    

    def __str__(self):
        return f"{self.usuario.first_name} {self.usuario.last_name} - Asistente"


class Participante(models.Model):
    usuario = models.OneToOneField(Usuario, on_delete=models.CASCADE, related_name='participante') 

    def __str__(self):
        return f"{self.usuario.first_name} {self.usuario.last_name} - Participante"


class Evaluador(models.Model):
    usuario = models.OneToOneField(Usuario, on_delete=models.CASCADE, related_name='evaluador') 

    def __str__(self):
        return f"{self.usuario.first_name} {self.usuario.last_name} - Evaluador"


class AdministradorEvento(models.Model):
    
    usuario = models.OneToOneField(Usuario, on_delete=models.CASCADE, related_name='administrador_evento') 

    def __str__(self):
        return f"{self.usuario.first_name} {self.usuario.last_name} - Administrador de Evento"





class InvitacionAdministrador(models.Model):
    email = models.EmailField(unique=True)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    creado_en = models.DateTimeField(default=timezone.now)
    usado = models.BooleanField(default=False)

    def __str__(self):
        return f"Invitación para {self.email}"

