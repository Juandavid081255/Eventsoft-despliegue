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

