from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Usuario, AdministradorEvento

@receiver(post_save, sender=Usuario)
def crear_admin_evento(sender, instance, created, **kwargs):
    """
    Crea automáticamente el registro de AdministradorEvento solo una vez.
    Evita duplicados al actualizar el usuario.
    """
    # Solo crear si el usuario tiene rol de ADMIN_EVENTO
    if instance.rol == Usuario.Roles.ADMIN_EVENTO:
        # Evitar duplicados
        AdministradorEvento.objects.get_or_create(usuario=instance)
