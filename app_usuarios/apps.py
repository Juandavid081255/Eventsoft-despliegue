# app_usuarios/apps.py
from django.apps import AppConfig

class AppUsuariosConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app_usuarios'
    label = 'app_usuarios'  # 👈 clave para que Django cree bien las tablas en test

    def ready(self):
        import app_usuarios.signals
