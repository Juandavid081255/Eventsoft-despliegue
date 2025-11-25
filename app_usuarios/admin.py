from datetime import timezone
from django.contrib import admin
from django.core.mail import send_mail
from django.conf import settings
from django.utils.html import format_html
from django.urls import reverse
import random
import string
from django.contrib import admin, messages

from app_asistentes.models import AsistenteEvento
from app_evaluadores.models import EvaluadorEvento
from app_participantes.models import ParticipanteEvento
from app_admin_eventos.models import Area, Categoria, Criterio, Evento, EventoCategoria, MemoriaEvento

from .models import Asistente, Evaluador, Participante, Usuario, AdministradorEvento, InvitacionAdministrador


# ---------------------------------------------------------
# ACCIÓN PERSONALIZADA: Activar Administradores Pendientes
# ---------------------------------------------------------
@admin.action(description="Activar administradores seleccionados y enviar credenciales")
def activar_administradores(modeladmin, request, queryset):
    for admin_evento in queryset:
        user = admin_evento.usuario

        # 🧠 Evitar intentar crear de nuevo la relación (ya existe desde el registro)
        if not hasattr(user, 'administrador_evento'):
            AdministradorEvento.objects.create(usuario=user)

        if not user.is_active:
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
            user.set_password(password)
            user.is_active = True
            user.save()

            # Enviar correo
            send_mail(
                subject="Tu cuenta de Administrador ha sido aprobada",
                message=(
                    f"Hola {user.first_name},\n\n"
                    f"Tu cuenta ha sido aprobada.\n"
                    f"Puedes ingresar con las siguientes credenciales:\n\n"
                    f"Usuario: {user.email}\n"
                    f"Contraseña: {password}\n\n"
                    f"Por favor, cambia tu contraseña después de iniciar sesión.\n\n"
                    f"Saludos,\nEquipo de Gestión de Eventos"
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )

    modeladmin.message_user(
        request,
        "Los administradores seleccionados han sido activados y notificados por correo electrónico."
    )




# ---------------------------------------------------------
# ADMIN: Invitaciones de Administradores
# ---------------------------------------------------------
@admin.register(InvitacionAdministrador)
class InvitacionAdministradorAdmin(admin.ModelAdmin):
    list_display = ('email', 'token', 'usado', 'creado_en')
    list_filter = ('usado',)
    search_fields = ('email',)
    ordering = ('-creado_en',)
    readonly_fields = ('token', 'creado_en', 'usado')

    def get_readonly_fields(self, request, obj=None):
        if obj:
            return self.readonly_fields + ('email',)
        return self.readonly_fields


# ---------------------------------------------------------
# ADMIN: Usuario
# ---------------------------------------------------------
@admin.register(Usuario)
class UsuarioAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'rol', 'cedula', 'telefono', 'is_active', 'is_superuser')
    list_filter = ('rol', 'is_active', 'is_superuser')
    search_fields = ('username', 'email', 'first_name', 'last_name', 'cedula')
    ordering = ('rol', 'username')
    readonly_fields = ('last_login', 'date_joined')

    fieldsets = (
        ("Información Personal", {
            'fields': ('username', 'first_name', 'last_name', 'email', 'cedula', 'telefono')
        }),
        ("Rol y Permisos", {
            'fields': ('rol', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')
        }),
        ("Fechas Importantes", {
            'fields': ('last_login', 'date_joined')
        }),
    )


# ---------------------------------------------------------
# ADMIN: AdministradorEvento
# ---------------------------------------------------------
@admin.register(AdministradorEvento)
class AdministradorEventoAdmin(admin.ModelAdmin):
    list_display = (
        'usuario_email',
        'nombre_completo',
        'cedula',
        'estado_cuenta',
        'ver_usuario_link'
    )
    list_filter = ('usuario__is_active',)
    search_fields = ('usuario__email', 'usuario__first_name', 'usuario__last_name', 'usuario__cedula')
    actions = [activar_administradores]

    def save_model(self, request, obj, form, change):
        """
        Sobrescribimos este método para evitar que el admin intente
        volver a guardar un AdministradorEvento ya existente.
        """
        if not obj.pk:  # Solo guarda si es nuevo
            super().save_model(request, obj, form, change)

    @admin.display(description="Email")
    def usuario_email(self, obj):
        return obj.usuario.email

    @admin.display(description="Nombre Completo")
    def nombre_completo(self, obj):
        return f"{obj.usuario.first_name} {obj.usuario.last_name}"

    @admin.display(description="Cédula")
    def cedula(self, obj):
        return obj.usuario.cedula

    @admin.display(description="Estado de Cuenta")
    def estado_cuenta(self, obj):
        return "✅ Activo" if obj.usuario.is_active else "❌ Pendiente"

    @admin.display(description="Ver Usuario")
    def ver_usuario_link(self, obj):
        url = reverse('admin:app_usuarios_usuario_change', args=[obj.usuario.id])
        return format_html('<a href="{}">Abrir</a>', url)






# --------------------------
# Configuración de Eventos
# --------------------------
class EventoAdmin(admin.ModelAdmin):
    list_display = ['eve_nombre', 'eve_ciudad', 'eve_lugar', 'eve_fecha_inicio', 'eve_fecha_fin', 'eve_estado']
    list_filter = ['eve_estado', 'eve_fecha_inicio', 'eve_fecha_fin']
    search_fields = ['eve_nombre', 'eve_ciudad', 'eve_lugar']

    # HU93: Publicar evento en sitio web
    def publicar_evento(self, request, queryset):
        updated = queryset.update(eve_estado="Publicado")
        self.message_user(request, f"{updated} evento(s) publicados en el sitio web.", level=messages.SUCCESS)

    publicar_evento.short_description = "HU93 - Publicar evento en el sitio Web"

    # HU95: Cerrar eventos después de un tiempo
    def cerrar_eventos_vencidos(self, request, queryset):
        hoy = timezone.now().date()
        cerrados = 0
        for evento in queryset:
            if evento.eve_fecha_fin < hoy and evento.eve_estado != "Cerrado":
                evento.eve_estado = "Cerrado"
                evento.save()
                cerrados += 1
        self.message_user(request, f"{cerrados} evento(s) cerrados automáticamente.", level=messages.WARNING)

    cerrar_eventos_vencidos.short_description = "HU95 - Cerrar eventos vencidos"

    # HU96: Eliminar eventos pasados
    def eliminar_eventos_pasados(self, request, queryset):
        hoy = timezone.now().date()
        eliminados = 0
        for evento in queryset:
            if evento.eve_fecha_fin < hoy:
                evento.delete()
                eliminados += 1
        self.message_user(request, f"{eliminados} evento(s) eliminados del sitio.", level=messages.ERROR)

    eliminar_eventos_pasados.short_description = "HU96 - Eliminar eventos pasados"

    actions = [publicar_evento, cerrar_eventos_vencidos, eliminar_eventos_pasados]


# --------------------------
# Configuración de Categorías y Áreas
# --------------------------
class CategoriaAdmin(admin.ModelAdmin):
    list_display = ['cat_nombre', 'cat_area_fk']
    search_fields = ['cat_nombre']


class AreaAdmin(admin.ModelAdmin):
    list_display = ['are_nombre']
    search_fields = ['are_nombre']


# --------------------------
# Configuración de Criterios
# --------------------------
class CriterioAdmin(admin.ModelAdmin):
    list_display = ['cri_descripcion', 'cri_peso', 'cri_evento_fk']
    list_filter = ['cri_evento_fk']


# --------------------------
# Configuración de Memorias
# --------------------------
class MemoriaEventoAdmin(admin.ModelAdmin):
    list_display = ['nombre', 'evento', 'subido_en']
    list_filter = ['evento']
    search_fields = ['nombre']





admin.site.register(Asistente)
admin.site.register(Participante)
admin.site.register(Evaluador)

admin.site.register(Evento, EventoAdmin)
admin.site.register(Categoria, CategoriaAdmin)
admin.site.register(Area, AreaAdmin)
admin.site.register(Criterio, CriterioAdmin)
admin.site.register(MemoriaEvento, MemoriaEventoAdmin)
admin.site.register(EventoCategoria)
admin.site.register(AsistenteEvento)
admin.site.register(EvaluadorEvento)
admin.site.register(ParticipanteEvento)