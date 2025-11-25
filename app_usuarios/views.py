from django.core.mail import send_mail, BadHeaderError
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from django.urls import reverse
from django.contrib import messages
from uuid import uuid4
import random
import string

from .models import InvitacionAdministrador, AdministradorEvento, Usuario
from .forms import RegistroAdministradorForm


# ---------------------------------------------------------
# SUPERADMIN - Enviar invitación
# ---------------------------------------------------------
@user_passes_test(lambda u: u.is_superuser)
def enviar_invitacion(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        # Eliminar invitaciones previas con el mismo correo
        InvitacionAdministrador.objects.filter(email=email).delete()

        # Crear nueva invitación
        invitacion = InvitacionAdministrador.objects.create(email=email, token=uuid4(), usado=False)
        link = request.build_absolute_uri(reverse('registro_admin_evento', args=[str(invitacion.token)]))

        mensaje = f"""
        Has sido invitado a registrarte como Administrador de Evento.
        Por favor, completa tu registro aquí:
        {link}
        """

        # Enviar el correo de invitación
        try:
            send_mail(
                subject="Invitación a ser Administrador de Evento",
                message=mensaje,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
        except BadHeaderError:
            messages.error(request, "Error al enviar el correo de invitación.")
            return redirect('enviar_invitacion')

        return render(request, 'invitacion_enviada.html', {'email': email})

    return render(request, 'enviar_invitacion.html')


# ---------------------------------------------------------
# REGISTRO - Administrador de evento desde la invitación
# ---------------------------------------------------------
def registro_admin_evento(request, token):
    invitacion = get_object_or_404(InvitacionAdministrador, token=token, usado=False)
    email = invitacion.email

    if request.method == 'POST':
        form = RegistroAdministradorForm(request.POST, email_fijo=email)
        if form.is_valid():
            # Evita duplicados de usuario
            if Usuario.objects.filter(email=email).exists():
                messages.error(request, "Ya existe una solicitud o usuario con este correo.")
                return render(request, 'registro_admin.html', {'form': form})

            # Crear nuevo usuario inactivo
            user = form.save(commit=False)
            user.email = email
            user.is_active = False
            user.rol = Usuario.Roles.ADMIN_EVENTO
            user.save()

            # ✅ Asegura que no se creen duplicados en la tabla AdministradorEvento
            AdministradorEvento.objects.get_or_create(usuario=user)

            # Marcar invitación como usada
            invitacion.usado = True
            invitacion.save()

            messages.success(request, "Tu solicitud fue enviada. Espera aprobación del SuperAdmin.")
            return render(request, 'registro_exitoso.html')
    else:
        form = RegistroAdministradorForm(email_fijo=email)

    return render(request, 'registro_admin.html', {'form': form})


# ---------------------------------------------------------
# SUPERADMIN - Activar administrador y enviar credenciales
# ---------------------------------------------------------
@user_passes_test(lambda u: u.is_superuser)
def activar_admin_evento(request, user_id):
    user = get_object_or_404(
        Usuario, id=user_id, rol=Usuario.Roles.ADMIN_EVENTO, is_active=False
    )

    # ✅ Asegurar que tenga su relación de AdministradorEvento
    AdministradorEvento.objects.get_or_create(usuario=user)

    # Generar contraseña aleatoria
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
    user.set_password(password)
    user.is_active = True
    user.save()

    # Enviar correo con las credenciales
    try:
        send_mail(
            subject="Cuenta de Administrador Aprobada",
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
    except BadHeaderError:
        messages.error(request, "Error al enviar el correo con credenciales.")
        return redirect('lista_admins_pendientes')

    messages.success(request, f"Administrador {user.email} activado y notificado por correo.")
    return redirect('lista_admins_pendientes')
