from datetime import date
from django.contrib import messages
from django.urls import reverse
from django.utils import timezone
from django.shortcuts import render, redirect, get_object_or_404
from django.views import View
from django.core.mail import send_mail
from django.core.mail import EmailMessage
from principal_eventos.settings import DEFAULT_FROM_EMAIL
from .models import AsistenteEvento
from app_usuarios.models import Asistente, Usuario
from django.utils.timezone import now, localtime
from django.contrib.auth.hashers import make_password
from app_admin_eventos.models import Evento
from .forms import AsistenteForm, EditarUsuarioAsistenteForm
import qrcode
import string
import random
import os
from django.core.files.base import ContentFile
from io import BytesIO
from django.utils.decorators import method_decorator
from principal_eventos.decorador import asistente_required, visitor_required
from django.views.generic import DetailView
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from app_admin_eventos.models import Evento, MemoriaEvento
from app_admin_eventos.models import Evento, MemoriaEvento
from app_asistentes.models import AsistenteEvento
from app_participantes.models import ParticipanteEvento
from app_evaluadores.models import EvaluadorEvento
from django.db.models import Q
from django.db import models
from django.contrib.auth import logout
from django.db import transaction
from django.views.generic import ListView, DetailView




###### MEMORIAS DE ASISTENTE ######
@method_decorator(login_required, name='dispatch')
class MemoriasAsistenteView(View):
    def get(self, request, evento_id):
        evento = get_object_or_404(Evento, id=evento_id)
        inscrito = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=evento,
            asi_eve_asistente_fk__usuario=request.user
        ).exists()
        if not inscrito:
            messages.error(request, "No estás inscrito como asistente en este evento.")
            return redirect('dashboard_user')
        memorias = MemoriaEvento.objects.filter(evento=evento).order_by('-subido_en')
        return render(request, 'dashboard_memorias_asistente.html', {
            'evento': evento,
            'memorias': memorias
        })


###### DASHBOARD DE ASISTENTE ######
@method_decorator(asistente_required, name='dispatch')
class DashboardAsistenteView(View):
    template_name = 'dashboard_principal_asistente.html'

    def get(self, request):
        asistente_id = request.session.get('asistente_id')
        if not asistente_id:
            messages.error(request, "Debe iniciar sesión como asistente.")
            return redirect('login_view')

        try:
            asistente = Asistente.objects.get(id=asistente_id)
        except Asistente.DoesNotExist:
            messages.error(request, "Asistente no encontrado.")
            return redirect('login_view')

        # Filtrar relaciones del asistente con eventos
        relaciones = AsistenteEvento.objects.filter(asi_eve_asistente_fk=asistente).select_related('asi_eve_evento_fk')

        # Separar eventos aprobados y pendientes
        eventos_aprobados = [rel.asi_eve_evento_fk for rel in relaciones if rel.asi_eve_estado == 'Aprobado']
        eventos_pendientes = [rel.asi_eve_evento_fk for rel in relaciones if rel.asi_eve_estado == 'Pendiente']

        relacion = AsistenteEvento.objects.filter(asi_eve_asistente_fk=asistente).first()

        context = {
            'asistente': asistente,
            'eventos': eventos_aprobados,
            'eventos_pendientes': eventos_pendientes,
            'relacion': relacion,  # <-- esto es importante
        }
        return render(request, self.template_name, context)



###### CREACIÓN DE ASISTENTE ######
@method_decorator(visitor_required, name='dispatch')
class AsistenteCreateView(View):
    def get(self, request, pk):
        evento = get_object_or_404(Evento, pk=pk)
        form = AsistenteForm()
        es_de_pago = evento.eve_tienecosto.lower() == "de pago"

        return render(request, 'crear_asistente.html', {
            'form': form,
            'evento': evento,
            'es_de_pago': es_de_pago,
        })

    def post(self, request, pk):
        evento = get_object_or_404(Evento, pk=pk)
        form = AsistenteForm(request.POST, request.FILES)
        es_de_pago = evento.eve_tienecosto.lower() == "de pago"

        # 🔹 Validar comprobante si el evento es de pago
        if es_de_pago and not request.FILES.get('asi_eve_soporte'):
            messages.error(request, "Debe cargar una imagen del comprobante de pago para este evento.")
            return render(request, 'crear_asistente.html', {
                'form': form, 'evento': evento, 'es_de_pago': es_de_pago
            })

        if form.is_valid():
            try:
                with transaction.atomic():
                    cedula = form.cleaned_data['cedula']
                    first_name = form.cleaned_data['first_name']
                    last_name = form.cleaned_data['last_name']
                    email = form.cleaned_data['email']
                    telefono = form.cleaned_data['telefono']
                    username = form.cleaned_data['username']

                    # 🔹 Buscar usuario existente
                    usuario = Usuario.objects.filter(
                        Q(cedula=cedula) | Q(email=email) | Q(username=username)
                    ).first()

                    creado = False

                    if usuario:
                        # 🔸 Evitar registro duplicado en otros roles del mismo evento
                        if ParticipanteEvento.objects.filter(
                            par_eve_evento_fk=evento,
                            par_eve_participante_fk__usuario=usuario
                        ).exists():
                            messages.error(request, f"Ya estás inscrito como PARTICIPANTE en el evento \"{evento.eve_nombre}\". No puedes registrarte también como Asistente.")
                            return render(request, 'crear_asistente.html', {
                                'form': form, 'evento': evento, 'es_de_pago': es_de_pago
                            })

                        if EvaluadorEvento.objects.filter(
                            eva_eve_evento_fk=evento,
                            eva_eve_evaluador_fk__usuario=usuario
                        ).exists():
                            messages.error(request, f"Ya estás inscrito como EVALUADOR en el evento \"{evento.eve_nombre}\". No puedes registrarte también como Asistente.")
                            return render(request, 'crear_asistente.html', {
                                'form': form, 'evento': evento, 'es_de_pago': es_de_pago
                            })

                        # 🔸 Actualizar datos del usuario
                        usuario.first_name = first_name
                        usuario.last_name = last_name
                        usuario.telefono = telefono
                        usuario.email = email
                        usuario.username = username
                        usuario.cedula = cedula

                        if usuario.rol != Usuario.Roles.ASISTENTE:
                            usuario.rol = Usuario.Roles.ASISTENTE
                        usuario.save(update_fields=['first_name', 'last_name', 'telefono', 'email', 'username', 'cedula', 'rol'])

                        asistente, _ = Asistente.objects.get_or_create(usuario=usuario)
                        password_plana = "Tu contraseña actual"

                    else:
                        # 🔹 Crear nuevo usuario
                        creado = True
                        password_plana = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
                        usuario = Usuario.objects.create(
                            username=username,
                            first_name=first_name,
                            last_name=last_name,
                            email=email,
                            telefono=telefono,
                            cedula=cedula,
                            is_superuser=False,
                            is_staff=False,
                            is_active=True,
                            date_joined=timezone.now(),
                            rol=Usuario.Roles.ASISTENTE,
                            password=make_password(password_plana),
                        )
                        asistente = Asistente.objects.create(usuario=usuario)

                    # 🔹 Validar capacidad disponible
                    if evento.eve_capacidad <= 0:
                        messages.error(request, "No hay más cupos disponibles para este evento.")
                        return render(request, 'crear_asistente.html', {
                            'form': form, 'evento': evento, 'es_de_pago': es_de_pago
                        })

                    # 🔹 Evitar duplicados
                    if AsistenteEvento.objects.filter(
                        asi_eve_evento_fk=evento,
                        asi_eve_asistente_fk=asistente
                    ).exists():
                        messages.warning(request, "Ya estás inscrito como asistente en este evento.")
                        return render(request, 'crear_asistente.html', {
                            'form': form, 'evento': evento, 'es_de_pago': es_de_pago
                        })

                    # 🔹 Crear registro de asistencia
                    documento_pago = request.FILES.get('asi_eve_soporte') if es_de_pago else None
                    estado = "Pendiente" if es_de_pago else "Aprobado"

                    clave = ""
                    qr_img_file = None
                    qr_bytes = None
                    qr_filename = None

                    # Solo generar QR si es gratis
                    if not es_de_pago:
                        clave = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
                        qr_data = f"Asistente: {first_name} {last_name}\nEvento: {evento.eve_nombre}\nClave: {clave}"
                        qr = qrcode.make(qr_data)
                        buffer = BytesIO()
                        qr.save(buffer, format='PNG')
                        qr_bytes = buffer.getvalue()
                        qr_filename = f"qr_{cedula}_{evento.pk}.png"
                        qr_img_file = ContentFile(qr_bytes, name=qr_filename)

                    AsistenteEvento.objects.create(
                        asi_eve_evento_fk=evento,
                        asi_eve_asistente_fk=asistente,
                        asi_eve_estado=estado,
                        asi_eve_clave=clave,
                        asi_eve_qr=qr_img_file if qr_img_file else None,
                        asi_eve_soporte=documento_pago,
                        asi_eve_fecha_hora=timezone.now(),
                    )

                    # 🔹 Reducir capacidad
                    evento.eve_capacidad -= 1
                    evento.save(update_fields=['eve_capacidad'])

                    # 🔹 Enviar correo
                    subject = f"🎟️ Registro exitoso - Evento \"{evento.eve_nombre}\""

                    if creado:
                        body = (
                            f"Hola Asistente {first_name} {last_name},\n\n"
                            f"Tu registro al evento \"{evento.eve_nombre}\" fue exitoso.\n\n"
                            f"Tu cuenta fue creada. Credenciales de acceso:\n"
                            f"- Correo: {email}\n"
                            f"- Contraseña generada: {password_plana}\n\n"
                        )
                    else:
                        body = (
                            f"Hola Asistente {first_name} {last_name},\n\n"
                            f"Tu registro al evento \"{evento.eve_nombre}\" fue exitoso.\n\n"
                            f"Ya tenías una cuenta. Credenciales de acceso:\n"
                            f"- Correo: {email}\n"
                            f"- Contraseña: La que usas actualmente.\n\n"
                        )

                    if not es_de_pago:
                        body += (
                            f"Tu clave de acceso al evento es: {clave}\n"
                            f"Adjunto encontrarás tu código QR para el ingreso.\n\n"
                        )

                    body += "¡Gracias por registrarte!\nEquipo de Event-Soft."

                    email_msg = EmailMessage(subject, body, DEFAULT_FROM_EMAIL, [email])
                    if not es_de_pago and qr_bytes and qr_filename:
                        email_msg.attach(qr_filename, qr_bytes, 'image/png')
                    try:
                        email_msg.send(fail_silently=False)
                    except Exception as e:
                        messages.warning(request, f"Asistente registrado, pero no se pudo enviar el correo: {e}")

                    # ✅ Mensaje de éxito garantizado ANTES del redirect
                    messages.success(request, f"Te has inscrito correctamente al evento \"{evento.eve_nombre}\".")
                    return redirect('pagina_principal')

            except Exception as e:
                messages.error(request, f"Ocurrió un error inesperado al registrarte: {str(e)}")
                return render(request, 'crear_asistente.html', {
                    'form': form, 'evento': evento, 'es_de_pago': es_de_pago
                })

        # ❗ Si el formulario no es válido
        messages.error(request, "Por favor, revisa los campos del formulario. Algunos datos no son válidos.")
        return render(request, 'crear_asistente.html', {
            'form': form,
            'evento': evento,
            'es_de_pago': es_de_pago,
        })



####### CAMBIO PASSWORD ASISTENTE ######
@method_decorator(asistente_required, name='dispatch')
class CambioPasswordAsistenteView(View):
    template_name = 'cambio_password_asistente.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 != password2:
            messages.error(request, "Las contraseñas no coinciden.")
            return render(request, self.template_name)

        if len(password1) < 6:
            messages.error(request, "La contraseña debe tener al menos 6 caracteres.")
            return render(request, self.template_name)

        asistente_id = request.session.get('asistente_id')
        asistente = get_object_or_404(Asistente, pk=asistente_id)
        usuario = asistente.usuario

        usuario.set_password(password1)
        usuario.last_login = timezone.now()  # Se actualiza solo aquí
        usuario.save()

        messages.success(request, "Contraseña cambiada correctamente.")
        return redirect('dashboard_asistente')

####### ELIMINAR DATOS ASISTENTE ######
@method_decorator(asistente_required, name='dispatch')
class EliminarAsistenteView(View):
    def get(self, request, asistente_id):
        # Aseguramos que el ID del asistente coincida con el usuario logueado por seguridad (aunque asistente_required ya ayuda)
        asistente = get_object_or_404(Asistente, id=asistente_id)
        usuario = asistente.usuario

        # 🔹 Buscar todas las inscripciones del asistente
        inscripciones = AsistenteEvento.objects.filter(asi_eve_asistente_fk=asistente)

        # 🔹 Verificar si tiene inscripciones activas (aprobadas)
        tiene_inscripciones_activas = inscripciones.filter(asi_eve_estado="Aprobado").exists()
        if tiene_inscripciones_activas:
            messages.error(
                request,
                "No puedes eliminar tu cuenta mientras tengas inscripciones activas. "
                "Por favor, cancela tus inscripciones antes de eliminar tu cuenta."
            )
            return redirect('pagina_principal')

        # 🔹 Liberar cupos solo de eventos pendientes (Mantenemos esta lógica)
        for inscripcion in inscripciones:
            if inscripcion.asi_eve_estado == "Pendiente":
                evento = inscripcion.asi_eve_evento_fk
                evento.eve_capacidad += 1
                evento.save(update_fields=["eve_capacidad"])

        # 🔹 Obtener el último evento inscrito (para referencia en el correo)
        ultimo_evento = inscripciones.first()
        nombre_evento = ultimo_evento.asi_eve_evento_fk.eve_nombre if ultimo_evento else "uno de nuestros eventos"
        
        # 🔑 PASO 1: ELIMINAR LA RELACIÓN (Perfil) ASISTENTE
        # Esto elimina automáticamente todas las inscripciones en AsistenteEvento (por CASCADE)
        asistente.delete()         


        # 🔹 Enviar correo antes de eliminar (Mantenemos la lógica de envío)
        if usuario.email:
             # Manejo de fallas de envío para evitar errores críticos
             try:
                send_mail(
                    subject='🗑️ Notificación de eliminación de perfil como Asistente', # Título ajustado
                    message=(
                        f'Estimado/a {usuario.first_name},\n\n'
                        f'Le informamos que su perfil de **Asistente** ha sido eliminado correctamente de Event-Soft.\n\n'
                        f'Todos sus datos de inscripción en eventos como "{nombre_evento}" '
                        f'han sido eliminados. **Su cuenta de usuario principal no ha sido eliminada**.\n\n'
                        f'Si desea volver a inscribirse como Asistente en el futuro, puede hacerlo usando su cuenta existente.\n\n'
                        f'Atentamente,\nEquipo de organización de eventos.'
                    ),
                    from_email=DEFAULT_FROM_EMAIL,
                    recipient_list=[usuario.email],
                    fail_silently=False
                )
             except Exception:
                 messages.warning(request, "El perfil de Asistente fue eliminado, pero no se pudo enviar el correo de notificación.")
        
        # 🔹 Cerrar sesión del usuario (Necesario para recargar la sesión sin el rol de Asistente)
        # Solo se elimina la información de la sesión, no el usuario.
        logout(request) # Usamos logout en lugar de flush para limpiar la sesión de forma segura y borrar cookies de Auth.


        messages.success(request, "Tu perfil de Asistente y tus inscripciones han sido eliminadas correctamente. Hemos cerrado tu sesión.")
        return redirect('pagina_principal')



####### CANCELAR EVENTO ASISTENTE  ######
@method_decorator(asistente_required, name='dispatch')
class AsistenteCancelacionView(View):
    """
    Permite a un asistente cancelar una preinscripción activa a un evento.
    El cupo se libera explícitamente al aumentar la capacidad del evento.
    """
    def post(self, request, evento_id):
        asistente = get_object_or_404(Asistente, usuario=request.user)
        evento = get_object_or_404(Evento, id=evento_id)

        # CA-10.1: Prohibir la cancelación si el evento ya terminó
        if evento.eve_fecha_fin < timezone.localdate():
            messages.error(request, "No puedes cancelar una inscripción a un evento que ya finalizó.")
            return redirect('dashboard_asistente')

        # 1. Buscar inscripción activa (estado 'Aprobado')
        inscripcion = AsistenteEvento.objects.filter(
            asi_eve_asistente_fk=asistente,
            asi_eve_evento_fk=evento,
            asi_eve_estado='Aprobado'
        ).first()

        # CA-10.5: No inscrito o no tiene estado 'Aprobado'
        if not inscripcion:
            messages.error(request, "No tienes una inscripción activa para este evento.")
            return redirect('dashboard_asistente')

        # 2. Cambiar el estado a 'Cancelado'
        inscripcion.asi_eve_estado = 'Cancelado'
        inscripcion.save(update_fields=['asi_eve_estado'])

        # 3. 🔹 Liberar cupo explícitamente
        evento.eve_capacidad += 1
        evento.save(update_fields=['eve_capacidad'])

        # 4. Mensaje de éxito
        messages.success(
            request,
            f"Has cancelado exitosamente tu inscripción al evento '{evento.eve_nombre}'. "
            f"Tu cupo ha sido liberado."
        )
        return redirect('dashboard_asistente')


######### EDITAR PREINSCRIPCION ########
@method_decorator(asistente_required, name='dispatch')
class EditarPreinscripcionAsistenteView(View):
    template_name = 'editar_preinscripcion_asistente.html'

    def get(self, request, id):
        relacion = get_object_or_404(AsistenteEvento, pk=id)
        asistente = relacion.asi_eve_asistente_fk
        evento = relacion.asi_eve_evento_fk
        form = EditarUsuarioAsistenteForm(instance=asistente.usuario)

        # 🔹 Traer todos los eventos donde está inscrito
        todas_relaciones = AsistenteEvento.objects.filter(
            asi_eve_asistente_fk=asistente
        ).select_related("asi_eve_evento_fk")

        return render(request, self.template_name, {
            'form': form,
            'evento': evento,
            'relacion': relacion,
            'usuario': asistente.usuario,
            'asistente': asistente,
            'todas_relaciones': todas_relaciones
        })

    def post(self, request, id):
        relacion = get_object_or_404(AsistenteEvento, pk=id)
        asistente = relacion.asi_eve_asistente_fk
        evento = relacion.asi_eve_evento_fk
        usuario = asistente.usuario

        form = EditarUsuarioAsistenteForm(request.POST, instance=usuario)

        # Contraseñas
        contrasena_actual = request.POST.get('nueva_contrasena')
        nueva_contrasena = request.POST.get('confirmar_contrasena_nueva')
        confirmar_nueva = request.POST.get('confirmar_contrasena')

        if form.is_valid():
            usuario = form.save(commit=False)
            usuario.ultimo_acceso = localtime(now())

            # Validar y cambiar contraseña si hay datos ingresados
            if contrasena_actual or nueva_contrasena or confirmar_nueva:
                if not usuario.check_password(contrasena_actual):
                    messages.error(request, "La contraseña actual no es correcta.")
                    return redirect('editar_preinscripcion_asistente', id=id)

                if nueva_contrasena != confirmar_nueva:
                    messages.error(request, "Las contraseñas nuevas no coinciden.")
                    return redirect('editar_preinscripcion_asistente', id=id)

                if len(nueva_contrasena) < 6:
                    messages.error(request, "La nueva contraseña debe tener al menos 6 caracteres.")
                    return redirect('editar_preinscripcion_asistente', id=id)

                usuario.set_password(nueva_contrasena)
                update_session_auth_hash(request, usuario)

            usuario.save()

            # 🔹 Procesar soportes para TODOS los eventos donde está inscrito
            todas_relaciones = AsistenteEvento.objects.filter(
                asi_eve_asistente_fk=asistente
            )

            for r in todas_relaciones:
                file_key = f"asi_eve_soporte_{r.id}"
                documento_pago = request.FILES.get(file_key)
                if documento_pago:
                    r.asi_eve_soporte = documento_pago
                    r.save()

            messages.success(request, "Tu información fue actualizada correctamente.")
            return redirect('editar_preinscripcion_asistente', id=id)

        # Si hay errores, volvemos a mostrar el formulario
        todas_relaciones = AsistenteEvento.objects.filter(
            asi_eve_asistente_fk=asistente
        ).select_related("asi_eve_evento_fk")

        return render(request, self.template_name, {
            'form': form,
            'evento': evento,
            'relacion': relacion,
            'usuario': asistente.usuario,
            'asistente': asistente,
            'todas_relaciones': todas_relaciones
        })


####### EVENTO DETALLE ######
@method_decorator(asistente_required, name='dispatch')
class EventoDetailAsistenteView(DetailView):
    """
    Vista PRIVADA para asistentes autenticados.
    Muestra detalles de eventos donde el asistente está inscrito.
    Requiere autenticación como asistente.
    """
    model = Evento
    template_name = 'info_evento_evento_asi.html'
    context_object_name = 'evento'
    pk_url_kwarg = 'pk'

    def dispatch(self, request, *args, **kwargs):
        evento = get_object_or_404(self.model, pk=kwargs['pk'])
        asistente_id = request.session.get('asistente_id')
        
        if asistente_id:
            asistente = get_object_or_404(Asistente, id=asistente_id)
            if not AsistenteEvento.objects.filter(asi_eve_asistente_fk=asistente, asi_eve_evento_fk=evento).exists():
                messages.error(request, "No tienes permiso para ver este evento.")
                return redirect('dashboard_asistente') 
        
        return super().dispatch(request, *args, **kwargs)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        evento = context['evento']
        relative_url = reverse('ver_info_evento_asi', kwargs={'pk': evento.pk})
        public_absolute_url = self.request.build_absolute_uri(relative_url)
        context['url_para_compartir'] = public_absolute_url 
        context['asistente'] = get_object_or_404(Asistente, id=self.request.session.get('asistente_id'))
        return context





####### ACCESO A EVENTO ######
@method_decorator(asistente_required, name='dispatch')
class IngresoEventoAsistenteView(View):
    template_name = 'ingreso_evento_asi.html'

    def get(self, request, pk):
        evento = get_object_or_404(Evento, pk=pk)
        asistente = get_object_or_404(Asistente, usuario=request.user)
        asistente_evento = get_object_or_404(
            AsistenteEvento, 
            asi_eve_evento_fk=evento, 
            asi_eve_asistente_fk=asistente
        )

        # ✅ NUEVO: Determinar si el QR debe mostrarse
        mostrar_qr = asistente_evento.asi_eve_estado == 'Aprobado'

        context = {
            'evento': evento,
            'asistente': asistente_evento,  # objeto con QR y soporte
            'mostrar_qr': mostrar_qr,        # booleano para el template
            'estado': asistente_evento.asi_eve_estado,  # estado para referencia
        }
        return render(request, self.template_name, context)
    

    
####### MEMORIAS DEL EVENTO PARA USUARIOS ######
@method_decorator(login_required, name='dispatch')
class MemoriasAsistenteView(View):
    def get(self, request, evento_id):
        evento = get_object_or_404(Evento, id=evento_id)
        # Verificar inscripción como asistente
        inscrito = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=evento,
            asi_eve_asistente_fk__usuario=request.user
        ).exists()
        if not inscrito:
            messages.error(request, "No estás inscrito como asistente en este evento.")
            return redirect('dashboard_asistente')
        memorias = MemoriaEvento.objects.filter(evento=evento).order_by('-subido_en')
        return render(request, 'memorias_asistente.html', {'evento': evento, 'memorias': memorias})


# Añade esto a app_asistentes/views.py

# Añade esto a app_asistentes/views.py

class NotificarAsistentesView(View):
    """
    Vista para que un administrador de evento envíe notificaciones a asistentes.
    Solo accesible por administradores de eventos.
    """
    template_name = 'notificar_asistentes.html'

    def dispatch(self, request, *args, **kwargs):
        # Verificar autenticación
        if not request.user.is_authenticated:
            return redirect('login_view')
        
        # Verificar rol de administrador
        if request.user.rol != Usuario.Roles.ADMIN_EVENTO:
            messages.error(request, "No tienes permiso para acceder a esta vista.")
            return redirect('dashboard_asistente')
        
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, evento_id):
        """Muestra el formulario para enviar notificaciones."""
        evento = get_object_or_404(Evento, id=evento_id)
        
        # Obtener asistentes inscritos en el evento
        inscripciones = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=evento
        ).select_related('asi_eve_asistente_fk__usuario').order_by('-asi_eve_fecha_hora')
        
        context = {
            'evento': evento,
            'inscripciones': inscripciones,
        }
        return render(request, self.template_name, context)

    def post(self, request, evento_id):
        """Procesa el envío de notificaciones."""
        evento = get_object_or_404(Evento, id=evento_id)
        
        # Obtener datos del formulario
        asistentes_ids = request.POST.getlist('asistentes')
        mensaje = request.POST.get('mensaje', '').strip()
        
        # Obtener inscripciones para el contexto
        inscripciones = AsistenteEvento.objects.filter(
            asi_eve_evento_fk=evento
        ).select_related('asi_eve_asistente_fk__usuario').order_by('-asi_eve_fecha_hora')
        
        context = {
            'evento': evento,
            'inscripciones': inscripciones,
        }
        
        # === Validación 1: Mensaje no vacío ===
        if not mensaje:
            messages.error(request, "El mensaje no puede estar vacío.")
            return render(request, self.template_name, context)
        
        # === Validación 2: Al menos un asistente seleccionado ===
        if not asistentes_ids:
            messages.error(request, "No seleccionaste ningún asistente.")
            return render(request, self.template_name, context)
        
        # === Obtener inscripciones seleccionadas ===
        inscripciones_seleccionadas = AsistenteEvento.objects.filter(
            id__in=asistentes_ids,
            asi_eve_evento_fk=evento
        ).select_related('asi_eve_asistente_fk__usuario')
        
        # === Enviar notificaciones ===
        emails_enviados = 0
        errores = []
        
        for inscripcion in inscripciones_seleccionadas:
            usuario = inscripcion.asi_eve_asistente_fk.usuario
            email = usuario.email
            
            if email:
                asunto = f"Notificación sobre el evento: {evento.eve_nombre}"
                cuerpo = (
                    f"Hola {usuario.first_name} {usuario.last_name},\n\n"
                    f"Tienes un nuevo mensaje del evento '{evento.eve_nombre}':\n\n"
                    f"{mensaje}\n\n"
                    f"Atentamente,\n"
                    f"Equipo de Event-Soft"
                )
                
                try:
                    send_mail(
                        subject=asunto,
                        message=cuerpo,
                        from_email=DEFAULT_FROM_EMAIL,
                        recipient_list=[email],
                        fail_silently=False
                    )
                    emails_enviados += 1
                except Exception as e:
                    errores.append(f"{email}: {str(e)}")
        
        # === Mensaje de éxito ===
        if emails_enviados > 0:
            messages.success(
                request,
                f"Notificación enviada exitosamente a {emails_enviados} asistente(s)."
            )
            if errores:
                for error in errores:
                    messages.warning(request, f"Error al enviar a {error}")
            return redirect('dashboard_asistente')
        else:
            messages.error(request, "No se pudo enviar la notificación a ningún asistente.")
            return render(request, self.template_name, context)