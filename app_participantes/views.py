from io import BytesIO
from django.utils import timezone
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import render, redirect, get_object_or_404
from django.views import View
from django.urls import reverse
import qrcode
from django.db.models import Q

from app_participantes.utils import send_mail_participante_grupo
from .models import ParticipanteEvento
from app_usuarios.models import Evaluador, Participante, Usuario
from app_admin_eventos.models import Evento, Criterio
from .forms import EditarUsuarioParticipanteForm, ParticipanteForm, MiembroParticipanteForm
from django.contrib import messages
from principal_eventos.settings import DEFAULT_FROM_EMAIL
from django.core.mail import send_mail
from django.utils.timezone import now, localtime
import random
import string
from django.utils.decorators import method_decorator
from principal_eventos.decorador import participante_required, visitor_required
from django.contrib.auth import update_session_auth_hash
from django.views.generic import DetailView
from django.db.models import Sum
from app_evaluadores.models import Calificacion
from django.contrib.auth.decorators import login_required
from app_admin_eventos.models import Evento, MemoriaEvento
from django.db import transaction
from django.contrib.auth.models import Group
from django.contrib.auth import logout
from app_asistentes.models import AsistenteEvento
from app_evaluadores.models import EvaluadorEvento
from django.contrib.auth.hashers import make_password 
from django.utils.crypto import get_random_string
from django.core.files.base import ContentFile
from django.shortcuts import redirect
from django.views import View
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.db import transaction
from django.http import HttpResponseForbidden
from .models import ParticipanteEvento
from app_usuarios.models import Participante
from app_admin_eventos.models import Evento


def crear_o_obtener_grupo_proyecto(codigo_proyecto, evento_nombre):
    # ... (Tu código de la función)
    nombre_grupo = f"Proyecto_{codigo_proyecto}_{evento_nombre[:20]}"
    grupo, created = Group.objects.get_or_create(
        name=nombre_grupo
    )
    return grupo



######## CREAR PARTICIPANTE ########
MAX_MIEMBROS_GRUPO = 5  # Incluye al líder
@method_decorator(visitor_required, name='dispatch')
class ParticipanteCreateView(View):
    """
    Vista para manejar el formulario de preinscripción de un Participante (Individual o Grupal)
    a un Evento específico.
    """
    
    # ----------------------------------------------------------------------
    # 1. GET: Mostrar el formulario de inscripción
    # ----------------------------------------------------------------------
    def get(self, request, pk):
        evento = get_object_or_404(Evento, pk=pk)
        form = ParticipanteForm(evento=evento) 
        return render(request, 'crear_participante.html', {
            'form': form,
            'evento': evento,
        })

    # ----------------------------------------------------------------------
    # 2. POST: Procesar el formulario de inscripción
    # ----------------------------------------------------------------------
    def post(self, request, pk):
        evento = get_object_or_404(Evento, pk=pk)
        form = ParticipanteForm(request.POST, request.FILES, evento=evento)
        
        documento = request.FILES.get('par_eve_documentos') 
        es_grupo = request.POST.get('tipo_participacion') == 'grupo'
        
        # Validaciones iniciales
        if not documento:
            messages.error(request, "Debe cargar el documento para continuar.")
            return render(request, 'crear_participante.html', {'form': form, 'evento': evento})

        if es_grupo:
            # === Validación de Límite de Miembros Adicionales ===
            miembros_adicionales_enviados = 0
            i = 1
            while f'miembro_{i}_cedula' in request.POST:
                cedula_miembro = request.POST.get(f'miembro_{i}_cedula')
                # Contamos si los campos esenciales del miembro están presentes.
                if cedula_miembro and request.POST.get(f'miembro_{i}_nombre') and request.POST.get(f'miembro_{i}_email'):
                    miembros_adicionales_enviados += 1
                i += 1
            
            total_personas = 1 + miembros_adicionales_enviados # Líder (1) + Adicionales
            
            if total_personas > MAX_MIEMBROS_GRUPO:
                messages.error(request, f"El grupo excede el límite. El máximo permitido es de {MAX_MIEMBROS_GRUPO} personas (incluyendo al líder). Se detectaron {total_personas}.")
                return render(request, 'crear_participante.html', {'form': form, 'evento': evento})
        # ======================================================

        if form.is_valid():
            try:
                with transaction.atomic():
                    cedula_lider = str(form.cleaned_data['cedula']).strip()
                    contrasena_generada = None 
                    
                    # ----------------------------------------------------------------
                    # A. Lógica para el Participante Líder / Individual
                    # ----------------------------------------------------------------
                    usuario_existente = Usuario.objects.filter(cedula=cedula_lider).first()
                    participante_lider = None
                    usuario = None
                    
                    if usuario_existente:
                        # 1. 🛑 Validación de Roles Cruzados (Líder) 🛑
                        if AsistenteEvento.objects.filter(asi_eve_evento_fk=evento, asi_eve_asistente_fk__usuario=usuario_existente).exists():
                            messages.error(request, f"🚫 El líder ({cedula_lider}) ya está inscrito como ASISTENTE en este evento.")
                            return render(request, 'crear_participante.html', {'form': form, 'evento': evento})
                        if EvaluadorEvento.objects.filter(eva_eve_evento_fk=evento, eva_eve_evaluador_fk__usuario=usuario_existente).exists():
                            messages.error(request, f"🚫 El líder ({cedula_lider}) ya está inscrito como EVALUADOR en este evento.")
                            return render(request, 'crear_participante.html', {'form': form, 'evento': evento})
                        
                        # Intentar obtener perfil Participante
                        try:
                            participante_existente = usuario_existente.participante 
                        except Participante.DoesNotExist:
                            participante_existente = None

                        if participante_existente:
                            # Validar que no esté ya inscrito en este evento
                            if ParticipanteEvento.objects.filter(par_eve_participante_fk=participante_existente, par_eve_evento_fk=evento).exists():
                                messages.error(request, f"Ya existe un participante con la cédula {cedula_lider} registrado para el evento '{evento.eve_nombre}'.")
                                return render(request, 'crear_participante.html', {'form': form, 'evento': evento})
                            
                            # Usuario y Perfil Participante existen (Solo actualizar datos de usuario)
                            participante_lider = participante_existente
                            usuario = usuario_existente
                            
                            usuario.first_name = form.cleaned_data['first_name']
                            usuario.last_name = form.cleaned_data['last_name']
                            usuario.telefono = form.cleaned_data['telefono']
                            usuario.username = form.cleaned_data['username']
                            usuario.rol = Usuario.Roles.PARTICIPANTE # Asegura el rol
                            usuario.save(update_fields=['first_name', 'last_name', 'telefono', 'username', 'rol'])
                            
                        else:
                            # Usuario existe, pero NO tiene perfil de Participante (Crearlo)
                            usuario_existente.first_name = form.cleaned_data['first_name']
                            usuario_existente.last_name = form.cleaned_data['last_name']
                            usuario_existente.telefono = form.cleaned_data['telefono']
                            usuario_existente.username = form.cleaned_data['username']
                            usuario_existente.rol = Usuario.Roles.PARTICIPANTE
                            usuario_existente.save(update_fields=['first_name', 'last_name', 'telefono', 'username', 'rol'])
                            
                            participante_lider = Participante.objects.create(usuario=usuario_existente)
                            usuario = usuario_existente
                            
                    else:
                        # Usuario y Participante son COMPLETAMENTE nuevos (Creación total y generación de contraseña)
                        contrasena_generada = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
                        
                        usuario = Usuario.objects.create(
                            username=form.cleaned_data['username'],
                            first_name=form.cleaned_data['first_name'],
                            last_name=form.cleaned_data['last_name'],
                            email=form.cleaned_data['email'],
                            telefono=form.cleaned_data['telefono'],
                            is_active=True,
                            date_joined=localtime(now()),
                            rol=Usuario.Roles.PARTICIPANTE,
                            cedula=cedula_lider,
                        )
                        usuario.password = make_password(contrasena_generada)
                        usuario.save(update_fields=['password'])
                        
                        participante_lider = Participante.objects.create(usuario=usuario)

                    # ----------------------------------------------------------------
                    # B. Creación de ParticipanteEvento (Registro del Proyecto)
                    # ----------------------------------------------------------------
                    participante_evento_lider = ParticipanteEvento.objects.create(
                        par_eve_evento_fk=evento,
                        par_eve_participante_fk=participante_lider,
                        par_eve_estado="Pendiente",
                        par_eve_documentos=documento,
                        par_eve_es_grupo=es_grupo,
                        # par_eve_proyecto_principal y par_eve_codigo_proyecto se manejan en el modelo/default
                    )

                    codigo_proyecto = participante_evento_lider.par_eve_codigo_proyecto 
                    correos_enviados = [usuario.email]
                    
                    # Manejo de Grupo de Django (para permisos/etc.)
                    grupo_django = None
                    if es_grupo:
                        nombre_grupo = f"{evento.eve_nombre[:20].strip()}-{codigo_proyecto}"
                        grupo_django, _ = Group.objects.get_or_create(name=nombre_grupo)
                        usuario.groups.add(grupo_django)

                    # ----------------------------------------------------------------
                    # C. Lógica para Miembros Adicionales (Si es Grupal)
                    # ----------------------------------------------------------------
                    miembros_creados = []
                    if es_grupo:
                        i = 1
                        # Iterar sobre los posibles campos de miembros (miembro_1, miembro_2, etc.)
                        while f'miembro_{i}_cedula' in request.POST:
                            cedula_miembro = request.POST.get(f'miembro_{i}_cedula')
                            nombre_miembro = request.POST.get(f'miembro_{i}_nombre')     # <--- Campo de Nombre
                            apellido_miembro = request.POST.get(f'miembro_{i}_apellido') # <--- Campo de Apellido
                            email_miembro = request.POST.get(f'miembro_{i}_email')
                            telefono_miembro = request.POST.get(f'miembro_{i}_telefono', '')

                            # Usamos nombre_miembro y apellido_miembro por separado
                            if cedula_miembro and nombre_miembro and apellido_miembro and email_miembro:
                                cedula_miembro = str(cedula_miembro).strip()
                                
                                # A diferencia de antes, YA NO NECESITAS la lógica de separación de nombre/apellido 
                                # porque los estás recibiendo separados del formulario.
                                nombre = nombre_miembro.strip()
                                apellido = apellido_miembro.strip()

                                usuario_miembro_existente = Usuario.objects.filter(cedula=cedula_miembro).first()
                                contrasena_miembro = None 
                                
                                if usuario_miembro_existente:
                                    # 🛑 Validación de Roles Cruzados (Miembro) 🛑
                                    if AsistenteEvento.objects.filter(asi_eve_evento_fk=evento, asi_eve_asistente_fk__usuario=usuario_miembro_existente).exists():
                                        messages.error(request, f"🚫 El miembro ({cedula_miembro}) ya está inscrito como ASISTENTE en este evento.")
                                        raise Exception("Error de rol cruzado.")
                                    if EvaluadorEvento.objects.filter(eva_eve_evento_fk=evento, eva_eve_evaluador_fk__usuario=usuario_miembro_existente).exists():
                                        messages.error(request, f"🚫 El miembro ({cedula_miembro}) ya está inscrito como EVALUADOR en este evento.")
                                        raise Exception("Error de rol cruzado.")

                                    # Obtener/Crear Perfil Participante para el miembro
                                    try:
                                        participante_miembro_existente = usuario_miembro_existente.participante
                                    except Participante.DoesNotExist:
                                        participante_miembro_existente = None
                                    
                                    if participante_miembro_existente:
                                        # Validar que no esté ya inscrito en este evento
                                        if ParticipanteEvento.objects.filter(par_eve_participante_fk=participante_miembro_existente, par_eve_evento_fk=evento).exists():
                                            messages.error(request, f"El miembro ({cedula_miembro}) ya está registrado para el evento '{evento.eve_nombre}'.")
                                            raise Exception("Participante ya inscrito.")

                                        participante_miembro = participante_miembro_existente
                                        usuario_miembro = participante_miembro.usuario
                                        
                                        # Actualizar datos de Usuario Existente
                                        usuario_miembro.first_name = nombre 
                                        usuario_miembro.last_name = apellido
                                        usuario_miembro.telefono = telefono_miembro
                                        usuario_miembro.rol = Usuario.Roles.PARTICIPANTE
                                        usuario_miembro.save(update_fields=['first_name', 'last_name', 'telefono', 'rol'])
                                    else:
                                        # Usuario Existe, Crear Perfil Participante
                                        usuario_miembro = usuario_miembro_existente
                                        
                                        # Actualizar datos de Usuario Existente
                                        usuario_miembro.first_name = nombre 
                                        usuario_miembro.last_name = apellido
                                        usuario_miembro.telefono = telefono_miembro
                                        usuario_miembro.rol = Usuario.Roles.PARTICIPANTE
                                        usuario_miembro.save(update_fields=['first_name', 'last_name', 'telefono', 'rol'])
                                        
                                        participante_miembro = Participante.objects.create(usuario=usuario_miembro)
                                        
                                else:
                                    # Usuario y Participante son COMPLETAMENTE nuevos (Creación total y generación de contraseña)
                                    username_miembro = f"{nombre.lower()}{cedula_miembro[-4:]}"
                                    contador = 1
                                    username_original = username_miembro
                                    # Asegurar que el username es único
                                    while Usuario.objects.filter(username=username_miembro).exists():
                                        username_miembro = f"{username_original}{contador}"
                                        contador += 1
                                    
                                    contrasena_miembro = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
                                    
                                    usuario_miembro = Usuario.objects.create(
                                        username=username_miembro,
                                        first_name=nombre, 
                                        last_name=apellido, 
                                        email=email_miembro,
                                        telefono=telefono_miembro,
                                        is_active=True,
                                        date_joined=localtime(now()),
                                        rol=Usuario.Roles.PARTICIPANTE,
                                        cedula=cedula_miembro
                                    )
                                    usuario_miembro.password = make_password(contrasena_miembro)
                                    usuario_miembro.save(update_fields=['password'])

                                    participante_miembro = Participante.objects.create(usuario=usuario_miembro)

                                # Añadir a grupo de Django y ParticipanteEvento
                                if grupo_django:
                                    usuario_miembro.groups.add(grupo_django)

                                # Crear la relación ParticipanteEvento (miembro)
                                ParticipanteEvento.objects.create(
                                    par_eve_evento_fk=evento,
                                    par_eve_participante_fk=participante_miembro,
                                    par_eve_estado="Pendiente",
                                    par_eve_es_grupo=True,
                                    par_eve_proyecto_principal=participante_evento_lider,
                                    par_eve_codigo_proyecto=codigo_proyecto,
                                )

                                # Registrar datos del miembro para el correo de notificación
                                miembros_creados.append({
                                    'nombre': nombre, # Usamos solo el nombre para el saludo
                                    'nombre_completo': f"{nombre} {apellido}", # Para el saludo completo si se requiere
                                    'email': email_miembro,
                                    'password': contrasena_miembro
                                })
                                correos_enviados.append(email_miembro)

                            i += 1
                    
                    # ----------------------------------------------------------------
                    # D. Envío de Correos y Mensajes de Éxito
                    # ----------------------------------------------------------------
                    try:
                        # Correo para Líder/Individual
                        accion_lider = "generada" if contrasena_generada else "actual (la misma que ya usas)"
                        mensaje_lider = f"Hola {usuario.first_name} {usuario.last_name},\n\n" \
                                        f"Te has registrado correctamente como {'líder del grupo' if es_grupo else 'participante'} " \
                                        f"al evento \"{evento.eve_nombre}\".\n\n" \
                                        f"Código del proyecto: {codigo_proyecto}\n"
                        if es_grupo and grupo_django:
                            mensaje_lider += f"Grupo asignado: {grupo_django.name}\n"

                        mensaje_lider += f"Puedes ingresar con tu correo: {usuario.email}\n" \
                                         f"Tu contraseña es: {contrasena_generada if contrasena_generada else 'la que ya tenías'} "

                        send_mail(
                            subject=f"🎟️ Registro exitoso - Evento \"{evento.eve_nombre}\" - Líder/Participante",
                            message=mensaje_lider,
                            from_email=None,
                            recipient_list=[usuario.email],
                            fail_silently=False
                        )

                        # Correo para Miembros (si es grupo)
                        if es_grupo:
                            for miembro in miembros_creados:
                                accion_miembro = "generada" if miembro['password'] else "actual"
                                # Usamos 'nombre_completo' para el saludo del correo del miembro
                                mensaje_miembro = f"Hola {miembro['nombre_completo']},\n\n" \
                                                  f"Has sido registrado como miembro del grupo para el evento \"{evento.eve_nombre}\".\n\n" \
                                                  f"Código del proyecto: {codigo_proyecto}\n" \
                                                  f"Grupo asignado: {grupo_django.name}\n" \
                                                  f"Líder: {usuario.first_name} {usuario.last_name}\n" \
                                                  f"Puedes ingresar con tu correo: {miembro['email']}\n" \
                                                  f"Tu contraseña es: {miembro['password'] if miembro['password'] else 'la que ya tenías'} "
                                
                                send_mail(
                                    subject=f"🎟️ Registro exitoso - Evento \"{evento.eve_nombre}\" - Miembro del grupo",
                                    message=mensaje_miembro,
                                    from_email=None,
                                    recipient_list=[miembro['email']],
                                    fail_silently=False
                                )

                    except Exception as e:
                        messages.warning(request, f"Registro exitoso, pero hubo un problema al enviar algunos correos: {e}")

                    tipo_mensaje = "grupal" if es_grupo else "individual"
                    mensaje_exito = f"La preinscripción {tipo_mensaje} fue exitosa al evento \"{evento.eve_nombre}\". " \
                                    f"Código del proyecto: {codigo_proyecto}. " \
                                    f"Revisa {'los correos' if es_grupo else 'tu correo'} para obtener las credenciales."
                    messages.success(request, mensaje_exito)
                    return redirect('pagina_principal') # Redirección a la página principal (o la que corresponda)

            except Exception as e:
                # Si una excepción fue lanzada (como en el error de rol cruzado), el transaction.atomic() se encargará del rollback
                if not messages.get_messages(request): # Si no hay mensajes de error previos (como el de rol cruzado)
                    messages.error(request, f"Ocurrió un error grave durante el registro: {str(e)}")
                
                return render(request, 'crear_participante.html', {
                    'form': form,
                    'evento': evento,
                })

        # Si el formulario no es válido
        return render(request, 'crear_participante.html', {
            'form': form,
            'evento': evento,
        })




#Ocurrió un error grave durante el registro: cannot access local variable 'make_password' where it is not associated with a value


######## CANCELAR PREINSCRIPCION PARTICIPANTE ########

@method_decorator(participante_required, name='dispatch')
class EliminarParticipanteView(View):
    def get(self, request, participante_id):
        # Aseguramos que el ID del participante coincida con el usuario logueado por seguridad (aunque participante_required ya ayuda)
        participante = get_object_or_404(Participante, id=participante_id)
        usuario = participante.usuario

        # 🔹 Buscar todas las inscripciones del participante
        inscripciones = ParticipanteEvento.objects.filter(par_eve_participante_fk=participante)

        # 🔹 Verificar si tiene inscripciones activas (aprobadas)
        # Esto previene la eliminación del perfil si está activamente asignado a un evento.
        tiene_inscripciones_activas = inscripciones.filter(par_eve_estado="Aprobado").exists()
        if tiene_inscripciones_activas:
            messages.error(
                request,
                "❌ No puedes eliminar tu perfil de Exponente mientras tengas inscripciones activas. "
                "Por favor, cancela tus inscripciones antes de eliminar tu perfil."
            )
            return redirect('pagina_principal')


        # 🔹 Obtener el último evento inscrito (para referencia en el correo)
        ultimo_evento = inscripciones.first()
        nombre_evento = ultimo_evento.par_eve_evento_fk.eve_nombre if ultimo_evento else "uno de nuestros eventos"

        # 🔑 PASO 1: ELIMINAR LA RELACIÓN (Perfil) PARTICIPANTE
        # Esto elimina automáticamente todas las inscripciones en ParticipanteEvento (por CASCADE)
        participante.delete()
        

        # 🔹 Enviar correo
        if usuario.email:
             try:
                send_mail(
                    subject='🗑️ Notificación de eliminación de perfil como Exponente',
                    message=(
                        f'Estimado/a {usuario.first_name},\n\n'
                        f'Le informamos que su perfil de **Exponente** ha sido eliminado correctamente de Event-Soft.\n\n'
                        f'Todos sus datos de evaluación en eventos como "{nombre_evento}" '
                        f'han sido eliminados. **Su cuenta de usuario principal no ha sido eliminada**.\n\n'
                        f'Si desea volver a inscribirse como Exponente en el futuro, puede hacerlo usando su cuenta existente.\n\n'
                        f'Atentamente,\nEquipo de organización de eventos.'
                    ),
                    from_email=DEFAULT_FROM_EMAIL,
                    recipient_list=[usuario.email],
                    fail_silently=False
                )
             except Exception:
                 messages.warning(request, "El perfil de Exponente fue eliminado, pero no se pudo enviar el correo de notificación.")

        # 🔹 Cerrar sesión del usuario
        logout(request)

        messages.success(request, "✅ Tu perfil de Exponente y tus inscripciones han sido eliminadas correctamente. Hemos cerrado tu sesión.")
        return redirect('pagina_principal')




########### VER INFORMACIÓN EVENTO ###########
@method_decorator(participante_required, name='dispatch')
class EventoDetailView(DetailView):
    model = Evento
    template_name = 'info_evento_evento_par.html'
    context_object_name = 'evento'
    pk_url_kwarg = 'pk'
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        evento = self.get_object()
        participante_id = self.request.session.get('participante_id')
        
        # Verificar si el participante está asignado a este evento
        if participante_id:
            participante = get_object_or_404(Participante, id=participante_id)
            if not ParticipanteEvento.objects.filter(par_eve_participante_fk=participante, par_eve_evento_fk=evento).exists():
                messages.error(self.request, "No tienes permiso para ver este evento.")
                return redirect('pagina_principal')

        context['participante'] = participante if participante_id else None
        return context



######## DASHBOARD PARTICIPANTE ########

@method_decorator(participante_required, name='dispatch')
class DashboardParticipanteView(View):
    template_name = 'dashboard_principal_participante.html'

    def get(self, request):
        participante_id = request.session.get('participante_id')
        if not participante_id:
            messages.error(request, "Debe iniciar sesión como participante.")
            return redirect('login_view')

        try:
            # Seleccionamos el usuario para posibles validaciones futuras
            participante = Participante.objects.select_related('usuario').get(id=participante_id)
        except Participante.DoesNotExist:
            messages.error(request, "Participante no encontrado.")
            return redirect('login_view')

        # Relación participante-evento
        relaciones = ParticipanteEvento.objects.filter(
            par_eve_participante_fk=participante
        ).select_related('par_eve_evento_fk')

        # Separar eventos aprobados y pendientes
        eventos_aprobados = [
            rel.par_eve_evento_fk for rel in relaciones if rel.par_eve_estado == 'Aprobado'
        ]
        eventos_pendientes = [
            rel.par_eve_evento_fk for rel in relaciones if rel.par_eve_estado == 'Pendiente'
        ]

        # Diccionarios de datos
        criterios_completos = {}
        calificaciones_registradas = {}
        # 🔥 NUEVA VARIABLE: Indica si el proyecto es grupal (> 1 persona)
        es_miembro_de_proyecto_grupal = {} 

        for evento in eventos_aprobados:
            rel = ParticipanteEvento.objects.filter(
                par_eve_evento_fk=evento,
                par_eve_participante_fk=participante
            ).first()

            if rel:
                # ---------------------------------------------------------------------------------
                # LÓGICA CLAVE: Se muestra el botón si el proyecto tiene 2 o más integrantes
                
                if rel.par_eve_proyecto_principal is not None:
                    # Caso 1: Es un MIEMBRO (par_eve_proyecto_principal NO es NULL) -> Es GRUPO.
                    es_miembro_de_proyecto_grupal[evento.id] = True
                    
                else:
                    # Caso 2: Es el LÍDER (par_eve_proyecto_principal es NULL).
                    # Verificamos si tiene al menos UN miembro que apunte a él como principal.
                    
                    conteo_miembros_asociados = ParticipanteEvento.objects.filter(
                        par_eve_proyecto_principal=rel
                    ).count()
                    
                    # Si el líder tiene miembros asociados (> 0), es un proyecto grupal.
                    es_miembro_de_proyecto_grupal[evento.id] = (conteo_miembros_asociados > 0)
                
                # ---------------------------------------------------------------------------------
                
                # Lógica de Criterios y Calificaciones (se mantiene)
                suma = Criterio.objects.filter(cri_evento_fk=evento).aggregate(total=Sum('cri_peso'))['total'] or 0
                criterios_completos[evento.id] = (suma == 100)
                calificaciones_registradas[evento.id] = rel.calificacion is not None
            else:
                es_miembro_de_proyecto_grupal[evento.id] = False
                criterios_completos[evento.id] = False
                calificaciones_registradas[evento.id] = False


        # Obtener una relación para usar en la vista (si es necesario)
        relacion = relaciones.first() 

        context = {
            'participante': participante,
            'eventos': eventos_aprobados,
            'eventos_pendientes': eventos_pendientes,
            'relacion': relacion,
            'criterios_completos': criterios_completos,
            'calificaciones_registradas': calificaciones_registradas,
            # 🔥 VARIABLE DE CONTROL DE GRUPO ENVIADA AL CONTEXTO
            'es_miembro_de_proyecto_grupal': es_miembro_de_proyecto_grupal, 
        }

        return render(request, self.template_name, context)


##################### --- Cambio de Contraseña Participante --- #####################

@method_decorator(participante_required, name='dispatch')
class CambioPasswordParticipanteView(View):
    template_name = 'cambio_password_participante.html'

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 != password2:
            messages.error(request, "❌ Las contraseñas no coinciden.")
            return render(request, self.template_name)

        if len(password1) < 6:
            messages.error(request, "❌ La contraseña debe tener al menos 6 caracteres.")
            return render(request, self.template_name)

        participante_id = request.session.get('participante_id')
        participante = get_object_or_404(Participante, pk=participante_id)
        usuario = participante.usuario

        usuario.set_password(password1)
        usuario.last_login = timezone.now()  # ✅ Se actualiza solo aquí
        usuario.save()

        messages.success(request, "✅ Contraseña cambiada correctamente.")
        return redirect('dashboard_participante')

######### EDITAR PREINSCRIPCION PARTICIPANTE ########
# app_participantes/views.py
# VISTA ESPECÍFICA PARA HU15 - Editar clave del participante (Solo para los tests)

from django.shortcuts import render, redirect, get_object_or_404
from django.views import View
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.http import HttpResponseForbidden
from django.contrib import messages
from django.urls import reverse
from datetime import date
from app_participantes.models import ParticipanteEvento
from app_participantes.forms import ParticipanteEventoEditForm


@method_decorator(login_required, name='dispatch')
class EditarPreinscripcionView(View):
    """
    Vista para editar SOLO la clave de un participante en un evento.
    Esto es ESPECÍFICAMENTE para HU15 (Editar preinscripción).
    
    Restricciones:
    1. Usuario debe ser el propietario del registro
    2. Estado debe ser "Preinscrito"
    3. El evento debe estar activo (fecha_fin > hoy)
    4. Los FK (evento y participante) NO pueden cambiar
    
    IMPORTANTE: No confundir con la vista de edición completa de perfil+documentos
    que está en otro lugar.
    """
    
    def get(self, request, id):
        """Mostrar formulario simple para editar la clave."""
        registro = get_object_or_404(ParticipanteEvento, pk=id)
        
        # VALIDACIÓN 1: ¿Es el propietario?
        if registro.par_eve_participante_fk.usuario != request.user:
            messages.error(request, "No tienes permiso para editar este registro")
            return redirect('dashboard_participante')
        
        # VALIDACIÓN 2: ¿Estado es Preinscrito?
        if registro.par_eve_estado != "Preinscrito":
            messages.error(request, "Solo se pueden editar registros en estado Preinscrito")
            return redirect('dashboard_participante')
        
        # VALIDACIÓN 3: ¿Evento activo?
        if registro.par_eve_evento_fk.eve_fecha_fin < date.today():
            messages.error(request, "No se pueden editar registros de eventos terminados")
            return redirect('dashboard_participante')
        
        form = ParticipanteEventoEditForm(instance=registro)
        context = {
            'form': form,
            'registro': registro,
            'evento': registro.par_eve_evento_fk
        }
        return render(request, 'app_participantes/editar_clave_preinscripcion.html', context)
    
    def post(self, request, id):
        """Procesar la edición de la clave."""
        registro = get_object_or_404(ParticipanteEvento, pk=id)
        
        # ===== VALIDACIONES DE SEGURIDAD =====
        
        # VALIDACIÓN 1: ¿Es el propietario?
        if registro.par_eve_participante_fk.usuario != request.user:
            messages.error(request, "No tienes permiso para editar este registro")
            return redirect('dashboard_participante')
        
        # VALIDACIÓN 2: ¿Estado es Preinscrito?
        if registro.par_eve_estado != "Preinscrito":
            messages.error(request, "Solo se pueden editar registros en estado Preinscrito")
            return redirect('dashboard_participante')
        
        # VALIDACIÓN 3: ¿Evento activo?
        if registro.par_eve_evento_fk.eve_fecha_fin < date.today():
            messages.error(request, "No se pueden editar registros de eventos terminados")
            return redirect('dashboard_participante')
        
        # Guardar referencias originales
        evento_original = registro.par_eve_evento_fk
        participante_original = registro.par_eve_participante_fk
        
        # Procesar formulario
        form = ParticipanteEventoEditForm(request.POST, instance=registro)
        
        if form.is_valid():
            # Proteger los FK
            form.instance.par_eve_evento_fk = evento_original
            form.instance.par_eve_participante_fk = participante_original
            
            # ✅ GUARDAR CAMBIOS
            form.save()
            
            messages.success(request, "Clave actualizada exitosamente")
            return redirect('dashboard_participante')
        else:
            # Si hay errores, mostrar el formulario nuevamente
            context = {
                'form': form,
                'registro': registro,
                'evento': registro.par_eve_evento_fk,
            }
            return render(request, 'app_participantes/editar_preinscripcion_participante.html', context)
    
    def post(self, request, id):
        """Procesar la edición de la clave."""
        registro = get_object_or_404(ParticipanteEvento, pk=id)
        
        # ===== VALIDACIONES DE SEGURIDAD =====
        
        # VALIDACIÓN 1: ¿Es el propietario?
        if registro.par_eve_participante_fk.usuario != request.user:
            messages.error(request, "No tienes permiso para editar este registro")
            return redirect('dashboard_participante')
        
        # VALIDACIÓN 2: ¿Estado es Preinscrito?
        if registro.par_eve_estado != "Preinscrito":
            messages.error(request, "Solo se pueden editar registros en estado Preinscrito")
            return redirect('dashboard_participante')
        
        # VALIDACIÓN 3: ¿Evento activo?
        if registro.par_eve_evento_fk.eve_fecha_fin < date.today():
            messages.error(request, "No se pueden editar registros de eventos terminados")
            return redirect('dashboard_participante')
        
        # Guardar referencias originales
        evento_original = registro.par_eve_evento_fk
        participante_original = registro.par_eve_participante_fk
        
        # Procesar formulario
        form = ParticipanteEventoEditForm(request.POST, instance=registro)
        
        if form.is_valid():
            # Proteger los FK
            form.instance.par_eve_evento_fk = evento_original
            form.instance.par_eve_participante_fk = participante_original
            
            # ✅ GUARDAR CAMBIOS
            form.save()
            
            messages.success(request, "Clave actualizada exitosamente")
            return redirect('dashboard_participante')
        else:
            # Si hay errores, mostrar el formulario nuevamente
            context = {
                'form': form,
                'registro': registro,
                'evento': registro.par_eve_evento_fk,
            }
            return render(request, 'app_participantes/editar_preinscripcion_simple.html', context)


####### ACCESO A EVENTO ######
@method_decorator(participante_required, name='dispatch')
class IngresoEventoParticipanteView(View):
    template_name = 'ingreso_evento_par.html'

    def get(self, request, pk):
        evento = get_object_or_404(Evento, pk=pk)
        participante = get_object_or_404(Participante, usuario=request.user)
        participante_evento = get_object_or_404(ParticipanteEvento, par_eve_evento_fk=evento, par_eve_participante_fk=participante)

        context = {
            'evento': evento,
            'participante': participante_evento  # este es el objeto que tiene el QR y el soporte
        }
        return render(request, self.template_name, context)
  


####### VER CRITERIOS ######
# En app_participantes/views.py
# Busca la vista VerCriteriosParticipanteView y actualízala:

@method_decorator(participante_required, name='dispatch')
class VerCriteriosParticipanteView(View):
    """
    Vista para que los participantes vean los criterios de evaluación del evento.
    Solo participantes inscritos y aprobados pueden acceder.
    """
    template_name = 'ver_criterios_par.html'  # O el nombre que uses

    def get(self, request, evento_id):
        evento = get_object_or_404(Evento, pk=evento_id)
        
        # Obtener el participante de la sesión
        participante_id = request.session.get('participante_id')
        
        if not participante_id:
            messages.error(request, 'No se encontró información del participante.')
            return redirect('dashboard_participante')
        
        # Obtener el participante
        try:
            participante = Participante.objects.get(id=participante_id)
        except Participante.DoesNotExist:
            messages.error(request, 'Participante no encontrado.')
            return redirect('dashboard_participante')
        
        # VALIDACIÓN CRÍTICA: Verificar que el participante esté inscrito en el evento
        try:
            from app_participantes.models import ParticipanteEvento
            registro_participante = ParticipanteEvento.objects.get(
                par_eve_participante_fk=participante,
                par_eve_evento_fk=evento
            )
        except ParticipanteEvento.DoesNotExist:
            messages.error(
                request,
                'No estás inscrito en este evento. Solo los participantes inscritos pueden ver los criterios.'
            )
            return redirect('dashboard_participante')
        
        # VALIDACIÓN: Verificar que el participante esté aprobado
        if registro_participante.par_eve_estado != 'Aprobado':
            messages.warning(
                request,
                'Tu inscripción aún no ha sido aprobada. Los criterios estarán disponibles una vez que seas aprobado.'
            )
            return redirect('dashboard_participante')
        
        # Obtener los criterios del evento
        from app_admin_eventos.models import Criterio
        criterios = Criterio.objects.filter(cri_evento_fk=evento).order_by('cri_descripcion')
        
        # Si todas las validaciones pasan, mostrar los criterios
        context = {
            'evento': evento,
            'criterios': criterios,
            'participante': participante,
        }
        
        return render(request, self.template_name, context)


####### VER CALIFICACIÓN ######
@method_decorator(participante_required, name='dispatch')
class VerCalificacionView(View):
    template_name = 'ver_notas.html'

    def get(self, request, evento_id):
        participante_id = request.session.get('participante_id')
        participante = get_object_or_404(Participante, pk=participante_id)
        evento = get_object_or_404(Evento, pk=evento_id)

        # Obtener relación del participante con el evento
        relacion = get_object_or_404(
            ParticipanteEvento,
            par_eve_evento_fk=evento,
            par_eve_participante_fk=participante
        )

        # Calificación del participante actual
        calificacion = relacion.calificacion

        # Obtener todos los participantes con calificación para este evento (para ranking)
        relaciones = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=evento,
            calificacion__isnull=False
        ).select_related('par_eve_participante_fk__usuario').order_by('-calificacion')

        puesto_actual = None
        for index, rel in enumerate(relaciones, start=1):
            if rel.par_eve_participante_fk.pk == participante.pk:
                puesto_actual = index
                break

        context = {
            'evento': evento,
            'participante': participante,
            'nombre_limpio': participante.usuario.first_name,
            'apellido_limpio': participante.usuario.last_name,
            'calificacion': calificacion,
            'puesto_actual': puesto_actual,
        }
        return render(request, self.template_name, context)

####### VER DETALLE CALIFICACIÓN ######
@method_decorator(participante_required, name='dispatch')
class DetalleCalificacionView(View):
    template_name = 'ver_detalle_calificacion.html'

    def get(self, request, evento_id):
        participante_id = request.session.get('participante_id')
        participante = get_object_or_404(Participante, pk=participante_id)
        evento = get_object_or_404(Evento, id=evento_id)

        participante_evento = get_object_or_404(
            ParticipanteEvento,
            par_eve_evento_fk=evento,
            par_eve_participante_fk=participante
        )

        calificaciones = Calificacion.objects.filter(
            cal_participante_fk=participante,
            cal_criterio_fk__cri_evento_fk=evento
        ).select_related('cal_criterio_fk', 'cal_evaluador_fk')

        context = {
            'participante': participante,
            'evento': evento,
            'participante_evento': participante_evento,
            'calificaciones': calificaciones,
        }
        return render(request, self.template_name, context)
    
####### VER MEMORIAS DE PARTICIPANTE ######
@method_decorator(login_required, name='dispatch')
class MemoriasParticipanteView(View):
    def get(self, request, evento_id):
        evento = get_object_or_404(Evento, id=evento_id)
        # Verificar inscripción como participante
        inscrito = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=evento,
            par_eve_participante_fk__usuario=request.user
        ).exists()
        if not inscrito:
            messages.error(request, "❌ No estás inscrito como participante en este evento.")
            return redirect('dashboard_user')
        memorias = MemoriaEvento.objects.filter(evento=evento).order_by('-subido_en')
        return render(request, 'memorias_participante.html', {'evento': evento, 'memorias': memorias})

@method_decorator(login_required, name='dispatch')
class ParticipanteCancelacionView(View):
    """
    Vista para que un participante cancele su inscripción a un evento.
    - Solo permite cancelar si el estado es "Preinscrito"
    - No permite cancelar si está "Aprobado"
    - Maneja grupos: si es líder, cancela a todos los miembros
    """

    def post(self, request, evento_id):
        """
        Permite al participante cancelar su inscripción al evento.
        """
        # 1. Obtener el participante logueado
        try:
            participante = request.user.participante
        except Participante.DoesNotExist:
            messages.error(request, "No estás registrado como participante.")
            return redirect('dashboard_participante')

        # 2. Obtener el evento
        evento = Evento.objects.filter(pk=evento_id).first()
        if not evento:
            messages.error(request, "Evento no encontrado.")
            return redirect('dashboard_participante')

        # 3. Obtener la inscripción del participante en este evento
        inscripcion = ParticipanteEvento.objects.filter(
            par_eve_participante_fk=participante,
            par_eve_evento_fk=evento
        ).select_related('par_eve_evento_fk').first()

        if not inscripcion:
            messages.error(request, "No tienes una inscripción activa en este evento.")
            return redirect('dashboard_participante')

        # 4. ⛔ VALIDACIÓN CRÍTICA: No permitir cancelar si está "Aprobado"
        if inscripcion.par_eve_estado.upper() == 'APROBADO':
            messages.error(
                request,
                f"❌ No puedes cancelar tu inscripción al evento '{evento.eve_nombre}' "
                f"porque ya fue aprobada. Contacta a los organizadores del evento."
            )
            return redirect('dashboard_participante')

        # 5. Si ya estaba cancelada
        if inscripcion.par_eve_estado.upper() == 'CANCELADO':
            messages.warning(request, "⚠️ Esta inscripción ya se encuentra cancelada.")
            return redirect('dashboard_participante')

        # 6. Proceder a cancelar
        with transaction.atomic():
            # Verificar si es líder de grupo
            es_lider = (inscripcion.par_eve_es_grupo == True and 
                       inscripcion.par_eve_proyecto_principal is None)

            if es_lider:
                # Caso: LÍDER DE GRUPO -> Cancelar al líder y todos los miembros
                miembros = ParticipanteEvento.objects.filter(
                    par_eve_proyecto_principal=inscripcion
                ).exclude(id=inscripcion.id)

                # Cancelar a todos los miembros
                for miembro in miembros:
                    if miembro.par_eve_estado.upper() != 'CANCELADO':
                        miembro.par_eve_estado = 'Cancelado'
                        miembro.save(update_fields=['par_eve_estado'])

                # Cancelar al líder
                inscripcion.par_eve_estado = 'Cancelado'
                inscripcion.save(update_fields=['par_eve_estado'])

                messages.success(
                    request,
                    f"✅ Tu proyecto en el evento '{evento.eve_nombre}' ha sido cancelado. "
                    f"Todos los miembros han sido notificados."
                )
            else:
                # Caso: PARTICIPANTE INDIVIDUAL o MIEMBRO DE GRUPO
                inscripcion.par_eve_estado = 'Cancelado'
                inscripcion.save(update_fields=['par_eve_estado'])

                messages.success(
                    request,
                    f"✅ Tu inscripción al evento '{evento.eve_nombre}' ha sido cancelada."
                )

        # 7. Redirigir al dashboard del participante
        return redirect('dashboard_participante')
    





############# AGREGAR MIEMBROS ################
@method_decorator(login_required, name='dispatch') 
class AgregarMiembrosView(View):
    template_name = 'agregar_miembros.html'
    
    # Máximo permitido de miembros en un grupo (incluido el líder)
    MAX_MIEMBROS = 5

    def get(self, request, evento_id):
        participante_lider_id = request.session.get('participante_id')
        if not participante_lider_id:
            messages.error(request, "Error de sesión. No se encontró el ID del líder.")
            return redirect('login_view')

        lider = get_object_or_404(Participante, id=participante_lider_id)
        evento = get_object_or_404(Evento, id=evento_id)
        
        # Obtener el registro principal del LÍDER (es_grupo=1 y principal=NULL)
        relacion_lider = get_object_or_404(
            ParticipanteEvento, 
            par_eve_participante_fk=lider, 
            par_eve_evento_fk=evento,
            par_eve_es_grupo=1, 
            par_eve_proyecto_principal__isnull=True 
        )
        
        # Contar miembros: (Miembros que apuntan al líder) + 1 (el líder)
        miembros_actuales = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=evento,
            par_eve_proyecto_principal=relacion_lider
        ).count() + 1 
        
        if miembros_actuales >= self.MAX_MIEMBROS:
            messages.error(request, f"El grupo del evento {evento.eve_nombre} ya alcanzó el máximo de {self.MAX_MIEMBROS} miembros.")
            return redirect('dashboard_participante')
            
        form = MiembroParticipanteForm() 
        
        return render(request, self.template_name, {
            'form': form,
            'evento': evento,
            'miembros_actuales': miembros_actuales,
            'max_miembros': self.MAX_MIEMBROS,
        })

    def post(self, request, evento_id):
        evento = get_object_or_404(Evento, id=evento_id)
        participante_lider_id = request.session.get('participante_id')
        lider = get_object_or_404(Participante, id=participante_lider_id)
        
        # Obtener el registro principal del LÍDER
        relacion_lider = get_object_or_404(
            ParticipanteEvento, 
            par_eve_participante_fk=lider, 
            par_eve_evento_fk=evento,
            par_eve_es_grupo=1, 
            par_eve_proyecto_principal__isnull=True 
        )
        
        miembros_actuales = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=evento,
            par_eve_proyecto_principal=relacion_lider
        ).count() + 1
        
        if miembros_actuales >= self.MAX_MIEMBROS:
            messages.error(request, f"El grupo del evento {evento.eve_nombre} ya alcanzó el máximo de {self.MAX_MIEMBROS} miembros.")
            return redirect('dashboard_participante')

        form = MiembroParticipanteForm(request.POST)

        if form.is_valid():
            cedula = form.cleaned_data['cedula']
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            telefono = form.cleaned_data['telefono']

            # 1. Validación de unicidad de Usuario
            if Usuario.objects.filter(cedula=cedula).exists() or \
               Usuario.objects.filter(username=username).exists() or \
               Usuario.objects.filter(email=email).exists():
                messages.error(request, "Error: Cédula, nombre de usuario o correo ya existen.")
                return redirect('agregar_miembro_par', evento_id=evento_id)

            contrasena_temporal = get_random_string(length=10)
            
            try:
                with transaction.atomic():
                    # 1. Crear el nuevo Usuario con el rol establecido
                    nuevo_usuario = Usuario.objects.create(
                        cedula=cedula,
                        username=username,
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                        telefono=telefono,
                        is_active=True,
                        password=make_password(contrasena_temporal),
                        last_login=None,
                        rol='PARTICIPANTE'  # Rol fijo para miembros
                    )
                    
                    # 2. Asignar el nuevo Usuario al Grupo del Evento (app_usuarios_usuario_groups)
                    codigo_proyecto = relacion_lider.par_eve_codigo_proyecto 
                    
                    # Búsqueda robusta por el código de proyecto
                    evento_group = Group.objects.filter(name__icontains=codigo_proyecto).first()
                    
                    if not evento_group:
                         raise Group.DoesNotExist(f"No se encontró el grupo de Django cuyo nombre contiene el código de proyecto: {codigo_proyecto}. Por favor, verifique la tabla auth_group.")

                    nuevo_usuario.groups.add(evento_group) # CREA LA RELACIÓN

                    # 3. Crear el registro de Participante
                    nuevo_participante = Participante.objects.create(
                        usuario=nuevo_usuario
                    )
                    
                    # 4. Crear el registro en ParticipanteEvento para el MIEMBRO (CORREGIDO)
                    nueva_relacion = ParticipanteEvento(
                        par_eve_participante_fk=nuevo_participante,
                        par_eve_evento_fk=evento,
                        par_eve_estado='Aprobado',
                        
                        # --- CORRECCIONES SOLICITADAS ---
                        par_eve_es_grupo=0, # 0 para miembros
                        par_eve_proyecto_principal=relacion_lider, # Apunta al ID del líder
                        par_eve_codigo_proyecto=None, # Solo el líder tiene el código
                        # --------------------------------
                    )

                    # Lógica de generación de CLAVE y QR
                    clave_acceso = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
                    nueva_relacion.par_eve_clave = clave_acceso
                    qr_data = f"Participante: {nuevo_usuario.username}, Evento: {evento.eve_nombre}, Clave: {clave_acceso}"
                    qr_img = qrcode.make(qr_data)
                    buffer = BytesIO()
                    qr_img.save(buffer, format='PNG')
                    file_name = f"qr_participante_{nuevo_participante.id}.png"
                    nueva_relacion.par_eve_qr.save(file_name, ContentFile(buffer.getvalue()), save=False)
                    nueva_relacion.save()

                # 5. Envío de correo electrónico
                try:
                    qr_file_path = nueva_relacion.par_eve_qr.path 
                    send_mail_participante_grupo(
                        to_email=nuevo_usuario.email,
                        event_name=evento.eve_nombre,
                        group_name='Participante', 
                        username=nuevo_usuario.username,
                        password=contrasena_temporal,
                        clave_acceso=clave_acceso,
                        qr_file_path=qr_file_path
                    )
                    messages.success(request, f"Miembro **{nuevo_usuario.username}** agregado y correo de bienvenida enviado. 🎉")
                except Exception as e:
                    messages.warning(request, f"Miembro **{nuevo_usuario.username}** agregado. ¡PERO! Hubo un error al enviar el correo. Verifique la configuración. 📧")
                    
                return redirect('dashboard_participante')

            except Group.DoesNotExist as e:
                messages.error(request, f"Error de configuración de Grupo: {e}")
                return redirect('agregar_miembro_par', evento_id=evento_id)
            except Exception as e:
                messages.error(request, f"Ocurrió un error al guardar el miembro: {e}")
                return redirect('agregar_miembro_par', evento_id=evento_id)
        
        # Si el formulario no es válido, renderizar de nuevo con errores
        miembros_actuales = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=evento,
            par_eve_proyecto_principal=relacion_lider
        ).count() + 1
        
        return render(request, self.template_name, {
            'form': form,
            'evento': evento,
            'miembros_actuales': miembros_actuales,
            'max_miembros': self.MAX_MIEMBROS,
        })


@method_decorator(login_required, name='dispatch') 
class ListaMiembrosView(View):
    template_name = 'lista_miembros.html'
    MAX_MIEMBROS = 5

    def _get_context_data(self, request, evento_id):
        # ... (La función auxiliar _get_context_data se mantiene sin cambios) ...
        participante_logueado_id = request.session.get('participante_id')
        if not participante_logueado_id:
            return None, None, None, None, "Error de sesión. No se encontró el ID del participante logueado."

        participante = get_object_or_404(Participante, id=participante_logueado_id)
        evento = get_object_or_404(Evento, id=evento_id)

        try:
            relacion_participante = ParticipanteEvento.objects.get(
                par_eve_participante_fk=participante, 
                par_eve_evento_fk=evento,
            )
        except ParticipanteEvento.DoesNotExist:
            return None, None, None, None, "No estás registrado como participante en este evento."

        if relacion_participante.par_eve_es_grupo == 1 and relacion_participante.par_eve_proyecto_principal is None:
            es_lider = True
            relacion_lider = relacion_participante
        elif relacion_participante.par_eve_es_grupo == 0 and relacion_participante.par_eve_proyecto_principal is not None:
            es_lider = False
            relacion_lider = relacion_participante.par_eve_proyecto_principal
        else:
            return None, None, None, None, "Si quieres crear un grupo, te recomendamos preinscribirte nuevamente con un grupo a este evento."

        miembros_del_grupo = ParticipanteEvento.objects.filter(
            Q(par_eve_evento_fk=evento) &
            (Q(par_eve_proyecto_principal=relacion_lider) | Q(id=relacion_lider.id))
        ).select_related('par_eve_participante_fk__usuario').order_by('-par_eve_es_grupo', 'par_eve_participante_fk__usuario__first_name') 
        
        miembros_actuales = miembros_del_grupo.count()
        
        miembros_a_borrar = [
            rel for rel in miembros_del_grupo if rel.par_eve_es_grupo == 0
        ]
        
        context = {
            'evento': evento,
            'relacion_lider': relacion_lider,
            'es_lider': es_lider, 
            'miembros': miembros_del_grupo,
            'miembros_a_borrar': miembros_a_borrar,
            'miembros_actuales': miembros_actuales,
            'max_miembros': self.MAX_MIEMBROS,
        }
        return context, participante, relacion_lider, es_lider, None
    # ----------------------------------------------------------------------------------

    def get(self, request, evento_id):
        # ... (get se mantiene igual) ...
        context, _, _, _, error_msg = self._get_context_data(request, evento_id)
        
        if error_msg:
            messages.error(request, error_msg)
            return redirect('dashboard_participante')
            
        return render(request, self.template_name, context)

    
    def post(self, request, evento_id):
        action = request.POST.get('action', 'eliminar')
        miembro_id_objetivo = request.POST.get('miembro_id')

        # ... (Validaciones iniciales de miembro_id, contexto, y es_lider se mantienen) ...
        if not miembro_id_objetivo:
            messages.error(request, "No se especificó el miembro objetivo.")
            return redirect('ver_miembros_par', evento_id=evento_id)

        context, _, relacion_lider_actual, es_lider, error_msg = self._get_context_data(request, evento_id)
        
        if error_msg:
            messages.error(request, error_msg)
            return redirect('dashboard_participante')
        
        if not es_lider:
            messages.error(request, "Solo el líder del grupo puede realizar esta acción.")
            return redirect('ver_miembros_par', evento_id=evento_id)

        # 1. Buscar la relación ParticipanteEvento del miembro objetivo
        try:
            relacion_miembro_objetivo = ParticipanteEvento.objects.get(
                id=miembro_id_objetivo,
                par_eve_proyecto_principal=relacion_lider_actual, 
                par_eve_es_grupo=0 # Debe ser un miembro
            )
        except ParticipanteEvento.DoesNotExist:
            messages.error(request, "El miembro no existe o no pertenece a tu grupo.")
            return redirect('ver_miembros_par', evento_id=evento_id)
        
        usuario_miembro = relacion_miembro_objetivo.par_eve_participante_fk.usuario
        nombre_miembro = f"{usuario_miembro.first_name} {usuario_miembro.last_name} ({usuario_miembro.username})"

        # -----------------------------------------------------------------
        # LÓGICA DE ELIMINAR MIEMBRO (Se mantiene igual)
        # -----------------------------------------------------------------
        if action == 'eliminar':
            # ... (Lógica de eliminación anterior) ...
            try:
                with transaction.atomic():
                    relacion_miembro_objetivo.delete()
                    relacion_miembro_objetivo.par_eve_participante_fk.usuario.delete() 
                    messages.success(request, f"El miembro **{usuario_miembro.first_name}** ha sido eliminado del grupo. 🗑️")
            except Exception as e:
                messages.error(request, f"Error al intentar eliminar al miembro: {e}")
            
            return redirect('ver_miembros_par', evento_id=evento_id)

        # -----------------------------------------------------------------
        # LÓGICA DE TRANSFERIR LIDERAZGO (CORREGIDA Y OPTIMIZADA)
        # -----------------------------------------------------------------
        elif action == 'transferir_liderazgo':
            try:
                with transaction.atomic():
                    
                    # El registro del LÍDER ACTUAL es 'relacion_lider_actual'
                    # El registro del NUEVO LÍDER es 'relacion_miembro_objetivo'
                    
                    # 1. Capturar los datos del proyecto del líder actual (código y documentos)
                    codigo_proyecto_antiguo = relacion_lider_actual.par_eve_codigo_proyecto
                    documentos_antiguos = getattr(relacion_lider_actual, 'par_eve_documentos', None) 

                    # 2. Promover al Miembro a Líder (Nuevo Líder)
                    # NOTA: Guardamos los cambios de liderazgo/código/documentos antes
                    # de actualizar a los demás miembros en el paso 4.
                    relacion_miembro_objetivo.par_eve_es_grupo = 1
                    relacion_miembro_objetivo.par_eve_proyecto_principal = None # El líder no tiene principal
                    relacion_miembro_objetivo.par_eve_codigo_proyecto = codigo_proyecto_antiguo # HEREDA CÓDIGO
                    relacion_miembro_objetivo.par_eve_documentos = documentos_antiguos # HEREDA DOCUMENTOS
                    relacion_miembro_objetivo.save() 
                    
                    # 3. Degradar al Líder Actual a Miembro (Antiguo Líder)
                    relacion_lider_actual.par_eve_es_grupo = 0
                    relacion_lider_actual.par_eve_proyecto_principal = relacion_miembro_objetivo # APUNTA al NUEVO LÍDER
                    relacion_lider_actual.par_eve_codigo_proyecto = None # CÓDIGO A NULL
                    relacion_lider_actual.par_eve_documentos = None # DOCUMENTOS A NULL
                    relacion_lider_actual.save()
                    
                    # 4. 🔥 CRUCIAL: Actualizar a TODOS los miembros restantes para que apunten al NUEVO líder.
                    # Se excluye al nuevo líder (ya está actualizado en el paso 2 y su principal es NULL).
                    # Se incluye al líder saliente (ya está actualizado en el paso 3 y su principal es el nuevo líder).
                    evento = relacion_lider_actual.par_eve_evento_fk  # Obtener el evento desde la relación del líder actual
                    ParticipanteEvento.objects.filter(
                        par_eve_evento_fk=evento,
                        par_eve_proyecto_principal=relacion_lider_actual # Apuntaban al antiguo líder
                    ).exclude(
                        id=relacion_miembro_objetivo.id # Excluye al nuevo líder (aunque ya tiene principal=NULL)
                    ).update(
                        par_eve_proyecto_principal=relacion_miembro_objetivo # ¡Asignan el nuevo líder!
                    )
                    
                    # NOTA: La lógica se puede simplificar en el paso 4 para actualizar todos
                    # los que apuntaban al antiguo líder, incluyendo al antiguo líder
                    # si no lo hubiéramos actualizado en el paso 3. Pero tal como está, 
                    # ya el paso 3 se encarga del antiguo líder y el paso 4 de los miembros.
                    # Mantenemos esta estructura explícita para mayor claridad de la transición.

                    messages.success(request, f"El liderazgo se ha transferido exitosamente a **{usuario_miembro.first_name}**. Ahora eres un miembro del proyecto. ✨")
                    
                return redirect('ver_miembros_par', evento_id=evento_id)

            except Exception as e:
                messages.error(request, f"Error al transferir el liderazgo: {e}")
                return redirect('ver_miembros_par', evento_id=evento_id)
        
        # -----------------------------------------------------------------
        
        messages.error(request, "Acción desconocida.")
        return redirect('ver_miembros_par', evento_id=evento_id)


