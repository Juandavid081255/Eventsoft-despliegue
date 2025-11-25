from typing import Counter
from django.utils.timezone import now
from django.utils import timezone
import re
from django.contrib import messages
from django.shortcuts import render
from django.shortcuts import redirect, get_object_or_404
from django.views import View
from django.core.mail import send_mail
from app_participantes.models import ParticipanteEvento
from app_usuarios.models import Evaluador, Participante, Usuario
from principal_eventos.settings import DEFAULT_FROM_EMAIL
from .models import Calificacion, EvaluadorEvento
from app_admin_eventos.models import Area, Categoria, Criterio, Evento
from app_asistentes.models import AsistenteEvento
from .forms import EvaluadorForm, EditarUsuarioEvaluadorForm
from django.views.generic import DetailView, ListView
from django.db.models import Q
from django.db.models import Exists, OuterRef
from django.utils.timezone import now, localtime
import random
import string
from django.contrib.auth.hashers import make_password , check_password
from django.utils.decorators import method_decorator
from principal_eventos.decorador import evaluador_required, visitor_required
from django.db import models
from django.db.models import Q, Sum
from django.contrib.auth.decorators import login_required
from app_admin_eventos.models import Evento, MemoriaEvento
from django.conf import settings
from django.contrib.auth import logout
from django.db import transaction
# AGREGAR ESTAS FUNCIONES AL FINAL DE app_evaluadores/views.py

from django.shortcuts import get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse
from app_evaluadores.models import EvaluadorEvento
from app_admin_eventos.models import Evento
from app_usuarios.models import AdministradorEvento
import qrcode
from io import BytesIO
from django.core.files.base import ContentFile
import uuid


def guardar_qr_evaluador(evaluador_evento):
    """
    Genera un código QR para un evaluador en un evento.
    
    El QR contiene:
    - ID del evento
    - ID del evaluador
    - Clave de acceso
    
    Args:
        evaluador_evento: Instancia de EvaluadorEvento
    
    Returns:
        bool: True si se generó correctamente, False en caso de error
    """
    try:
        # Crear datos para el QR
        evento_id = evaluador_evento.eva_eve_evento_fk.pk
        evaluador_id = evaluador_evento.eva_eve_evaluador_fk.usuario.pk
        clave = evaluador_evento.eva_eve_clave
        
        # Crear string con información del QR
        datos_qr = f"EVENTO:{evento_id}|EVALUADOR:{evaluador_id}|CLAVE:{clave}"
        
        # Generar código QR
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(datos_qr)
        qr.make(fit=True)
        
        # Crear imagen PNG
        img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
        
        # Convertir a bytes
        img_bytes = BytesIO()
        img.save(img_bytes, format='PNG')
        img_bytes.seek(0)
        
        # Crear nombre de archivo único
        nombre_archivo = f"qr_eva_{evaluador_evento.pk}_{uuid.uuid4().hex[:8]}.png"
        
        # Guardar en el modelo
        evaluador_evento.eva_eve_qr.save(
            nombre_archivo,
            ContentFile(img_bytes.getvalue()),
            save=True
        )
        
        print(f"✓ QR generado correctamente para evaluador {evaluador_evento.pk}")
        return True
        
    except Exception as e:
        print(f"✗ Error al generar QR: {str(e)}")
        import traceback
        traceback.print_exc()
        return False



@login_required
@require_http_methods(["POST"])
def aprobar_eva(request, evento_id, evaluador_evento_id):
    """
    Aprueba un evaluador para un evento.
    Solo el administrador del evento puede aprobar.
    
    HU33: Cambiar estado a Aprobado y notificar
    HU34: Incluir clave de acceso en el email
    HU35: Generar y enviar QR
    """
    try:
        evento = get_object_or_404(Evento, pk=evento_id)
        evaluador_evento = get_object_or_404(
            EvaluadorEvento, 
            pk=evaluador_evento_id, 
            eva_eve_evento_fk=evento
        )
        
        # Verificar que el usuario sea admin del evento
        try:
            admin_evento = AdministradorEvento.objects.get(usuario=request.user)
            if evento.eve_administrador_fk != admin_evento:
                return redirect('dashboard_evaluador')
        except AdministradorEvento.DoesNotExist:
            return redirect('login')
        
        # Cambiar estado a Aprobado
        evaluador_evento.eva_eve_estado = "Aprobado"
        evaluador_evento.save()
        
        # Generar QR (HU35)
        qr_generado = guardar_qr_evaluador(evaluador_evento)
        
        # Refrescar para obtener el QR guardado
        evaluador_evento.refresh_from_db()
        
        # Obtener la clave de acceso
        usuario_evaluador = evaluador_evento.eva_eve_evaluador_fk.usuario
        clave_acceso = evaluador_evento.eva_eve_clave
        
        # Crear mensaje CON LA CLAVE (HU34)
        mensaje = (
            f"Hola {usuario_evaluador.first_name},\n\n"
            f"Ha sido aprobado como evaluador para el evento:\n"
            f"{evento.eve_nombre}\n\n"
            f"Fecha: {evento.eve_fecha_inicio} a {evento.eve_fecha_fin}\n"
            f"Lugar: {evento.eve_lugar}\n\n"
            f"CLAVE DE ACCESO: {clave_acceso}\n\n"
            f"Utilice esta clave para acceder a los recursos del evento.\n"
            f"No comparta esta clave con otros usuarios.\n\n"
            f"Adjunto encontrará su código QR de inscripción.\n\n"
            f"Saludos cordiales,\n"
            f"Equipo de Eventos"
        )
        
        # Enviar email
        send_mail(
            subject=f"Aprobación como Evaluador - {evento.eve_nombre}",
            message=mensaje,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[usuario_evaluador.email],
            fail_silently=True,
        )
        
        return redirect('dashboard_evaluador')
    
    except Exception as e:
        print(f"Error en aprobar_eva: {str(e)}")
        import traceback
        traceback.print_exc()
        return redirect('dashboard_evaluador')
    
# AGREGAR ESTO AL FINAL DE app_evaluadores/views.py (después de aprobar_eva)

@login_required
@require_http_methods(["POST"])
def rechazar_eva(request, evento_id, evaluador_evento_id):
    """
    Rechaza un evaluador para un evento.
    Solo el administrador del evento puede rechazar.
    
    HU33: Cambiar estado a Rechazado y notificar
    HU34: NO incluir clave en el email de rechazo
    HU35: NO generar QR para rechazados
    """
    try:
        evento = get_object_or_404(Evento, pk=evento_id)
        evaluador_evento = get_object_or_404(
            EvaluadorEvento, 
            pk=evaluador_evento_id, 
            eva_eve_evento_fk=evento
        )
        
        # Verificar que el usuario sea admin del evento
        try:
            admin_evento = AdministradorEvento.objects.get(usuario=request.user)
            if evento.eve_administrador_fk != admin_evento:
                return redirect('dashboard_evaluador')
        except AdministradorEvento.DoesNotExist:
            return redirect('login')
        
        # Cambiar estado a Rechazado
        evaluador_evento.eva_eve_estado = "Rechazado"
        evaluador_evento.save()
        
        # NO generar QR para rechazados (HU35)
        
        # Crear mensaje SIN LA CLAVE (HU34)
        usuario_evaluador = evaluador_evento.eva_eve_evaluador_fk.usuario
        
        mensaje = (
            f"Hola {usuario_evaluador.first_name},\n\n"
            f"Lamentablemente, su solicitud para ser evaluador en el evento:\n"
            f"{evento.eve_nombre}\n\n"
            f"ha sido rechazada.\n\n"
            f"Si tiene alguna pregunta o desea conocer las razones, "
            f"contacte al administrador del evento.\n\n"
            f"Saludos cordiales,\n"
            f"Equipo de Eventos"
        )
        
        # Enviar email
        send_mail(
            subject=f"Rechazo de Solicitud de Evaluador - {evento.eve_nombre}",
            message=mensaje,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[usuario_evaluador.email],
            fail_silently=True,
        )
        
        return redirect('dashboard_evaluador')
    
    except Exception as e:
        print(f"Error en rechazar_eva: {str(e)}")
        import traceback
        traceback.print_exc()
        return redirect('dashboard_evaluador')


########### VISTA DEL DASHBOARD DEL EVALUADOR ###########
@method_decorator(evaluador_required, name='dispatch')
class DashboardEvaluadorView(View):
    def get(self, request):
        evaluador_id = request.session.get('evaluador_id')
        if not evaluador_id:
            messages.error(request, "Debe iniciar sesión como evaluador.")
            return redirect('login_view')

        try:
            evaluador = Evaluador.objects.get(id=evaluador_id)
        except Evaluador.DoesNotExist:
            messages.error(request, "Evaluador no encontrado.")
            return redirect('login_view')

        # Relación completa con estado
        relaciones = EvaluadorEvento.objects.filter(eva_eve_evaluador_fk=evaluador).select_related('eva_eve_evento_fk')

        # Separar eventos según estado
        eventos_aprobados = [rel.eva_eve_evento_fk for rel in relaciones if rel.eva_eve_estado == 'Aprobado']
        eventos_pendientes = [rel.eva_eve_evento_fk for rel in relaciones if rel.eva_eve_estado == 'Pendiente']

        # Aplicar filtros sobre eventos_aprobados
        nombre = request.GET.get('nombre')
        ciudad = request.GET.get('ciudad')
        area_id = request.GET.get('area')
        categoria_id = request.GET.get('categoria')
        costo = request.GET.get('costo')
        estado = request.GET.get('estado')

        eventos = Evento.objects.filter(id__in=[e.id for e in eventos_aprobados])

        if nombre:
            eventos = eventos.filter(eve_nombre__icontains=nombre)
        if ciudad:
            eventos = eventos.filter(eve_lugar__icontains=ciudad)
        if area_id:
            eventos = eventos.filter(categorias__cat_area_fk__id=area_id).distinct()
        if categoria_id:
            eventos = eventos.filter(categorias__id=categoria_id).distinct()
        if costo:
            eventos = eventos.filter(eve_costo=costo)
        if estado:
            eventos = eventos.filter(eve_estado=estado)

        # Verificar si los criterios suman 100 para habilitar botón
        criterios_completos = {}
        for evento in eventos:
            suma_pesos = Criterio.objects.filter(cri_evento_fk=evento).aggregate(total=models.Sum('cri_peso'))['total'] or 0
            criterios_completos[evento.id] = (suma_pesos == 100)

        context = {
            'evaluador': evaluador,
            'eventos': eventos,
            'eventos_pendientes': eventos_pendientes,
            'areas': Area.objects.all(),
            'categorias': Categoria.objects.all(),
            'criterios_completos': criterios_completos,
        }
        return render(request, 'dashboard_principal_evaluador.html', context)

    #Iniciar sesion una vez y cambiar contraseña
    def dispatch(self, request, *args, **kwargs):
        evaluador_id = request.session.get('evaluador_id')
        evaluador = get_object_or_404(Evaluador, pk=evaluador_id)

        # Si nunca ha iniciado sesión, forzar cambio de contraseña
        if not evaluador.usuario.last_login:
            return redirect('cambio_password_evaluador')

        return super().dispatch(request, *args, **kwargs)


##################### --- Cambio de Contraseña Evaluador --- #####################

@method_decorator(evaluador_required, name='dispatch')
class CambioPasswordEvaluadorView(View):
    template_name = 'cambio_password_evaluador.html'

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

        evaluador_id = request.session.get('evaluador_id')
        evaluador = get_object_or_404(Evaluador, pk=evaluador_id)
        usuario = evaluador.usuario

        usuario.set_password(password1)
        usuario.ultimo_acceso = timezone.now()  # ✅ Se actualiza solo aquí
        usuario.save()

        messages.success(request, "✅ Contraseña cambiada correctamente.")
        return redirect('dashboard_evaluador')


########### CREAR EVALUADOR ###########

@method_decorator(visitor_required, name='dispatch') 
class EvaluadorCreateView(View):
    def get(self, request, evento_id):
        evento = get_object_or_404(Evento, pk=evento_id)
        form = EvaluadorForm()
        return render(request, 'crear_evaluador.html', {
            'form': form,
            'evento': evento
        })

    def post(self, request, evento_id):
        evento = get_object_or_404(Evento, pk=evento_id)
        # Asume que EvaluadorForm tiene el argumento 'evento'
        form = EvaluadorForm(request.POST, request.FILES, evento=evento) 

        if form.is_valid():
            try: # 🔄 Añadimos un bloque try-except para manejo de errores generales

                with transaction.atomic(): # 🔒 Usamos transacción atómica para seguridad
                    cedula = form.cleaned_data['cedula']
                    username = form.cleaned_data['username']
                    first_name = form.cleaned_data['first_name']
                    last_name = form.cleaned_data['last_name']
                    email = form.cleaned_data['email']
                    telefono = form.cleaned_data['telefono']

                    # 🔹 Buscar usuario existente por cédula, correo o username
                    usuario_existente = Usuario.objects.filter(
                        Q(cedula=cedula) | Q(email=email) | Q(username=username) # Usamos Q
                    ).first()

                    documento = request.FILES.get('eva_eve_documento')
                    
                    # --- 🔑 INICIO DEL BLOQUE DE REUTILIZACIÓN DE DATOS (Modificado) 🔑 ---
                    
                    if usuario_existente:
                        usuario = usuario_existente
                        creado = False
                        password_plana = None

                        # 🛑 APLICACIÓN DE VERIFICACIÓN DE ROLES CRUZADA (CLAVE) 🛑
                        
                        # 1. Verificar si ya es Asistente en este evento
                        if AsistenteEvento.objects.filter(
                            asi_eve_evento_fk=evento,
                            asi_eve_asistente_fk__usuario=usuario # Seguimiento al usuario
                        ).exists():
                            messages.error(request, f"🚫 El usuario ya está inscrito como ASISTENTE en el evento \"{evento.eve_nombre}\".")
                            return render(request, 'crear_evaluador.html', {'form': form, 'evento': evento})

                        # 2. Verificar si ya es Participante en este evento
                        if ParticipanteEvento.objects.filter(
                            par_eve_evento_fk=evento,
                            par_eve_participante_fk__usuario=usuario # Seguimiento al usuario
                        ).exists():
                            messages.error(request, f"🚫 El usuario ya está inscrito como PARTICIPANTE en el evento \"{evento.eve_nombre}\".")
                            return render(request, 'crear_evaluador.html', {'form': form, 'evento': evento})

                        # Si pasa las verificaciones de roles cruzados...
                        
                        # Actualizar datos del usuario
                        usuario.first_name = first_name
                        usuario.last_name = last_name
                        usuario.telefono = telefono
                        usuario.username = username
                        usuario.cedula = cedula
                        
                        # Asegurar que el rol principal se establezca en EVALUADOR
                        if usuario.rol != Usuario.Roles.EVALUADOR:
                            usuario.rol = Usuario.Roles.EVALUADOR
                            
                        usuario.save(update_fields=['first_name', 'last_name', 'telefono', 'username', 'cedula', 'rol'])
                        
                    else:
                        # Usuario nuevo
                        creado = True
                        password_plana = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
                        
                        usuario = Usuario.objects.create(
                            email=email,
                            username=username,
                            first_name=first_name,
                            last_name=last_name,
                            telefono=telefono,
                            is_superuser=False,
                            is_staff=False,
                            is_active=True,
                            date_joined=localtime(now()),
                            rol=Usuario.Roles.EVALUADOR,
                            cedula=cedula,
                            password=make_password(password_plana)
                        )
                        
                    # --- 🔑 FIN DEL BLOQUE DE REUTILIZACIÓN DE DATOS 🔑 ---
                    
                    # 🔹 Verificar si ya existe un Evaluador (perfil de rol) con ese usuario
                    # get_or_create garantiza que el perfil de Evaluador exista para el usuario
                    evaluador, evaluador_creado = Evaluador.objects.get_or_create(usuario=usuario) 

                    # 🔹 Verificar si ya está inscrito en este evento como EVALUADOR (Revisión de duplicados)
                    if EvaluadorEvento.objects.filter(
                        eva_eve_evaluador_fk=evaluador,
                        eva_eve_evento_fk=evento
                    ).exists():
                        messages.warning(request, f"⚠️ El usuario {usuario.username} ya está registrado como evaluador en este evento.")
                        return redirect('pagina_principal')

                    # 🔹 Crear relación EvaluadorEvento
                    EvaluadorEvento.objects.create(
                        eva_eve_evaluador_fk=evaluador,
                        eva_eve_evento_fk=evento,
                        eva_eve_fecha_hora=now(),
                        eva_eve_estado="Pendiente",
                        eva_eve_documento=documento
                    )

                    # 🔹 Enviar correo (Se mantiene la lógica de correo)
                    try:
                        # ... lógica de correo (no modificada) ...
                        if creado:
                            mensaje = (
                                f"Hola Evaluador {usuario.first_name},\n\n"
                                f"Te has registrado correctamente al evento \"{evento.eve_nombre}\".\n"
                                f"Tu estado actual es 'Pendiente' y será revisado por el administrador del evento.\n\n"
                                f"Puedes iniciar sesión con las siguientes credenciales:\n"
                                f"Correo registrado: {usuario.email}\n"
                                f"Contraseña generada: {password_plana}\n\n"
                                f"Recomendamos cambiar tu contraseña después de iniciar sesión.\n\n"
                                f"Atentamente,\nEquipo Event-Soft"
                            )
                        else:
                            mensaje = (
                                f"Hola Evaluador {usuario.first_name},\n\n"
                                f"Te has inscrito correctamente al evento \"{evento.eve_nombre}\".\n"
                                f"Tu estado actual es 'Pendiente' y será revisado por el administrador del evento.\n\n"
                                f"Recuerda que debes iniciar sesión con tu correo: {usuario.email}\n"
                                f"y tu contraseña actual (la misma que ya usas en Event-Soft).\n\n"
                                f"Atentamente,\nEquipo Event-Soft"
                            )

                        send_mail(
                            subject=f"🎟️ Datos de acceso - Evento \"{evento.eve_nombre}\"",
                            message=mensaje,
                            from_email=settings.DEFAULT_FROM_EMAIL, # Asume que settings.DEFAULT_FROM_EMAIL está disponible
                            recipient_list=[usuario.email],
                            fail_silently=False
                        )
                    except Exception as e:
                        messages.warning(request, f"Evaluador registrado, pero no se pudo enviar el correo: {e}")

                    messages.success(
                        request,
                        f"✅ Evaluador registrado correctamente al evento '{evento.eve_nombre}'. Estado: Pendiente de aprobación."
                    )
                    return redirect('pagina_principal')

            except Exception as e:
                # Captura cualquier error ocurrido dentro de la transacción
                messages.error(request, f"❌ Ocurrió un error inesperado al registrar el evaluador: {str(e)}")
                # Si esto ocurre, la transacción se revertirá automáticamente.
                
            # Renderizar el formulario con errores si es necesario
            return render(request, 'crear_evaluador.html', {
                'form': form,
                'evento': evento
            })


        # Si el formulario no es válido
        messages.error(request, "Corrija los errores en el formulario.")
        return render(request, 'crear_evaluador.html', {
            'form': form,
            'evento': evento
        })


######### EDITAR EVALUADOR ##########

@method_decorator(evaluador_required, name='dispatch')
class EditarEvaluadorView(View):
    template_name = 'editar_evaluador.html'

    def get(self, request, evaluador_id):
        evaluador = get_object_or_404(Evaluador, id=evaluador_id)
        usuario = evaluador.usuario
        form = EditarUsuarioEvaluadorForm(instance=usuario)

        # Traer todas las relaciones del evaluador con los eventos
        todas_relaciones = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=evaluador
        ).select_related("eva_eve_evento_fk")

        return render(request, self.template_name, {
            'form': form,
            'evaluador': evaluador,
            'usuario': usuario,
            'todas_relaciones': todas_relaciones
        })

    def post(self, request, evaluador_id):
        evaluador = get_object_or_404(Evaluador, id=evaluador_id)
        usuario = evaluador.usuario
        form = EditarUsuarioEvaluadorForm(request.POST, request.FILES, instance=usuario)

        nueva_contrasena = request.POST.get('nueva_contrasena')
        confirmar_contrasena = request.POST.get('confirmar_contrasena')
        confirmar_contrasena_nueva = request.POST.get('confirmar_contrasena_nueva')

        if form.is_valid():
            # 🔹 Verificar y actualizar contraseña
            if nueva_contrasena and confirmar_contrasena and confirmar_contrasena_nueva:
                if not check_password(nueva_contrasena, usuario.password):
                    messages.error(request, "❌ La contraseña antigua no es correcta.")
                    return self.get(request, evaluador_id)

                if confirmar_contrasena != confirmar_contrasena_nueva:
                    messages.error(request, "❌ Las nuevas contraseñas no coinciden.")
                    return self.get(request, evaluador_id)

                if len(confirmar_contrasena) < 6:
                    messages.error(request, "❌ La nueva contraseña debe tener al menos 6 caracteres.")
                    return self.get(request, evaluador_id)

                usuario.set_password(confirmar_contrasena)

            # ✅ Guardar documentos subidos (revisar por cada relación)
            todas_relaciones = EvaluadorEvento.objects.filter(eva_eve_evaluador_fk=evaluador)
            for relacion in todas_relaciones:
                input_name = f"eva_eve_documento_{relacion.id}"
                if input_name in request.FILES:
                    documento = request.FILES[input_name]
                    if not documento.name.lower().endswith('.pdf'):
                        messages.error(request, f"❌ El documento para {relacion.eva_eve_evento_fk.eve_nombre} debe ser un PDF.")
                        return self.get(request, evaluador_id)

                    relacion.eva_eve_documento = documento
                    relacion.save()

            # ✅ Guardar datos del usuario
            form.save()
            usuario.save()

            messages.success(request, "✅ Los datos del evaluador y documentos se actualizaron correctamente.")
            return redirect('editar_evaluador', evaluador_id=evaluador_id)

        else:
            messages.error(request, "❌ No se pudo guardar. Revisa los errores del formulario.")
            return self.get(request, evaluador_id)





########### VER INFORMACIÓN EVENTO ###########
@method_decorator(evaluador_required, name='dispatch')
class EventoDetailView(DetailView):
    model = Evento
    template_name = 'info_evento_evento_eva.html'
    context_object_name = 'evento'
    pk_url_kwarg = 'pk'
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        evento = self.get_object()
        evaluador_id = self.request.session.get('evaluador_id')
        
        # Verificar si el evaluador está asignado a este evento
        if evaluador_id:
            evaluador = get_object_or_404(Evaluador, id=evaluador_id)
            if not EvaluadorEvento.objects.filter(eva_eve_evaluador_fk=evaluador, eva_eve_evento_fk=evento).exists():
                messages.error(self.request, "No tienes permiso para ver este evento.")
                return redirect('pagina_principal')

        context['evaluador'] = evaluador if evaluador_id else None
        return context


######## VER CRITERIOS DE EVALUACIÓN #########
@method_decorator(evaluador_required, name='dispatch')
class CriterioEvaListView(ListView):
    model = Criterio
    template_name = 'crear_criterios_evaluacion_eva.html'
    context_object_name = 'criterios'

    def get_queryset(self):
        evento_id = self.kwargs.get('evento_id')
        return Criterio.objects.filter(cri_evento_fk__id=evento_id).order_by('cri_descripcion')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        evento_id = self.kwargs.get('evento_id')
        evento = get_object_or_404(Evento, id=evento_id)
        criterios = context['criterios']  # queryset con criterios filtrados

        suma_pesos = sum(criterio.cri_peso for criterio in criterios)
        context['evento'] = evento
        context['suma_pesos'] = round(suma_pesos, 2)

        # Validación para saber si ya están completos los 100 puntos
        context['completo_100'] = (suma_pesos == 100)

        return context
 
@method_decorator(evaluador_required, name='dispatch')
class CrearCriterioEvaView(View):
    def get(self, request, evento_id):
        evento = get_object_or_404(Evento, pk=evento_id)
        criterios = Criterio.objects.filter(cri_evento_fk=evento)
        suma_pesos = sum(criterio.cri_peso for criterio in criterios)

        return render(request, 'crear_criterios_evaluacion_eva.html', {
            'evento': evento,
            'criterios': criterios,
            'suma_pesos': round(suma_pesos, 2),
        })

    def post(self, request, evento_id):
        evento = get_object_or_404(Evento, pk=evento_id)
        descripcion = request.POST.get('cri_descripcion', '').strip()  # Agregar .strip()
        peso_str = request.POST.get('cri_peso', '0')

        # VALIDACIÓN 1: Descripción no vacía
        if not descripcion:
            messages.error(request, 'La descripción del criterio es obligatoria.')
            return redirect('crear_criterio_eva', evento_id=evento_id)

        # VALIDACIÓN 2: Peso debe ser un número válido
        try:
            peso = float(peso_str)
        except ValueError:
            messages.error(request, 'El peso debe ser un número válido.')
            return redirect('crear_criterio_eva', evento_id=evento_id)

        # VALIDACIÓN 3: Peso debe ser mayor a 0 (NUEVA)
        if peso <= 0:
            messages.error(request, 'El peso del criterio debe ser mayor a 0.')
            return redirect('crear_criterio_eva', evento_id=evento_id)

        # Obtener los criterios existentes y su suma de pesos
        criterios = Criterio.objects.filter(cri_evento_fk=evento)
        suma_pesos = sum(criterio.cri_peso for criterio in criterios)

        # Validar si ya se alcanzó el máximo
        if suma_pesos >= 100:
            messages.error(request, 'La suma de los pesos ya llegó a 100%. No se pueden agregar más criterios.')
            return redirect('crear_criterio_eva', evento_id=evento_id)

        # Validar que la suma con el nuevo peso no exceda 100
        if suma_pesos + peso > 100:
            messages.error(
                request,
                f'La suma de los pesos no puede superar 100%. Actualmente hay {round(suma_pesos, 2)}%.'
            )
            return redirect('crear_criterio_eva', evento_id=evento_id)

        # Crear el nuevo criterio
        Criterio.objects.create(
            cri_descripcion=descripcion,
            cri_peso=peso,
            cri_evento_fk=evento
        )

        messages.success(request, 'Criterio creado exitosamente.')
        return redirect('ver_criterios_agregados_eva', evento_id=evento_id)  # CAMBIAR redirección


# 2. REEMPLAZA ActualizarEvaCriterioView (alrededor de la línea 720)
@method_decorator(evaluador_required, name='dispatch')
class ActualizarEvaCriterioView(View):
    def post(self, request, criterio_id):
        criterio = get_object_or_404(Criterio, pk=criterio_id)
        evento_id = criterio.cri_evento_fk.pk
        
        # VALIDACIÓN CRÍTICA: Verificar si tiene calificaciones (NUEVA)
        tiene_calificaciones = Calificacion.objects.filter(
            cal_criterio_fk=criterio
        ).exists()
        
        if tiene_calificaciones:
            messages.warning(
                request,
                'Este criterio ya tiene calificaciones asociadas. '
                'No se pueden realizar modificaciones que afecten las evaluaciones existentes.'
            )
            return redirect('ver_criterios_agregados_eva', evento_id=evento_id)
        
        descripcion = request.POST.get('cri_descripcion', '').strip()  # Agregar .strip()
        peso_str = request.POST.get('cri_peso', '0')

        # VALIDACIÓN 1: Descripción no vacía
        if not descripcion:
            messages.error(request, 'La descripción del criterio es obligatoria.')
            return redirect('ver_criterios_agregados_eva', evento_id=evento_id)

        # VALIDACIÓN 2: Peso válido
        try:
            nuevo_peso = float(peso_str)
        except ValueError:
            messages.error(request, 'El peso debe ser un número válido.')
            return redirect('ver_criterios_agregados_eva', evento_id=evento_id)
        
        # VALIDACIÓN 3: Peso mayor a 0 (NUEVA)
        if nuevo_peso <= 0:
            messages.error(request, 'El peso del criterio debe ser mayor a 0.')
            return redirect('ver_criterios_agregados_eva', evento_id=evento_id)

        # Obtener criterios del mismo evento excepto el que se está actualizando
        criterios = Criterio.objects.filter(cri_evento_fk=criterio.cri_evento_fk).exclude(pk=criterio.pk)
        suma_pesos_otros = sum(c.cri_peso for c in criterios)

        # Validar suma total con nuevo peso
        if suma_pesos_otros + nuevo_peso > 100:
            messages.error(
                request,
                f'La suma total de pesos no puede superar 100%. Actualmente hay {round(suma_pesos_otros, 2)}%.'
            )
            return redirect('ver_criterios_agregados_eva', evento_id=evento_id)

        # Guardar si pasa validación
        criterio.cri_descripcion = descripcion
        criterio.cri_peso = nuevo_peso
        criterio.save()

        messages.success(request, 'Criterio actualizado exitosamente.')
        return redirect('ver_criterios_agregados_eva', evento_id=evento_id)


# 3. REEMPLAZA EliminarEvaCriterioView (alrededor de la línea 760)
@method_decorator(evaluador_required, name='dispatch')
class EliminarEvaCriterioView(View):
    def post(self, request, criterio_id):
        criterio = get_object_or_404(Criterio, pk=criterio_id)
        evento_id = criterio.cri_evento_fk.pk
        
        # VALIDACIÓN CRÍTICA: No eliminar si tiene calificaciones (NUEVA)
        tiene_calificaciones = Calificacion.objects.filter(
            cal_criterio_fk=criterio
        ).exists()
        
        if tiene_calificaciones:
            messages.error(
                request,
                'No se puede eliminar este criterio porque ya tiene calificaciones asociadas. '
                'Eliminar este criterio afectaría las evaluaciones existentes.'
            )
            return redirect('ver_criterios_agregados_eva', evento_id=evento_id)
        
        # Si no tiene calificaciones, eliminar
        descripcion = criterio.cri_descripcion
        criterio.delete()

        messages.success(request, f'El criterio "{descripcion}" ha sido eliminado exitosamente.')
        return redirect('ver_criterios_agregados_eva', evento_id=evento_id)


# 4. ACTUALIZA CriterioAgregadosEvaListView (alrededor de la línea 770)
@method_decorator(evaluador_required, name='dispatch')
class CriterioAgregadosEvaListView(ListView):
    model = Criterio
    template_name = 'ver_criterios_evaluador_eva.html'
    context_object_name = 'criterios'

    def get_queryset(self):
        evento_id = self.kwargs.get('evento_id')
        return Criterio.objects.filter(cri_evento_fk__id=evento_id).order_by('cri_descripcion')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        evento_id = self.kwargs.get('evento_id')
        evento = get_object_or_404(Evento, id=evento_id)
        
        # Obtener todos los criterios del evento
        criterios = context['criterios']
        
        # Verificar cuáles tienen calificaciones (NUEVO)
        criterios_con_info = []
        for criterio in criterios:
            tiene_calificaciones = Calificacion.objects.filter(
                cal_criterio_fk=criterio
            ).exists()
            
            criterios_con_info.append({
                'criterio': criterio,
                'tiene_calificaciones': tiene_calificaciones,
                'puede_eliminar': not tiene_calificaciones,
                'puede_modificar': not tiene_calificaciones,
            })
        
        context['evento'] = evento
        context['criterios_con_info'] = criterios_con_info  # NUEVO contexto
        
        return context
    

############ CALIFICAR PARTICIPANTES MODIFICADO PARA GRUPOS ###########

@method_decorator(evaluador_required, name='dispatch')
class CalificarParticipantesView(View):
    """Vista para listar participantes a calificar."""
    template_name = 'ver_lista_participantes.html'

    def get(self, request, evento_id):
        evaluador = get_object_or_404(Evaluador, id=request.session['evaluador_id'])
        evento = get_object_or_404(Evento, pk=evento_id)

        # VALIDACIÓN CRÍTICA: Verificar que el evaluador esté inscrito en el evento
        try:
            registro_evaluador = EvaluadorEvento.objects.get(
                eva_eve_evaluador_fk=evaluador,
                eva_eve_evento_fk=evento
            )
        except EvaluadorEvento.DoesNotExist:
            messages.error(
                request,
                'No estás inscrito en este evento. Solo los evaluadores inscritos pueden calificar.'
            )
            return redirect('dashboard_evaluador')
        
        # VALIDACIÓN: Verificar que esté aprobado
        if registro_evaluador.eva_eve_estado != 'Aprobado':
            messages.warning(
                request,
                'Tu inscripción aún no ha sido aprobada. Podrás calificar una vez que seas aprobado.'
            )
            return redirect('dashboard_evaluador')

        # Obtener los criterios del evento (para luego filtrar calificaciones)
        criterios = Criterio.objects.filter(cri_evento_fk=evento)

        # Participantes en el evento, solo aquellos con estado 'aprobado'
        # Solo mostrar líderes de grupo o participantes individuales
        participantes_evento = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=evento_id,
            par_eve_estado='Aprobado',
            par_eve_proyecto_principal__isnull=True  # Solo líderes o individuales
        )

        # Filtro por nombre o cédula
        filtro = request.GET.get('filtro')
        if filtro:
            participantes_evento = participantes_evento.filter(
                Q(par_eve_participante_fk__usuario__first_name__icontains=filtro) |
                Q(par_eve_participante_fk__usuario__email__icontains=filtro) |
                Q(par_eve_participante_fk__usuario__last_name__icontains=filtro)
            )

        # Excluir participantes que ya tienen calificaciones para los criterios del evento
        # Para grupos, verificar si el líder ya fue calificado
        calificados = Calificacion.objects.filter(
            cal_evaluador_fk=evaluador,
            cal_participante_fk=OuterRef('par_eve_participante_fk'),
            cal_criterio_fk__in=criterios
        )

        participantes_evento = participantes_evento.annotate(
            ya_calificado=Exists(calificados)
        ).filter(ya_calificado=False)

        # Lista de participantes que aún no han sido calificados
        participantes = [pe.par_eve_participante_fk for pe in participantes_evento]

        return render(request, self.template_name, {
            'participantes': participantes,
            'evento_id': evento_id,
            'evento': evento,
            'evaluador': evaluador
        })

@method_decorator(evaluador_required, name='dispatch')
class CalificandoParticipanteView(View):
    def get(self, request, participante_id, evento_id):
        participante = get_object_or_404(Participante, pk=participante_id)
        evento = get_object_or_404(Evento, pk=evento_id)
        criterios = Criterio.objects.filter(cri_evento_fk=evento)
        
        # Obtener la relación ParticipanteEvento del participante
        participante_evento = get_object_or_404(ParticipanteEvento, 
                                               par_eve_participante_fk=participante,
                                               par_eve_evento_fk=evento,
                                               par_eve_proyecto_principal__isnull=True)  # Solo líderes
        
        # Verificar si es un grupo y obtener todos los miembros
        miembros_grupo = []
        es_grupo = participante_evento.par_eve_es_grupo
        
        if es_grupo:
            todos_miembros = participante_evento.get_todos_miembros_proyecto()
            miembros_grupo = todos_miembros
        else:
            miembros_grupo = [participante_evento]

        return render(request, 'evaluador_califica_participante.html', {
            'participante': participante,
            'evento': evento,
            'criterios': criterios,
            'es_grupo': es_grupo,
            'miembros_grupo': miembros_grupo,
            'participante_evento': participante_evento,
            'codigo_proyecto': participante_evento.par_eve_codigo_proyecto if es_grupo else None
        })

    def post(self, request, participante_id, evento_id):
        participante = get_object_or_404(Participante, pk=participante_id)
        evento = get_object_or_404(Evento, pk=evento_id)
        criterios = Criterio.objects.filter(cri_evento_fk=evento)
        evaluador_id = request.session.get('evaluador_id')
        evaluador = get_object_or_404(Evaluador, pk=evaluador_id)

        # Obtener la relación ParticipanteEvento del líder
        participante_evento_lider = get_object_or_404(ParticipanteEvento, 
                                                     par_eve_participante_fk=participante,
                                                     par_eve_evento_fk=evento,
                                                     par_eve_proyecto_principal__isnull=True)

        # Lista para almacenar las calificaciones obtenidas
        calificaciones = []
        
        # Variable para controlar si hay errores
        hay_errores = False

        # Guardar las calificaciones de cada criterio para el líder
        for criterio in criterios:
            campo = f'calificacion_{criterio.id}'
            valor_str = request.POST.get(campo)
            
            if not valor_str:
                messages.error(request, f'Debe calificar el criterio: {criterio.cri_descripcion}')
                hay_errores = True
                continue
            
            try:
                valor = int(valor_str)
                
                # VALIDACIÓN CRÍTICA: Verificar que el valor esté en el rango 0-100
                if valor < 0 or valor > 100:
                    messages.error(
                        request,
                        f'La calificación para "{criterio.cri_descripcion}" debe estar entre 0 y 100. Recibido: {valor}'
                    )
                    hay_errores = True
                    continue
                
                calificaciones.append(valor)
                
                # Guardamos la calificación solo para el líder
                Calificacion.objects.update_or_create(
                    cal_evaluador_fk=evaluador,
                    cal_criterio_fk=criterio,
                    cal_participante_fk=participante,
                    defaults={'cal_valor': valor}
                )
            except ValueError:
                messages.error(
                    request,
                    f'La calificación para "{criterio.cri_descripcion}" debe ser un número válido.'
                )
                hay_errores = True
                continue
        
        # Si hay errores, redirigir de vuelta al formulario
        if hay_errores:
            return redirect('calificando_participante', participante_id=participante_id, evento_id=evento_id)

        # Calcular promedio de las calificaciones actuales
        if calificaciones:
            promedio = sum(calificaciones) / len(calificaciones)
            calificacion_final = round(promedio)
            
            # Aplicar la calificación a todo el grupo
            if participante_evento_lider.par_eve_es_grupo:
                # Obtener todos los miembros del proyecto (incluido el líder)
                todos_miembros = participante_evento_lider.get_todos_miembros_proyecto()
                
                for miembro_pe in todos_miembros:
                    miembro_pe.calificacion = calificacion_final
                    miembro_pe.save()
                
                # Crear registro de calificación para todos los miembros (para tracking)
                for miembro_pe in todos_miembros:
                    if miembro_pe.par_eve_participante_fk != participante:  # Evitar duplicar para el líder
                        for criterio in criterios:
                            campo = f'calificacion_{criterio.id}'
                            valor = request.POST.get(campo)
                            if valor:
                                try:
                                    valor_int = int(valor)
                                    if 0 <= valor_int <= 100:
                                        Calificacion.objects.update_or_create(
                                            cal_evaluador_fk=evaluador,
                                            cal_criterio_fk=criterio,
                                            cal_participante_fk=miembro_pe.par_eve_participante_fk,
                                            defaults={'cal_valor': valor_int}
                                        )
                                except ValueError:
                                    pass
                
                mensaje_exito = f"Calificaciones para el grupo de {participante.usuario.first_name} {participante.usuario.last_name} guardadas correctamente. La calificación se aplicó a todos los {len(todos_miembros)} miembros del grupo."
            else:
                # Participante individual
                participante_evento_lider.calificacion = calificacion_final
                participante_evento_lider.save()
                mensaje_exito = f"Calificaciones para {participante.usuario.first_name} {participante.usuario.last_name} guardadas correctamente."

            messages.success(request, mensaje_exito)
        else:
            messages.error(request, "No se pudieron guardar las calificaciones. Verifique los valores ingresados.")

        return redirect('calificar_participantes', evento_id=evento_id)
# Función auxiliar para obtener información de grupo (opcional)
def obtener_info_grupo_participante(participante, evento):
    """
    Función auxiliar que devuelve información sobre si un participante pertenece a un grupo
    """
    try:
        participante_evento = ParticipanteEvento.objects.get(
            par_eve_participante_fk=participante,
            par_eve_evento_fk=evento
        )
        
        if participante_evento.par_eve_proyecto_principal:
            # Es miembro de un grupo, obtener info del líder
            lider_pe = participante_evento.par_eve_proyecto_principal
            return {
                'es_miembro_grupo': True,
                'es_lider': False,
                'lider': lider_pe.par_eve_participante_fk,
                'codigo_proyecto': lider_pe.par_eve_codigo_proyecto,
                'participante_evento': participante_evento
            }
        elif participante_evento.par_eve_es_grupo:
            # Es líder de grupo
            miembros = participante_evento.get_todos_miembros_proyecto()
            return {
                'es_miembro_grupo': True,
                'es_lider': True,
                'miembros': miembros,
                'codigo_proyecto': participante_evento.par_eve_codigo_proyecto,
                'participante_evento': participante_evento
            }
        else:
            # Participante individual
            return {
                'es_miembro_grupo': False,
                'es_lider': False,
                'participante_evento': participante_evento
            }
    except ParticipanteEvento.DoesNotExist:
        return None




################## VER PODIO ################

@method_decorator(evaluador_required, name='dispatch')
class VerPodioParticipantesView(View):
    def get(self, request, evento_id):
        evento = get_object_or_404(Evento, pk=evento_id)
        
        # CAMBIO 1: Obtener evaluador desde el usuario autenticado
        try:
            evaluador = request.user.evaluador
        except:
            return render(request, 'error.html', {
                'mensaje': 'No tienes perfil de evaluador'
            }, status=403)
        
        # CAMBIO 2: Verificar que el evaluador está APROBADO en este evento
        es_evaluador_evento = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=evaluador,
            eva_eve_evento_fk=evento,
            eva_eve_estado='Aprobado'
        ).exists()
        
        if not es_evaluador_evento:
            return render(request, 'error.html', {
                'mensaje': 'No estás autorizado para ver esto'
            }, status=403)

        # CAMBIO 3: Query optimizada con ordenamiento en BD
        participantes_evento = ParticipanteEvento.objects.filter(
            par_eve_evento_fk=evento_id,
            calificacion__isnull=False
        ).select_related('par_eve_participante_fk').order_by(
            '-calificacion',  # Descendente por calificación
            'par_eve_fecha'   # Ascendente por fecha (más temprano primero)
        )

        participantes_calificados = []
        for pe in participantes_evento:
            participante = pe.par_eve_participante_fk
            if participante and participante.id:
                pe.participante = participante

                # Extraer primer nombre y apellido
                first_name = participante.usuario.first_name.split()[0].upper()
                last_name = participante.usuario.last_name.split()[0].upper()

                # Guardar como atributos personalizados
                pe.nombre_limpio = first_name
                pe.apellido_limpio = last_name

                participantes_calificados.append(pe)

        return render(request, 'ver_notas_participantes.html', {
            'participantes': participantes_calificados,
            'evento': evento,
            'evaluador': evaluador
        })



########## VER NOTAS DE PARTICIPANTES #########

@method_decorator(evaluador_required, name='dispatch')
class DetalleCalificacionView(DetailView):
    template_name = 'ver_detalle_calificacion_podio.html'
    context_object_name = 'participante'
    model = Participante

    def get_object(self):
        return get_object_or_404(Participante, id=self.kwargs['participante_id'])

    def dispatch(self, request, *args, **kwargs):
        """
        Validaciones de seguridad antes de procesar la petición
        """
        # Llamar al dispatch del decorador primero
        response = super().dispatch(request, *args, **kwargs)
        
        # Si el decorador ya redirigió, retornar esa respuesta
        if isinstance(response, redirect.__class__):
            return response
            
        return response

    def get(self, request, *args, **kwargs):
        """
        Sobrescribir get para agregar validaciones de seguridad
        """
        evento_id = self.kwargs['evento_id']
        participante_id = self.kwargs['participante_id']
        
        # Obtener el evaluador de la sesión
        evaluador_id = request.session.get('evaluador_id')
        
        if not evaluador_id:
            messages.error(request, 'No se encontró información del evaluador.')
            return redirect('dashboard_evaluador')
        
        # Verificar que el evaluador esté inscrito en el evento
        try:
            from app_usuarios.models import Evaluador
            evaluador = Evaluador.objects.get(id=evaluador_id)
            
            registro_evaluador = EvaluadorEvento.objects.get(
                eva_eve_evaluador_fk=evaluador,
                eva_eve_evento_fk_id=evento_id
            )
        except (Evaluador.DoesNotExist, EvaluadorEvento.DoesNotExist):
            messages.error(request, 'No estás inscrito en este evento.')
            return redirect('dashboard_evaluador')
        
        # VALIDACIÓN CRÍTICA: Verificar que el evaluador esté APROBADO
        if registro_evaluador.eva_eve_estado != 'Aprobado':
            messages.error(
                request, 
                'Solo los evaluadores aprobados pueden acceder a la información de los participantes.'
            )
            return redirect('dashboard_evaluador')
        
        # Verificar que el participante existe y está en el evento
        participante = self.get_object()
        evento = get_object_or_404(Evento, id=evento_id)
        
        try:
            participante_evento = ParticipanteEvento.objects.get(
                par_eve_evento_fk=evento,
                par_eve_participante_fk=participante
            )
        except ParticipanteEvento.DoesNotExist:
            messages.error(request, 'El participante no está inscrito en este evento.')
            return redirect('ver_calificaciones', evento_id=evento_id)
        
        # VALIDACIÓN: No mostrar participantes cancelados
        if participante_evento.par_eve_estado == 'Cancelado':
            messages.error(request, 'Este participante ha cancelado su inscripción.')
            return redirect('ver_calificaciones', evento_id=evento_id)
        
        # Si todas las validaciones pasan, continuar con el comportamiento normal
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        evento_id = self.kwargs['evento_id']
        participante = self.get_object()
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

        context.update({
            'evento': evento,
            'participante_evento': participante_evento,
            'calificaciones': calificaciones,
        })

        return context


######### ELIMINAR EVALUADOR #########

@method_decorator(evaluador_required, name='dispatch')
class EliminarEvaluadorView(View):
    def get(self, request, evaluador_id):
        # Aseguramos que el ID del evaluador coincida con el usuario logueado por seguridad (aunque evaluador_required ya ayuda)
        evaluador = get_object_or_404(Evaluador, id=evaluador_id)
        usuario = evaluador.usuario

        # 🔹 Buscar todas las inscripciones del evaluador
        inscripciones = EvaluadorEvento.objects.filter(eva_eve_evaluador_fk=evaluador)

        # 🔹 Verificar si tiene inscripciones activas (aprobadas)
        # Esto previene la eliminación del perfil si está activamente asignado a un evento.
        tiene_inscripciones_activas = inscripciones.filter(eva_eve_estado="Aprobado").exists()
        if tiene_inscripciones_activas:
            messages.error(
                request,
                "❌ No puedes eliminar tu perfil de Evaluador mientras tengas inscripciones activas. "
                "Por favor, cancela tus inscripciones antes de eliminar tu perfil."
            )
            return redirect('pagina_principal')

        # 🔑 LÓGICA ELIMINADA: Se quita el loop que intentaba liberar cupos (eve_capacidad)
        # for inscripcion in inscripciones:
        #     if inscripcion.eva_eve_estado == "Aprobado":
        #         evento = inscripcion.eva_eve_evento_fk
        #         # evento.eve_capacidad += 1
        #         # evento.save(update_fields=["eve_capacidad"])

        # 🔹 Obtener el último evento inscrito (para referencia en el correo)
        ultimo_evento = inscripciones.first()
        nombre_evento = ultimo_evento.eva_eve_evento_fk.eve_nombre if ultimo_evento else "uno de nuestros eventos"

        # 🔑 PASO 1: ELIMINAR LA RELACIÓN (Perfil) EVALUADOR
        # Esto elimina automáticamente todas las inscripciones en EvaluadorEvento (por CASCADE)
        evaluador.delete()         


        # 🔹 Enviar correo
        if usuario.email:
             try:
                send_mail(
                    subject='🗑️ Notificación de eliminación de perfil como Evaluador',
                    message=(
                        f'Estimado/a {usuario.first_name},\n\n'
                        f'Le informamos que su perfil de **Evaluador** ha sido eliminado correctamente de Event-Soft.\n\n'
                        f'Todos sus datos de evaluación en eventos como "{nombre_evento}" '
                        f'han sido eliminados. **Su cuenta de usuario principal no ha sido eliminada**.\n\n'
                        f'Si desea volver a inscribirse como Evaluador en el futuro, puede hacerlo usando su cuenta existente.\n\n'
                        f'Atentamente,\nEquipo de organización de eventos.'
                    ),
                    from_email=DEFAULT_FROM_EMAIL,
                    recipient_list=[usuario.email],
                    fail_silently=False
                )
             except Exception:
                 messages.warning(request, "El perfil de evaluador fue eliminado, pero no se pudo enviar el correo de notificación.")

        # 🔹 Cerrar sesión del usuario
        logout(request)

        messages.success(request, "✅ Tu perfil de Evaluador y tus inscripciones han sido eliminadas correctamente. Hemos cerrado tu sesión.")
        return redirect('pagina_principal')

    
    
######### LISTADO DE PARTICIPANTES ##########

@method_decorator(evaluador_required, name='dispatch')
class ListadoParticipantesPorEventoView(View):
    template_name = 'listado_participantes.html'

    def get(self, request, evento_id):
        evento = get_object_or_404(Evento, pk=evento_id)

        # Todos los participantes del evento (para contar todos los estados)
        todos_los_participantes = ParticipanteEvento.objects.filter(par_eve_evento_fk=evento)

        # Conteo por estado
        estados = todos_los_participantes.values_list('par_eve_estado', flat=True)
        conteo = Counter(estados)

        # Solo participantes Aprobados (para mostrar)
        participantes_evento = todos_los_participantes.filter(par_eve_estado='Aprobado')

        # Filtro por búsqueda si se aplica
        query = request.GET.get('q')
        if query:
            participantes_evento = participantes_evento.filter(
                Q(par_eve_participante_fk__usuario__first_name__icontains=query) |
                Q(par_eve_participante_fk__usuario__last_name__icontains=query) |
                Q(par_eve_participante_fk__id__icontains=query)
            )

        participantes = []
        for p in participantes_evento:
            participantes.append({
                'cedula': p.par_eve_participante_fk.id,
                'nombre': p.par_eve_participante_fk.usuario.first_name,
                'apellido': p.par_eve_participante_fk.usuario.last_name,
                'correo': p.par_eve_participante_fk.usuario.email,
                'telefono': p.par_eve_participante_fk.usuario.telefono,
                'par_eve_estado': p.par_eve_estado,
                'documento_url': p.par_eve_documentos.url if p.par_eve_documentos else None
            })

        return render(request, self.template_name, {
            'evento': evento,
            'participantes': participantes,
            'query': query,
            'conteo_aprobados': conteo.get('Aprobado', 0),
            'conteo_pendientes': conteo.get('Pendiente', 0),
            'conteo_rechazados': conteo.get('Rechazado', 0),
        })


######### RÚBRICA DEL EVENTO ##########

@method_decorator(evaluador_required, name='dispatch')
class InformacionTecnicaEventoEvaluadorView(View):
    """
    Vista para que los evaluadores vean la información técnica del evento.
    Solo evaluadores inscritos y aprobados pueden acceder.
    """
    template_name = 'info_tecnica_evento_eva.html'

    def get(self, request, pk):
        evento = get_object_or_404(Evento, pk=pk)
        
        # Obtener el evaluador de la sesión
        evaluador_id = request.session.get('evaluador_id')
        
        if not evaluador_id:
            messages.error(request, 'No se encontró información del evaluador.')
            return redirect('dashboard_evaluador')
        
        # Obtener el evaluador
        try:
            evaluador = Evaluador.objects.get(id=evaluador_id)
        except Evaluador.DoesNotExist:
            messages.error(request, 'Evaluador no encontrado.')
            return redirect('dashboard_evaluador')
        
        # VALIDACIÓN CRÍTICA: Verificar que el evaluador esté inscrito en el evento
        try:
            registro_evaluador = EvaluadorEvento.objects.get(
                eva_eve_evaluador_fk=evaluador,
                eva_eve_evento_fk=evento
            )
        except EvaluadorEvento.DoesNotExist:
            messages.error(
                request,
                'No estás inscrito en este evento. Solo los evaluadores inscritos pueden acceder a la información técnica.'
            )
            return redirect('dashboard_evaluador')
        
        # VALIDACIÓN: Verificar que el evaluador esté aprobado (opcional pero recomendado)
        if registro_evaluador.eva_eve_estado != 'Aprobado':
            messages.warning(
                request,
                'Tu inscripción aún no ha sido aprobada. La información técnica estará disponible una vez que seas aprobado.'
            )
            return redirect('dashboard_evaluador')
        
        # Si pasa todas las validaciones, mostrar la información técnica
        context = {
            'evento': evento,
            'evaluador': evaluador,
            'tiene_info_tecnica': bool(evento.eve_informacion_tecnica),
        }
        
        return render(request, self.template_name, context)

####### ACCESO A EVENTO ######
@method_decorator(evaluador_required, name='dispatch')
class IngresoEventoEvaluadorView(View):
    template_name = 'ingreso_evento_eva.html'

    def get(self, request, pk):
        evento = get_object_or_404(Evento, pk=pk)
        evaluador = get_object_or_404(Evaluador, usuario=request.user)
        evaluador_evento = get_object_or_404(EvaluadorEvento, eva_eve_evento_fk=evento, eva_eve_evaluador_fk=evaluador)

        context = {
            'evento': evento,
            'evaluador': evaluador_evento  # este es el objeto que tiene el QR y el soporte
        }
        return render(request, self.template_name, context)
  
########## VER CRITERIOS DE EVALUACIÓN PARA PARTICIPANTES #########

@method_decorator(evaluador_required, name='dispatch')
class VerCriteriosEvaluadorView(View):
    """
    Vista para que los evaluadores vean los criterios de evaluación del evento.
    Solo evaluadores inscritos y aprobados pueden acceder.
    """
    template_name = 'ver_criterios_evaluador_eva.html'  # Cambiar al template correcto

    def get(self, request, evento_id):
        evento = get_object_or_404(Evento, pk=evento_id)
        
        # Obtener el evaluador de la sesión
        evaluador_id = request.session.get('evaluador_id')
        
        if not evaluador_id:
            messages.error(request, 'No se encontró información del evaluador.')
            return redirect('dashboard_evaluador')
        
        # Obtener el evaluador
        try:
            evaluador = Evaluador.objects.get(id=evaluador_id)
        except Evaluador.DoesNotExist:
            messages.error(request, 'Evaluador no encontrado.')
            return redirect('dashboard_evaluador')
        
        # VALIDACIÓN CRÍTICA: Verificar que el evaluador esté inscrito en el evento
        try:
            registro_evaluador = EvaluadorEvento.objects.get(
                eva_eve_evaluador_fk=evaluador,
                eva_eve_evento_fk=evento
            )
        except EvaluadorEvento.DoesNotExist:
            messages.error(
                request,
                'No estás inscrito en este evento. Solo los evaluadores inscritos pueden ver los criterios.'
            )
            return redirect('dashboard_evaluador')
        
        # VALIDACIÓN: Verificar que el evaluador esté aprobado (opcional pero recomendado)
        if registro_evaluador.eva_eve_estado != 'Aprobado':
            messages.warning(
                request,
                'Tu inscripción aún no ha sido aprobada. Los criterios estarán disponibles una vez que seas aprobado.'
            )
            return redirect('dashboard_evaluador')
        
        # Obtener los criterios del evento
        criterios = Criterio.objects.filter(cri_evento_fk=evento).order_by('cri_descripcion')
        
        # Si todas las validaciones pasan, mostrar los criterios
        context = {
            'evento': evento,
            'criterios': criterios,
            'evaluador': evaluador,
        }
        
        return render(request, self.template_name, context)




################ #### VER MEMORIAS DE EVALUADOR ##########
@method_decorator(login_required, name='dispatch')
class MemoriasEvaluadorView(View):
    """
    Vista para que los evaluadores vean las memorias del evento.
    
    HU49: Descargar Memorias
    - CA4: Solo evaluadores APROBADOS
    - CA5: Solo usuarios con rol EVALUADOR
    - CA1.2: Mostrar memorias disponibles
    - CA1.3, CA2.2: Estructura y contenido filtrado
    - CA2.1: Manejo de eventos activos (sin memorias)
    """
    
    def get(self, request, evento_id):
        evento = get_object_or_404(Evento, id=evento_id)
        
        # CA5: Verificar que sea evaluador
        if request.user.rol != Usuario.Roles.EVALUADOR:
            messages.error(request, "❌ Solo los evaluadores pueden acceder a las memorias del evento.")
            return redirect('pagina_principal')  # O la página principal de tu proyecto
        
        # Obtener el perfil de evaluador
        try:
            evaluador = request.user.evaluador
        except:
            messages.error(request, "❌ No tienes perfil de evaluador.")
            return redirect('pagina_principal')
        
        # CA4: Verificar inscripción Y que esté APROBADO
        try:
            registro_eval = EvaluadorEvento.objects.get(
                eva_eve_evento_fk=evento,
                eva_eve_evaluador_fk=evaluador
            )
            
            # Validar que esté aprobado (CA4)
            if registro_eval.eva_eve_estado != 'Aprobado':
                messages.error(
                    request, 
                    f"❌ Tu inscripción en este evento está en estado '{registro_eval.eva_eve_estado}'. "
                    f"Solo los evaluadores aprobados pueden acceder a las memorias."
                )
                return redirect('dashboard_evaluador')
                
        except EvaluadorEvento.DoesNotExist:
            messages.error(request, "❌ No estás inscrito como evaluador en este evento.")
            return redirect('dashboard_evaluador')
        
        # CA1.2, CA1.3: Obtener memorias del evento
        memorias = MemoriaEvento.objects.filter(evento=evento).order_by('-subido_en')
        
        # CA2.1: Si no hay memorias y el evento está activo, mostrar mensaje
        if memorias.count() == 0 and evento.eve_estado == "Activo":
            messages.info(request, f"ℹ️ El evento '{evento.eve_nombre}' aún está en curso. Las memorias estarán disponibles cuando finalice.")
        
        return render(request, 'memorias_evaluador.html', {
            'evento': evento,
            'memorias': memorias,
            'evaluador': evaluador
        })


########## CANCELAR INSCRIPCIÓN AL EVENTO ##########


@method_decorator(login_required, name='dispatch')
class EvaluadorCancelacionView(View):
    def post(self, request, evento_id):
        evaluador = get_object_or_404(Evaluador, usuario=request.user)
        evento = get_object_or_404(Evento, id=evento_id)

        # Buscar inscripción activa del evaluador en este evento
        inscripcion = EvaluadorEvento.objects.filter(
            eva_eve_evaluador_fk=evaluador,
            eva_eve_evento_fk=evento,
            eva_eve_estado='Aprobado'
        ).first()

        if not inscripcion:
            messages.error(request, "❌ No tienes una inscripción activa para este evento.")
            return redirect('dashboard_evaluador')

        # Cambiar el estado a Cancelado
        inscripcion.eva_eve_estado = 'Cancelado'
        inscripcion.save()

        messages.success(request, f"✅ Has cancelado tu inscripción al evento '{evento.eve_nombre}'.")
        return redirect('dashboard_evaluador')




# ========================
# AGREGAR A app_evaluadores/views.py (al final del archivo)
# ========================

from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from django.core.files.base import ContentFile
from django.http import JsonResponse
from datetime import datetime


def generar_certificado_pdf(evaluador, evento):
    """
    Genera un certificado en PDF para un evaluador.
    
    Args:
        evaluador: Instancia de Evaluador
        evento: Instancia de Evento
    
    Returns:
        BytesIO: Buffer con el contenido del PDF
    """
    try:
        # Crear buffer para el PDF
        buffer = BytesIO()
        
        # Crear documento PDF
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )
        
        # Contenedor para los elementos
        elements = []
        
        # Estilos
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor='#1a1a1a',
            spaceAfter=30,
            alignment=1,  # Centrado
        )
        
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=12,
            spaceAfter=12,
            alignment=4,  # Justificado
        )
        
        # Título
        elements.append(Paragraph("CERTIFICADO DE EVALUADOR", title_style))
        elements.append(Spacer(1, 0.3*inch))
        
        # Contenido
        nombre_evaluador = f"{evaluador.usuario.first_name} {evaluador.usuario.last_name}"
        fecha_hoy = datetime.now().strftime("%d de %B de %Y")
        
        contenido = f"""
        <b>Se certifica que:</b><br/>
        {nombre_evaluador}<br/>
        <br/>
        Ha participado como evaluador en el evento:<br/>
        <b>{evento.eve_nombre}</b><br/>
        <br/>
        Realizado en {evento.eve_lugar}, {evento.eve_ciudad}<br/>
        Del {evento.eve_fecha_inicio} al {evento.eve_fecha_fin}<br/>
        <br/>
        El evaluador ha cumplido satisfactoriamente con sus obligaciones de calificación 
        según los criterios establecidos para el evento.<br/>
        <br/>
        Expedido en: {fecha_hoy}
        """
        
        elements.append(Paragraph(contenido, normal_style))
        elements.append(Spacer(1, 0.5*inch))
        
        # Firma
        firma_text = "_" * 40
        elements.append(Paragraph(firma_text, normal_style))
        elements.append(Paragraph("Administrador del Evento", normal_style))
        
        # Construir PDF
        doc.build(elements)
        buffer.seek(0)
        
        return buffer
        
    except Exception as e:
        print(f"Error generando certificado PDF: {str(e)}")
        raise


@method_decorator(evaluador_required, name='dispatch')
class SolicitarCertificadoEvaluadorView(View):
    """
    Vista para que los evaluadores soliciten su certificado.
    
    HU48: Solicitar Certificado de Evaluador
    - CA1.2: Bloquear si tiene calificaciones pendientes
    - CA1.3, CA1.4, CA2.4: Generar y enviar certificado
    - CA2.1: Bloquear si evento no está finalizado
    - CA5: Solo evaluadores pueden acceder
    """
    
    def post(self, request, evento_id):
        try:
            evento = get_object_or_404(Evento, pk=evento_id)
            
            # Obtener evaluador desde el usuario autenticado
            try:
                evaluador = request.user.evaluador
            except:
                return JsonResponse({
                    'error': 'No tienes perfil de evaluador'
                }, status=403)
            
            # CA2.1: Verificar que evento esté finalizado
            if evento.eve_estado not in ["Finalizado", "Cerrado", "Completado"]:
                return JsonResponse({
                    'error': f'El evento aún está en curso. Estado: {evento.eve_estado}. Los certificados solo están disponibles cuando el evento finaliza.'
                }, status=400)
            
            # Verificar que evaluador está registrado en el evento
            try:
                registro_eval = EvaluadorEvento.objects.get(
                    eva_eve_evaluador_fk=evaluador,
                    eva_eve_evento_fk=evento,
                    eva_eve_estado='Aprobado'
                )
            except EvaluadorEvento.DoesNotExist:
                return JsonResponse({
                    'error': 'No estás registrado o aprobado en este evento'
                }, status=403)
            
            # CA1.2: Verificar que evaluador tiene todas las calificaciones
            total_participantes = ParticipanteEvento.objects.filter(
                par_eve_evento_fk=evento,
                par_eve_estado="Aprobado"
            ).count()
            
            calif_hechas = Calificacion.objects.filter(
                cal_evaluador_fk=evaluador,
                cal_criterio_fk__cri_evento_fk=evento
            ).values('cal_participante_fk').distinct().count()
            
            if calif_hechas < total_participantes:
                return JsonResponse({
                    'error': f'Debes completar todas las calificaciones. Actualmente tienes {calif_hechas}/{total_participantes}.'
                }, status=400)
            
            # CA1.3: Generar certificado PDF
            try:
                buffer_pdf = generar_certificado_pdf(evaluador, evento)
                
                # CA1.4: Enviar por correo
                usuario = evaluador.usuario
                
                send_mail(
                    subject=f'Tu Certificado de Evaluador - {evento.eve_nombre}',
                    message=(
                        f'Estimado/a {usuario.first_name},\n\n'
                        f'Tu certificado como evaluador en el evento "{evento.eve_nombre}" '
                        f'ha sido generado exitosamente.\n\n'
                        f'Adjunto encontrarás tu certificado en PDF.\n\n'
                        f'Saludos cordiales,\n'
                        f'Equipo de Eventos'
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[usuario.email],
                    fail_silently=False,
                    attachments=[
                        (f'certificado_{evento.pk}_{datetime.now().strftime("%Y%m%d")}.pdf', 
                         buffer_pdf.getvalue(), 
                         'application/pdf')
                    ]
                )
                
                return JsonResponse({
                    'success': 'Certificado generado y enviado a tu correo exitosamente'
                })
                
            except Exception as e:
                print(f"Error en generación de certificado: {str(e)}")
                return JsonResponse({
                    'error': f'Error al generar certificado: {str(e)}'
                }, status=500)
        
        except Exception as e:
            print(f"Error en SolicitarCertificadoEvaluadorView: {str(e)}")
            return JsonResponse({
                'error': 'Error interno del servidor'
            }, status=500)

