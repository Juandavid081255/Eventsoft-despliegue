from .models import ParticipanteEvento
from app_usuarios.models import Participante

def obtener_proyectos_por_evento(evento):
    """
    Obtiene todos los proyectos (individuales y grupales) de un evento
    Retorna solo los líderes de proyecto (no duplica miembros)
    """
    return ParticipanteEvento.objects.filter(
        par_eve_evento_fk=evento,
        par_eve_proyecto_principal__isnull=True  # Solo líderes
    )

def obtener_miembros_proyecto(participante_evento):
    """
    Obtiene todos los miembros de un proyecto incluyendo el líder
    """
    if participante_evento.par_eve_proyecto_principal:
        # Si es miembro, obtener desde el proyecto principal
        return participante_evento.par_eve_proyecto_principal.get_todos_miembros_proyecto()
    else:
        # Si es líder, obtener todos los miembros
        return participante_evento.get_todos_miembros_proyecto()

def es_lider_proyecto(participante_evento):
    """
    Verifica si un participante es líder de proyecto
    """
    return participante_evento.par_eve_proyecto_principal is None

def obtener_proyecto_principal(participante_evento):
    """
    Obtiene el proyecto principal (líder) de un participante
    """
    if participante_evento.par_eve_proyecto_principal:
        return participante_evento.par_eve_proyecto_principal
    else:
        return participante_evento  # Es el líder

def contar_miembros_proyecto(participante_evento):
    """
    Cuenta el total de miembros de un proyecto (incluyendo líder)
    """
    proyecto_principal = obtener_proyecto_principal(participante_evento)
    return 1 + proyecto_principal.miembros_proyecto.count()  # 1 (líder) + miembros

def obtener_participantes_por_codigo_proyecto(codigo_proyecto, evento):
    """
    Obtiene todos los participantes de un proyecto por código
    """
    return ParticipanteEvento.objects.filter(
        par_eve_codigo_proyecto=codigo_proyecto,
        par_eve_evento_fk=evento
    )

def obtener_estadisticas_evento(evento):
    """
    Obtiene estadísticas de participación de un evento
    """
    proyectos_individuales = ParticipanteEvento.objects.filter(
        par_eve_evento_fk=evento,
        par_eve_es_grupo=False
    ).count()
    
    proyectos_grupales = ParticipanteEvento.objects.filter(
        par_eve_evento_fk=evento,
        par_eve_es_grupo=True,
        par_eve_proyecto_principal__isnull=True  # Solo líderes
    ).count()
    
    total_participantes = ParticipanteEvento.objects.filter(
        par_eve_evento_fk=evento
    ).count()
    
    return {
        'proyectos_individuales': proyectos_individuales,
        'proyectos_grupales': proyectos_grupales,
        'total_proyectos': proyectos_individuales + proyectos_grupales,
        'total_participantes': total_participantes
    }







# tu_app/utils.py

from django.core.mail import EmailMessage
from django.conf import settings
import os
from django.template.loader import render_to_string # Opcional: usar template HTML para el cuerpo del correo

def send_mail_participante_grupo(to_email, event_name, group_name, username, password, clave_acceso, qr_file_path):
    """
    Envía un correo electrónico al nuevo participante de un grupo con sus credenciales 
    y el código QR de acceso.

    Args:
        to_email (str): Correo electrónico del destinatario.
        event_name (str): Nombre del evento al que ha sido asignado.
        group_name (str): Nombre del grupo/rol asignado ('PARTICIPANTE').
        username (str): Nombre de usuario para iniciar sesión.
        password (str): Contraseña temporal generada.
        clave_acceso (str): Clave de acceso específica del evento.
        qr_file_path (str): Ruta completa al archivo QR guardado en el sistema de archivos.
    """
    
    # 1. Definir el asunto y el cuerpo del mensaje
    subject = f"¡Asignación Exitosa! Acceso a {event_name} - {group_name}"
    
    # Puedes usar un template HTML para un correo más profesional:
    # html_content = render_to_string('emails/participante_asignado.html', {
    #     'username': username,
    #     'password': password,
    #     'clave_acceso': clave_acceso,
    #     'event_name': event_name,
    #     'group_name': group_name,
    #     # ... otros datos
    # })
    
    # Usando un cuerpo de texto plano por simplicidad:
    body = f"""
    ¡Hola Exponente {username}!

    Has sido exitosamente asignado como miembro del grupo en el evento - {event_name}.
    Tus credenciales de acceso a la plataforma son:
    
    - Usuario: {username}
    - Contraseña: {password}
    
    Tu clave de acceso específica para este evento es: **{clave_acceso}**
    Adjunto a este correo encontrarás tu Código QR para un acceso rápido al evento.
    Por favor, cambia tu contraseña al iniciar sesión por primera vez.
    ¡Te esperamos!
    
    Equipo de Exponente-Eventos | Event-Soft
    """
    
    # 2. Crear el objeto EmailMessage
    email = EmailMessage(
        subject,
        body,
        settings.EMAIL_HOST_USER,  # Remitente (definido en settings.py)
        [to_email],                # Destinatario
    )
    
    # Si usas HTML:
    # email.content_subtype = "html"
    # email.attach_alternative(html_content, "text/html")

    # 3. Adjuntar el archivo QR
    if os.path.exists(qr_file_path):
        email.attach_file(qr_file_path)
    else:
        # Esto solo sirve como alerta, idealmente el QR ya está guardado.
        print(f"Advertencia: No se encontró el archivo QR en la ruta: {qr_file_path}")

    # 4. Enviar el correo
    try:
        email.send()
        return True
    except Exception as e:
        print(f"Error al enviar correo a {to_email}: {e}")
        return False