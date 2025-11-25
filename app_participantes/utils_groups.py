from django.contrib.auth.models import Group, User
from .models import ParticipanteEvento
from app_usuarios.models import Usuario

def obtener_usuarios_grupo_proyecto(codigo_proyecto, evento):
    """
    Obtiene todos los usuarios de un grupo proyecto por código
    """
    participantes_evento = ParticipanteEvento.objects.filter(
        par_eve_codigo_proyecto=codigo_proyecto,
        par_eve_evento_fk=evento
    )
    
    usuarios = []
    for pe in participantes_evento:
        usuarios.append(pe.par_eve_participante_fk.usuario)
    
    return usuarios

def obtener_grupo_django_por_codigo(codigo_proyecto, evento_nombre):
    """
    Obtiene el grupo de Django por código de proyecto
    """
    nombre_grupo = f"Proyecto_{codigo_proyecto}_{evento_nombre[:20]}"
    try:
        return Group.objects.get(name=nombre_grupo)
    except Group.DoesNotExist:
        return None

def agregar_usuario_a_grupo_proyecto(usuario, codigo_proyecto, evento_nombre):
    """
    Agrega un usuario a un grupo proyecto existente
    """
    grupo = obtener_grupo_django_por_codigo(codigo_proyecto, evento_nombre)
    if grupo:
        usuario.groups.add(grupo)
        return True
    return False

def remover_usuario_de_grupo_proyecto(usuario, codigo_proyecto, evento_nombre):
    """
    Remueve un usuario de un grupo proyecto
    """
    grupo = obtener_grupo_django_por_codigo(codigo_proyecto, evento_nombre)
    if grupo:
        usuario.groups.remove(grupo)
        return True
    return False

def listar_grupos_proyecto_usuario(usuario):
    """
    Lista todos los grupos proyecto a los que pertenece un usuario
    """
    grupos = usuario.groups.filter(name__startswith='Proyecto_')
    return grupos

def obtener_miembros_grupo_django(grupo):
    """
    Obtiene todos los usuarios que pertenecen a un grupo de Django
    """
    return grupo.user_set.all()

def eliminar_grupo_proyecto_completo(codigo_proyecto, evento_nombre):
    """
    Elimina completamente un grupo proyecto y sus relaciones
    """
    grupo = obtener_grupo_django_por_codigo(codigo_proyecto, evento_nombre)
    if grupo:
        # Remover todos los usuarios del grupo
        grupo.user_set.clear()
        # Eliminar el grupo
        grupo.delete()
        return True
    return False

def obtener_estadisticas_grupos_evento(evento):
    """
    Obtiene estadísticas de los grupos de un evento
    """
    proyectos_grupales = ParticipanteEvento.objects.filter(
        par_eve_evento_fk=evento,
        par_eve_es_grupo=True,
        par_eve_proyecto_principal__isnull=True  # Solo líderes
    )
    
    estadisticas = {
        'total_grupos': proyectos_grupales.count(),
        'grupos_detalle': []
    }
    
    for proyecto in proyectos_grupales:
        miembros = proyecto.get_todos_miembros_proyecto()
        grupo_django = obtener_grupo_django_por_codigo(
            proyecto.par_eve_codigo_proyecto, 
            evento.eve_nombre
        )
        
        estadisticas['grupos_detalle'].append({
            'codigo_proyecto': proyecto.par_eve_codigo_proyecto,
            'lider': f"{proyecto.par_eve_participante_fk.usuario.first_name} {proyecto.par_eve_participante_fk.usuario.last_name}",
            'total_miembros': len(miembros),
            'grupo_django': grupo_django.name if grupo_django else None,
            'grupo_django_id': grupo_django.id if grupo_django else None
        })
    
    return estadisticas

def verificar_integridad_grupos(evento):
    """
    Verifica que todos los proyectos grupales tengan su correspondiente grupo de Django
    """
    proyectos_grupales = ParticipanteEvento.objects.filter(
        par_eve_evento_fk=evento,
        par_eve_es_grupo=True,
        par_eve_proyecto_principal__isnull=True
    )
    
    problemas = []
    
    for proyecto in proyectos_grupales:
        grupo_django = obtener_grupo_django_por_codigo(
            proyecto.par_eve_codigo_proyecto, 
            evento.eve_nombre
        )
        
        if not grupo_django:
            problemas.append({
                'tipo': 'grupo_faltante',
                'codigo_proyecto': proyecto.par_eve_codigo_proyecto,
                'lider': proyecto.par_eve_participante_fk.usuario.username
            })
        else:
            # Verificar que todos los miembros estén en el grupo Django
            miembros_proyecto = proyecto.get_todos_miembros_proyecto()
            miembros_grupo_django = set(grupo_django.user_set.all())
            
            for miembro in miembros_proyecto:
                usuario = miembro.par_eve_participante_fk.usuario
                if usuario not in miembros_grupo_django:
                    problemas.append({
                        'tipo': 'miembro_faltante_en_grupo',
                        'codigo_proyecto': proyecto.par_eve_codigo_proyecto,
                        'usuario_faltante': usuario.username
                    })
    
    return problemas