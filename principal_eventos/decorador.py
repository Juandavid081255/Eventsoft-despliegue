from functools import wraps
from django.shortcuts import redirect

def redirigir_por_rol_sesion(session):
    if session.get('admin_id'):
        return redirect('dashboard_admin')
    elif session.get('evaluador_id'):
        return redirect('dashboard_evaluador')
    elif session.get('participante_id'):
        return redirect('dashboard_participante')
    elif session.get('asistente_id'):
        return redirect('dashboard_asistente')
    return redirect('login_view')

def admin_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('admin_id'):
            return redirigir_por_rol_sesion(request.session)
        return view_func(request, *args, **kwargs)
    return wrapper

def evaluador_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('evaluador_id'):
            return redirigir_por_rol_sesion(request.session)
        return view_func(request, *args, **kwargs)
    return wrapper

def participante_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('participante_id'):
            return redirigir_por_rol_sesion(request.session)
        return view_func(request, *args, **kwargs)
    return wrapper

def asistente_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('asistente_id'):
            return redirigir_por_rol_sesion(request.session)
        return view_func(request, *args, **kwargs)
    return wrapper

def visitor_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # Si el usuario tiene sesión activa con algún rol, redirigirlo a su dashboard
        if request.session.get('admin_id') or \
           request.session.get('evaluador_id') or \
           request.session.get('participante_id') or \
           request.session.get('asistente_id'):
            return redirigir_por_rol_sesion(request.session)
        # Si no hay sesión activa, puede continuar como visitante
        return view_func(request, *args, **kwargs)
    return wrapper