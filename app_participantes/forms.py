from django import forms
from app_usuarios.models import Usuario, Participante
from .models import ParticipanteEvento
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django import forms
from app_participantes.models import ParticipanteEvento


class ParticipanteEventoEditForm(forms.ModelForm):
    """
    Formulario SIMPLE para editar solo la clave del participante.
    Usado por EditarPreinscripcionView (HU15 - Tests).
    
    Este es un formulario minimalista que solo toca par_eve_clave.
    No confundir con el flujo de edición completa de perfil+documentos.
    """
    
    class Meta:
        model = ParticipanteEvento
        fields = ['par_eve_clave']
        labels = {
            'par_eve_clave': 'Clave de Participante'
        }
        widgets = {
            'par_eve_clave': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Ingresa tu clave',
                'maxlength': '45'
            })
        }
    
    def clean_par_eve_clave(self):
        """Validar que la clave no esté vacía."""
        clave = self.cleaned_data.get('par_eve_clave', '').strip()
        if not clave:
            raise forms.ValidationError("La clave no puede estar vacía")
        if len(clave) > 45:
            raise forms.ValidationError("La clave no puede exceder 45 caracteres")
        return clave
# Obtenemos el modelo de Usuario
UserModel = get_user_model() 

class ParticipanteForm(forms.ModelForm):
    # Campos que corresponden al modelo Usuario o campos extra
    cedula = forms.CharField(
        label="Cédula",
        max_length=20,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Ingresa tu número de cédula',
            'required': True
        })
    )

    username = forms.CharField(
        label="Nombre de usuario",
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Nombre de usuario',
            'required': True
        })
    )

    email = forms.EmailField(
        label="Correo electrónico",
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'tu@email.com',
            'required': True
        })
    )

    telefono = forms.CharField(
        label="Teléfono",
        max_length=15,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Número de teléfono',
            'required': True
        })
    )

    first_name = forms.CharField(
        label="Nombre",
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Tu nombre',
            'required': True
        })
    )

    last_name = forms.CharField(
        label="Apellido",
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Tu apellido',
            'required': True
        })
    )

    # El campo de archivo (pertenece a ParticipanteEvento)
    par_eve_documentos = forms.FileField(
        label="Documento de Exposición (solo PDF)", 
        required=True, 
        widget=forms.ClearableFileInput(attrs={
            'class': 'form-control',
            'accept': 'application/pdf'
        })
    )

    class Meta:
        model = Participante
        # CORRECCIÓN PARA EVITAR ImproperlyConfigured: 
        # Indicamos que no debe usar campos automáticos del modelo Participante.
        fields = [] 

    def __init__(self, *args, **kwargs):
        self.evento = kwargs.pop('evento', None)
        super().__init__(*args, **kwargs)

    def clean_par_eve_documentos(self):
        documento = self.files.get('par_eve_documentos')
        if not documento:
            raise forms.ValidationError("Debe cargar el documento para continuar.")
            
        if not documento.content_type.startswith('application/pdf'):
            raise forms.ValidationError("Solo se permiten archivos en formato PDF.")
        return documento

    def clean_cedula(self):
        cedula = self.cleaned_data.get('cedula')
        # La validación de unicidad estricta para el campo 'cedula' se maneja
        # si es un usuario nuevo.
        return cedula
    

    def clean(self):
        cleaned_data = super().clean()
        cedula = cleaned_data.get('cedula')
        evento = self.evento
        
        # Validar si el usuario ya está inscrito en el evento
        if cedula and evento:
            try:
                usuario_existente = UserModel.objects.get(cedula=cedula)
                if Participante.objects.filter(usuario=usuario_existente).exists():
                    participante_existente = Participante.objects.get(usuario=usuario_existente)
                    if ParticipanteEvento.objects.filter(
                        par_eve_participante_fk=participante_existente, 
                        par_eve_evento_fk=evento
                    ).exists():
                        raise forms.ValidationError(
                            {'cedula': f"Ya existe un participante con la cédula {cedula} registrado para el evento '{evento.eve_nombre}'."}
                        )
                
            except UserModel.DoesNotExist:
                pass # Es un usuario nuevo, no hay conflicto de inscripción previa.

        return cleaned_data


# Form para editar
class EditarUsuarioParticipanteForm(forms.ModelForm):
    class Meta:
        model = Usuario
        fields = ['first_name', 'last_name', 'telefono']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'telefono': forms.TextInput(attrs={'class': 'form-control'}),
        }



# app_eventos/forms.py o donde estén tus formularios

class MiembroParticipanteForm(forms.Form): # Usar forms.Form o forms.ModelForm del Usuario
    # NO heredamos de ModelForm de Participante, solo definimos los campos
    # Necesarios para el Usuario.

    # Usar get_user_model() si Usuario es el modelo de usuario custom de Django
    # Si Usuario es un modelo que extiende, sigue con UserModel
    # Usaremos forms.Form para mayor simplicidad en un formulario que solo crea un objeto.
    
    cedula = forms.CharField(
        label="Cédula", max_length=20,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Ingresa tu número de cédula', 'required': True})
    )

    username = forms.CharField(
        label="Nombre de usuario",
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Nombre de usuario', 'required': True})
    )

    email = forms.EmailField(
        label="Correo electrónico",
        widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'tu@email.com', 'required': True})
    )

    telefono = forms.CharField(
        label="Teléfono", max_length=15,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Número de teléfono', 'required': True})
    )

    first_name = forms.CharField(
        label="Nombre",
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Tu nombre', 'required': True})
    )

    last_name = forms.CharField(
        label="Apellido",
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Tu apellido', 'required': True})
    )
    
    # Aquí puedes añadir un clean_ para la validación de si el usuario
    # ya está en el evento, o dejar esa lógica en la vista, como ya lo tienes.
    
    # NOTA: En este nuevo Form, ¡DEBES ELIMINAR TODA REFERENCIA A par_eve_documentos!