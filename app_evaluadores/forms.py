from django import forms
from app_usuarios.models import Usuario, Evaluador
from app_evaluadores.models import EvaluadorEvento



class EvaluadorForm(forms.ModelForm):
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
            'required': True,
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

    eva_eve_documento = forms.FileField(
        label="Comprobante de pago (solo PDF)",
        required=False,
        widget=forms.ClearableFileInput(attrs={
            'class': 'form-control',
            'accept': 'application/pdf'
        })
    )

    class Meta:
        model = Evaluador
        fields = ['cedula', 'first_name', 'last_name', 'email', 'telefono', 'username']

    def __init__(self, *args, **kwargs):
        self.evento = kwargs.pop('evento', None)
        super().__init__(*args, **kwargs)

    def clean_eva_eve_documento(self):
        soporte = self.files.get('eva_eve_documento')
        if soporte and not soporte.content_type.startswith('application/pdf'):
            raise forms.ValidationError("Solo se permiten archivos pdf (pdf).")
        return soporte


    

# Form para editar
class EditarUsuarioEvaluadorForm(forms.ModelForm):
    class Meta:
        model = Usuario
        fields = ['first_name', 'last_name', 'telefono']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'telefono': forms.TextInput(attrs={'class': 'form-control'}),
        }
