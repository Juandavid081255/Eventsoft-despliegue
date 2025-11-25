from django import forms
from .models import Usuario


class RegistroAdministradorForm(forms.ModelForm):
    class Meta:
        model = Usuario
        fields = ['username', 'first_name', 'last_name', 'cedula', 'telefono', 'email']
        labels = {
            'username': 'Nombre de usuario',
            'first_name': 'Nombre',
            'last_name': 'Apellido',
            'cedula': 'Cédula',
            'telefono': 'Teléfono',
            'email': 'Correo electrónico',
        }

    def __init__(self, *args, **kwargs):
        email_fijo = kwargs.pop('email_fijo', None)
        super().__init__(*args, **kwargs)

        # 🔒 Hace que todos los campos sean obligatorios
        for field in self.fields.values():
            field.required = True
            field.widget.attrs.update({
                'class': 'form-control',
                'placeholder': f'Ingresa {field.label.lower()}',
            })

        # Si el correo viene fijo por invitación, lo bloquea
        if email_fijo:
            self.fields['email'].initial = email_fijo
            self.fields['email'].disabled = True
