from datetime import timezone
from django import forms
from .models import Evento, Categoria, Area
from app_usuarios.models import Usuario



class EventoForm(forms.ModelForm):
    area = forms.ModelChoiceField(
        queryset=Area.objects.all(),
        required=True,
        label="Área"
    )

    categorias = forms.ModelMultipleChoiceField(
        queryset=Categoria.objects.all(),
        widget=forms.SelectMultiple(attrs={'class': 'form-control', 'id': 'id_categoria'}),
        required=True,
        label="Categorías"
    )


    eve_fecha_inicio = forms.DateField(
        widget=forms.DateInput(
            attrs={'type': 'date', 'class': 'form-control'},
            format='%Y-%m-%d'
        ),
        input_formats=['%Y-%m-%d'],
        required=True
    )

    eve_fecha_fin = forms.DateField(
        widget=forms.DateInput(
            attrs={'type': 'date', 'class': 'form-control'},
            format='%Y-%m-%d'
        ),
        input_formats=['%Y-%m-%d'],
        required=True
    )

    class Meta:
        model = Evento
        fields = [
            'eve_nombre', 'eve_descripcion', 'eve_ciudad', 'eve_lugar', 'eve_fecha_inicio',
            'eve_fecha_fin', 'eve_estado', 'eve_imagen', 'eve_tienecosto',
            'eve_capacidad', 'eve_programacion'
        ]
        labels = {
            'eve_nombre': 'Título del evento',
            'eve_descripcion': 'Descripción',
            'eve_ciudad': 'Ciudad',
            'eve_lugar': 'Lugar',
            'eve_fecha_inicio': 'Fecha de inicio',
            'eve_fecha_fin': 'Fecha de fin',
            'eve_estado': 'Estado',
            'eve_imagen': 'Imagen del evento',
            'eve_tienecosto': '¿Tiene costo?',
            'eve_capacidad': 'Capacidad de personas',
            'eve_programacion': 'Archivo de programación',
        }
        widgets = {
            'eve_nombre': forms.TextInput(attrs={'class': 'form-control'}),
            'eve_descripcion': forms.Textarea(attrs={'class': 'form-control'}),
            'eve_ciudad': forms.TextInput(attrs={'class': 'form-control'}),
            'eve_lugar': forms.TextInput(attrs={'class': 'form-control'}),
            'eve_fecha_inicio': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'eve_fecha_fin': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'eve_estado': forms.TextInput(attrs={'class': 'form-control'}),
            'eve_imagen': forms.ClearableFileInput(attrs={'class': 'form-control-file'}),
            'eve_programacion': forms.ClearableFileInput(attrs={'class': 'form-control-file'}),
            'eve_capacidad': forms.NumberInput(attrs={'class': 'form-control'}),
            'eve_tienecosto': forms.Select(attrs={'class': 'form-control'}),
        }


        def clean(self):
            cleaned_data = super().clean()
            fecha_inicio = cleaned_data.get('eve_fecha_inicio')
            fecha_fin = cleaned_data.get('eve_fecha_fin')
            hoy = timezone.localdate()

            if fecha_inicio and fecha_inicio < hoy:
                self.add_error('eve_fecha_inicio', 'La fecha de inicio no puede ser anterior a hoy.')

            if fecha_fin and fecha_fin < hoy:
                self.add_error('eve_fecha_fin', 'La fecha de finalización no puede ser anterior a hoy.')

            if fecha_inicio and fecha_fin and fecha_fin < fecha_inicio:
                self.add_error('eve_fecha_fin', 'La fecha de finalización no puede ser anterior a la fecha de inicio.')

            return cleaned_data


class EditarUsuarioAdministradorForm(forms.ModelForm):
    class Meta:
        model = Usuario
        fields = ['username', 'first_name', 'last_name', 'telefono']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Ingrese nombre de usuario', 'readonly': True}),
            'first_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Ingrese su nombre'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Ingrese su apellido'}),
            'telefono': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Ingrese su teléfono', 'type': 'number'}),
        }


    



class CategoriaForm(forms.ModelForm):
    class Meta:
        model = Categoria
        fields = ["cat_nombre", "cat_descripcion", "cat_area_fk"]
        labels = {
            "cat_nombre": "Nombre de la Categoría",
            "cat_descripcion": "Descripción de la Categoría",
            "cat_area_fk": "Área",
        }
        widgets = {
            "cat_descripcion": forms.Textarea(attrs={"rows": 3}),
        }
