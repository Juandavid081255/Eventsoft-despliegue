from django.db import models
from cloudinary.models import CloudinaryField


class Area(models.Model):
    are_nombre = models.CharField(max_length=45)
    are_descripcion = models.CharField(max_length=400)

    def __str__(self):
        return self.are_nombre

class Categoria(models.Model):
    cat_nombre = models.CharField(max_length=45)
    cat_descripcion = models.CharField(max_length=400)
    cat_area_fk = models.ForeignKey(Area, on_delete=models.CASCADE)

    def __str__(self):
        return self.cat_nombre

class Evento(models.Model):
    eve_nombre = models.CharField(max_length=100)
    eve_descripcion = models.CharField(max_length=520)
    eve_ciudad = models.CharField(max_length=45)
    eve_lugar = models.CharField(max_length=100)
    eve_fecha_inicio = models.DateField()
    eve_fecha_fin = models.DateField()
    eve_estado = models.CharField(max_length=45)
    
    eve_imagen = CloudinaryField(
        "imegen/Logo del evento",
        folder="eventos/imagenes/",
        resource_type="image",
    )
    eve_administrador_fk = models.ForeignKey('app_usuarios.AdministradorEvento', on_delete=models.CASCADE)
    eve_tienecosto = models.CharField(max_length=45)
    eve_capacidad = models.IntegerField()


    eve_programacion = CloudinaryField(
        "Archivo de programacion",
        folder="eventos/archivos/",
        resource_type="raw",

    )

    eve_informacion_tecnica = CloudinaryField(
        "Archivo de informacion tecnica",
        folder="eventos/archivos/",
        resource_type="raw",
        blank=True,
        null=True,
    )

    preinscripcion_habilitada_asistentes = models.BooleanField(default=False)
    preinscripcion_habilitada_participantes = models.BooleanField(default=False)
    preinscripcion_habilitada_evaluadores = models.BooleanField(default=False)
    categorias = models.ManyToManyField(Categoria, through='EventoCategoria')

    def __str__(self):
        return self.eve_nombre
    

    def get_programacion_url_inline(self):
        """Retorna URL de Cloudinary para visualizar PDF en navegador"""
        if self.eve_programacion:
            return f"{self.eve_programacion.url}?fl_inline"
        return None

    def get_programacion_url_download(self):
        """Retorna URL de Cloudinary para descargar PDF"""
        if self.eve_programacion:
            return f"{self.eve_programacion.url}?fl_attachment"
        return None

    def get_informacion_tecnica_url_inline(self):
        """Retorna URL de Cloudinary para visualizar PDF técnico en navegador"""
        if self.eve_informacion_tecnica:
            return f"{self.eve_informacion_tecnica.url}?fl_inline"
        return None

    def get_informacion_tecnica_url_download(self):
        """Retorna URL de Cloudinary para descargar PDF técnico"""
        if self.eve_informacion_tecnica:
            return f"{self.eve_informacion_tecnica.url}?fl_attachment"
        return None

    def tiene_programacion(self):
        """Verifica si el evento tiene archivo de programación"""
        return bool(self.eve_programacion)

    def tiene_informacion_tecnica(self):
        """Verifica si el evento tiene archivo de información técnica"""
        return bool(self.eve_informacion_tecnica)
   

class EventoCategoria(models.Model):
    eve_cat_evento_fk = models.ForeignKey(Evento, on_delete=models.CASCADE)
    eve_cat_categoria_fk = models.ForeignKey(Categoria, on_delete=models.CASCADE)

class Criterio(models.Model):
    cri_descripcion = models.CharField(max_length=150)
    cri_peso = models.FloatField()
    cri_evento_fk = models.ForeignKey(Evento, on_delete=models.CASCADE)

    def __str__(self):
        return self.cri_descripcion
    
class MemoriaEvento(models.Model):
    
    evento = models.ForeignKey(Evento, on_delete=models.CASCADE, related_name='memorias')
    nombre = models.CharField(max_length=100, help_text="Texto descriptivo para el archivo")
    archivo = models.FileField(upload_to='upload/')
    subido_en = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.nombre} ({self.evento.eve_nombre})"

