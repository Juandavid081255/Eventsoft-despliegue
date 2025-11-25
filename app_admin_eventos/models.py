from django.db import models


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
    eve_imagen = models.ImageField(upload_to='upload/', verbose_name="Imagen/Logo del Evento")
    eve_administrador_fk = models.ForeignKey('app_usuarios.AdministradorEvento', on_delete=models.CASCADE)
    eve_tienecosto = models.CharField(max_length=45)
    eve_capacidad = models.IntegerField()
    eve_programacion = models.FileField(upload_to='upload/', verbose_name="Archivo de Programación")
    eve_informacion_tecnica = models.FileField(upload_to='upload/', null=True, blank=True, verbose_name="Información Técnica Opcional")
    preinscripcion_habilitada_asistentes = models.BooleanField(default=False)
    preinscripcion_habilitada_participantes = models.BooleanField(default=False)
    preinscripcion_habilitada_evaluadores = models.BooleanField(default=False)
    categorias = models.ManyToManyField(Categoria, through='EventoCategoria')

    def __str__(self):
        return self.eve_nombre

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

