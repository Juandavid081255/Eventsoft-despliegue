"""Como visitante web (Asistente), quiero Ver los diferentes eventos próximos a realizarse 
para Saber si existe algún evento de mi interés """

from django.test import TestCase, Client
from django.urls import reverse
from datetime import date, datetime, timedelta
from unittest.mock import patch
from django.db.models import Q 
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db.models.manager import BaseManager

# ----------------------------------------------------------------------
# ASUNCIONES DE MODELOS (Necesarias para que la prueba se ejecute)
# ----------------------------------------------------------------------
# NOTA: Asegúrate de que las importaciones reales de tus modelos sean funcionales.
try:
    from app_admin_eventos.models import Evento, Area, Categoria
    from app_usuarios.models import AdministradorEvento, Usuario
except ImportError:
    # Usar clases de simulación si el entorno de prueba no las carga automáticamente.
    print("WARNING: Usando clases dummy para modelos. Asegúrese de que las rutas son correctas.")
    class Usuario:
        @staticmethod
        def objects(): return type('Manager', (object,), {'get_or_create': lambda **k: (type('U', (object,), {'id':1})(), True)})()
    class AdministradorEvento:
        @staticmethod
        def objects(): return type('Manager', (object,), {'get_or_create': lambda **k: (type('AE', (object,), {'id':'A1'})(), True)})()
    class Area: 
        objects = type('Manager', (object,), {'create': lambda **k: type('A', (object,), {'id':k.get('id',1)})()})
    class Categoria:
        objects = type('Manager', (object,), {'create': lambda **k: type('C', (object,), {'id':k.get('id',1)})()})
    class Evento:
        class Manager(BaseManager):
            def filter(self, *args, **kwargs): return self
            def update(self, **kwargs): return 1
            def order_by(self, *args): return self
            def distinct(self): return self
            def refresh_from_db(self): pass
            
            def create(self, **kwargs): 
                obj = type('E', (object,), kwargs)
                obj.refresh_from_db = self.refresh_from_db
                obj.categorias = type('CatMan', (object,), {'add': lambda x: None})()
                obj.save = lambda: None
                obj.eve_estado = kwargs.get('eve_estado', 'Publicado')
                return obj
            
        objects = Manager()
        

# 📌 RUTA DE MOCKEO: AJUSTAR SI LA VISTA NO ESTÁ EN 'app_asistentes.views'
MOCK_NOW_PATH = 'app_asistentes.views.now' 


# --- SETUP HELPERS ---
def setup_administrador():
    usuario, _ = Usuario.objects.get_or_create(username='admin_filter', rol='ADMIN_EVENTO')
    return AdministradorEvento.objects.get_or_create(usuario=usuario)[0]

def create_evento(admin, nombre, tienecosto, capacidad, habilitado_asi=True, estado="Publicado", fecha_inicio=date.today() + timedelta(days=10)):
    dummy_file = SimpleUploadedFile("dummy.pdf", b"c", content_type="application/pdf")
    dummy_image = SimpleUploadedFile("dummy.jpg", b"c", content_type="image/jpeg")
    
    return Evento.objects.create(
        eve_nombre=nombre, eve_descripcion="Desc", eve_ciudad="Ciudad", eve_lugar="Lugar",
        eve_fecha_inicio=fecha_inicio,
        eve_fecha_fin=fecha_inicio + timedelta(days=2),
        eve_estado=estado, 
        eve_imagen=dummy_image,
        eve_administrador_fk=admin, eve_tienecosto=tienecosto, eve_capacidad=capacidad,
        eve_programacion=dummy_file,
        preinscripcion_habilitada_asistentes=habilitado_asi
    )


class EventoFiltradoVisitanteTest(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.admin = setup_administrador()
        cls.url = reverse('pagina_principal') 

        # 📌 FECHA FIJA DE PRUEBA: Usamos una fecha conocida para la prueba de actualización
        cls.FECHA_DE_PRUEBA = date(2099, 1, 15) 
        
        # 1. Configuración de Áreas y Categorías
        cls.area_ciencia = Area.objects.create(id=10, are_nombre="Ciencia", are_descripcion="...")
        cls.area_arte = Area.objects.create(id=20, are_nombre="Arte", are_descripcion="...")
        
        cls.cat_fisica = Categoria.objects.create(id=100, cat_nombre="Física", cat_area_fk=cls.area_ciencia)
        cls.cat_pintura = Categoria.objects.create(id=200, cat_nombre="Pintura", cat_area_fk=cls.area_arte)

        # 2. Creación de Eventos
        
        # Evento de referencia para filtros
        cls.evento_publico_gratis_ciencia = create_evento(
            cls.admin, "TALLER de Fisica", 'No tiene costo', 100, True, estado="Publicado",
            fecha_inicio=cls.FECHA_DE_PRUEBA + timedelta(days=5)
        )
        cls.evento_publico_gratis_ciencia.categorias.add(cls.cat_fisica)
        
        # Evento para filtro de Costo
        cls.evento_pago_arte = create_evento(
            cls.admin, "Conferencia de Arte", 'De pago', 50, True, estado="Publicado",
            fecha_inicio=cls.FECHA_DE_PRUEBA + timedelta(days=15)
        )
        cls.evento_pago_arte.categorias.add(cls.cat_pintura)
        
        # CP-2.4 (Actualización de Estado - Evento que debe finalizar en la fecha fija)
        cls.evento_termina_hoy = create_evento(
            cls.admin, "Seminario Finalizando", 'No tiene costo', 50, True, estado="Publicado",
            fecha_inicio=cls.FECHA_DE_PRUEBA - timedelta(days=1)
        )
        cls.evento_termina_hoy.eve_fecha_fin = cls.FECHA_DE_PRUEBA # La fecha final es la fecha fija
        cls.evento_termina_hoy.save()

    def setUp(self):
        self.client = Client()
        
    

    # --- CP-2.1: Verificar filtro por Nombre (CA-2.1) ---
    def test_cp_2_1_filtro_por_nombre_icontains(self):
        """Verifica el filtro por nombre parcial e insensible a mayúsculas."""
        response = self.client.get(self.url, {'nombre': 'taller'}) 
        eventos_filtrados = response.context.get('eventos')
        self.assertEqual(len(eventos_filtrados), 1)

    # --- CP-2.2: Verificar filtro por Costo (CA-2.2) ---
    def test_cp_2_2_filtro_por_costo_iexact(self):
        """Verifica que el filtro por costo sea exacto e insensible a mayúsculas."""
        response = self.client.get(self.url, {'costo': 'De pago'}) 
        eventos_filtrados = response.context.get('eventos')
        nombres_eventos = [e.eve_nombre for e in eventos_filtrados]
        
        self.assertIn(self.evento_pago_arte.eve_nombre, nombres_eventos)
        self.assertNotIn(self.evento_publico_gratis_ciencia.eve_nombre, nombres_eventos)

    # --- CP-2.3: Verificar filtro por Área (CA-2.3) ---
    def test_cp_2_3_filtro_por_area_complejo(self):
        """Verifica el filtro complejo basado en el ID del Área."""
        response = self.client.get(self.url, {'area': self.area_ciencia.id}) 
        eventos_filtrados = response.context.get('eventos')
        self.assertEqual(len(eventos_filtrados), 1)
        self.assertEqual(eventos_filtrados[0].eve_nombre, self.evento_publico_gratis_ciencia.eve_nombre)

    # --- CP-2.5: Verificar aplicación de múltiples filtros (CA-2.5) ---
    def test_cp_2_5_aplicacion_multiples_filtros(self):
        """Verifica que la combinación de Nombre, Ciudad y Estado funcione correctamente."""
        
        filtros = {
            'nombre': 'taller', 
            'ciudad': 'Ciudad', 
            'estado': 'Publicado' 
        }
        response = self.client.get(self.url, filtros) 
        
        eventos_filtrados = response.context.get('eventos')
        self.assertEqual(len(eventos_filtrados), 1, "La combinación de filtros no devolvió el evento esperado.")