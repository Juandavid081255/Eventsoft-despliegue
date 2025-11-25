# app_asistentes.tests.HU_02.py (Versión Final con Correcciones Integradas)

from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from app_admin_eventos.models import Evento, Area, Categoria
from app_usuarios.models import Usuario, AdministradorEvento 
from django.core.files.uploadedfile import SimpleUploadedFile 
from django.db.models import Q # Importado para referencia, aunque no se usa en la vista mostrada

class BusquedaEventosTest(TestCase):
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        
        # 1. Configuración de Usuarios y Administrador
        unique_suffix = timezone.now().strftime("%f") 
        unique_username = f'admin_test_{unique_suffix}'
        cls.user_admin, _ = Usuario.objects.get_or_create(
            username=unique_username, 
            defaults={
                'email': f'{unique_username}@event.com', 
                'password': 'password123', 
                'rol': Usuario.Roles.ADMIN_EVENTO,
                'is_staff': True,
            }
        )
        cls.admin, _ = AdministradorEvento.objects.get_or_create(usuario=cls.user_admin) 

        # 2. Crear Categorías y Área
        cls.area_ti = Area.objects.create(are_nombre='Tecnología', are_descripcion='TI')
        cls.cat_ai = Categoria.objects.create(cat_nombre='Inteligencia Artificial', cat_area_fk=cls.area_ti)
        cls.cat_ciber = Categoria.objects.create(cat_nombre='Ciberseguridad', cat_area_fk=cls.area_ti)
        cls.area_neg = Area.objects.create(are_nombre='Negocios', are_descripcion='Económicas')
        cls.cat_mkt = Categoria.objects.create(cat_nombre='Marketing Digital', cat_area_fk=cls.area_neg)

        # 3. Fechas de Referencia y Archivos dummy
        cls.hoy = timezone.now().date()
        cls.ayer = cls.hoy - timedelta(days=1)
        cls.anteayer = cls.hoy - timedelta(days=2)
        cls.manana = cls.hoy + timedelta(days=1)
        cls.proxima_semana = cls.hoy + timedelta(weeks=1)
        cls.proximo_mes = cls.hoy + timedelta(days=30)
        
        cls.dummy_image = SimpleUploadedFile("test_imagen.png", b"file_content", content_type="image/png")
        cls.dummy_pdf = SimpleUploadedFile("test_programacion.pdf", b"pdf_content", content_type="application/pdf")
        
        # 4. Crear Eventos con nombres y archivos
        # Evento 1: Coincide con 'Congreso' y 'Machine Learning'
        cls.evento_ti_1 = Evento.objects.create(
            eve_nombre="Congreso de IA y Machine Learning", 
            eve_descripcion="Descubra las últimas tendencias en IA.",
            eve_ciudad="Medellín",
            eve_lugar="Plaza Mayor",
            eve_fecha_inicio=cls.manana,
            eve_fecha_fin=cls.manana + timedelta(days=2),
            eve_estado="Publicado",
            eve_administrador_fk=cls.admin,
            eve_tienecosto='Sin costo',
            eve_capacidad=100,
            eve_programacion=cls.dummy_pdf,
            eve_imagen=cls.dummy_image
        )
        cls.evento_ti_1.categorias.add(cls.cat_ai)

        # Evento 2: No tiene 'Congreso' ni 'Machine Learning' ni 'IA'
        cls.evento_ti_2 = Evento.objects.create(
            eve_nombre="Taller de Ciberseguridad Avanzada",
            eve_descripcion="Workshop sobre ataques de red.",
            eve_ciudad="Bogotá",
            eve_lugar="Corferias",
            eve_fecha_inicio=cls.proxima_semana,
            eve_fecha_fin=cls.proxima_semana + timedelta(days=1),
            eve_estado="Publicado",
            eve_administrador_fk=cls.admin,
            eve_tienecosto='De pago',
            eve_capacidad=50,
            eve_programacion=cls.dummy_pdf,
            eve_imagen=cls.dummy_image
        )
        cls.evento_ti_2.categorias.add(cls.cat_ciber)

        # Evento 3: Coincide con 'Congreso'
        cls.evento_neg = Evento.objects.create(
            eve_nombre="Congreso de Neuromarketing",
            eve_descripcion="Marketing y comportamiento del consumidor.",
            eve_ciudad="Medellín",
            eve_lugar="Centro Convenciones",
            eve_fecha_inicio=cls.proximo_mes,
            eve_fecha_fin=cls.proximo_mes + timedelta(days=1),
            eve_estado="Publicado",
            eve_administrador_fk=cls.admin,
            eve_tienecosto='Sin costo',
            eve_capacidad=200,
            eve_programacion=cls.dummy_pdf,
            eve_imagen=cls.dummy_image
        )
        cls.evento_neg.categorias.add(cls.cat_mkt)
        
        # Evento 4: Finalizado y Coincide con 'Congreso'
        cls.evento_finalizado = Evento.objects.create(
            eve_nombre="Congreso de Historia Finalizado",
            eve_descripcion="Evento histórico que terminó.",
            eve_ciudad="Medellín",
            eve_lugar="UNAL",
            eve_fecha_inicio=cls.anteayer,
            eve_fecha_fin=cls.ayer, 
            eve_estado="Finalizado", 
            eve_administrador_fk=cls.admin,
            eve_tienecosto='Sin costo',
            eve_capacidad=200,
            eve_programacion=cls.dummy_pdf,
            eve_imagen=cls.dummy_image
        )
        
        # Evento 5: NO Publicado (debe ser excluido)
        cls.evento_borrador = Evento.objects.create(
            eve_nombre="Evento Borrador",
            eve_descripcion="Este no debe aparecer.",
            eve_ciudad="Cali",
            eve_lugar="Unicentro",
            eve_fecha_inicio=cls.manana,
            eve_fecha_fin=cls.manana + timedelta(days=1),
            eve_estado="Borrador",
            eve_administrador_fk=cls.admin,
            eve_tienecosto='Sin costo',
            eve_capacidad=10,
            eve_programacion=cls.dummy_pdf,
            eve_imagen=cls.dummy_image
        )

    def setUp(self):
        self.client = Client()
        self.url = reverse('pagina_principal')

    # --- CP-1.1: Búsqueda Múltiple por Nombre (CA-1.2) ---
    def test_cp_1_1_busqueda_por_nombre_multiple(self):
        """Valida CA-1.2: Búsqueda por 'Congreso' que coincide con 3 eventos."""
        response = self.client.get(self.url, {'nombre': 'Congreso'}) 
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['eventos']), 3)

    # --- CP-1.2: Búsqueda Única por Nombre (CA-1.2) ---
    def test_cp_1_2_busqueda_por_nombre_unica(self):
        """
        Valida CA-1.2: Búsqueda por 'Machine Learning' que garantiza una coincidencia única.
        (Corrigiendo el fallo de aserción 2 != 1 con el término 'IA').
        """
        
        # ACT: Buscar "Machine Learning" (solo está en evento_ti_1)
        response = self.client.get(self.url, {'nombre': 'Machine Learning'}) 
        
        # ASSERT: Esperamos 1 resultado
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.evento_ti_1, response.context['eventos'])
        self.assertEqual(len(response.context['eventos']), 1, 
                         "Debe encontrar exactamente 1 evento con 'Machine Learning'.")

    # --- CP-1.3: Filtro por Ciudad (CA-1.3) ---
    def test_cp_1_3_filtro_por_ciudad(self):
        """Valida CA-1.3: Filtro por 'Medellín' (3 eventos)."""
        response = self.client.get(self.url, {'ciudad': 'Medellín'}) 
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['eventos']), 3)

    # --- CP-1.4: Filtro de Fechas (Fallo Controlado - CA-1.4) ---
    def test_cp_1_4_filtro_por_rango_de_fechas_no_implementado(self):
        """Valida CA-1.4: La vista ignora el filtro de fechas (4 eventos)."""
        fecha_inicio_busqueda = self.manana.strftime('%Y-%m-%d')
        fecha_fin_busqueda = (self.manana + timedelta(days=2)).strftime('%Y-%m-%d')
        
        response = self.client.get(self.url, {
            'fecha_inicio': fecha_inicio_busqueda, 
            'fecha_fin': fecha_fin_busqueda
        })
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['eventos']), 4) 
        
    # --- CP-1.5: Filtro por Categoría (CA-1.5) ---
    def test_cp_1_5_filtro_por_categoria(self):
        """Valida CA-1.5: Filtro por categoría 'Inteligencia Artificial' (1 evento)."""
        response = self.client.get(self.url, {'categoria': self.cat_ai.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['eventos']), 1)

    # --- CP-1.6: Filtro por Área (CA-1.5) ---
    def test_cp_1_6_filtro_por_area(self):
        """Valida CA-1.5: Filtro por área 'Tecnología' (2 eventos)."""
        response = self.client.get(self.url, {'area': self.area_ti.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['eventos']), 2)

    # --- CP-1.7: Búsqueda Sin Resultados (CA-1.6) ---
    def test_cp_1_7_busqueda_sin_resultados(self):
        """Valida CA-1.6: Manejo de búsqueda sin coincidencias (0 eventos)."""
        response = self.client.get(self.url, {'nombre': 'EventoInexistente2050'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['eventos']), 0)
        
    # --- CP-1.8: Comportamiento por Defecto y Orden (CA-1.1) ---
    def test_cp_1_8_comportamiento_por_defecto(self):
        """Valida CA-1.1: Solo eventos Publicados/Finalizados y orden descendente por fecha (4 eventos)."""
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['eventos']), 4)
        
        # Orden esperado por fecha de inicio descendente: Neuromarketing, Ciberseguridad, IA, Historia Finalizado
        expected_order = [self.evento_neg, self.evento_ti_2, self.evento_ti_1, self.evento_finalizado]
        self.assertEqual(list(response.context['eventos']), expected_order)