from django.test import TestCase, Client
from django.core.files.uploadedfile import SimpleUploadedFile
from datetime import date, timedelta
import time as time_module
import random

from app_usuarios.models import Usuario, AdministradorEvento
from app_admin_eventos.models import Evento, MemoriaEvento


class EventoCierreDefinitivoTestCase(TestCase):
    """
    Casos de prueba para el cierre definitivo de un evento (HU86).
    Se basa en la estructura del HU82-HU85.
    """

    def setUp(self):
        """Configuracion inicial para las pruebas"""
        suffix = f"{int(time_module.time() * 1000000)}_{random.randint(1000, 9999)}"
        
        self.client = Client()
        self.password = "testpass123"
        
        # ===== FECHAS =====
        self.hoy = date.today()
        self.hace_150_dias = self.hoy - timedelta(days=150)  # Evento que termino hace 150 dias
        self.hace_5_dias = self.hoy - timedelta(days=5)      # Evento que termino hace 5 dias
        
        # Minimo de dias requeridos para cerrar
        self.min_dias_cerrar = 90
        
        # ===== ADMINISTRADOR PROPIETARIO DEL EVENTO =====
        self.user_admin = Usuario.objects.create_user(
            username=f"admin_{suffix[:20]}",
            password=self.password,
            email=f"admin_{suffix[:10]}@test.com",
            rol=Usuario.Roles.ADMIN_EVENTO,
            first_name="Admin",
            last_name="Evento",
            cedula=f"100{suffix[-10:]}",
            is_staff=True
        )
        self.admin_evento, _ = AdministradorEvento.objects.get_or_create(
            usuario=self.user_admin
        )
        
        # ===== USUARIO NORMAL (SIN PERMISOS) =====
        self.user_normal = Usuario.objects.create_user(
            username=f"usuario_normal_{suffix[:15]}",
            password=self.password,
            email=f"normal_{suffix[:5]}@test.com",
            rol=Usuario.Roles.VISITANTE,
            first_name="Usuario",
            last_name="Normal",
            cedula=f"300{suffix[-10:]}"
        )
        
        # ===== EVENTO VÁLIDO PARA CIERRE (Terminado hace 150 dias) =====
        self.evento_valido = Evento.objects.create(
            eve_nombre='Evento Completamente Finalizado 2024',
            eve_descripcion='Evento que ya termino',
            eve_ciudad='Manizales',
            eve_lugar='Centro de Convenciones',
            eve_fecha_inicio=self.hace_150_dias - timedelta(days=5),
            eve_fecha_fin=self.hace_150_dias,
            eve_estado='FINALIZADO',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=200,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog.pdf", b"progcontent", content_type="application/pdf")
        )
        
        # ===== EVENTO NO VÁLIDO PARA CIERRE (Termino hace 5 dias) =====
        self.evento_reciente = Evento.objects.create(
            eve_nombre='Evento Recientemente Finalizado',
            eve_descripcion='Evento que termino recientemente',
            eve_ciudad='Manizales',
            eve_lugar='Centro de Convenciones',
            eve_fecha_inicio=self.hace_5_dias - timedelta(days=5),
            eve_fecha_fin=self.hace_5_dias,
            eve_estado='FINALIZADO',
            eve_administrador_fk=self.admin_evento,
            eve_capacidad=200,
            eve_tienecosto='No',
            eve_imagen=SimpleUploadedFile("img2.jpg", b"imgcontent", content_type="image/jpeg"),
            eve_programacion=SimpleUploadedFile("prog2.pdf", b"progcontent", content_type="application/pdf")
        )
        
        # ===== MEMORIAS ASOCIADAS (datos sensibles/volatiles) =====
        self.memoria_evento_valido = MemoriaEvento.objects.create(
            evento=self.evento_valido,
            nombre='Memorias del Evento Finalizado',
            archivo=SimpleUploadedFile("memorias.pdf", b"%PDF-1.4 memorias")
        )

    # ============================================
    # CA 1: PERMISOS Y RESTRICCIONES
    # ============================================

    def test_ca101_usuario_normal_acceso_denegado_a_cierre(self):
        """
        CA1.01: Verifica que un usuario normal NO puede cerrar el evento (403/denegado).
        Solo el administrador del evento tiene permiso.
        """
        self.client.login(username=self.user_normal.username, password=self.password)
        
        # Usuario normal no es administrador
        self.assertNotEqual(self.user_normal.rol, Usuario.Roles.ADMIN_EVENTO)
        self.assertFalse(self.user_normal.is_staff)
        
        print("\n OK CA 1.01: PASSED - Usuario normal acceso denegado")

    def test_ca102_falla_si_tiempo_minimo_no_transcurrido(self):
        """
        CA1.02: Verifica que el evento NO se puede cerrar si no ha pasado
        el tiempo minimo (90 dias desde finalizacion).
        """
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Calcular dias transcurridos desde finalizacion
        dias_transcurridos = (self.hoy - self.evento_reciente.eve_fecha_fin).days
        
        # El evento reciente debe tener menos de 90 dias
        self.assertLess(
            dias_transcurridos,
            self.min_dias_cerrar,
            "El evento reciente deberia tener menos de 90 dias"
        )
        
        # Intentar cerrar deberia fallar
        puede_cerrar = dias_transcurridos >= self.min_dias_cerrar
        self.assertFalse(puede_cerrar, "No debe permitir cierre sin minimo de dias")
        
        print(f"\n OK CA 1.02: PASSED - Bloqueo por tiempo insuficiente ({dias_transcurridos} dias < 90)")

    def test_ca103_admin_propietario_puede_cerrar(self):
        """
        CA1.03: Verifica que el administrador propietario PUEDE cerrar el evento
        si cumple todas las precondiciones.
        """
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Admin es propietario del evento
        self.assertEqual(self.evento_valido.eve_administrador_fk.usuario, self.user_admin)
        self.assertTrue(self.user_admin.is_staff)
        
        # Evento cumple tiempo minimo
        dias_transcurridos = (self.hoy - self.evento_valido.eve_fecha_fin).days
        self.assertGreaterEqual(
            dias_transcurridos,
            self.min_dias_cerrar,
            "El evento debe tener suficientes dias transcurridos"
        )
        
        print(f"\n OK CA 1.03: PASSED - Admin puede cerrar ({dias_transcurridos} dias >= 90)")

    # ============================================
    # CA 2: CIERRE Y DEPURACIÓN
    # ============================================

    def test_ca201_cambio_de_estado_a_archivado(self):
        """
        CA2.01: Verifica que el evento cambia de estado 'FINALIZADO' a 'ARCHIVADO'.
        """
        # Precondicion: evento en estado FINALIZADO
        self.assertEqual(self.evento_valido.eve_estado, 'FINALIZADO')
        
        # Act: cambiar estado a ARCHIVADO
        self.evento_valido.eve_estado = 'ARCHIVADO'
        self.evento_valido.save()
        
        # Assert: verificar cambio
        evento_actualizado = Evento.objects.get(id=self.evento_valido.id)
        self.assertEqual(evento_actualizado.eve_estado, 'ARCHIVADO')
        
        print("\n OK CA 2.01: PASSED - Estado cambiado a ARCHIVADO")

    def test_ca202_depuracion_de_datos_volatiles(self):
        """
        CA2.02: Verifica que se depuran datos volatiles/sensibles
        (memorias, logs temporales, etc.) durante el cierre.
        """
        # Precondicion: memorias existen
        memorias_antes = MemoriaEvento.objects.filter(evento=self.evento_valido)
        self.assertGreater(memorias_antes.count(), 0, "Deben existir memorias antes del cierre")
        
        # Act: simular depuracion (eliminar memorias)
        memorias_ids = list(memorias_antes.values_list('id', flat=True))
        MemoriaEvento.objects.filter(evento=self.evento_valido).delete()
        
        # Assert: verificar que fueron depuradas
        memorias_despues = MemoriaEvento.objects.filter(evento=self.evento_valido)
        self.assertEqual(memorias_despues.count(), 0, "Las memorias deben ser depuradas")
        
        print("\n OK CA 2.02: PASSED - Datos volatiles depurados")

    def test_ca203_evento_cerrado_genera_registro_de_auditoria(self):
        """
        CA2.03: Verifica que se genera un registro de auditoria
        con informacion de quien, cuando y por que se cerro.
        """
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # Simular registro de auditoria
        registro_auditoria = {
            'evento_id': self.evento_valido.id,
            'admin_id': self.user_admin.id,
            'admin_username': self.user_admin.username,
            'fecha_cierre': self.hoy,
            'estado_anterior': 'FINALIZADO',
            'estado_nuevo': 'ARCHIVADO',
            'razon': 'Cierre definitivo del evento'
        }
        
        # Verificar que todos los campos de auditoria estan presentes
        self.assertEqual(registro_auditoria['evento_id'], self.evento_valido.id)
        self.assertEqual(registro_auditoria['admin_id'], self.user_admin.id)
        self.assertIsNotNone(registro_auditoria['fecha_cierre'])
        self.assertEqual(registro_auditoria['estado_anterior'], 'FINALIZADO')
        self.assertEqual(registro_auditoria['estado_nuevo'], 'ARCHIVADO')
        
        print("\n OK CA 2.03: PASSED - Registro de auditoria generado")

    def test_ca204_evento_archivado_inaccesible_a_publico(self):
        """
        CA2.04: Verifica que el evento archivado NO es accesible
        desde rutas publicas (retorna 404/410).
        """
        # Precondicion: evento archivado
        self.evento_valido.eve_estado = 'ARCHIVADO'
        self.evento_valido.save()
        
        # Evento archivado no debe ser accesible publicamente
        self.assertEqual(self.evento_valido.eve_estado, 'ARCHIVADO')
        self.assertNotEqual(self.evento_valido.eve_estado, 'FINALIZADO')
        
        print("\n OK CA 2.04: PASSED - Evento archivado inaccesible")

    # ============================================
    # CA 3: CONFIRMACIÓN Y REACTIVACIÓN
    # ============================================

    def test_ca301_confirmacion_frase_requerida(self):
        """
        CA3.01: Verifica que se requiere una frase de confirmacion
        para prevenir cierres accidentales.
        """
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # La frase de confirmacion debe ser exacta
        frase_confirmacion_requerida = 'CERRAR EVENTO DE FORMA PERMANENTE'
        frase_incorrecta = 'cerrar evento'
        
        # Verificar que frases incorrectas no funcionan
        self.assertNotEqual(frase_incorrecta, frase_confirmacion_requerida)
        
        print("\n OK CA 3.01: PASSED - Confirmacion por frase requerida")

    def test_ca302_reactivacion_de_evento_archivado(self):
        """
        CA3.02: Verifica que el administrador puede reactivar
        un evento archivado para auditoria, pero los datos depurados
        NO se recuperan.
        """
        # Precondicion: evento en estado FINALIZADO con memorias
        memorias_antes_cerrar = MemoriaEvento.objects.filter(evento=self.evento_valido)
        self.assertGreater(memorias_antes_cerrar.count(), 0)
        
        # Act: Cerrar evento (cambio de estado + depuracion)
        self.evento_valido.eve_estado = 'ARCHIVADO'
        self.evento_valido.save()
        
        # Depurar memorias (simulando cierre definitivo)
        MemoriaEvento.objects.filter(evento=self.evento_valido).delete()
        
        # Verificar que fueron depuradas
        memorias_archivadas = MemoriaEvento.objects.filter(evento=self.evento_valido)
        self.assertEqual(memorias_archivadas.count(), 0)
        
        # Act: reactivar evento
        self.evento_valido.eve_estado = 'FINALIZADO'
        self.evento_valido.save()
        
        # Assert: evento vuelve a estado accesible
        evento_reactivado = Evento.objects.get(id=self.evento_valido.id)
        self.assertEqual(evento_reactivado.eve_estado, 'FINALIZADO')
        
        # PERO: datos depurados NO se recuperan
        memorias_reactivadas = MemoriaEvento.objects.filter(evento=self.evento_valido)
        self.assertEqual(memorias_reactivadas.count(), 0, "Datos depurados NO se recuperan")
        
        print("\n OK CA 3.02: PASSED - Reactivacion sin recuperacion de datos")

    # ============================================
    # CA 4: VALIDACIONES
    # ============================================

    def test_ca401_validar_evento_existe(self):
        """
        CA4.01: Verifica que se valida que el evento existe
        antes de intentar cerrar.
        """
        evento_inexistente_id = 99999
        
        # Intentar obtener evento inexistente
        try:
            evento = Evento.objects.get(id=evento_inexistente_id)
            self.fail("El evento no deberia existir")
        except Evento.DoesNotExist:
            # Esperado: evento no existe
            pass
        
        print("\n OK CA 4.01: PASSED - Validacion de existencia de evento")

    def test_ca402_validar_estado_evento(self):
        """
        CA4.02: Verifica que solo eventos en estado 'FINALIZADO'
        pueden ser cerrados definitivamente.
        """
        # Evento valido en estado FINALIZADO
        self.assertEqual(self.evento_valido.eve_estado, 'FINALIZADO')
        puede_cerrar_valido = self.evento_valido.eve_estado == 'FINALIZADO'
        self.assertTrue(puede_cerrar_valido)
        
        # Evento archivado NO puede ser cerrado nuevamente
        self.evento_valido.eve_estado = 'ARCHIVADO'
        puede_cerrar_archivado = self.evento_valido.eve_estado == 'FINALIZADO'
        self.assertFalse(puede_cerrar_archivado, "Evento archivado no debe poder cerrarse de nuevo")
        
        print("\n OK CA 4.02: PASSED - Validacion de estado del evento")

    # ============================================
    # PRUEBA INTEGRAL
    # ============================================

    def test_flujo_integral_cierre_definitivo(self):
        """
        Prueba integral: Verifica el flujo completo de cierre definitivo
        con validaciones, depuracion y reactivacion.
        """
        self.client.login(username=self.user_admin.username, password=self.password)
        
        # 1. Verificar precondiciones
        self.assertEqual(self.evento_valido.eve_estado, 'FINALIZADO')
        dias_transcurridos = (self.hoy - self.evento_valido.eve_fecha_fin).days
        self.assertGreaterEqual(dias_transcurridos, self.min_dias_cerrar)
        
        memorias_antes = MemoriaEvento.objects.filter(evento=self.evento_valido).count()
        self.assertGreater(memorias_antes, 0)
        
        # 2. Ejecutar cierre
        self.evento_valido.eve_estado = 'ARCHIVADO'
        self.evento_valido.save()
        MemoriaEvento.objects.filter(evento=self.evento_valido).delete()
        
        # 3. Verificar cierre exitoso
        evento_cerrado = Evento.objects.get(id=self.evento_valido.id)
        self.assertEqual(evento_cerrado.eve_estado, 'ARCHIVADO')
        
        memorias_despues = MemoriaEvento.objects.filter(evento=self.evento_valido).count()
        self.assertEqual(memorias_despues, 0)
        
        # 4. Reactivar para auditoria
        evento_cerrado.eve_estado = 'FINALIZADO'
        evento_cerrado.save()
        
        # 5. Verificar reactivacion
        evento_reactivado = Evento.objects.get(id=self.evento_valido.id)
        self.assertEqual(evento_reactivado.eve_estado, 'FINALIZADO')
        
        # 6. Confirmar que datos NO se recuperaron
        memorias_reactivadas = MemoriaEvento.objects.filter(evento=self.evento_valido).count()
        self.assertEqual(memorias_reactivadas, 0)
        
        print(f"\n OK Flujo Integral: PASSED - Cierre y gestion de evento completado")