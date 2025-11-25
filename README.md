#############
|           |
|  ¡NOTAS!  |
|           |
#############             

29/05/2025
- En la base de datos se creo eve_cancelacion_inicial en la tabla Evento

02/06/2025
- Se elimino la tabla Notificaciones


super admin
sebas
admin@admin.com
Desarrollo123


###############
|             |
|  PROBLEMAS  |
|             |
###############

❌: Sin corregir     ✅: Corregido

29/05/2025
- El boton de deshabilitar y habilitar asistentes, asi este desahbilitado, puede entrar por puerta trasera ✅: Corregido
- Para que el evento se cancele y envie correos electronicos avisando de que el evento se cancelo y elimine las relaciones del evento en la db, hay que 
    hacer que el servidor corra cada 10 minutos y actualice ese datos para que haga dicha funcion ❌: Sin corregir 
- El evento no esta enlazado con un administrador de eventos, se intento relacionar los eventos al administrador de un evento y no se logro por url, se buscara otra   manera ✅: Corregido (Se implemento el login el ID se rastrea con la session.request)


17-06-2025
- El evaluador cuando se preinscribe debe quedar en estado Pendiente y pero aun asi se le envia al correo la session para que verifique su aprobacion  ✅: Corregido 
- Se debe hacer el login de participantes y asistentes y poner el decorador para no entrar por puertas traseras ❌: Sin corregir 


19-06-2025

-Modificaciones para el dashboard del participante y el login para el asistente. ❌: Sin corregir 







Añadir y corregir
El evaluador cuando es aceptado o rechazado deja mostrar el evento lo cual se debe corregir 
Arreglar la clave de acceso que envia el super admin al administrador (HU88)
Añadir la historia de usuario de las notificaciones del administrador para que pueda enviar a los participantes, asistentes y evaluadores (HU70,HU71,HU72)

