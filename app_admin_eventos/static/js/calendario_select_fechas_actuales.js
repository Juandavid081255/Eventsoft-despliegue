
document.addEventListener("DOMContentLoaded", function() {
    const today = new Date().toISOString().split("T")[0];
    const fechaInicio = document.getElementById("id_eve_fecha_inicio");
    const fechaFin = document.getElementById("id_eve_fecha_fin");

    if (fechaInicio) {
        fechaInicio.setAttribute("min", today);
    }
    if (fechaFin) {
        fechaFin.setAttribute("min", today);
    }

    // Ajuste dinámico: si cambia la fecha de inicio, actualiza el mínimo de la fecha fin
    fechaInicio.addEventListener("change", function() {
        fechaFin.min = fechaInicio.value;
    });
});
