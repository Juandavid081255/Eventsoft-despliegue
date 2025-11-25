function contarCaracteres() {
    const textarea = document.getElementById("id_eve_descripcion");
    const contador = document.getElementById("contador_descripcion");
    const alerta = document.getElementById("alerta_max_caracteres");

    const longitud = textarea.value.length;
    contador.textContent = `${longitud} / 499 caracteres`;

    if (longitud > 499) {
        alerta.style.display = "block";
    } else {
        alerta.style.display = "none";
    }
}

// Inicializar contador al cargar la página si ya hay contenido
document.addEventListener("DOMContentLoaded", contarCaracteres);

