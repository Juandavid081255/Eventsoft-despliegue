document.addEventListener('DOMContentLoaded', function() {
    const input = document.getElementById('input-busqueda-navbar');
    const form = document.getElementById('buscador-navbar');
    let timeout = null;

    input.addEventListener('input', function() {
        clearTimeout(timeout);
        timeout = setTimeout(function() {
            form.submit();
        }, 600); // Espera 600ms después de dejar de escribir
    });
});