document.addEventListener("DOMContentLoaded", function() {
    const categoriaSelect = document.getElementById("id_categoria");
    const descripcionTextarea = document.getElementById("cat_descripcion");

    function actualizarDescripcion() {
        const seleccionadas = Array.from(categoriaSelect.selectedOptions);
        if (seleccionadas.length === 0) {
            descripcionTextarea.value = "";
            return;
        }

        // Muestra las descripciones de todas las categorías seleccionadas
        const descripciones = seleccionadas.map(opt => opt.dataset.descripcion).join("\n\n");
        descripcionTextarea.value = descripciones;
    }

    categoriaSelect.addEventListener("change", actualizarDescripcion);
    actualizarDescripcion(); // Para inicializar si ya hay seleccionadas
});
