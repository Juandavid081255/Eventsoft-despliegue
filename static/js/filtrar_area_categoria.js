document.addEventListener("DOMContentLoaded", function () {
            // === Filtrar Categorías por Área ===
            const areaSelect = document.getElementById("id_area");
            const categoriaSelect = document.getElementById("id_categoria");

            areaSelect.addEventListener("change", function () {
                const selectedAreaId = this.value;
                const categoriaOptions = categoriaSelect.options;

                for (let i = 0; i < categoriaOptions.length; i++) {
                    const option = categoriaOptions[i];
                    if (option.getAttribute("data-area") === selectedAreaId || selectedAreaId === "") {
                        option.style.display = "";
                    } else {
                        option.style.display = "none";
                    }
                }
            });
        });