
document.addEventListener("DOMContentLoaded", function () {
    const areaSelect = document.getElementById("id_area");
    const categoriaSelect = document.getElementById("id_categoria");
    const allOptions = Array.from(categoriaSelect.options);

    areaSelect.addEventListener("change", function () {
        const selectedArea = this.value;

        categoriaSelect.innerHTML = "";

        allOptions.forEach(option => {
            if (option.value === "" || option.dataset.area === selectedArea) {
                categoriaSelect.appendChild(option);
            }
        });
    });
});

