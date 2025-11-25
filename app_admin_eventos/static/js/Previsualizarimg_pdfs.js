document.addEventListener("DOMContentLoaded", function () {
    const inputIDs = ["id_eve_imagen"]; // Agrega más IDs si es necesario
    const previewImagen = document.getElementById("preview_imagen");

    inputIDs.forEach((id) => {
        const input = document.getElementById(id);
        if (input) {
            input.setAttribute("accept", "image/*"); // Restringe tipos aceptados

            input.addEventListener("change", function () {
                const file = this.files[0];
                if (file && file.type.startsWith("image/")) {
                    const reader = new FileReader();
                    reader.onload = function (e) {
                        previewImagen.src = e.target.result;
                        previewImagen.style.display = "block";
                    };
                    reader.readAsDataURL(file);
                } else {
                    alert("Solo se permiten archivos de imagen.");
                    this.value = "";  // Limpia el input
                    previewImagen.src = "#";
                    previewImagen.style.display = "none";
                }
            });
        }
    });
});


document.addEventListener("DOMContentLoaded", () => {
    const inputIDs = ["id_par_eve_documentos", "id_eve_programacion"];
    const previewPDF = document.getElementById("preview_pdf");

    inputIDs.forEach((id) => {
        const input = document.getElementById(id);
        if (input) {
            // Restringe los tipos aceptados directamente en el input
            input.setAttribute("accept", "application/pdf");

            input.addEventListener("change", function () {
                const file = this.files[0];
                if (file && file.type === "application/pdf") {
                    const fileURL = URL.createObjectURL(file);
                    previewPDF.src = fileURL;
                    previewPDF.style.display = "block";
                } else {
                    alert("Solo se permiten archivos PDF.");
                    this.value = "";  // Limpia el campo si el archivo no es válido
                    previewPDF.src = "";
                    previewPDF.style.display = "none";
                }
            });
        }
    });
});



    
