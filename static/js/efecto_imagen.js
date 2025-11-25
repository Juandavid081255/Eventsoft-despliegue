document.addEventListener("DOMContentLoaded", () => {
  const img = document.querySelector(".evento-img");

  if (img) {
    const title = img.alt || "Imagen del Evento";
    img.style.cursor = "pointer";

    img.addEventListener("click", () => {
      showLightbox(img.src, title);
    });
  }

  function showLightbox(src, title) {
    const overlay = document.createElement("div");
    overlay.style.position = "fixed";
    overlay.style.top = 0;
    overlay.style.left = 0;
    overlay.style.width = "100vw";
    overlay.style.height = "100vh";
    overlay.style.backgroundColor = "rgba(0, 0, 0, 0.9)";
    overlay.style.display = "flex";
    overlay.style.flexDirection = "column";
    overlay.style.alignItems = "center";
    overlay.style.justifyContent = "center";
    overlay.style.zIndex = "9999";
    overlay.style.overflow = "auto";

    const img = document.createElement("img");
    img.src = src;
    img.alt = title;
    img.style.maxWidth = "80%";
    img.style.maxHeight = "80%";
    img.style.border = "4px solid white";
    img.style.borderRadius = "10px";
    img.style.boxShadow = "0 0 20px rgba(255,255,255,0.5)" ;
    img.style.marginBottom = "20px";

    const caption = document.createElement("div");
    caption.textContent = title;
    caption.style.color = "#fff";
    caption.style.fontSize = "1.5em";
    caption.style.fontWeight = "bold";
    caption.style.textAlign = "center";

    overlay.addEventListener("click", () => {
      document.body.removeChild(overlay);
    });

    overlay.appendChild(img);
    overlay.appendChild(caption);
    document.body.appendChild(overlay);
  }
});
