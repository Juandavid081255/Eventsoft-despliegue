
    document.addEventListener("DOMContentLoaded", function () {
        const alerts = document.querySelectorAll('.alert-success');
        alerts.forEach(function(alert) {
            setTimeout(function() {
                alert.remove();
            }, 7000); // 7000 ms = 7s para coincidir con la animación
        });
    });

