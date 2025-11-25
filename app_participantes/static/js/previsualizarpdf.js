document.getElementById('pdfInput').addEventListener('change', function (event) {
            const file = event.target.files[0];
            const previewContainer = document.getElementById('pdfPreviewContainer');
            const previewFrame = document.getElementById('pdfPreview');

            if (file && file.type === 'application/pdf') {
            const fileURL = URL.createObjectURL(file);
            previewFrame.src = fileURL;
            previewContainer.style.display = 'block';
            } else {
            previewContainer.style.display = 'none';
            previewFrame.src = '';
            }
        });