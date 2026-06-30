(function () {
    mermaid.initialize({ startOnLoad: true, theme: 'default' });

    document.getElementById('refresh-btn').addEventListener('click', () => {
        location.reload();
    });

    document.getElementById('export-btn').addEventListener('click', () => {
        alert('Export to SVG/PNG not implemented in this demo, but would use canvas/svg extraction here.');
    });
}());
