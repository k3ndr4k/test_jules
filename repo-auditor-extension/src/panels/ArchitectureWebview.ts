import * as vscode from 'vscode';

export class ArchitectureWebview {
    public static currentPanel: ArchitectureWebview | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private _disposables: vscode.Disposable[] = [];

    private constructor(panel: vscode.WebviewPanel, markdownContent: string) {
        this._panel = panel;
        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
        this._update(markdownContent);
    }

    public static createOrShow(markdownContent: string) {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (ArchitectureWebview.currentPanel) {
            ArchitectureWebview.currentPanel._panel.reveal(column);
            ArchitectureWebview.currentPanel._update(markdownContent);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            'architectureWebview',
            'Architecture Map',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true
            }
        );

        ArchitectureWebview.currentPanel = new ArchitectureWebview(panel, markdownContent);
    }

    private dispose() {
        ArchitectureWebview.currentPanel = undefined;
        this._panel.dispose();
        while (this._disposables.length) {
            const x = this._disposables.pop();
            if (x) {
                x.dispose();
            }
        }
    }

    private _update(markdownContent: string) {
        const webview = this._panel.webview;
        this._panel.webview.html = this._getHtmlForWebview(webview, markdownContent);
    }

    private _getHtmlForWebview(webview: vscode.Webview, markdownContent: string): string {
        // Simple extraction of mermaid blocks
        const mermaidRegex = /```mermaid\n([\s\S]*?)```/g;
        let match;
        const diagrams: string[] = [];

        while ((match = mermaidRegex.exec(markdownContent)) !== null) {
            diagrams.push(match[1].trim());
        }

        const mermaidBlocksHtml = diagrams.map((d, index) =>
            `<div class="diagram-container">
                <h3>Diagram ${index + 1}</h3>
                <div class="mermaid">${d}</div>
            </div>`
        ).join('\n');

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${webview.cspSource} data: https:; script-src 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'unsafe-inline';">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Architecture Map</title>
    <style>
        body {
            font-family: var(--vscode-font-family);
            padding: 20px;
            color: var(--vscode-editor-foreground);
            background-color: var(--vscode-editor-background);
        }
        .header {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        button {
            background-color: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            padding: 8px 12px;
            cursor: pointer;
            border-radius: 2px;
        }
        button:hover {
            background-color: var(--vscode-button-hoverBackground);
        }
        .diagram-container {
            margin-bottom: 30px;
            border: 1px solid var(--vscode-panel-border);
            padding: 15px;
            border-radius: 4px;
            background: white; /* Ensure mermaid graphs are visible */
        }
        h3 {
            margin-top: 0;
            color: var(--vscode-editor-foreground);
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <script>
        mermaid.initialize({ startOnLoad: true, theme: 'default' });
    </script>
</head>
<body>
    <div class="header">
        <button onclick="location.reload()">Refresh</button>
        <button onclick="alert('Export to SVG/PNG not implemented in this demo, but would use canvas/svg extraction here.')">Export to SVG/PNG</button>
    </div>

    <div id="content">
        ${diagrams.length > 0 ? mermaidBlocksHtml : '<p>No Mermaid diagrams found in the generated markdown.</p>'}
    </div>
</body>
</html>`;
    }
}
