import * as vscode from 'vscode';
import * as crypto from 'crypto';


export function getNonce() {
    return crypto.randomBytes(16).toString('hex');
}

export class ArchitectureWebview {
    private readonly _extensionUri: vscode.Uri;
    public static currentPanel: ArchitectureWebview | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private _disposables: vscode.Disposable[] = [];

    private constructor(panel: vscode.WebviewPanel, markdownContent: string, extensionUri: vscode.Uri) {
        this._extensionUri = extensionUri;
        this._panel = panel;
        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
        this._update(markdownContent);
    }

    public static createOrShow(markdownContent: string, extensionUri: vscode.Uri) {
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
                retainContextWhenHidden: true,
                localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'media')]
            }
        );

        ArchitectureWebview.currentPanel = new ArchitectureWebview(panel, markdownContent, extensionUri);
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

    private _escapeHtml(unsafe: string): string {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    private _getHtmlForWebview(webview: vscode.Webview, markdownContent: string): string {
        const nonce = getNonce();

        const scriptUri = webview.asWebviewUri(
            vscode.Uri.joinPath(this._extensionUri, 'media', 'main.js')
        );
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
                <div class="mermaid">${this._escapeHtml(d)}</div>
            </div>`
        ).join('\n');

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${webview.cspSource} data: https:; script-src 'nonce-${nonce}' https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js; style-src 'nonce-${nonce}';">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Architecture Map</title>
    <style nonce="${nonce}">
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
</head>
<body>
    <div class="header">
        <button id="refresh-btn">Refresh</button>
        <button id="export-btn">Export to SVG/PNG</button>
    </div>

    <div id="content">
        ${diagrams.length > 0 ? mermaidBlocksHtml : '<p>No Mermaid diagrams found in the generated markdown.</p>'}
    </div>
    <script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
    }
}
