/* eslint-disable @typescript-eslint/naming-convention */
import * as vscode from 'vscode';
import { ArchitectureWebview, getNonce } from './ArchitectureWebview';

jest.mock('vscode', () => ({
    window: {
        activeTextEditor: undefined,
        createWebviewPanel: jest.fn()
    },
    ViewColumn: {
        One: 1
    },
    Uri: {
        joinPath: jest.fn((uri, ...pathSegments) => ({
            fsPath: `${uri.fsPath}/${pathSegments.join('/')}`
        }))
    }
}));

describe('ArchitectureWebview', () => {
    let mockPanel: any;
    let mockExtensionUri: vscode.Uri;

    beforeEach(() => {
        jest.clearAllMocks();
        ArchitectureWebview.currentPanel = undefined;

        mockPanel = {
            webview: {
                html: '',
                asWebviewUri: jest.fn((uri) => uri),
                cspSource: 'vscode-webview-resource:'
            },
            onDidDispose: jest.fn(),
            reveal: jest.fn(),
            dispose: jest.fn()
        };

        (vscode.window.createWebviewPanel as jest.Mock).mockReturnValue(mockPanel);

        mockExtensionUri = { fsPath: '/test/extension' } as unknown as vscode.Uri;
    });

    it('should create a new panel if one does not exist', () => {
        ArchitectureWebview.createOrShow('test markdown', mockExtensionUri);

        expect(vscode.window.createWebviewPanel).toHaveBeenCalledWith(
            'architectureWebview',
            'Architecture Map',
            1, // vscode.ViewColumn.One
            expect.any(Object)
        );
        expect(ArchitectureWebview.currentPanel).toBeDefined();
        expect(mockPanel.onDidDispose).toHaveBeenCalled();
    });

    it('should reuse existing panel if one exists', () => {
        ArchitectureWebview.createOrShow('first markdown', mockExtensionUri);
        const firstPanel = ArchitectureWebview.currentPanel;

        ArchitectureWebview.createOrShow('second markdown', mockExtensionUri);

        expect(vscode.window.createWebviewPanel).toHaveBeenCalledTimes(1);
        expect(ArchitectureWebview.currentPanel).toBe(firstPanel);
        expect(mockPanel.reveal).toHaveBeenCalled();
    });

    it('should correctly escape HTML in mermaid blocks', () => {
        const markdown = '```mermaid\ngraph TD;\n  A<"malicious&">B;\n```';
        ArchitectureWebview.createOrShow(markdown, mockExtensionUri);

        const html = mockPanel.webview.html;
        expect(html).toContain('A&lt;&quot;malicious&amp;&quot;&gt;B');
    });

    it('should extract mermaid blocks and generate HTML', () => {
        const markdown = '```mermaid\ngraph TD;\n  A-->B;\n```';
        ArchitectureWebview.createOrShow(markdown, mockExtensionUri);

        const html = mockPanel.webview.html;
        expect(html).toContain('graph TD;\n  A--&gt;B;'); // Note html escaped
        expect(html).toContain('<div class="mermaid">');
    });

    it('should show a message if no mermaid blocks are found', () => {
        const markdown = '# Just some text';
        ArchitectureWebview.createOrShow(markdown, mockExtensionUri);

        const html = mockPanel.webview.html;
        expect(html).toContain('No Mermaid diagrams found in the generated markdown.');
    });

    it('should clean up resources on dispose', () => {
        ArchitectureWebview.createOrShow('test markdown', mockExtensionUri);

        // Get the dispose callback registered with the panel
        const disposeCallback = mockPanel.onDidDispose.mock.calls[0][0];

        disposeCallback();

        expect(ArchitectureWebview.currentPanel).toBeUndefined();
        expect(mockPanel.dispose).toHaveBeenCalled();
    });
});

describe('getNonce', () => {
    it('should generate a 32-character hex string', () => {
        const nonce = getNonce();
        expect(nonce).toBeDefined();
        expect(typeof nonce).toBe('string');
        expect(nonce.length).toBe(32);
        expect(/^[0-9a-f]{32}$/i.test(nonce)).toBe(true);
    });

    it('should generate random strings', () => {
        const nonce1 = getNonce();
        const nonce2 = getNonce();
        expect(nonce1).not.toBe(nonce2);
    });
});