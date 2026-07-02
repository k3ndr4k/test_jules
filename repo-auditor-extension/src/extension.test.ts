import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { activate, deactivate } from './extension';
import { ArchitectureWebview } from './panels/ArchitectureWebview';

// Mock vscode
jest.mock('vscode', () => {
    return {
        commands: {
            registerCommand: jest.fn()
        },
        window: {
            showOpenDialog: jest.fn(),
            withProgress: jest.fn(),
            showErrorMessage: jest.fn(),
            showInformationMessage: jest.fn()
        },
        ProgressLocation: {
            Notification: 15
        },
        Uri: {
            file: (f: string) => ({ fsPath: f })
        }
    };
});

jest.mock('child_process', () => ({
    execFile: jest.fn()
}));

jest.mock('fs', () => ({
    existsSync: jest.fn(),
    promises: {
        readFile: jest.fn()
    }
}));

jest.mock('./panels/ArchitectureWebview', () => ({
    ArchitectureWebview: {
        createOrShow: jest.fn()
    }
}));

describe('Extension Activation', () => {
    let mockContext: vscode.ExtensionContext;

    beforeEach(() => {
        jest.clearAllMocks();
        mockContext = {
            subscriptions: [],
            extensionUri: { fsPath: '/test/extension/uri' } as unknown as vscode.Uri,
        } as unknown as vscode.ExtensionContext;

        // Suppress console.log and console.error in tests to keep output clean
        jest.spyOn(console, 'log').mockImplementation(() => {});
        jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    it('should register the auditRepository command and push to subscriptions', () => {
        const dummyDisposable = { dispose: jest.fn() };
        (vscode.commands.registerCommand as jest.Mock).mockReturnValue(dummyDisposable);

        activate(mockContext);

        expect(vscode.commands.registerCommand).toHaveBeenCalledWith(
            'extension.auditRepository',
            expect.any(Function)
        );
        expect(mockContext.subscriptions).toContain(dummyDisposable);
        expect(console.log).toHaveBeenCalledWith('Repo Auditor is now active!');
    });

    describe('Command: extension.auditRepository', () => {
        let commandCallback: (uri?: vscode.Uri) => Promise<void>;

        beforeEach(() => {
            activate(mockContext);
            commandCallback = (vscode.commands.registerCommand as jest.Mock).mock.calls[0][1];

            // By default, make withProgress execute its callback immediately
            (vscode.window.withProgress as jest.Mock).mockImplementation((_options, task) => {
                return task({ report: jest.fn() });
            });
        });

        it('should use provided URI if available', async () => {
            const mockUri = { fsPath: '/test/path' } as vscode.Uri;

            // Mock execFile to immediately call the callback without error
            (cp.execFile as unknown as jest.Mock).mockImplementation((file, args, options, callback) => {
                callback(null, 'stdout', 'stderr');
            });

            // Mock fs.existsSync to return true
            (fs.existsSync as jest.Mock).mockReturnValue(true);
            (fs.promises.readFile as jest.Mock).mockResolvedValue('markdown content');

            await commandCallback(mockUri);

            expect(vscode.window.showOpenDialog).not.toHaveBeenCalled();
            expect(cp.execFile).toHaveBeenCalledWith(
                'repo-auditor',
                ['--path', '/test/path'],
                { cwd: '/test/path' },
                expect.any(Function)
            );
        });

        it('should show open dialog if no URI provided, and execute for selected folder', async () => {
            (vscode.window.showOpenDialog as jest.Mock).mockResolvedValue([{ fsPath: '/dialog/path' }]);

            (cp.execFile as unknown as jest.Mock).mockImplementation((file, args, options, callback) => {
                callback(null, '', '');
            });
            (fs.existsSync as jest.Mock).mockReturnValue(true);
            (fs.promises.readFile as jest.Mock).mockResolvedValue('markdown content');

            await commandCallback();

            expect(vscode.window.showOpenDialog).toHaveBeenCalledWith({
                canSelectFiles: false,
                canSelectFolders: true,
                canSelectMany: false,
                openLabel: 'Select Folder to Audit'
            });

            expect(cp.execFile).toHaveBeenCalledWith(
                'repo-auditor',
                ['--path', '/dialog/path'],
                { cwd: '/dialog/path' },
                expect.any(Function)
            );
        });

        it('should return early if open dialog is canceled', async () => {
            (vscode.window.showOpenDialog as jest.Mock).mockResolvedValue(undefined);

            await commandCallback();

            expect(vscode.window.withProgress).not.toHaveBeenCalled();
            expect(cp.execFile).not.toHaveBeenCalled();
        });

        it('should return early if open dialog returns empty array', async () => {
            (vscode.window.showOpenDialog as jest.Mock).mockResolvedValue([]);

            await commandCallback();

            expect(vscode.window.withProgress).not.toHaveBeenCalled();
            expect(cp.execFile).not.toHaveBeenCalled();
        });

        it('should handle repo-auditor execution failure', async () => {
            const mockUri = { fsPath: '/test/path' } as vscode.Uri;
            const error = new Error('execution failed');

            (cp.execFile as unknown as jest.Mock).mockImplementation((file, args, options, callback) => {
                callback(error, '', 'stderr output');
            });

            await commandCallback(mockUri);

            expect(vscode.window.showErrorMessage).toHaveBeenCalledWith(`Error running repo-auditor: ${error.message}`);
            expect(console.error).toHaveBeenCalledWith('stderr output');
            expect(fs.existsSync).not.toHaveBeenCalled();
        });

        it('should handle repo-auditor execution failure with ENOENT (not found)', async () => {
            const mockUri = { fsPath: '/test/path' } as vscode.Uri;
            const error: any = new Error('spawn repo-auditor ENOENT');
            error.code = 'ENOENT';

            (cp.execFile as unknown as jest.Mock).mockImplementation((file, args, options, callback) => {
                callback(error, '', '');
            });

            await commandCallback(mockUri);

            expect(vscode.window.showErrorMessage).toHaveBeenCalledWith(`Error running repo-auditor: ${error.message}`);
            expect(console.error).toHaveBeenCalledWith('');
            expect(fs.existsSync).not.toHaveBeenCalled();
        });

        it('should handle missing architecture_map.md after successful execution', async () => {
            const mockUri = { fsPath: '/test/path' } as vscode.Uri;

            (cp.execFile as unknown as jest.Mock).mockImplementation((file, args, options, callback) => {
                callback(null, '', '');
            });
            (fs.existsSync as jest.Mock).mockReturnValue(false);

            await commandCallback(mockUri);

            expect(fs.existsSync).toHaveBeenCalledWith(path.join('/test/path', 'architecture_map.md'));
            expect(vscode.window.showErrorMessage).toHaveBeenCalledWith('Auditing completed, but architecture_map.md was not found.');
            expect(ArchitectureWebview.createOrShow).not.toHaveBeenCalled();
        });

        it('should handle file read failure for architecture_map.md', async () => {
            const mockUri = { fsPath: '/test/path' } as vscode.Uri;
            const readError = new Error('read failed');

            (cp.execFile as unknown as jest.Mock).mockImplementation((file, args, options, callback) => {
                callback(null, '', '');
            });
            (fs.existsSync as jest.Mock).mockReturnValue(true);
            (fs.promises.readFile as jest.Mock).mockRejectedValue(readError);

            await commandCallback(mockUri);

            expect(vscode.window.showErrorMessage).toHaveBeenCalledWith(`Failed to read architecture_map.md: ${readError.message}`);
            expect(ArchitectureWebview.createOrShow).not.toHaveBeenCalled();
            expect(vscode.window.showInformationMessage).not.toHaveBeenCalled();
        });

        it('should show webview and info message on success', async () => {
            const mockUri = { fsPath: '/test/path' } as vscode.Uri;

            (cp.execFile as unknown as jest.Mock).mockImplementation((file, args, options, callback) => {
                callback(null, '', '');
            });
            (fs.existsSync as jest.Mock).mockReturnValue(true);
            (fs.promises.readFile as jest.Mock).mockResolvedValue('dummy markdown');

            await commandCallback(mockUri);

            expect(ArchitectureWebview.createOrShow).toHaveBeenCalledWith('dummy markdown', mockContext.extensionUri);
            expect(vscode.window.showInformationMessage).toHaveBeenCalledWith('Architecture Map generated successfully!');
        });
    });

    it('should have a deactivate function', () => {
        expect(deactivate).toBeDefined();
        expect(() => deactivate()).not.toThrow();
    });
});
