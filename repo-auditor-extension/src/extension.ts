import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ArchitectureWebview } from './panels/ArchitectureWebview';

export function activate(context: vscode.ExtensionContext) {
    console.log('Repo Auditor is now active!');

    const disposable = vscode.commands.registerCommand('extension.auditRepository', async (uri?: vscode.Uri) => {
        let targetPath: string;

        if (uri && uri.fsPath) {
            targetPath = uri.fsPath;
        } else {
            const folderUris = await vscode.window.showOpenDialog({
                canSelectFiles: false,
                canSelectFolders: true,
                canSelectMany: false,
                openLabel: 'Select Folder to Audit'
            });

            if (!folderUris || folderUris.length === 0) {
                return;
            }
            targetPath = folderUris[0].fsPath;
        }

        const config = vscode.workspace.getConfiguration('repoAuditor');
        const binaryPath = config.get<string>('binaryPath') || 'repo-auditor';

        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: `Auditing repository at ${targetPath}...`,
            cancellable: false
        }, async (progress) => {
            return new Promise<void>((resolve, reject) => {
                cp.execFile(binaryPath, ['--path', targetPath], { cwd: targetPath }, (error, stdout, stderr) => {
                    if (error) {
                        vscode.window.showErrorMessage(`Error running repo-auditor: ${error.message}`);
                        console.error(stderr);
                        resolve();
                        return;
                    }

                    const mapFilePath = path.join(targetPath, 'architecture_map.md');
                    if (!fs.existsSync(mapFilePath)) {
                        vscode.window.showErrorMessage('Auditing completed, but architecture_map.md was not found.');
                        resolve();
                        return;
                    }

                    try {
                        const markdownContent = fs.readFileSync(mapFilePath, 'utf8');
                        ArchitectureWebview.createOrShow(markdownContent);
                        vscode.window.showInformationMessage('Architecture Map generated successfully!');
                    } catch (readError: any) {
                        vscode.window.showErrorMessage(`Failed to read architecture_map.md: ${readError.message}`);
                    }
                    resolve();
                });
            });
        });
    });

    context.subscriptions.push(disposable);
}

export function deactivate() {}
