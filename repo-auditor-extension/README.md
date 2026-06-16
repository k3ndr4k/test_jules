# Repo Auditor Extension

A VS Code extension that acts as a graphical interface for the `repo-auditor` Go binary. It allows you to select a local folder, executes the audit in the background, and displays the generated Mermaid.js architecture and security reports in an interactive Webview.

## Prerequisites

1.  **repo-auditor binary**: Ensure you have compiled the `repo-auditor` Go binary and that it is available in your system's PATH, or configure its location in the extension settings (`repoAuditor.binaryPath`).
2.  **(Optional but Recommended) Security Tools**:
    *   **Trivy**: For vulnerability scanning (`trivy` in PATH).
    *   **Gitleaks**: For secret detection (`gitleaks` in PATH).
    *   **Hadolint**: For Dockerfile linting (`hadolint` in PATH).

## How to Compile and Run

1.  **Install Dependencies**:
    Open a terminal in the `repo-auditor-extension` folder and run:
    ```bash
    npm install
    ```

2.  **Compile the Extension**:
    ```bash
    npm run compile
    ```

3.  **Test / Debug (F5)**:
    Open the `repo-auditor-extension` folder in VS Code. Press `F5` to open a new "Extension Development Host" window.
    *   Open the Command Palette (`Ctrl+Shift+P` or `Cmd+Shift+P`).
    *   Run **"Audit Repository"**.
    *   Select a folder containing your Git projects.
    *   Wait for the progress bar to finish. A Webview panel will automatically open showing your Mermaid diagrams and Security reports.

## Features
*   **Background Execution**: Runs the high-speed Go binary asynchronously without blocking the UI.
*   **Interactive Diagrams**: Extracts Mermaid.js blocks from the markdown output and renders them natively using the Mermaid.js CDN.
*   **Refresh/Export UI**: Includes buttons to easily reload the diagram or (in the future) export to PNG/SVG.
