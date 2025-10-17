/**
 * Main extension file for the CognitiveTrust Security Scanner.
 * This version includes all required and optional features, using Google's Gemini API.
 *
 * REQUIRED FEATURES:
 * 1.  Detects hardcoded secrets & missing authorization.
 * 2.  Checks for outdated libraries in requirements.txt.
 * 3.  Provides Quick Fix suggestions.
 * 4.  Rescans on save after a fix is applied.
 *
 * OPTIONAL FEATURES:
 * 1.  (AI Refactoring) "Refactor with AI" Quick Fix using the Gemini API for ALL issue types.
 * 2.  (Scan History & Metrics) Logs scan history and tracks the number of fixes applied.
 * 3.  (Workspace Scan) Provides a command to scan all files in the workspace.
 */
import * as vscode from 'vscode';
import { exec } from 'child_process';
import * as path from 'path';
import * as semver from 'semver';
import axios from 'axios'; // For Gemini API calls

// A map of vulnerable Python libraries and their minimum secure versions.
const VULNERABLE_LIBRARIES: { [key: string]: string } = {
    'requests': '2.25.0',
    'flask': '1.1.2',
    'django': '3.2.0'
};

const SECRET_STORAGE_KEY = 'geminiApiKey'; // Key for VS Code's SecretStorage
const FIX_COUNT_KEY = 'fixesAppliedCount'; // Key for tracking fix metrics

export function activate(context: vscode.ExtensionContext) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('security');
    context.subscriptions.push(diagnosticCollection);
    
    // Initialize the fix counter metric
    context.workspaceState.update(FIX_COUNT_KEY, context.workspaceState.get(FIX_COUNT_KEY, 0));

    // Initial scan for the currently active editor
    if (vscode.window.activeTextEditor) {
        updateDiagnostics(vscode.window.activeTextEditor.document, diagnosticCollection, context);
    }

    // Register listeners for file open and save events to trigger scans.
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor) {
                updateDiagnostics(editor.document, diagnosticCollection, context);
            }
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(document => {
            updateDiagnostics(document, diagnosticCollection, context);
        })
    );
    
    // Register the Code Action Provider for our Quick Fixes (including AI).
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            ['python', { scheme: 'file', language: 'pip-requirements' }],
            new SecurityFixer(),
            { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
        )
    );

    // --- OPTIONAL FEATURE: COMMANDS ---
    // Register command handlers for our quick fixes
    context.subscriptions.push(
        vscode.commands.registerCommand('cognitivetrust.applyStandardFix', (document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {
            standardFixHandler(document, diagnostic, context);
        })
    );
    context.subscriptions.push(
        vscode.commands.registerCommand('cognitivetrust.refactorWithAI', (document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {
            geminiRefactorHandler(document, diagnostic, context);
        })
    );

    // Register command for showing scan history
    context.subscriptions.push(
        vscode.commands.registerCommand('cognitivetrust.showHistory', () => showScanHistory(context))
    );

    // Register command for scanning the entire workspace
    context.subscriptions.push(
        vscode.commands.registerCommand('cognitivetrust.scanWorkspace', () => scanWorkspace(diagnosticCollection, context))
    );
    
    // Register command to clear the stored API key
    context.subscriptions.push(
        vscode.commands.registerCommand('cognitivetrust.clearApiKey', async () => {
            await context.secrets.delete(SECRET_STORAGE_KEY);
            vscode.window.showInformationMessage('CognitiveTrust: Gemini API Key has been cleared.');
        })
    );
}

// --- Main Scanning Logic (Updated for History) ---
async function updateDiagnostics(document: vscode.TextDocument, collection: vscode.DiagnosticCollection, context: vscode.ExtensionContext): Promise<void> {
    let diagnostics: vscode.Diagnostic[] = [];
    if (document.languageId === 'python' && document.fileName.endsWith('.py')) {
        diagnostics = await runSemgrepScan(document);
    } else if (document.fileName.endsWith('requirements.txt')) {
        diagnostics = checkOutdatedLibraries(document);
    }
    collection.set(document.uri, diagnostics);

    // --- OPTIONAL FEATURE: Scan History ---
    logScanResult(document, diagnostics, context);
}

// Semgrep and library scanning functions remain the same.
function runSemgrepScan(document: vscode.TextDocument): Promise<vscode.Diagnostic[]> {
    const rulesPath = path.join(__dirname, '..', 'rules');
    const command = `semgrep scan --config "${rulesPath}" --json "${document.fileName}"`;
    return new Promise((resolve) => {
        exec(command, (error, stdout, stderr) => {
            if (stderr) console.log('Semgrep process output:', stderr);
            if (!stdout) {
                if (error) console.error(`Semgrep process exited with code ${error.code}`);
                return resolve([]);
            }
            try {
                const results = JSON.parse(stdout);
                const diagnostics = (results.results || []).map((finding: any) => {
                    const range = new vscode.Range(finding.start.line - 1, finding.start.col - 1, finding.end.line - 1, finding.end.col - 1);
                    const severity = finding.extra.severity === 'ERROR' ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning;
                    const diagnostic = new vscode.Diagnostic(range, finding.extra.message, severity);
                    diagnostic.source = 'Security Scanner';
                    diagnostic.code = finding.check_id; // e.g., 'hardcoded-secret', 'missing-authorization'
                    return diagnostic;
                });
                resolve(diagnostics);
            } catch (e) {
                console.error('Failed to parse Semgrep JSON output.', e);
                resolve([]);
            }
        });
    });
}

function checkOutdatedLibraries(document: vscode.TextDocument): vscode.Diagnostic[] {
    const diagnostics: vscode.Diagnostic[] = [];
    const lines = document.getText().split('\n');
    lines.forEach((line, index) => {
        line = line.trim();
        if (!line || line.startsWith('#')) return;
        const match = line.match(/^([a-zA-Z0-9_-]+)(==|>=|<=|>|<)?([0-9.]+)?/);
        if (!match) return;
        const libName = match[1];
        const version = match[3];
        if (VULNERABLE_LIBRARIES[libName] && version && semver.lt(version, VULNERABLE_LIBRARIES[libName])) {
            const range = new vscode.Range(index, 0, index, line.length);
            const message = `${libName} version ${version} is outdated. Please upgrade to ${VULNERABLE_LIBRARIES[libName]} or later.`;
            const diagnostic = new vscode.Diagnostic(range, message, vscode.DiagnosticSeverity.Warning);
            diagnostic.source = 'Security Scanner';
            diagnostic.code = 'outdated-library';
            diagnostics.push(diagnostic);
        }
    });
    return diagnostics;
}


// --- CodeActionProvider (Updated for AI) ---
class SecurityFixer implements vscode.CodeActionProvider {
    public provideCodeActions(document: vscode.TextDocument, range: vscode.Range, context: vscode.CodeActionContext): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];
        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== 'Security Scanner') {
                continue;
            }
            const codeStr = diagnostic.code ? String(diagnostic.code) : '';
            
            if (codeStr.includes('hardcoded-secret')) {
                const standardFix = this.createStandardFixAction(document, diagnostic);
                standardFix.isPreferred = true;
                actions.push(standardFix);
            }
            
            const aiFix = this.createAiRefactorAction(document, diagnostic);
            if (!actions.some(a => a.isPreferred)) {
                aiFix.isPreferred = true;
            }
            actions.push(aiFix);
        }
        return actions;
    }

    private createStandardFixAction(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.CodeAction {
        const fix = new vscode.CodeAction('Replace with environment variable', vscode.CodeActionKind.QuickFix);
        fix.diagnostics = [diagnostic];
        fix.command = {
            command: 'cognitivetrust.applyStandardFix',
            title: 'Replace with environment variable',
            arguments: [document, diagnostic]
        };
        return fix;
    }

    private createAiRefactorAction(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.CodeAction {
        const fix = new vscode.CodeAction('Refactor with Gemini ✨', vscode.CodeActionKind.QuickFix);
        fix.diagnostics = [diagnostic];
        fix.command = {
            command: 'cognitivetrust.refactorWithAI',
            title: 'Refactor with Gemini',
            arguments: [document, diagnostic]
        };
        return fix;
    }
}

// --- Fix Handlers ---

// This handler applies the standard, non-AI fix and tracks the metric.
async function standardFixHandler(document: vscode.TextDocument, diagnostic: vscode.Diagnostic, context: vscode.ExtensionContext) {
    const edit = new vscode.WorkspaceEdit();
    const originalLine = document.lineAt(diagnostic.range.start.line).text;
    const match = originalLine.match(/^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=/);
    
    if (match) {
        const variableName = match[1].trim();
        const replacementText = `${variableName} = os.getenv('${variableName.toUpperCase()}')`;
        const indent = originalLine.match(/^\s*/)?.[0] || '';
        const lineRange = document.lineAt(diagnostic.range.start.line).range;
        edit.replace(document.uri, lineRange, indent + replacementText);

        if (!document.getText().includes('import os')) {
            edit.insert(document.uri, new vscode.Position(0, 0), 'import os\n');
        }
        
        await vscode.workspace.applyEdit(edit);
        incrementFixCount(context); // Track the fix
        vscode.window.showInformationMessage('Fix applied successfully.');
    }
}

// This handler applies the AI-powered fix and tracks the metric.
async function geminiRefactorHandler(document: vscode.TextDocument, diagnostic: vscode.Diagnostic, context: vscode.ExtensionContext) {
    let apiKey = await context.secrets.get(SECRET_STORAGE_KEY);

    if (!apiKey) {
        apiKey = await vscode.window.showInputBox({
            prompt: 'Please enter your Google AI Gemini API Key',
            ignoreFocusOut: true,
            password: true,
            title: 'Gemini API Key'
        });

        if (apiKey) {
            await context.secrets.store(SECRET_STORAGE_KEY, apiKey);
        } else {
            vscode.window.showWarningMessage('Refactoring with Gemini cancelled. No API key was provided.');
            return;
        }
    }
    
    const range = diagnostic.range;
    const insecureCode = document.getText(range);
    const issueDescription = diagnostic.message;
    const diagnosticCode = diagnostic.code ? String(diagnostic.code) : '';

    let prompt = '';
    switch (diagnosticCode) {
        case 'outdated-library':
            prompt = `You are a dependency management expert. The following line from a Python requirements.txt file specifies an outdated library: "${insecureCode}". The specific issue is: "${issueDescription}". Please provide only the corrected line, updated to a secure version that fixes the issue.`;
            break;
        case 'missing-authorization':
            prompt = `You are a Python Flask security expert. The following route definition is missing an authorization check: \n\`\`\`python\n${insecureCode}\n\`\`\`\nThe specific issue is: "${issueDescription}". Add a placeholder authorization decorator (like '@login_required' from a common library like Flask-Login) to the function. Provide the complete, corrected function definition as a single block of code, without any explanation.`;
            break;
        case 'hardcoded-secret':
        default:
            prompt = `You are a Python security expert. Refactor the following line of code to remove the hardcoded secret by using the 'os' module to get it from an environment variable. The insecure code is: "${insecureCode}". Provide only the single, corrected line of Python code, without any explanation or extra text.`;
            break;
    }

    const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=${apiKey}`;

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Asking Gemini to refactor code...",
        cancellable: false
    }, async (progress) => {
        try {
            const response = await axios.post(apiUrl, {
                contents: [{ parts: [{ text: prompt }] }]
            }, {
                headers: { 'Content-Type': 'application/json' }
            });

            const refactoredCode = response.data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim();

            if (!refactoredCode) {
                 throw new Error("Received an empty or invalid response from the Gemini API.");
            }
            
            const edit = new vscode.WorkspaceEdit();
            edit.replace(document.uri, range, refactoredCode);

            if (diagnosticCode.includes('hardcoded-secret') && !document.getText().includes('import os')) {
                edit.insert(document.uri, new vscode.Position(0, 0), 'import os\n');
            }

            await vscode.workspace.applyEdit(edit);
            incrementFixCount(context); // Track the fix
            vscode.window.showInformationMessage('Code refactored successfully by Gemini.');
        } catch (error: any) {
            console.error(error);
            const errorMessage = error.response?.data?.error?.message || error.message || "An unknown error occurred.";
            vscode.window.showErrorMessage(`Failed to refactor with Gemini: ${errorMessage}`);
        }
    });
}


// --- OPTIONAL FEATURE 2: Scan History & Metrics Functions ---
function incrementFixCount(context: vscode.ExtensionContext) {
    const currentCount = context.workspaceState.get<number>(FIX_COUNT_KEY, 0);
    context.workspaceState.update(FIX_COUNT_KEY, currentCount + 1);
}

function logScanResult(document: vscode.TextDocument, diagnostics: vscode.Diagnostic[], context: vscode.ExtensionContext) {
    const history = context.workspaceState.get<any[]>('scanHistory', []);
    history.unshift({
        file: vscode.workspace.asRelativePath(document.fileName),
        timestamp: new Date().toLocaleString(),
        issuesFound: diagnostics.length
    });
    if (history.length > 50) {
        history.pop();
    }
    context.workspaceState.update('scanHistory', history);
}

function showScanHistory(context: vscode.ExtensionContext) {
    const outputChannel = vscode.window.createOutputChannel("Scan History");
    const history = context.workspaceState.get<any[]>('scanHistory', []);
    const fixesApplied = context.workspaceState.get<number>(FIX_COUNT_KEY, 0);
    
    outputChannel.clear();
    
    // Display the metric at the top
    outputChannel.appendLine(`--- METRICS ---`);
    outputChannel.appendLine(`Total Fixes Applied: ${fixesApplied}`);
    outputChannel.appendLine(`---`);
    outputChannel.appendLine(``);

    if (history.length === 0) {
        outputChannel.appendLine("No scan history found.");
    } else {
        outputChannel.appendLine("Recent Scans (newest first):\n");
        history.forEach(item => {
            outputChannel.appendLine(`- [${item.timestamp}] ${item.file} - Found ${item.issuesFound} issues.`);
        });
    }
    outputChannel.show();
}

// --- OPTIONAL FEATURE 3: Workspace Scanning Function ---
async function scanWorkspace(collection: vscode.DiagnosticCollection, context: vscode.ExtensionContext) {
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Scanning workspace for security issues...",
        cancellable: false
    }, async (progress) => {
        collection.clear();
        const pythonFiles = await vscode.workspace.findFiles('**/*.py', '**/node_modules/**');
        const reqFiles = await vscode.workspace.findFiles('**/requirements.txt', '**/node_modules/**');
        const allFiles = [...pythonFiles, ...reqFiles];
        
        for (const fileUri of allFiles) {
            const document = await vscode.workspace.openTextDocument(fileUri);
            await updateDiagnostics(document, collection, context);
        }
    });
    vscode.window.showInformationMessage('Workspace scan complete. Check the "Problems" panel for results.');
}

export function deactivate() {}
