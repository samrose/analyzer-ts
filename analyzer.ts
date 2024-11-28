import * as fs from 'fs';
import * as path from 'path';
import * as ts from 'typescript';

interface FileAnalysis {
    imports: string[];
    exports: string[];
    interfaces: string[];
    classes: string[];
    functions: string[];
    dependencies: Set<string>;
}

interface CodebaseMetrics {
    totalFiles: number;
    totalLines: number;
    totalImports: number;
    totalExports: number;
    totalInterfaces: number;
    totalClasses: number;
    totalFunctions: number;
}

// Added 'export' keyword here
export class TypeScriptAnalyzer {
    private metrics: CodebaseMetrics = {
        totalFiles: 0,
        totalLines: 0,
        totalImports: 0,
        totalExports: 0,
        totalInterfaces: 0,
        totalClasses: 0,
        totalFunctions: 0
    };

    private fileAnalyses: Map<string, FileAnalysis> = new Map();
    private dependencyGraph: Map<string, Set<string>> = new Map();

    async analyzeDirectory(directoryPath: string): Promise<void> {
        const files = await this.getTypeScriptFiles(directoryPath);
        this.metrics.totalFiles = files.length;

        for (const file of files) {
            const analysis = await this.analyzeFile(file);
            this.fileAnalyses.set(file, analysis);
            this.updateMetrics(analysis);
            this.dependencyGraph.set(file, analysis.dependencies);
        }
    }

    private async getTypeScriptFiles(dir: string): Promise<string[]> {
        const files: string[] = [];
        
        const items = await fs.promises.readdir(dir, { withFileTypes: true });
        
        for (const item of items) {
            const fullPath = path.join(dir, item.name);
            
            if (item.isDirectory()) {
                files.push(...await this.getTypeScriptFiles(fullPath));
            } else if (item.isFile() && /\.tsx?$/.test(item.name)) {
                files.push(fullPath);
            }
        }
        
        return files;
    }

    private async analyzeFile(filePath: string): Promise<FileAnalysis> {
        const content = await fs.promises.readFile(filePath, 'utf-8');
        const sourceFile = ts.createSourceFile(
            filePath,
            content,
            ts.ScriptTarget.Latest,
            true
        );

        const analysis: FileAnalysis = {
            imports: [],
            exports: [],
            interfaces: [],
            classes: [],
            functions: [],
            dependencies: new Set()
        };

        this.visitNode(sourceFile, analysis);
        return analysis;
    }

    private visitNode(node: ts.Node, analysis: FileAnalysis): void {
        if (ts.isImportDeclaration(node)) {
            const importPath = (node.moduleSpecifier as ts.StringLiteral).text;
            analysis.imports.push(importPath);
            analysis.dependencies.add(importPath);
        }

        if (ts.isExportDeclaration(node)) {
            if (node.moduleSpecifier) {
                analysis.exports.push((node.moduleSpecifier as ts.StringLiteral).text);
            }
        }

        if (ts.isInterfaceDeclaration(node)) {
            analysis.interfaces.push(node.name.text);
        }

        if (ts.isClassDeclaration(node)) {
            if (node.name) {
                analysis.classes.push(node.name.text);
            }
        }

        if (ts.isFunctionDeclaration(node)) {
            if (node.name) {
                analysis.functions.push(node.name.text);
            }
        }

        node.forEachChild(child => this.visitNode(child, analysis));
    }

    private updateMetrics(analysis: FileAnalysis): void {
        this.metrics.totalImports += analysis.imports.length;
        this.metrics.totalExports += analysis.exports.length;
        this.metrics.totalInterfaces += analysis.interfaces.length;
        this.metrics.totalClasses += analysis.classes.length;
        this.metrics.totalFunctions += analysis.functions.length;
    }

    generateReport(): string {
        let report = '# TypeScript Codebase Analysis Report\n\n';
        
        report += '## Overall Metrics\n';
        report += `- Total TypeScript Files: ${this.metrics.totalFiles}\n`;
        report += `- Total Imports: ${this.metrics.totalImports}\n`;
        report += `- Total Exports: ${this.metrics.totalExports}\n`;
        report += `- Total Interfaces: ${this.metrics.totalInterfaces}\n`;
        report += `- Total Classes: ${this.metrics.totalClasses}\n`;
        report += `- Total Functions: ${this.metrics.totalFunctions}\n\n`;

        report += '## Dependency Analysis\n';
        for (const [file, analysis] of this.fileAnalyses) {
            report += `\n### ${path.basename(file)}\n`;
            report += `- Imports: ${analysis.imports.join(', ')}\n`;
            report += `- Exports: ${analysis.exports.join(', ')}\n`;
            report += `- Interfaces: ${analysis.interfaces.join(', ')}\n`;
            report += `- Classes: ${analysis.classes.join(', ')}\n`;
            report += `- Functions: ${analysis.functions.join(', ')}\n`;
        }

        return report;
    }
    
    generateMermaidDiagram(): string {
        let diagram = 'graph LR\n';
        
        for (const [file, dependencies] of this.dependencyGraph) {
            const fileId = this.sanitizeId(path.basename(file));
            
            for (const dep of dependencies) {
                const depId = this.sanitizeId(dep);
                diagram += `    ${fileId}-->${depId}\n`;
            }
        }
        
        return diagram;
    }

    private sanitizeId(id: string): string {
        return id.replace(/[^a-zA-Z0-9]/g, '_');
    }
}
