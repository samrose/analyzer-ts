// cli.ts
import { program } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import { TypeScriptAnalyzer } from './analyzer';

async function main() {
    program
        .name('ts-analyzer')
        .description('Analyze TypeScript project structure and dependencies')
        .argument('[dir]', 'project directory to analyze', '.')
        .option('-o, --output <dir>', 'output directory for reports', './analysis')
        .action(async (dir, options) => {
            try {
                // Resolve paths
                const projectPath = path.resolve(dir);
                const outputPath = path.resolve(options.output);

                // Create output directory if it doesn't exist
                if (!fs.existsSync(outputPath)) {
                    fs.mkdirSync(outputPath, { recursive: true });
                }

                console.log(`Analyzing TypeScript project in: ${projectPath}`);
                console.log(`Output will be saved to: ${outputPath}`);

                // Run analysis
                const analyzer = new TypeScriptAnalyzer();
                await analyzer.analyzeDirectory(projectPath);

                // Generate and save reports
                const report = analyzer.generateReport();
                const diagram = analyzer.generateMermaidDiagram();

                await fs.promises.writeFile(
                    path.join(outputPath, 'codebase-analysis.md'),
                    report
                );
                await fs.promises.writeFile(
                    path.join(outputPath, 'dependency-diagram.mmd'),
                    diagram
                );

                console.log('Analysis complete! Generated files:');
                console.log('- codebase-analysis.md');
                console.log('- dependency-diagram.mmd');
            } catch (error) {
                console.error('Error during analysis:', error);
                process.exit(1);
            }
        });

    await program.parseAsync();
}

main();
