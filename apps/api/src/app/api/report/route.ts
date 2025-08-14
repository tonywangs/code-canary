import { NextRequest, NextResponse } from 'next/server';
import { ReportGenerator } from '@/lib/report-generator';
import { agentService } from '@/lib/agent-service';
import puppeteer from 'puppeteer';

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const projectId = searchParams.get('projectId');
    const format = searchParams.get('format') || 'pdf';

    if (!projectId) {
      return NextResponse.json(
        { error: 'Missing projectId parameter' },
        { status: 400 }
      );
    }

    const sbom = agentService.getSBOM(projectId);
    if (!sbom) {
      return NextResponse.json(
        { error: 'SBOM not found for project' },
        { status: 404 }
      );
    }

    const generator = new ReportGenerator();
    const markdown = generator.generateMarkdown(sbom);

    if (format === 'markdown') {
      return new NextResponse(markdown, {
        headers: {
          'Content-Type': 'text/markdown',
          'Content-Disposition': `attachment; filename=report-${projectId}.md`,
        },
      });
    }

    if (format === 'pdf') {
      const html = `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Dependency Security Report</title>
          <style>
            body { 
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
              line-height: 1.6;
              color: #333;
              max-width: 800px;
              margin: 0 auto;
              padding: 20px;
            }
            h1, h2, h3, h4 { color: #2563eb; }
            h1 { border-bottom: 3px solid #2563eb; padding-bottom: 10px; }
            h2 { border-bottom: 1px solid #e5e7eb; padding-bottom: 5px; margin-top: 30px; }
            table { border-collapse: collapse; width: 100%; margin: 20px 0; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f8fafc; }
            code { background-color: #f1f5f9; padding: 2px 4px; border-radius: 3px; }
            .risk-high { color: #dc2626; font-weight: bold; }
            .risk-medium { color: #ea580c; }
            .risk-low { color: #16a34a; }
            @page { margin: 1in; }
          </style>
        </head>
        <body>
          ${markdownToHtml(markdown)}
        </body>
        </html>
      `;

      const browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
      });
      
      const page = await browser.newPage();
      await page.setContent(html, { waitUntil: 'networkidle0' });
      
      const pdf = await page.pdf({
        format: 'A4',
        printBackground: true,
        margin: {
          top: '1in',
          bottom: '1in',
          left: '1in',
          right: '1in',
        },
      });

      await browser.close();

      return new NextResponse(pdf as BufferSource, {
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Disposition': `attachment; filename=report-${projectId}.pdf`,
        },
      });
    }

    return NextResponse.json(
      { error: 'Invalid format. Supported: markdown, pdf' },
      { status: 400 }
    );
  } catch (error) {
    console.error('Report API error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

function markdownToHtml(markdown: string): string {
    return markdown
      .replace(/^# (.*$)/gm, '<h1>$1</h1>')
      .replace(/^## (.*$)/gm, '<h2>$1</h2>')
      .replace(/^### (.*$)/gm, '<h3>$1</h3>')
      .replace(/^#### (.*$)/gm, '<h4>$1</h4>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`(.*?)`/g, '<code>$1</code>')
      .replace(/^\- (.*$)/gm, '<li>$1</li>')
      .replace(/(<li>.*<\/li>)/g, '<ul>$1</ul>')
      .replace(/\n\n/g, '</p><p>')
      .replace(/^(.*)$/gm, '<p>$1</p>')
      .replace(/<p><h/g, '<h')
      .replace(/<\/h([1-6])><\/p>/g, '</h$1>')
      .replace(/<p><ul>/g, '<ul>')
      .replace(/<\/ul><\/p>/g, '</ul>')
      .replace(/\|(.+)\|/g, (match, content) => {
        const cells = content.split('|').map((cell: string) => cell.trim());
        return '<tr>' + cells.map((cell: string) => `<td>${cell}</td>`).join('') + '</tr>';
      })
      .replace(/(<tr>.*<\/tr>)/g, '<table>$1</table>')
      .replace(/<p><table>/g, '<table>')
      .replace(/<\/table><\/p>/g, '</table>');
}