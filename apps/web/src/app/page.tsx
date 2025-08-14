'use client';

import { useState } from 'react';
import { ScanRequest, EnrichedSBOM, AgentAnswer } from '@dependency-canary/shared';
import UploadForm from '@/components/upload-form';
import KPITiles from '@/components/kpi-tiles';
import SimpleGraph from '@/components/simple-graph';
import DependencyGraphViz from '@/components/dependency-graph-viz';
import QAPanel from '@/components/qa-panel';

export default function HomePage() {
  const [loading, setLoading] = useState(false);
  const [sbom, setSBOM] = useState<EnrichedSBOM | null>(null);

  const handleScan = async (request: ScanRequest) => {
    setLoading(true);
    setSBOM(null);

    try {
      const scanResponse = await fetch('http://localhost:3001/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      });

      if (!scanResponse.ok) {
        throw new Error(`Scan failed: ${scanResponse.statusText}`);
      }

      const { jobId } = await scanResponse.json();

      let enrichResult;
      let attempts = 0;
      const maxAttempts = 30;

      do {
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        const enrichResponse = await fetch(`http://localhost:3001/api/enrich?jobId=${jobId}`);
        
        if (enrichResponse.ok) {
          enrichResult = await enrichResponse.json();
          break;
        }
        
        attempts++;
      } while (attempts < maxAttempts);

      if (!enrichResult) {
        throw new Error('Failed to get enriched SBOM after maximum attempts');
      }

      setSBOM(enrichResult);
    } catch (error) {
      console.error('Scan error:', error);
      alert(error instanceof Error ? error.message : 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const handleAsk = async (question: string): Promise<AgentAnswer> => {
    if (!sbom) {
      throw new Error('No SBOM available');
    }

    const response = await fetch('http://localhost:3001/api/ask', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        projectId: sbom.projectId,
        question,
      }),
    });

    if (!response.ok) {
      throw new Error(`Failed to get answer: ${response.statusText}`);
    }

    return response.json();
  };

  const handleGenerateReport = async () => {
    if (!sbom) return;

    const response = await fetch(`http://localhost:3001/api/report?projectId=${sbom.projectId}&format=pdf`);
    
    if (!response.ok) {
      alert('Failed to generate report');
      return;
    }

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = `dependency-report-${sbom.projectId}.pdf`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-7xl mx-auto">
      <div className="text-center mb-8">
        <h1 className="text-4xl font-bold text-gray-900 mb-4">
          Dependency Canary
        </h1>
        <p className="text-xl text-gray-600 mb-8">
          AI-powered dependency vulnerability analysis and supply chain security
        </p>
      </div>

      <UploadForm onSubmit={handleScan} loading={loading} />

      <div className="bg-blue-50 border border-blue-200 rounded-lg p-6 mb-8">
        <h3 className="text-lg font-semibold text-blue-900 mb-2">Quick Demo</h3>
        <p className="text-blue-700 mb-4">
          Want to see the dependency graph visualization? Try the demo with sample data.
        </p>
        <button
          onClick={() => {
            // Mock SBOM data for demo
            const demoSBOM: EnrichedSBOM = {
              projectId: 'demo-project',
              generatedAt: new Date().toISOString(),
              metadata: {
                languages: ['typescript', 'javascript'],
                services: ['web', 'api']
              },
              packages: [
                {
                  name: 'react',
                  version: '18.2.0',
                  eco: 'npm',
                  direct: true,
                  requires: [{ name: 'typescript', version: '5.9.2' }],
                  vulns: []
                },
                {
                  name: 'next',
                  version: '14.1.0',
                  eco: 'npm',
                  direct: true,
                  requires: [
                    { name: 'react', version: '18.2.0' },
                    { name: 'typescript', version: '5.9.2' }
                  ],
                  vulns: [
                    { 
                      id: 'CVE-2024-1234', 
                      source: 'NVD',
                      cvss: 3.1,
                      severity: 'LOW', 
                      published: '2024-01-01',
                      summary: 'Test vulnerability',
                      affectedRanges: ['<14.2.0']
                    }
                  ]
                },
                {
                  name: 'typescript',
                  version: '5.9.2',
                  eco: 'npm',
                  direct: false,
                  requires: [],
                  vulns: []
                },
                {
                  name: 'd3',
                  version: '7.8.5',
                  eco: 'npm',
                  direct: true,
                  requires: [{ name: 'typescript', version: '5.9.2' }],
                  vulns: []
                },
                {
                  name: 'tailwindcss',
                  version: '3.4.0',
                  eco: 'npm',
                  direct: true,
                  requires: [],
                  vulns: [
                    { 
                      id: 'CVE-2024-5678', 
                      source: 'NVD',
                      cvss: 5.5,
                      severity: 'MEDIUM', 
                      published: '2024-01-02',
                      summary: 'Another test vulnerability',
                      affectedRanges: ['<3.5.0']
                    }
                  ]
                },
                {
                  name: 'lodash',
                  version: '4.17.21',
                  eco: 'npm',
                  direct: true,
                  requires: [],
                  vulns: []
                }
              ],
              summary: {
                counts: {
                  packages: 6,
                  direct: 5,
                  transitive: 1,
                  vulns: 2,
                  critical: 0,
                  high: 0,
                  medium: 1,
                  low: 1
                },
                topRisks: [
                  { package: 'tailwindcss', version: '3.4.0', score: 0.6, reason: 'Medium severity vulnerability' },
                  { package: 'next', version: '14.1.0', score: 0.3, reason: 'Low severity vulnerability' }
                ]
              }
            };
            setSBOM(demoSBOM);
          }}
          className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors"
        >
          View Demo Graph
        </button>
      </div>

      {loading && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-6 mb-8">
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mr-3"></div>
            <p className="text-blue-800">
              Scanning dependencies and analyzing vulnerabilities...
            </p>
          </div>
        </div>
      )}

      {sbom && (
        <div className="space-y-8">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-2xl font-bold text-gray-900">Analysis Results</h2>
              <p className="text-gray-600">
                Generated on {new Date(sbom.generatedAt).toLocaleString()}
              </p>
            </div>
            <button
              onClick={handleGenerateReport}
              className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700 transition-colors"
            >
              Download PDF Report
            </button>
          </div>

          <KPITiles sbom={sbom} />

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2">
              <DependencyGraphViz sbom={sbom} />
            </div>

            <div>
              <QAPanel projectId={sbom.projectId} onAsk={handleAsk} />
            </div>
          </div>

          {sbom.summary.topRisks.length > 0 && (
            <div className="bg-white rounded-lg shadow-md p-6">
              <h3 className="text-lg font-semibold mb-4">Top Risk Packages</h3>
              <div className="space-y-3">
                {sbom.summary.topRisks.map((risk, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-red-50 rounded-md">
                    <div>
                      <p className="font-medium text-red-900">
                        {risk.package}@{risk.version}
                      </p>
                      <p className="text-sm text-red-700">{risk.reason}</p>
                    </div>
                    <div className="bg-red-600 text-white px-2 py-1 rounded text-sm font-medium">
                      {Math.round(risk.score * 100)}% risk
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}