'use client';

import { useState } from 'react';
import { ScanRequest, EnrichedSBOM, AgentAnswer } from '@dependency-canary/shared';
import UploadForm from '@/components/upload-form';
import KPITiles from '@/components/kpi-tiles';
import SimpleGraph from '@/components/simple-graph';
import QAPanel from '@/components/qa-panel';

export default function HomePage() {
  const [loading, setLoading] = useState(false);
  const [sbom, setSBOM] = useState<EnrichedSBOM | null>(null);
  const [selectedService, setSelectedService] = useState<string>('');
  const [selectedNode, setSelectedNode] = useState<string>('');

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
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Filter by Service:
                </label>
                <select
                  value={selectedService}
                  onChange={(e) => setSelectedService(e.target.value)}
                  className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">All Services</option>
                  {sbom.metadata.services.map((service) => (
                    <option key={service} value={service}>
                      {service}
                    </option>
                  ))}
                </select>
              </div>
              
              <SimpleGraph 
                sbom={sbom} 
                selectedService={selectedService}
                onNodeSelect={setSelectedNode}
              />

              {selectedNode && (
                <div className="mt-4 p-4 bg-gray-50 rounded-md">
                  <p className="text-sm text-gray-600">
                    Selected: <strong>{selectedNode}</strong>
                  </p>
                </div>
              )}
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