'use client';

import DependencyGraphViz from '@/components/dependency-graph-viz';
import { EnrichedSBOM } from '@dependency-canary/shared';

// Mock SBOM data for testing
const mockSBOM: EnrichedSBOM = {
  projectId: 'test-project',
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
      requires: [
        { name: 'typescript', version: '5.9.2' }
      ],
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
      requires: [
        { name: 'typescript', version: '5.9.2' }
      ],
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
    }
  ],
  summary: {
    counts: {
      packages: 5,
      direct: 4,
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

export default function TestGraphPage() {
  return (
    <div className="max-w-7xl mx-auto p-8">
      <h1 className="text-3xl font-bold mb-8">Dependency Graph Test</h1>
      <DependencyGraphViz sbom={mockSBOM} />
    </div>
  );
} 