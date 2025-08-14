'use client';

import { useEffect, useRef, useState } from 'react';
import { EnrichedSBOM, Package } from '@dependency-canary/shared';

interface DependencyGraphProps {
  sbom: EnrichedSBOM;
  selectedService?: string;
  onNodeSelect?: (nodeId: string) => void;
}

export default function DependencyGraph({ 
  sbom, 
  selectedService, 
  onNodeSelect 
}: DependencyGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [networkLoaded, setNetworkLoaded] = useState(false);
  const networkRef = useRef<any>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const loadVisNetwork = async () => {
      try {
        const visNetwork = await import('vis-network/standalone/umd/vis-network.min.js');
        const { Network, DataSet } = (visNetwork as any).default || visNetwork;

        const filteredPackages = selectedService
          ? sbom.packages.filter(pkg => pkg.serviceRefs?.includes(selectedService))
          : sbom.packages;

        const nodeData = filteredPackages.map(pkg => {
          const severity = getHighestSeverity(pkg);
          const color = getSeverityColor(severity);
          
          return {
            id: pkg.name,
            label: `${pkg.name}@${pkg.version}`,
            title: createNodeTooltip(pkg),
            color: {
              background: color,
              border: pkg.direct ? '#2563eb' : '#6b7280',
            },
            borderWidth: pkg.direct ? 3 : 1,
            shape: pkg.direct ? 'box' : 'ellipse',
            font: {
              color: severity === 'CRITICAL' || severity === 'HIGH' ? 'white' : 'black',
              size: pkg.direct ? 14 : 12,
            },
          };
        });

        const edgeData = filteredPackages.flatMap(pkg => 
          (pkg.requires || [])
            .filter(dep => filteredPackages.some(p => p.name === dep.name))
            .map(dep => ({
              from: pkg.name,
              to: dep.name,
              arrows: 'to',
              color: { color: '#6b7280', opacity: 0.6 },
            }))
        );

        const nodes = new DataSet(nodeData);
        const edges = new DataSet(edgeData);
        const data = { nodes, edges };

        const options = {
          layout: {
            hierarchical: {
              enabled: true,
              direction: 'UD',
              sortMethod: 'directed',
              levelSeparation: 150,
              nodeSpacing: 200,
            },
          },
          physics: {
            enabled: false,
          },
          interaction: {
            hover: true,
            selectConnectedEdges: true,
          },
          nodes: {
            chosen: true,
            shadow: {
              enabled: true,
              color: 'rgba(0,0,0,0.2)',
              size: 10,
              x: 2,
              y: 2,
            },
          },
          edges: {
            smooth: {
              type: 'cubicBezier',
              forceDirection: 'vertical',
              roundness: 0.4,
            },
          },
        };

        if (networkRef.current) {
          networkRef.current.destroy();
        }

        networkRef.current = new Network(containerRef.current, data, options);

        if (onNodeSelect) {
          networkRef.current.on('selectNode', (event: any) => {
            if (event.nodes.length > 0) {
              onNodeSelect(event.nodes[0]);
            }
          });
        }

        setNetworkLoaded(true);
      } catch (error) {
        console.error('Failed to load vis-network:', error);
      }
    };

    loadVisNetwork();

    return () => {
      if (networkRef.current) {
        networkRef.current.destroy();
        networkRef.current = null;
      }
    };
  }, [sbom, selectedService, onNodeSelect]);

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold">Dependency Graph</h3>
        <div className="flex items-center gap-4 text-sm">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-blue-600 rounded border-2 border-blue-600"></div>
            <span>Direct</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-gray-400 rounded-full border border-gray-600"></div>
            <span>Transitive</span>
          </div>
        </div>
      </div>
      
      <div className="mb-4">
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 bg-red-600 rounded"></div>
            <span>Critical</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 bg-orange-500 rounded"></div>
            <span>High</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 bg-yellow-500 rounded"></div>
            <span>Medium</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 bg-green-500 rounded"></div>
            <span>Low/None</span>
          </div>
        </div>
      </div>

      <div
        ref={containerRef}
        className="w-full h-96 border border-gray-200 rounded-md flex items-center justify-center"
      >
        {!networkLoaded && (
          <div className="flex items-center gap-2 text-gray-500">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
            <span>Loading dependency graph...</span>
          </div>
        )}
      </div>
    </div>
  );
}

function getHighestSeverity(pkg: Package): string {
  if (!pkg.vulns?.length) return 'NONE';
  
  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  
  for (const severity of severityOrder) {
    if (pkg.vulns.some(v => v.severity === severity)) {
      return severity;
    }
  }
  
  return 'NONE';
}

function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return '#dc2626';
    case 'HIGH': return '#f97316';
    case 'MEDIUM': return '#eab308';
    case 'LOW': return '#16a34a';
    default: return '#e5e7eb';
  }
}

function createNodeTooltip(pkg: Package): string {
  const vulnCount = pkg.vulns?.length || 0;
  const severity = getHighestSeverity(pkg);
  
  return `
    <strong>${pkg.name}@${pkg.version}</strong><br/>
    Type: ${pkg.direct ? 'Direct' : 'Transitive'}<br/>
    Ecosystem: ${pkg.eco}<br/>
    Vulnerabilities: ${vulnCount}<br/>
    ${vulnCount > 0 ? `Highest Severity: ${severity}<br/>` : ''}
    Services: ${pkg.serviceRefs?.join(', ') || 'None'}<br/>
    License: ${pkg.license || 'Unknown'}
  `.trim();
}