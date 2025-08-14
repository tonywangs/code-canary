'use client';

import { useState } from 'react';
import { EnrichedSBOM, Package } from '@dependency-canary/shared';

interface SimpleGraphProps {
  sbom: EnrichedSBOM;
  selectedService?: string;
  onNodeSelect?: (nodeId: string) => void;
}

export default function SimpleGraph({ 
  sbom, 
  selectedService, 
  onNodeSelect 
}: SimpleGraphProps) {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const filteredPackages = selectedService
    ? sbom.packages.filter(pkg => pkg.serviceRefs?.includes(selectedService))
    : sbom.packages;

  const handleNodeClick = (pkg: Package) => {
    setSelectedNode(pkg.name);
    onNodeSelect?.(pkg.name);
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold">Dependency Overview</h3>
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

      <div className="space-y-4 max-h-96 overflow-y-auto">
        {filteredPackages.length === 0 && (
          <div className="text-center text-gray-500 py-8">
            No packages found for the selected service.
          </div>
        )}
        
        {filteredPackages.map((pkg) => {
          const severity = getHighestSeverity(pkg);
          const severityColor = getSeverityColor(severity);
          const vulnCount = pkg.vulns?.length || 0;
          
          return (
            <div
              key={`${pkg.name}-${pkg.version}`}
              onClick={() => handleNodeClick(pkg)}
              className={`p-4 border rounded-lg cursor-pointer transition-all hover:shadow-md ${
                selectedNode === pkg.name
                  ? 'border-blue-500 bg-blue-50'
                  : 'border-gray-200 hover:border-gray-300'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div
                    className={`w-4 h-4 rounded ${
                      pkg.direct ? 'border-2 border-blue-600' : 'border border-gray-600'
                    }`}
                    style={{ backgroundColor: severityColor }}
                  />
                  <div>
                    <h4 className="font-medium text-gray-900">
                      {pkg.name}@{pkg.version}
                    </h4>
                    <div className="flex items-center gap-2 text-sm text-gray-600">
                      <span className="px-2 py-0.5 bg-gray-100 rounded text-xs">
                        {pkg.eco}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-xs ${
                        pkg.direct 
                          ? 'bg-blue-100 text-blue-800' 
                          : 'bg-gray-100 text-gray-600'
                      }`}>
                        {pkg.direct ? 'Direct' : 'Transitive'}
                      </span>
                      {pkg.serviceRefs && pkg.serviceRefs.length > 0 && (
                        <span className="text-gray-500">
                          → {pkg.serviceRefs.join(', ')}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
                
                <div className="text-right">
                  {vulnCount > 0 ? (
                    <div className="flex flex-col items-end gap-1">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                        severity === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                        severity === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-gray-100 text-gray-600'
                      }`}>
                        {vulnCount} vuln{vulnCount !== 1 ? 's' : ''}
                      </span>
                      {severity !== 'NONE' && (
                        <span className="text-xs text-gray-500">
                          {severity}
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="px-2 py-1 bg-green-100 text-green-800 rounded text-xs font-medium">
                      No vulns
                    </span>
                  )}
                </div>
              </div>
              
              {selectedNode === pkg.name && (
                <div className="mt-3 pt-3 border-t border-gray-200">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="font-medium text-gray-700">License:</span>
                      <span className="ml-2 text-gray-600">{pkg.license || 'Unknown'}</span>
                    </div>
                    <div>
                      <span className="font-medium text-gray-700">Dependencies:</span>
                      <span className="ml-2 text-gray-600">{pkg.requires?.length || 0}</span>
                    </div>
                    {pkg.stats?.weeklyDownloads && (
                      <div>
                        <span className="font-medium text-gray-700">Downloads/week:</span>
                        <span className="ml-2 text-gray-600">
                          {pkg.stats.weeklyDownloads.toLocaleString()}
                        </span>
                      </div>
                    )}
                    {pkg.stats?.lastCommit && (
                      <div>
                        <span className="font-medium text-gray-700">Last commit:</span>
                        <span className="ml-2 text-gray-600">{pkg.stats.lastCommit}</span>
                      </div>
                    )}
                  </div>
                  
                  {vulnCount > 0 && (
                    <div className="mt-3">
                      <span className="font-medium text-gray-700">Vulnerabilities:</span>
                      <div className="mt-2 space-y-2">
                        {pkg.vulns!.slice(0, 3).map((vuln) => (
                          <div key={vuln.id} className="bg-gray-50 p-2 rounded">
                            <div className="flex items-center justify-between">
                              <span className="font-medium text-sm">{vuln.id}</span>
                              <span className={`px-2 py-0.5 rounded text-xs ${
                                vuln.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                                vuln.severity === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                                vuln.severity === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
                                'bg-gray-100 text-gray-600'
                              }`}>
                                {vuln.severity} (CVSS: {vuln.cvss})
                              </span>
                            </div>
                            <p className="text-sm text-gray-600 mt-1">
                              {vuln.summary}
                            </p>
                          </div>
                        ))}
                        {pkg.vulns!.length > 3 && (
                          <p className="text-sm text-gray-500">
                            ... and {pkg.vulns!.length - 3} more vulnerabilities
                          </p>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
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