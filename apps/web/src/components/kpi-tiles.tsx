'use client';

import { EnrichedSBOM } from '@dependency-canary/shared';

interface KPITilesProps {
  sbom: EnrichedSBOM;
}

export default function KPITiles({ sbom }: KPITilesProps) {
  const { summary } = sbom;

  const tiles = [
    {
      label: 'Total Packages',
      value: summary.counts.packages,
      subtext: `${summary.counts.direct} direct, ${summary.counts.transitive} transitive`,
      color: 'bg-blue-500',
    },
    {
      label: 'Critical Vulnerabilities',
      value: summary.counts.critical,
      subtext: 'Require immediate attention',
      color: summary.counts.critical > 0 ? 'bg-red-500' : 'bg-green-500',
    },
    {
      label: 'High Severity',
      value: summary.counts.high,
      subtext: 'High priority fixes needed',
      color: summary.counts.high > 0 ? 'bg-orange-500' : 'bg-green-500',
    },
    {
      label: 'Total Vulnerabilities',
      value: summary.counts.vulns,
      subtext: `${summary.counts.medium || 0} medium, ${summary.counts.low || 0} low`,
      color: summary.counts.vulns > 0 ? 'bg-yellow-500' : 'bg-green-500',
    },
    {
      label: 'Languages',
      value: sbom.metadata.languages.length,
      subtext: sbom.metadata.languages.join(', '),
      color: 'bg-purple-500',
    },
    {
      label: 'Services',
      value: sbom.metadata.services.length,
      subtext: sbom.metadata.services.join(', '),
      color: 'bg-indigo-500',
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
      {tiles.map((tile, index) => (
        <div key={index} className="bg-white rounded-lg shadow-md p-6">
          <div className="flex items-center">
            <div className={`${tile.color} w-12 h-12 rounded-lg flex items-center justify-center mr-4`}>
              <span className="text-white font-bold text-lg">{tile.value}</span>
            </div>
            <div>
              <h3 className="font-semibold text-gray-900">{tile.label}</h3>
              <p className="text-sm text-gray-600">{tile.subtext}</p>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}