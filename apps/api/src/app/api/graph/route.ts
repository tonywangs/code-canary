import { NextRequest, NextResponse } from 'next/server';
import { agentService } from '@/lib/agent-service';
import { corsResponse } from '@/lib/cors';

export async function OPTIONS(request: NextRequest) {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': 'http://localhost:3000',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const projectId = searchParams.get('projectId');
    const depth = parseInt(searchParams.get('depth') || '1');

    if (!projectId) {
      return corsResponse(
        { error: 'Missing projectId parameter' },
        400
      );
    }

    let sbom = agentService.getSBOM(projectId);
    
    // If not in agent service, try to get from the enrich endpoint
    if (!sbom) {
      // For now, we'll return a mock graph since we don't have persistent SBOM storage
      // In a real implementation, you'd want to store SBOM data in a database
      const mockNodes = [
        { id: 'react@18.2.0', name: 'react', version: '18.2.0', direct: true, severity: 'NONE', group: 1 },
        { id: 'next@14.1.0', name: 'next', version: '14.1.0', direct: true, severity: 'LOW', group: 1 },
        { id: 'typescript@5.9.2', name: 'typescript', version: '5.9.2', direct: false, severity: 'NONE', group: 2 }
      ];
      
      const mockLinks = [
        { source: 'next@14.1.0', target: 'react@18.2.0' },
        { source: 'next@14.1.0', target: 'typescript@5.9.2' }
      ];
      
      return corsResponse({
        nodes: mockNodes.slice(0, depth * 2), // Limit based on depth
        links: mockLinks.slice(0, depth)
      });
    }

    // Generate graph data
    const nodes: any[] = [];
    const links: any[] = [];
    const nodeMap = new Map<string, any>();

    // Add packages based on depth
    sbom.packages.forEach((pkg) => {
      if (pkg.direct || depth > 1) {
        const node = {
          id: `${pkg.name}@${pkg.version}`,
          name: pkg.name,
          version: pkg.version,
          direct: pkg.direct,
          severity: getHighestSeverity(pkg),
          group: pkg.direct ? 1 : 2
        };
        nodes.push(node);
        nodeMap.set(node.id, node);
      }
    });

    // Add links based on depth
    sbom.packages.forEach(pkg => {
      if (pkg.direct || depth > 1) {
        // Add requires relationships
        pkg.requires?.forEach(required => {
          const sourceId = `${pkg.name}@${pkg.version}`;
          const targetId = `${required.name}@${required.version}`;
          
          if (nodeMap.has(sourceId) && nodeMap.has(targetId)) {
            links.push({ source: sourceId, target: targetId });
          }
        });

        // Add requiredBy relationships (for depth > 1)
        if (depth > 1) {
          pkg.requiredBy?.forEach(requiredBy => {
            const sourceId = `${requiredBy.name}@${requiredBy.version}`;
            const targetId = `${pkg.name}@${pkg.version}`;
            
            if (nodeMap.has(sourceId) && nodeMap.has(targetId)) {
              links.push({ source: sourceId, target: targetId });
            }
          });
        }
      }
    });

    return corsResponse({
      nodes,
      links,
      stats: {
        totalNodes: nodes.length,
        totalLinks: links.length,
        directDependencies: nodes.filter(n => n.direct).length,
        transitiveDependencies: nodes.filter(n => !n.direct).length
      }
    });
  } catch (error) {
    console.error('Graph API error:', error);
    return corsResponse(
      { error: 'Internal server error' },
      500
    );
  }
}

function getHighestSeverity(pkg: any): string {
  if (!pkg.vulns || pkg.vulns.length === 0) return 'NONE';
  
  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  for (const severity of severityOrder) {
    if (pkg.vulns.some((v: any) => v.severity === severity)) {
      return severity;
    }
  }
  return 'NONE';
} 