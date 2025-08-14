'use client';

import { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { EnrichedSBOM, Package } from '@dependency-canary/shared';

interface DependencyGraphVizProps {
  sbom: EnrichedSBOM;
}

interface GraphNode extends d3.SimulationNodeDatum {
  id: string;
  name: string;
  version: string;
  direct: boolean;
  severity: string;
  group: number;
}

interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  source: string;
  target: string;
}

export default function DependencyGraphViz({ sbom }: DependencyGraphVizProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [depth, setDepth] = useState(1);
  const [graphData, setGraphData] = useState<{ nodes: GraphNode[], links: GraphLink[] }>({ nodes: [], links: [] });

  // Build graph data based on depth
  useEffect(() => {
    const nodes: GraphNode[] = [];
    const links: GraphLink[] = [];
    const nodeMap = new Map<string, GraphNode>();

    // Add central project node
    const projectNode: GraphNode = {
      id: 'PROJECT_ROOT',
      name: sbom.projectId,
      version: 'main',
      direct: true,
      severity: 'NONE',
      group: 0 // Central node group
    };
    nodes.push(projectNode);
    nodeMap.set(projectNode.id, projectNode);

    // Add all packages that should be shown based on depth
    sbom.packages.forEach((pkg) => {
      // Show direct dependencies always, and transitive based on depth
      if (pkg.direct || depth > 1) {
        const node: GraphNode = {
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

    // Add links from project to direct dependencies
    sbom.packages.forEach(pkg => {
      if (pkg.direct) {
        const targetId = `${pkg.name}@${pkg.version}`;
        if (nodeMap.has(targetId)) {
          links.push({ 
            source: 'PROJECT_ROOT', 
            target: targetId 
          });
        }
      }
    });

    // Add links between packages (for depth > 1)
    if (depth > 1) {
      sbom.packages.forEach(pkg => {
        if (pkg.direct || depth > 1) {
          const sourceId = `${pkg.name}@${pkg.version}`;
          
          // Add requires relationships
          if (pkg.requires && pkg.requires.length > 0) {
            pkg.requires.forEach(required => {
              const targetId = `${required.name}@${required.version}`;
              
              // Only add link if both nodes exist in our graph
              if (nodeMap.has(sourceId) && nodeMap.has(targetId)) {
                links.push({ 
                  source: sourceId, 
                  target: targetId 
                });
              }
            });
          }
        }
      });
    }

    console.log('Graph data:', { nodes: nodes.length, links: links.length, depth });
    setGraphData({ nodes, links });
  }, [sbom, depth]);

  // Render the graph
  useEffect(() => {
    if (!svgRef.current || graphData.nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = 800;
    const height = 600;

    // Set SVG dimensions
    svg.attr("width", width).attr("height", height);

    // Create simulation
    const simulation = d3.forceSimulation(graphData.nodes)
      .force("link", d3.forceLink(graphData.links).id((d: any) => d.id).distance(100))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2));

    // Create links
    const link = svg.append("g")
      .selectAll("line")
      .data(graphData.links)
      .join("line")
      .attr("stroke", "#999")
      .attr("stroke-opacity", 0.6)
      .attr("stroke-width", 1);

    // Create nodes
    const node = svg.append("g")
      .selectAll("circle")
      .data(graphData.nodes)
      .join("circle")
      .attr("r", (d: any) => d.group === 0 ? 12 : (d.direct ? 8 : 5))
      .attr("fill", (d: any) => d.group === 0 ? "#3b82f6" : getSeverityColor(d.severity))
      .attr("stroke", (d: any) => d.group === 0 ? "#1d4ed8" : (d.direct ? "#333" : "#666"))
      .attr("stroke-width", (d: any) => d.group === 0 ? 3 : (d.direct ? 2 : 1))
      .call(drag(simulation) as any);

    // Create labels
    const label = svg.append("g")
      .selectAll("text")
      .data(graphData.nodes)
      .join("text")
      .text((d: any) => d.group === 0 ? d.name : d.name)
      .attr("font-size", (d: any) => d.group === 0 ? "12px" : "10px")
      .attr("font-weight", (d: any) => d.group === 0 ? "bold" : "normal")
      .attr("fill", "#374151")
      .attr("text-anchor", "middle")
      .attr("dy", (d: any) => d.group === 0 ? "25" : "15")
      .call(drag(simulation) as any);

    // Add tooltips
    node.append("title")
      .text((d: any) => d.group === 0 ? 
        `Project: ${d.name}\nRoot node` : 
        `${d.name}@${d.version}\n${d.direct ? 'Direct' : 'Transitive'}\nSeverity: ${d.severity}`
      );



    // Update positions on simulation tick
    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);

      node
        .attr("cx", (d: any) => d.x)
        .attr("cy", (d: any) => d.y);

      label
        .attr("x", (d: any) => d.x)
        .attr("y", (d: any) => d.y);
    });

    // Drag behavior
    function drag(simulation: d3.Simulation<any, undefined>) {
      function dragstarted(event: any) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        event.subject.fx = event.subject.x;
        event.subject.fy = event.subject.y;
      }

      function dragged(event: any) {
        event.subject.fx = event.x;
        event.subject.fy = event.y;
      }

      function dragended(event: any) {
        if (!event.active) simulation.alphaTarget(0);
        event.subject.fx = null;
        event.subject.fy = null;
      }

      return d3.drag()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended);
    }

    return () => {
      simulation.stop();
    };
  }, [graphData]);

  function getHighestSeverity(pkg: Package): string {
    if (!pkg.vulns || pkg.vulns.length === 0) return 'NONE';
    
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
      case 'HIGH': return '#ea580c';
      case 'MEDIUM': return '#d97706';
      case 'LOW': return '#16a34a';
      default: return '#6b7280';
    }
  }

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold">Dependency Graph</h3>
        <div className="flex items-center gap-2">
          <label className="text-sm font-medium">Depth:</label>
          <select
            value={depth}
            onChange={(e) => setDepth(Number(e.target.value))}
            className="px-2 py-1 border border-gray-300 rounded text-sm"
          >
            <option value={1}>Direct Only</option>
            <option value={2}>Direct + Transitive</option>
            <option value={3}>Full Graph</option>
          </select>
        </div>
      </div>

      <div className="text-sm text-gray-600 mb-4">
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-blue-600"></div>
            <span>Project</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-gray-400"></div>
            <span>No vulnerabilities</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-green-500"></div>
            <span>Low</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
            <span>Medium</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-orange-500"></div>
            <span>High</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-red-600"></div>
            <span>Critical</span>
          </div>
        </div>
        <p className="mt-2">
          Showing {graphData.nodes.length - 1} packages ({graphData.nodes.filter(n => n.direct && n.group !== 0).length} direct, {graphData.nodes.filter(n => !n.direct).length} transitive)
        </p>
      </div>

      <div className="border border-gray-200 rounded-lg overflow-hidden bg-gray-50">
        <svg
          ref={svgRef}
          width="800"
          height="600"
          className="w-full h-auto"
          style={{ minHeight: '600px' }}
        />
      </div>

      {graphData.nodes.length === 0 && (
        <div className="text-center py-8 text-gray-500">
          No dependencies to display at this depth
        </div>
      )}
    </div>
  );
} 