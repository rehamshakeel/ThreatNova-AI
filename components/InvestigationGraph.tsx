'use client';

import { useEffect, useMemo, useRef } from 'react';
import { hierarchy, linkHorizontal, select, tree, type HierarchyPointNode } from 'd3';
import { adaptInvestigationToTree, type TreeNodeItem } from '@/lib/graph-adapter';
import { createDemoInvestigation } from '@/lib/demo-data';
import type { Investigation } from '@/lib/types';

interface InvestigationGraphProps {
  investigation?: Investigation | null;
  className?: string;
}

const severityColors: Record<string, string> = {
  critical: '#EF4444',
  high: '#EF4444',
  medium: '#F59E0B',
  low: '#10B981',
  info: '#3B82F6',
};

export default function InvestigationGraph({
  investigation: propInvestigation,
  className = '',
}: InvestigationGraphProps) {
  const graphRef = useRef<SVGSVGElement>(null);

  const activeInvestigation = useMemo(() => {
    return propInvestigation || createDemoInvestigation();
  }, [propInvestigation]);

  useEffect(() => {
    if (!graphRef.current || !activeInvestigation) return;

    const svg = select(graphRef.current);
    svg.selectAll('*').remove();

    const { root: adaptedRoot, totalEvidenceCount, emptyReason } = adaptInvestigationToTree(activeInvestigation);

    if (!adaptedRoot || totalEvidenceCount === 0) {
      const g = svg.append('g').attr('class', 'empty-tree-state');
      g.append('text')
        .attr('x', 190)
        .attr('y', 80)
        .attr('text-anchor', 'middle')
        .attr('fill', '#F2F2F2')
        .attr('font-size', 11)
        .attr('font-weight', '600')
        .text('No Telemetry Evidence Available');
      g.append('text')
        .attr('x', 190)
        .attr('y', 100)
        .attr('text-anchor', 'middle')
        .attr('fill', '#8E8E8E')
        .attr('font-size', 8.5)
        .text(emptyReason || 'Reconnaissance pipeline returned no telemetry findings');
      return;
    }

    const rootHierarchy = hierarchy<TreeNodeItem>(adaptedRoot);
    const leafCount = Math.max(1, rootHierarchy.leaves().length);

    // Dynamic vertical layout spacing centered within viewBox 380x180
    const treeHeight = Math.min(140, Math.max(80, leafCount * 26));
    const offsetY = Math.max(18, (180 - treeHeight) / 2);

    const treeLayout = tree<TreeNodeItem>()
      .size([treeHeight, 220])
      .separation(() => 1);

    const pointRoot = treeLayout(rootHierarchy);

    // Coordinate mapping: d.x is vertical (Y), d.y is horizontal (X)
    const nodeX = (d: HierarchyPointNode<TreeNodeItem>) => d.y + 40;
    const nodeY = (d: HierarchyPointNode<TreeNodeItem>) => d.x + offsetY;

    // Curved link generator for left-to-right hierarchy
    const linkGen = linkHorizontal<any, HierarchyPointNode<TreeNodeItem>>()
      .x(nodeX)
      .y(nodeY);

    const g = svg.append('g').attr('class', 'mini-tree-container');

    // Draw Curved Connection Links
    g.append('g')
      .selectAll('path')
      .data(pointRoot.links())
      .join('path')
      .attr('d', linkGen)
      .attr('fill', 'none')
      .attr('stroke', '#292929')
      .attr('stroke-width', 1.2)
      .attr('stroke-opacity', 0.85);

    // Draw Nodes
    const nodes = g
      .append('g')
      .selectAll('g')
      .data(pointRoot.descendants())
      .join('g')
      .attr('transform', (d) => `translate(${nodeX(d)}, ${nodeY(d)})`);

    nodes.each(function (d) {
      const nodeG = select(this);
      const isRoot = d.data.nodeType === 'root';
      const isCat = d.data.nodeType === 'category';
      const isFinding = d.data.nodeType === 'finding';
      const color = d.data.severity ? severityColors[d.data.severity] || '#8E8E8E' : '#8E8E8E';

      if (isRoot) {
        // Root Target node
        nodeG
          .append('circle')
          .attr('r', 11)
          .attr('fill', '#171717')
          .attr('stroke', '#EF4444')
          .attr('stroke-width', 1.5);

        nodeG.append('circle').attr('r', 3.5).attr('fill', '#EF4444');

        nodeG
          .append('text')
          .attr('x', 0)
          .attr('y', 19)
          .attr('text-anchor', 'middle')
          .attr('fill', '#F2F2F2')
          .attr('font-size', 8)
          .attr('font-family', 'monospace')
          .attr('font-weight', 'bold')
          .text(d.data.name.length > 14 ? `${d.data.name.slice(0, 12)}…` : d.data.name);
      } else if (isCat) {
        // Category Branch node
        nodeG
          .append('rect')
          .attr('x', -24)
          .attr('y', -8)
          .attr('width', 48)
          .attr('height', 16)
          .attr('rx', 4)
          .attr('fill', '#171717')
          .attr('stroke', '#292929')
          .attr('stroke-width', 1);

        nodeG
          .append('circle')
          .attr('cx', -16)
          .attr('cy', 0)
          .attr('r', 2.5)
          .attr('fill', color);

        nodeG
          .append('text')
          .attr('x', -9)
          .attr('y', 2.5)
          .attr('fill', '#F2F2F2')
          .attr('font-size', 6.5)
          .attr('font-family', 'sans-serif')
          .text(d.data.name);
      } else if (isFinding) {
        // Finding Leaf node
        nodeG
          .append('rect')
          .attr('x', 0)
          .attr('y', -7)
          .attr('width', 68)
          .attr('height', 14)
          .attr('rx', 3)
          .attr('fill', '#171717')
          .attr('stroke', '#292929')
          .attr('stroke-width', 0.8);

        nodeG
          .append('rect')
          .attr('x', 0)
          .attr('y', -7)
          .attr('width', 2.5)
          .attr('height', 14)
          .attr('rx', 1)
          .attr('fill', color);

        nodeG
          .append('text')
          .attr('x', 6)
          .attr('y', 3)
          .attr('fill', '#F2F2F2')
          .attr('font-size', 6)
          .attr('font-family', 'sans-serif')
          .text(d.data.name);
      }
    });

    return () => {
      svg.selectAll('*').remove();
    };
  }, [activeInvestigation]);

  return (
    <svg
      ref={graphRef}
      viewBox="0 0 380 180"
      role="img"
      aria-label="Root tree indicator hierarchy preview"
      className={`h-auto w-full max-h-48 ${className}`}
    />
  );
}
