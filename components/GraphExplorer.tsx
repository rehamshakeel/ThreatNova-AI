'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  hierarchy,
  linkHorizontal,
  select,
  tree,
  zoom,
  zoomIdentity,
  type HierarchyPointNode,
  type ZoomBehavior,
} from 'd3';
import {
  Check,
  ChevronRight,
  Copy,
  Layers,
  Maximize2,
  Network,
  RotateCcw,
  Search,
  Zap,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import SeverityBadge from '@/components/SeverityBadge';
import { createDemoHistory, createDemoInvestigation } from '@/lib/demo-data';
import { getSavedInvestigations } from '@/lib/storage';
import { fetchInvestigation, fetchInvestigations } from '@/lib/api';
import { adaptInvestigationToTree, type TreeNodeItem } from '@/lib/graph-adapter';
import type { Investigation, Severity } from '@/lib/types';

interface GraphExplorerProps {
  investigation?: Investigation | null;
}

const severityColors: Record<Severity, string> = {
  critical: '#EF4444',
  high: '#EF4444',
  medium: '#F59E0B',
  low: '#10B981',
  info: '#3B82F6',
};

export default function GraphExplorer({ investigation: propInvestigation }: GraphExplorerProps = {}) {
  const router = useRouter();
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<SVGSVGElement>(null);
  const viewportRef = useRef<SVGGElement | null>(null);
  const zoomBehaviorRef = useRef<ZoomBehavior<SVGSVGElement, unknown> | null>(null);

  const [size, setSize] = useState({ width: 0, height: 560 });
  const [availableInvestigations, setAvailableInvestigations] = useState<Investigation[]>([]);
  const [selectedInvestigationId, setSelectedInvestigationId] = useState<string>('');
  const [searchFilter, setSearchFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // 1. Discover available investigations from prop, URL search query, storage, and demo history
  useEffect(() => {
    let isMounted = true;

    async function loadInvestigations() {
      const saved = getSavedInvestigations();
      let liveList: Investigation[] = [];
      try {
        liveList = await fetchInvestigations(30, 0);
      } catch (err) {
        console.debug('Backend investigations fetch error (using local store):', err);
      }

      if (!isMounted) return;

      const mergedMap = new Map<string, Investigation>();
      if (propInvestigation) {
        mergedMap.set(propInvestigation.id, propInvestigation);
      }
      for (const inv of liveList) mergedMap.set(inv.id, inv);
      for (const inv of saved) {
        if (!mergedMap.has(inv.id)) mergedMap.set(inv.id, inv);
      }
      for (const inv of createDemoHistory()) {
        if (!mergedMap.has(inv.id)) mergedMap.set(inv.id, inv);
      }

      const combined = Array.from(mergedMap.values());
      setAvailableInvestigations(combined);

      // Check URL query parameters (e.g. ?q=... or ?id=...)
      let initialId = propInvestigation?.id || '';
      if (!initialId && typeof window !== 'undefined') {
        const urlParams = new URLSearchParams(window.location.search);
        const qParam = urlParams.get('q') || urlParams.get('query');
        const idParam = urlParams.get('id');

        if (idParam) {
          const match = combined.find((inv) => inv.id === idParam);
          if (match) initialId = match.id;
        } else if (qParam) {
          const match = combined.find(
            (inv) => inv.query.toLowerCase() === qParam.trim().toLowerCase()
          );
          if (match) initialId = match.id;
        }
      }

      if (!initialId && combined.length > 0) {
        initialId = combined[0].id;
      }

      setSelectedInvestigationId(initialId);
    }

    loadInvestigations();

    return () => {
      isMounted = false;
    };
  }, [propInvestigation]);

  const [currentInvestigationFull, setCurrentInvestigationFull] = useState<Investigation | null>(null);

  // Fetch full investigation details (findings, domainIntel, graphNodes) when selected
  useEffect(() => {
    let isMounted = true;
    if (!selectedInvestigationId) return;

    const matched = availableInvestigations.find((i) => i.id === selectedInvestigationId);
    if (matched && Array.isArray(matched.findings) && matched.findings.length > 0) {
      setCurrentInvestigationFull(matched);
      return;
    }

    fetchInvestigation(selectedInvestigationId)
      .then((fullInv) => {
        if (!isMounted || !fullInv) return;
        setCurrentInvestigationFull(fullInv);
        setAvailableInvestigations((prev) =>
          prev.map((item) => (item.id === fullInv.id ? fullInv : item))
        );
      })
      .catch((err) => {
        console.debug('Failed to fetch full investigation in GraphExplorer:', err);
      });

    return () => {
      isMounted = false;
    };
  }, [selectedInvestigationId]);

  // Active investigation object
  const currentInvestigation = useMemo(() => {
    if (propInvestigation) return propInvestigation;
    if (currentInvestigationFull && currentInvestigationFull.id === selectedInvestigationId) {
      return currentInvestigationFull;
    }
    return (
      availableInvestigations.find((inv) => inv.id === selectedInvestigationId) ||
      availableInvestigations[0] ||
      createDemoInvestigation()
    );
  }, [propInvestigation, currentInvestigationFull, availableInvestigations, selectedInvestigationId]);

  // Auto-select root node when investigation changes
  useEffect(() => {
    if (currentInvestigation) {
      setSelectedNodeId(`root-${currentInvestigation.id}`);
    }
  }, [currentInvestigation?.id]);

  // Resize Observer
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      const width = Math.round(entry.contentRect.width);
      const height = Math.round(entry.contentRect.height);
      if (width > 0 && height > 0) setSize({ width, height });
    });

    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  // 2. Build hierarchical Root Tree data model (Target -> Branches -> Leaves)
  const { root: hierarchicalTreeData, totalEvidenceCount, emptyReason } = useMemo(() => {
    if (!currentInvestigation) {
      return { root: null, totalEvidenceCount: 0, emptyReason: 'No investigation selected' };
    }
    return adaptInvestigationToTree(currentInvestigation, severityFilter);
  }, [currentInvestigation, severityFilter]);

  // Fit View helper
  const handleFitView = useCallback(() => {
    const svgElement = graphRef.current;
    const gElement = viewportRef.current;
    if (!svgElement || !gElement || !zoomBehaviorRef.current) return;

    const svg = select(svgElement);
    const bbox = gElement.getBBox();
    if (!bbox || bbox.width === 0 || bbox.height === 0) return;

    const fullWidth = size.width;
    const fullHeight = size.height;
    const padding = 50;

    const scale = Math.min(
      1.25,
      Math.max(
        0.35,
        0.88 /
          Math.max(
            (bbox.width + padding * 2) / fullWidth,
            (bbox.height + padding * 2) / fullHeight
          )
      )
    );

    const tx = (fullWidth - bbox.width * scale) / 2 - bbox.x * scale;
    const ty = (fullHeight - bbox.height * scale) / 2 - bbox.y * scale;

    svg
      .transition()
      .duration(350)
      .call(
        zoomBehaviorRef.current.transform,
        zoomIdentity.translate(tx, ty).scale(scale)
      );
  }, [size]);

  // 3. Render D3 Left-to-Right Hierarchical Tree
  useEffect(() => {
    const svgElement = graphRef.current;
    if (!svgElement || size.width === 0 || !hierarchicalTreeData) return;

    const svg = select(svgElement)
      .attr('viewBox', `0 0 ${size.width} ${size.height}`)
      .attr('width', size.width)
      .attr('height', size.height);

    svg.selectAll('*').remove();

    // Defs for filters and gradients
    const defs = svg.append('defs');

    // Subtle glow filter for active nodes
    const filter = defs
      .append('filter')
      .attr('id', 'tree-node-glow')
      .attr('x', '-20%')
      .attr('y', '-20%')
      .attr('width', '140%')
      .attr('height', '140%');
    filter
      .append('feGaussianBlur')
      .attr('stdDeviation', '4')
      .attr('result', 'blur');
    filter
      .append('feComposite')
      .attr('in', 'SourceGraphic')
      .attr('in2', 'blur')
      .attr('operator', 'over');

    const viewport = svg.append('g').attr('class', 'tree-viewport');
    viewportRef.current = viewport.node();

    // D3 Hierarchy setup
    const rootHierarchy = hierarchy<TreeNodeItem>(hierarchicalTreeData);
    const leafNodes = rootHierarchy.leaves();
    const leafCount = Math.max(1, leafNodes.length);

    // Dynamic vertical layout spacing
    const dynamicHeight = Math.max(size.height - 80, leafCount * 58);
    const dynamicWidth = Math.max(760, size.width - 240);

    const treeLayout = tree<TreeNodeItem>()
      .size([dynamicHeight, dynamicWidth])
      .separation((a, b) => (a.parent === b.parent ? 1.15 : 1.45));

    const pointRoot = treeLayout(rootHierarchy);

    // Coordinate mapping: d.x is vertical (Y), d.y is horizontal (X)
    const nodeX = (d: HierarchyPointNode<TreeNodeItem>) => d.y + 110;
    const nodeY = (d: HierarchyPointNode<TreeNodeItem>) => d.x + 35;

    // Curved link generator for left-to-right tree
    const linkGen = linkHorizontal<any, HierarchyPointNode<TreeNodeItem>>()
      .x(nodeX)
      .y(nodeY);

    // 1. Draw Links
    const linksGroup = viewport.append('g').attr('class', 'tree-links');

    const linksData = pointRoot.links();
    linksGroup
      .selectAll('path')
      .data(linksData)
      .join('path')
      .attr('class', 'tree-link')
      .attr('d', linkGen)
      .attr('fill', 'none')
      .attr('stroke', (d) => {
        const isChildSelected = selectedNodeId === d.target.data.id;
        const isParentSelected = selectedNodeId === d.source.data.id;
        return isChildSelected || isParentSelected ? '#EF4444' : '#292929';
      })
      .attr('stroke-width', (d) => {
        const isChildSelected = selectedNodeId === d.target.data.id;
        const isParentSelected = selectedNodeId === d.source.data.id;
        return isChildSelected || isParentSelected ? 2.2 : 1.4;
      })
      .attr('stroke-opacity', (d) => {
        const isChildSelected = selectedNodeId === d.target.data.id;
        const isParentSelected = selectedNodeId === d.source.data.id;
        return isChildSelected || isParentSelected ? 1 : 0.75;
      });

    // 2. Draw Nodes
    const nodesGroup = viewport.append('g').attr('class', 'tree-nodes');

    const nodeSelection = nodesGroup
      .selectAll<SVGGElement, HierarchyPointNode<TreeNodeItem>>('g')
      .data(pointRoot.descendants())
      .join('g')
      .attr('class', 'tree-node cursor-pointer')
      .attr('transform', (d) => `translate(${nodeX(d)}, ${nodeY(d)})`)
      .on('click', (_event, d) => {
        setSelectedNodeId(d.data.id);
      });

    // Node Rendering based on depth / nodeType
    nodeSelection.each(function (d) {
      const g = select(this);
      const isSelected = selectedNodeId === d.data.id;
      const isRoot = d.data.nodeType === 'root';
      const isCategory = d.data.nodeType === 'category';
      const isFinding = d.data.nodeType === 'finding';

      if (isRoot) {
        // ── Root Node: Target Indicator ──
        const rectWidth = 190;
        const rectHeight = 44;

        g.append('rect')
          .attr('x', -rectWidth / 2)
          .attr('y', -rectHeight / 2)
          .attr('width', rectWidth)
          .attr('height', rectHeight)
          .attr('rx', 8)
          .attr('ry', 8)
          .attr('fill', '#171717')
          .attr('stroke', isSelected ? '#F2F2F2' : '#EF4444')
          .attr('stroke-width', isSelected ? 2.5 : 1.8)
          .attr('filter', isSelected ? 'url(#tree-node-glow)' : null);

        // Core dot
        g.append('circle')
          .attr('cx', -rectWidth / 2 + 16)
          .attr('cy', 0)
          .attr('r', 5)
          .attr('fill', '#EF4444');

        // Target label
        const displayLabel =
          d.data.name.length > 20 ? `${d.data.name.slice(0, 18)}…` : d.data.name;

        g.append('text')
          .attr('x', -rectWidth / 2 + 28)
          .attr('y', -3)
          .attr('fill', '#F2F2F2')
          .attr('font-size', 11)
          .attr('font-weight', '700')
          .attr('font-family', 'monospace')
          .text(displayLabel);

        // Subtitle
        const riskLevel = d.data.investigationRef?.risk.level || 'HIGH';
        const riskScore = d.data.investigationRef?.risk.score ?? 75;
        g.append('text')
          .attr('x', -rectWidth / 2 + 28)
          .attr('y', 11)
          .attr('fill', '#8E8E8E')
          .attr('font-size', 9)
          .attr('font-family', 'monospace')
          .text(`ROOT TARGET · ${riskScore}/100 ${riskLevel.toUpperCase()}`);
      } else if (isCategory) {
        // ── Branch Node: Category ──
        const rectWidth = 165;
        const rectHeight = 34;
        const sevColor = d.data.severity ? severityColors[d.data.severity] : '#8E8E8E';

        g.append('rect')
          .attr('x', -rectWidth / 2)
          .attr('y', -rectHeight / 2)
          .attr('width', rectWidth)
          .attr('height', rectHeight)
          .attr('rx', 6)
          .attr('ry', 6)
          .attr('fill', '#171717')
          .attr('stroke', isSelected ? '#F2F2F2' : '#292929')
          .attr('stroke-width', isSelected ? 2.2 : 1.4);

        // Category Severity dot
        g.append('circle')
          .attr('cx', -rectWidth / 2 + 14)
          .attr('cy', 0)
          .attr('r', 4.5)
          .attr('fill', sevColor);

        // Category title
        const catLabel =
          d.data.name.length > 18 ? `${d.data.name.slice(0, 16)}…` : d.data.name;

        g.append('text')
          .attr('x', -rectWidth / 2 + 25)
          .attr('y', 3.5)
          .attr('fill', '#F2F2F2')
          .attr('font-size', 10.5)
          .attr('font-weight', '600')
          .text(catLabel);

        // Count Badge
        const badgeX = rectWidth / 2 - 14;
        g.append('circle')
          .attr('cx', badgeX)
          .attr('cy', 0)
          .attr('r', 8.5)
          .attr('fill', '#292929');

        g.append('text')
          .attr('x', badgeX)
          .attr('y', 3)
          .attr('text-anchor', 'middle')
          .attr('fill', '#F2F2F2')
          .attr('font-size', 8.5)
          .attr('font-family', 'monospace')
          .attr('font-weight', '700')
          .text(String(d.data.findingCount || 0));
      } else if (isFinding) {
        // ── Leaf Node: Finding ──
        const rectWidth = 225;
        const rectHeight = 36;
        const sevColor = d.data.severity ? severityColors[d.data.severity] : '#8E8E8E';

        g.append('rect')
          .attr('x', 0)
          .attr('y', -rectHeight / 2)
          .attr('width', rectWidth)
          .attr('height', rectHeight)
          .attr('rx', 6)
          .attr('ry', 6)
          .attr('fill', '#171717')
          .attr('stroke', isSelected ? '#F2F2F2' : '#292929')
          .attr('stroke-width', isSelected ? 2.2 : 1.2);

        // Severity Indicator Bar on Left
        g.append('rect')
          .attr('x', 0)
          .attr('y', -rectHeight / 2)
          .attr('width', 4)
          .attr('height', rectHeight)
          .attr('rx', 2)
          .attr('ry', 2)
          .attr('fill', sevColor);

        // Finding title text
        const findingTitle =
          d.data.name.length > 27 ? `${d.data.name.slice(0, 25)}…` : d.data.name;

        g.append('text')
          .attr('x', 14)
          .attr('y', -2)
          .attr('fill', '#F2F2F2')
          .attr('font-size', 10.5)
          .attr('font-weight', '500')
          .text(findingTitle);

        // Severity Sub-tag
        g.append('text')
          .attr('x', 14)
          .attr('y', 10)
          .attr('fill', sevColor)
          .attr('font-size', 8.5)
          .attr('font-family', 'monospace')
          .attr('font-weight', '700')
          .text((d.data.severity || 'info').toUpperCase());
      }
    });

    // Zoom and Pan Behavior
    const zoomBehavior = zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.3, 3.5])
      .on('zoom', (event) => {
        viewport.attr('transform', event.transform.toString());
      });

    zoomBehaviorRef.current = zoomBehavior;
    svg.call(zoomBehavior).on('dblclick.zoom', null);

    // Initial view alignment
    handleFitView();

    return () => {
      svg.on('.zoom', null);
      svg.selectAll('*').remove();
    };
  }, [hierarchicalTreeData, size, selectedNodeId, handleFitView]);

  // Selected item reference for right sidebar
  const selectedNodeData = useMemo<TreeNodeItem | null>(() => {
    if (!hierarchicalTreeData || !selectedNodeId) return null;
    const stack: TreeNodeItem[] = [hierarchicalTreeData];
    while (stack.length > 0) {
      const cur = stack.pop()!;
      if (cur.id === selectedNodeId) return cur;
      if (cur.children) {
        for (const child of cur.children) stack.push(child);
      }
    }
    return hierarchicalTreeData;
  }, [hierarchicalTreeData, selectedNodeId]);

  // Search filtering opacity update
  useEffect(() => {
    const svgElement = graphRef.current;
    if (!svgElement) return;

    const term = searchFilter.trim().toLowerCase();
    const svg = select(svgElement);

    if (!term) {
      svg.selectAll('.tree-node').attr('opacity', 1);
      svg.selectAll('.tree-link').attr('opacity', 0.85);
      return;
    }

    svg.selectAll<SVGGElement, HierarchyPointNode<TreeNodeItem>>('.tree-node').attr('opacity', (d) => {
      const match =
        d.data.name.toLowerCase().includes(term) ||
        (d.data.category && d.data.category.toLowerCase().includes(term)) ||
        (d.data.severity && d.data.severity.toLowerCase().includes(term)) ||
        (d.data.findingRef?.description && d.data.findingRef.description.toLowerCase().includes(term));
      return match ? 1 : 0.18;
    });
  }, [searchFilter]);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleZoomIn = () => {
    const svgElement = graphRef.current;
    if (!svgElement || !zoomBehaviorRef.current) return;
    select(svgElement).transition().duration(250).call(zoomBehaviorRef.current.scaleBy, 1.25);
  };

  const handleZoomOut = () => {
    const svgElement = graphRef.current;
    if (!svgElement || !zoomBehaviorRef.current) return;
    select(svgElement).transition().duration(250).call(zoomBehaviorRef.current.scaleBy, 0.75);
  };

  const handleInvestigateTarget = () => {
    if (!currentInvestigation) return;
    router.push(
      `/scanning?type=${currentInvestigation.type}&indicator=${encodeURIComponent(
        currentInvestigation.query
      )}`
    );
  };

  const totalFindingsCount = totalEvidenceCount;

  return (
    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
      {/* Interactive Hierarchical Tree Area */}
      <section className="min-w-0 overflow-hidden rounded-xl border border-tn-border bg-tn-surface shadow-md flex flex-col">
        {/* Controls Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-tn-border px-5 py-3.5 bg-tn-surface/90">
          <div className="flex flex-wrap items-center gap-3">
            {/* Investigation Selector */}
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono uppercase text-tn-muted hidden sm:inline">
                Target:
              </span>
              <select
                value={selectedInvestigationId}
                onChange={(e) => setSelectedInvestigationId(e.target.value)}
                className="h-8 rounded-lg border border-tn-border bg-tn-card px-2.5 text-xs text-tn-text font-mono focus:outline-none focus:border-tn-muted max-w-[210px] truncate"
              >
                {availableInvestigations.map((inv) => (
                  <option key={inv.id} value={inv.id}>
                    {inv.query} ({inv.type.toUpperCase()})
                  </option>
                ))}
              </select>
            </div>

            {/* Filter Search Input */}
            <div className="relative">
              <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-tn-muted" />
              <input
                type="text"
                placeholder="Filter tree nodes…"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                className="h-8 w-40 sm:w-52 rounded-lg border border-tn-border bg-tn-card pl-8 pr-2.5 text-xs text-tn-text placeholder:text-tn-muted/60 focus:outline-none focus:border-tn-muted font-mono"
              />
            </div>

            {/* Severity Filter Dropdown */}
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="h-8 rounded-lg border border-tn-border bg-tn-card px-2.5 text-xs text-tn-text focus:outline-none focus:border-tn-muted"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical Only</option>
              <option value="high">High Only</option>
              <option value="medium">Medium Only</option>
              <option value="low">Low Only</option>
              <option value="info">Informational</option>
            </select>
          </div>

          {/* Canvas Controls: Zoom & Fit View */}
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={handleZoomIn}
              title="Zoom In"
              className="p-1.5 rounded-lg border border-tn-border bg-tn-card text-tn-muted hover:text-tn-text hover:border-tn-muted transition-colors"
            >
              <ZoomIn size={14} />
            </button>
            <button
              type="button"
              onClick={handleZoomOut}
              title="Zoom Out"
              className="p-1.5 rounded-lg border border-tn-border bg-tn-card text-tn-muted hover:text-tn-text hover:border-tn-muted transition-colors"
            >
              <ZoomOut size={14} />
            </button>
            <button
              type="button"
              onClick={handleFitView}
              title="Fit View & Center Hierarchy"
              className="inline-flex items-center gap-1.5 rounded-lg border border-tn-border bg-tn-card px-2.5 py-1.5 text-xs font-medium text-tn-text hover:border-tn-muted transition-colors cursor-pointer"
            >
              <Maximize2 size={13} />
              Fit View
            </button>
            <button
              type="button"
              onClick={() => {
                setSearchFilter('');
                setSeverityFilter('all');
                handleFitView();
              }}
              title="Reset Layout"
              className="inline-flex items-center gap-1.5 rounded-lg border border-tn-border bg-tn-card px-2.5 py-1.5 text-xs font-medium text-tn-muted hover:text-tn-text hover:border-tn-muted transition-colors cursor-pointer"
            >
              <RotateCcw size={13} />
              Reset
            </button>
          </div>
        </div>

        {/* Tree Canvas */}
        <div
          ref={containerRef}
          className="h-[480px] sm:h-[600px] w-full touch-none relative bg-[#080808]"
        >
          {totalFindingsCount === 0 ? (
            <div className="absolute inset-0 flex flex-col items-center justify-center p-6 text-center text-tn-muted">
              <Network size={36} className="text-tn-border mb-3" />
              <p className="text-sm font-semibold text-tn-text">No investigation findings recorded</p>
              <p className="text-xs text-tn-muted mt-1 max-w-sm">
                {emptyReason || 'This indicator currently has no empirical findings or telemetry categories to plot in the hierarchical tree.'}
              </p>
            </div>
          ) : (
            <svg
              ref={graphRef}
              role="group"
              aria-label="Hierarchical root tree threat graph"
              className="h-full w-full"
            />
          )}

          {/* Canvas Navigation Hint */}
          <div className="pointer-events-none absolute bottom-3 left-4 text-[10px] text-tn-muted/80 font-mono">
            Scroll to zoom · Drag canvas to pan · Click any node to inspect evidence
          </div>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center justify-between gap-x-5 gap-y-2 border-t border-tn-border px-5 py-3 bg-tn-surface/80 text-[11px] text-tn-muted font-mono">
          <div className="flex flex-wrap items-center gap-4">
            <span className="font-semibold text-tn-text">Hierarchy:</span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full border border-[#EF4444] bg-[#EF4444]/20" />
              <span className="text-tn-text">Root (Target)</span>
            </span>
            <span className="text-tn-muted">➔</span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded border border-[#292929] bg-[#171717]" />
              <span className="text-tn-text">Branches (Categories)</span>
            </span>
            <span className="text-tn-muted">➔</span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-2 w-3 rounded-sm bg-[#171717] border-l-2 border-[#EF4444]" />
              <span className="text-tn-text">Leaves (Findings)</span>
            </span>
          </div>

          <div className="flex items-center gap-3">
            <span className="inline-flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-[#EF4444]" /> Critical / High
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-[#F59E0B]" /> Medium
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="h-2 w-2 rounded-full bg-[#10B981]" /> Low
            </span>
          </div>
        </div>
      </section>

      {/* Node Inspector Sidebar */}
      <aside className="space-y-4">
        <section className="rounded-xl border border-tn-border bg-tn-surface p-5 shadow-md">
          <div className="flex items-center justify-between pb-3 border-b border-tn-border">
            <h3 className="text-sm font-semibold text-tn-text flex items-center gap-2">
              <Layers size={15} className="text-tn-info" />
              Inspected Node
            </h3>
            <span className="text-[9px] font-mono font-semibold uppercase px-2 py-0.5 rounded bg-tn-card border border-tn-border text-tn-muted">
              {selectedNodeData?.nodeType.toUpperCase() || 'NODE'}
            </span>
          </div>

          {selectedNodeData ? (
            <div className="mt-4 space-y-4">
              {/* Header Title */}
              <div>
                <span className="text-[10px] font-mono uppercase tracking-wider text-tn-muted block">
                  {selectedNodeData.nodeType === 'root'
                    ? 'Investigated Indicator'
                    : selectedNodeData.nodeType === 'category'
                    ? 'Telemetry Category'
                    : 'Evidence Finding'}
                </span>
                <div className="mt-1 flex items-start justify-between gap-2">
                  <h4 className="font-mono text-sm font-bold text-tn-text break-all">
                    {selectedNodeData.name}
                  </h4>
                  <button
                    type="button"
                    onClick={() => handleCopy(selectedNodeData.name)}
                    className="p-1 rounded text-tn-muted hover:text-tn-text hover:bg-tn-card transition-colors shrink-0"
                    title="Copy identifier"
                  >
                    {copied ? <Check size={14} className="text-tn-success" /> : <Copy size={14} />}
                  </button>
                </div>
              </div>

              {/* Severity / Risk rating */}
              {selectedNodeData.severity && (
                <div className="flex items-center justify-between py-2 border-y border-tn-border/60 text-xs">
                  <span className="text-tn-muted">Risk Posture</span>
                  <SeverityBadge severity={selectedNodeData.severity} />
                </div>
              )}

              {/* If Root Node */}
              {selectedNodeData.nodeType === 'root' && selectedNodeData.investigationRef && (
                <div className="space-y-3">
                  <div className="rounded-lg border border-tn-border bg-tn-card/50 p-3 text-xs space-y-1.5 font-mono">
                    <div className="flex justify-between">
                      <span className="text-tn-muted">Indicator Type:</span>
                      <span className="text-tn-text uppercase">{selectedNodeData.investigationRef.type}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-tn-muted">Deterministic Risk:</span>
                      <span className="text-[#EF4444] font-bold">
                        {selectedNodeData.investigationRef.risk.score}/100
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-tn-muted">Confidence Score:</span>
                      <span className="text-tn-text">
                        {selectedNodeData.investigationRef.risk.confidence}%
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-tn-muted">Total Findings:</span>
                      <span className="text-tn-text font-bold">
                        {selectedNodeData.investigationRef.findings?.length || 0}
                      </span>
                    </div>
                  </div>

                  <p className="text-xs text-tn-muted leading-relaxed">
                    {selectedNodeData.investigationRef.risk.explanation}
                  </p>

                  <button
                    type="button"
                    onClick={handleInvestigateTarget}
                    className="w-full flex items-center justify-center gap-2 rounded-lg border border-tn-border bg-tn-card hover:bg-tn-border px-3 py-2 text-xs font-semibold text-tn-info transition-colors cursor-pointer"
                  >
                    <Zap size={13} className="text-tn-warn" />
                    Re-scan Target Indicator
                  </button>
                </div>
              )}

              {/* If Category Branch */}
              {selectedNodeData.nodeType === 'category' && (
                <div className="space-y-3">
                  <div className="rounded-lg border border-tn-border bg-tn-card/50 p-3 text-xs space-y-1.5 font-mono">
                    <div className="flex justify-between">
                      <span className="text-tn-muted">Category:</span>
                      <span className="text-tn-text">{selectedNodeData.name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-tn-muted">Child Findings:</span>
                      <span className="text-tn-text font-bold">{selectedNodeData.findingCount || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-tn-muted">Peak Severity:</span>
                      <span className="text-[#EF4444] font-bold">
                        {(selectedNodeData.severity || 'info').toUpperCase()}
                      </span>
                    </div>
                  </div>

                  <p className="text-xs text-tn-muted">
                    Click any leaf node on the tree to view specific forensic proof and observation logs for this category.
                  </p>
                </div>
              )}

              {/* If Finding Leaf Node */}
              {selectedNodeData.nodeType === 'finding' && selectedNodeData.findingRef && (
                <div className="space-y-3">
                  <div>
                    <h5 className="text-[10px] font-mono uppercase tracking-wider text-tn-muted mb-1">
                      Observation Description
                    </h5>
                    <p className="text-xs text-tn-muted leading-relaxed bg-tn-card/40 rounded-lg p-3 border border-tn-border/60">
                      {selectedNodeData.findingRef.description}
                    </p>
                  </div>

                  {/* Metadata */}
                  <dl className="space-y-1.5 text-xs bg-tn-card/40 rounded-lg p-3 border border-tn-border/60 font-mono">
                    <div className="flex items-start justify-between gap-2">
                      <dt className="text-tn-muted">Category:</dt>
                      <dd className="text-tn-text text-right">{selectedNodeData.findingRef.category}</dd>
                    </div>
                    <div className="flex items-start justify-between gap-2">
                      <dt className="text-tn-muted">Source Engine:</dt>
                      <dd className="text-tn-text text-right truncate max-w-[170px]">
                        {selectedNodeData.findingRef.source}
                      </dd>
                    </div>
                    {selectedNodeData.findingRef.confidence && (
                      <div className="flex items-start justify-between gap-2">
                        <dt className="text-tn-muted">Confidence:</dt>
                        <dd className="text-tn-text text-right">{selectedNodeData.findingRef.confidence}%</dd>
                      </div>
                    )}
                  </dl>

                  {/* Evidence Artifacts */}
                  {selectedNodeData.findingRef.evidence &&
                    selectedNodeData.findingRef.evidence.length > 0 && (
                      <div>
                        <h5 className="text-[10px] font-mono uppercase tracking-wider text-tn-muted mb-1.5">
                          Empirical Evidence Artifacts ({selectedNodeData.findingRef.evidence.length})
                        </h5>
                        <div className="space-y-2">
                          {selectedNodeData.findingRef.evidence.map((ev, idx) => (
                            <div
                              key={idx}
                              className="rounded-lg border border-tn-border bg-tn-bg/80 p-2.5 text-xs font-mono space-y-1"
                            >
                              <div className="flex items-center justify-between text-[10px]">
                                <span className="text-tn-info font-bold uppercase">{ev.type}</span>
                                <span className="text-tn-muted">{ev.label}</span>
                              </div>
                              <p className="text-tn-text break-all text-[11px] leading-relaxed">
                                {ev.content}
                              </p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                </div>
              )}
            </div>
          ) : (
            <p className="mt-4 text-xs text-tn-muted">Click any node on the tree canvas to inspect forensic evidence.</p>
          )}
        </section>

        {/* Quick Branch Directory */}
        <section className="rounded-xl border border-tn-border bg-tn-surface p-5 shadow-md">
          <h3 className="text-sm font-semibold text-tn-text pb-2.5 border-b border-tn-border">
            Hierarchy Directory
          </h3>

          <div className="mt-3 space-y-1.5 max-h-60 overflow-y-auto font-mono text-xs">
            {hierarchicalTreeData?.children && hierarchicalTreeData.children.length > 0 ? (
              hierarchicalTreeData.children.map((branch) => (
                <button
                  key={branch.id}
                  type="button"
                  onClick={() => setSelectedNodeId(branch.id)}
                  className={`w-full text-left p-2 rounded-lg border transition-all flex items-center justify-between ${
                    selectedNodeId === branch.id
                      ? 'border-[#EF4444] bg-tn-card text-[#F2F2F2]'
                      : 'border-tn-border/50 bg-tn-card/30 text-tn-muted hover:border-tn-muted hover:text-tn-text'
                  }`}
                >
                  <span className="truncate flex items-center gap-1.5">
                    <ChevronRight size={13} className="text-[#EF4444]" />
                    {branch.name}
                  </span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-tn-surface border border-tn-border text-tn-text">
                    {branch.findingCount}
                  </span>
                </button>
              ))
            ) : (
              <p className="text-xs text-tn-muted py-2">No category branches recorded.</p>
            )}
          </div>
        </section>
      </aside>
    </div>
  );
}
