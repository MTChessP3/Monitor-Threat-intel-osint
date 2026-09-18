// Domain relationship graph builder.
// Produces a node/edge graph linking:
//   domain -> subdomains -> IPs -> ASN, and domain -> MX hosts -> IPs -> ASN
// for the interactive Domain Intel panel.

import type { DomainGraph, GraphNode, GraphEdge, SubdomainInfo, IpInfo, MxHostInfo, DnsSection } from './types';

const MAX_NODES = 60;

function addNode(nodes: GraphNode[], n: GraphNode): void {
  if (!nodes.some((x) => x.id === n.id)) nodes.push(n);
}

function addEdge(edges: GraphEdge[], e: GraphEdge): void {
  if (!edges.some((x) => x.source === e.source && x.target === e.target)) edges.push(e);
}

export function buildDomainGraph(params: {
  domain: string;
  records: DnsSection;
  subdomains: SubdomainInfo[];
  ips: IpInfo[];
  mxHosts: MxHostInfo[];
}): DomainGraph {
  const { domain, subdomains, ips, mxHosts } = params;
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  addNode(nodes, { id: domain, label: domain, kind: 'domain', meta: 'Root domain' });

  const asnById = new Map<string, { id: string; name: string }>();
  const getAsn = (asn: string, name: string) => {
    if (!asn) return null;
    if (!asnById.has(asn)) {
      asnById.set(asn, { id: `asn-${asn}`, name: name || `AS${asn}` });
      addNode(nodes, { id: `asn-${asn}`, label: name || `AS${asn}`, kind: 'asn', meta: asn });
    }
    return asnById.get(asn)!;
  };

  // subdomain -> ip -> asn
  for (const sub of subdomains.slice(0, 40)) {
    addNode(nodes, { id: sub.name, label: sub.name, kind: 'subdomain' });
    addEdge(edges, { source: domain, target: sub.name });
    for (const ip of sub.ips) {
      addNode(nodes, { id: ip, label: ip, kind: 'ip' });
      addEdge(edges, { source: sub.name, target: ip });
    }
  }

  // root A/AAAA -> ips
  for (const rec of [...(params.records.A || []), ...(params.records.AAAA || [])]) {
    addNode(nodes, { id: rec.data, label: rec.data, kind: 'ip' });
    addEdge(edges, { source: domain, target: rec.data, label: rec.type });
  }

  // mx hosts -> ips -> asn
  for (const mx of mxHosts) {
    addNode(nodes, { id: mx.host, label: mx.host, kind: 'mx' });
    addEdge(edges, { source: domain, target: mx.host, label: 'MX' });
    if (mx.ip) {
      addNode(nodes, { id: mx.ip, label: mx.ip, kind: 'ip' });
      addEdge(edges, { source: mx.host, target: mx.ip });
    }
    if (mx.asn) {
      const asn = getAsn(mx.asn, mx.asname || '');
      if (asn) addEdge(edges, { source: mx.host, target: asn.id });
    }
  }

  // attach ASN to known IPs
  for (const info of ips) {
    if (info.asn) {
      const asn = getAsn(info.asn, info.asname || '');
      if (asn) addEdge(edges, { source: info.ip, target: asn.id });
    }
  }

  // Trim to a sane renderable size, keeping the root + asn hubs.
  if (nodes.length > MAX_NODES) {
    const keep = new Set<string>([domain]);
    nodes.forEach((n) => {
      if (n.kind === 'asn' || n.kind === 'mx') keep.add(n.id);
    });
    const rootIps = edges.filter((e) => e.source === domain && e.target.startsWith('.') === false);
    rootIps.forEach((e) => {
      if (keep.size < MAX_NODES - 8) keep.add(e.target);
    });
    for (const n of nodes) {
      if (keep.size >= MAX_NODES) break;
      keep.add(n.id);
    }
    const kept = nodes.filter((n) => keep.has(n.id));
    const keptIds = new Set(kept.map((n) => n.id));
    return {
      nodes: kept,
      edges: edges.filter((e) => keptIds.has(e.source) && keptIds.has(e.target)),
    };
  }

  return { nodes, edges };
}
