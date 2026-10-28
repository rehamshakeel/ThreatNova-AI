'use client';

import React from 'react';
import { Globe2, MapPin, MapPinOff, Info, Server } from 'lucide-react';
import type { Investigation } from '@/lib/types';
import { indicatorTypeLabel } from '@/lib/indicators';

export interface OriginGeoLocation {
  ip: string;
  city: string;
  region: string;
  country: string;
  countryCode: string;
  lat: number;
  lng: number;
  asn?: string;
  org?: string;
  source?: string;
  isProxy?: boolean;
  isTor?: boolean;
  isVPN?: boolean;
  isEmailDomain?: boolean;
  is_cdn_edge?: boolean;
  note?: string;
}

export function resolveInvestigationGeo(inv: Investigation | undefined): OriginGeoLocation | null {
  if (!inv) return null;

  // 1. Primary path: Read live evidence-backed geolocation from investigation response
  const geo = inv.geolocation || (inv as any).enrichment?.geo || inv.domainIntel?.geo;
  if (
    geo &&
    typeof geo.latitude === 'number' &&
    typeof geo.longitude === 'number' &&
    !isNaN(geo.latitude) &&
    !isNaN(geo.longitude)
  ) {
    return {
      ip: geo.resolved_ip || geo.ip || (inv.type === 'ip' ? inv.query : ''),
      city: geo.city || 'Unknown',
      region: geo.region || 'Unknown',
      country: geo.country || 'Unknown',
      countryCode: geo.countryCode || '',
      lat: geo.latitude,
      lng: geo.longitude,
      asn: geo.asn,
      org: geo.org,
      source: geo.source,
      isProxy: geo.isProxy,
      isTor: geo.isTor,
      isVPN: geo.isVPN,
      isEmailDomain: inv.type === 'email',
      is_cdn_edge: geo.is_cdn_edge,
      note: geo.note,
    };
  }

  // 2. Secondary path: domainIntel.ipInfo if it carries numeric coordinates
  const ipInfo = inv.domainIntel?.ipInfo;
  if (
    ipInfo &&
    typeof ipInfo.latitude === 'number' &&
    typeof ipInfo.longitude === 'number' &&
    !isNaN(ipInfo.latitude) &&
    !isNaN(ipInfo.longitude)
  ) {
    return {
      ip: ipInfo.ip || inv.query,
      city: ipInfo.city || 'Unknown',
      region: ipInfo.region || 'Unknown',
      country: ipInfo.country || 'Unknown',
      countryCode: ipInfo.countryCode || '',
      lat: ipInfo.latitude,
      lng: ipInfo.longitude,
      asn: ipInfo.asn,
      org: ipInfo.org,
      source: ipInfo.source || 'IP Telemetry',
      isProxy: ipInfo.isProxy,
      isTor: ipInfo.isTor,
      isVPN: ipInfo.isVPN,
      isEmailDomain: inv.type === 'email',
      is_cdn_edge: (ipInfo as any).is_cdn_edge,
      note: (ipInfo as any).note,
    };
  }

  // 3. Fallback only for designated demonstration fixtures (clearly labelled demo indicators)
  const norm = inv.query.trim().toLowerCase();
  if (norm.includes('dark-stealer') || norm.includes('198.51.100')) {
    return {
      ip: '198.51.100.23',
      city: 'Amsterdam',
      region: 'North Holland',
      country: 'Netherlands',
      countryCode: 'NL',
      lat: 52.3676,
      lng: 4.9041,
      asn: 'AS64496',
      org: 'ThreatNet Server Colocation',
      source: 'Demo Fixture',
      isProxy: true,
      isTor: true,
      isVPN: true,
      isEmailDomain: false,
      is_cdn_edge: true,
      note: 'CDN Edge Location - closest to resolver',
    };
  }

  return null;
}

interface InvestigationOriginMapProps {
  investigation?: Investigation;
  isLoading?: boolean;
}

export default function InvestigationOriginMap({
  investigation,
  isLoading = false,
}: InvestigationOriginMapProps) {
  const resolvedGeo = resolveInvestigationGeo(investigation);

  return (
    <section
      aria-labelledby="investigation-origin-map-title"
      className="overflow-hidden rounded-xl border border-tn-border bg-tn-surface shadow-md"
    >
      <div className="flex flex-col gap-2 border-b border-tn-border px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-tn-border bg-tn-card text-tn-info">
            <Globe2 size={16} />
          </div>
          <div>
            <h3 id="investigation-origin-map-title" className="text-sm font-semibold text-tn-text">
              Investigation Origin Map
            </h3>
            <p className="text-xs text-tn-muted">
              Approximate geographic geolocation for resolved infrastructure associated with the selected investigation.
            </p>
          </div>
        </div>
        {investigation && (
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-tn-muted uppercase tracking-wider">Selected Target:</span>
            <span className="rounded border border-tn-border bg-tn-card px-2 py-0.5 text-xs font-mono font-medium text-tn-text">
              {investigation.query}
            </span>
          </div>
        )}
      </div>

      <div className="p-5">
        {isLoading ? (
          <div className="flex min-h-[340px] sm:min-h-[400px] flex-col items-center justify-center rounded-lg border border-tn-border bg-tn-card/40 p-8 text-center animate-pulse">
            <div className="flex h-12 w-12 items-center justify-center rounded-full border border-tn-border bg-tn-surface text-tn-info mb-3">
              <Globe2 size={24} className="animate-spin" />
            </div>
            <h4 className="text-sm font-semibold text-tn-text">Resolving Infrastructure Telemetry...</h4>
            <p className="mt-1 text-xs text-tn-muted">Fetching live geolocation and routing records.</p>
          </div>
        ) : resolvedGeo ? (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* Left / Top: Google Maps Embed View */}
            <div className="lg:col-span-2 relative min-h-[340px] sm:min-h-[400px] rounded-lg border border-tn-border bg-tn-card overflow-hidden">
              <iframe
                title={`Google Maps showing approximate location for ${resolvedGeo.ip}`}
                width="100%"
                height="100%"
                className="w-full h-full min-h-[340px] sm:min-h-[400px]"
                style={{ border: 0 }}
                loading="lazy"
                allowFullScreen
                referrerPolicy="no-referrer-when-downgrade"
                src={`https://maps.google.com/maps?q=${resolvedGeo.lat},${resolvedGeo.lng}&hl=en&z=10&output=embed`}
              />

              {/* Floating Map Marker Overlay */}
              <div className="absolute top-3 left-3 z-10 flex items-center gap-2 rounded-lg border border-tn-border bg-tn-surface/95 px-3 py-1.5 backdrop-blur-md shadow-lg text-xs">
                <MapPin size={14} className="text-tn-danger animate-pulse" />
                <span className="font-mono font-semibold text-tn-text">
                  {resolvedGeo.city}, {resolvedGeo.region ? `${resolvedGeo.region}, ` : ''}{resolvedGeo.country}
                </span>
                <span className="text-[10px] font-mono text-tn-muted">
                  [{resolvedGeo.lat.toFixed(2)}, {resolvedGeo.lng.toFixed(2)}]
                </span>
              </div>

              {/* CDN / Edge Infrastructure Banner Overlay */}
              {resolvedGeo.is_cdn_edge && (
                <div className="absolute top-12 left-3 z-10 flex items-center gap-2 rounded-lg border border-tn-info/40 bg-tn-surface/95 px-3 py-1.5 backdrop-blur-md shadow-lg text-xs text-tn-info">
                  <Server size={13} className="shrink-0 text-tn-info" />
                  <span className="font-medium">CDN/Edge Infrastructure - Location shows nearest edge node</span>
                </div>
              )}
            </div>

            {/* Right / Bottom: Resolved Location Details */}
            <div className="flex flex-col justify-between rounded-lg border border-tn-border bg-tn-card/40 p-4">
              <div className="space-y-3.5">
                <div className="flex items-center justify-between border-b border-tn-border/60 pb-2.5">
                  <span className="text-xs font-mono font-semibold uppercase tracking-wider text-tn-info">
                    Location Telemetry
                  </span>
                  <div className="flex items-center gap-1.5">
                    {resolvedGeo.is_cdn_edge && (
                      <span className="text-[9px] font-mono rounded bg-tn-info/15 border border-tn-info/30 px-1.5 py-0.5 text-tn-info font-semibold">
                        CDN EDGE
                      </span>
                    )}
                    <span className="text-[10px] font-mono rounded bg-emerald-500/15 border border-emerald-500/30 px-2 py-0.5 text-emerald-400 font-semibold">
                      RESOLVED
                    </span>
                  </div>
                </div>

                <div className="space-y-2 text-xs">
                  <div className="flex justify-between items-center py-1 border-b border-tn-border/30">
                    <span className="text-tn-muted">Resolved IP:</span>
                    <code className="font-mono font-semibold text-tn-text">{resolvedGeo.ip || 'Unavailable'}</code>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-tn-border/30">
                    <span className="text-tn-muted">City:</span>
                    <span className="font-medium text-tn-text">{resolvedGeo.city}</span>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-tn-border/30">
                    <span className="text-tn-muted">Region / State:</span>
                    <span className="font-medium text-tn-text">{resolvedGeo.region || 'Unavailable'}</span>
                  </div>
                  <div className="flex justify-between items-center py-1 border-b border-tn-border/30">
                    <span className="text-tn-muted">Country:</span>
                    <span className="font-medium text-tn-text">{resolvedGeo.country}{resolvedGeo.countryCode ? ` (${resolvedGeo.countryCode})` : ''}</span>
                  </div>
                  {resolvedGeo.asn && (
                    <div className="flex justify-between items-center py-1 border-b border-tn-border/30">
                      <span className="text-tn-muted">Routing / ASN:</span>
                      <span className="font-mono text-[11px] text-tn-text">{resolvedGeo.asn}</span>
                    </div>
                  )}
                  {resolvedGeo.org && (
                    <div className="flex justify-between items-center py-1 border-b border-tn-border/30">
                      <span className="text-tn-muted">Organization:</span>
                      <span className="text-[11px] text-tn-text text-right truncate max-w-[160px]">{resolvedGeo.org}</span>
                    </div>
                  )}
                  {resolvedGeo.source && (
                    <div className="flex justify-between items-center py-1 border-b border-tn-border/30">
                      <span className="text-tn-muted">Source:</span>
                      <span className="font-mono text-[11px] text-tn-info">{resolvedGeo.source}</span>
                    </div>
                  )}
                  <div className="flex justify-between items-center py-1">
                    <span className="text-tn-muted">Network Traits:</span>
                    <div className="flex flex-wrap gap-1 justify-end">
                      {resolvedGeo.isTor && (
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-tn-danger/15 border border-tn-danger/30 text-tn-danger">TOR</span>
                      )}
                      {resolvedGeo.isVPN && (
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-tn-warn/15 border border-tn-warn/30 text-tn-warn">VPN</span>
                      )}
                      {resolvedGeo.isProxy && (
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-tn-info/15 border border-tn-info/30 text-tn-info">PROXY</span>
                      )}
                      {!resolvedGeo.isTor && !resolvedGeo.isVPN && !resolvedGeo.isProxy && (
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-tn-surface border border-tn-border text-tn-muted">HOSTING</span>
                      )}
                    </div>
                  </div>
                </div>

                {resolvedGeo.isEmailDomain && (
                  <div className="mt-2.5 rounded border border-tn-info/30 bg-tn-info/10 p-2 text-[10px] text-tn-info leading-tight">
                    <strong>Email Domain Infrastructure:</strong> Geolocation indicates mail exchange / MX routing infrastructure, not the sender&apos;s physical location.
                  </div>
                )}
              </div>

              {/* Mandatory Geolocation Accuracy & Privacy Disclaimer */}
              <div className="mt-4 rounded border border-tn-border/60 bg-tn-surface/60 p-2.5 text-[10px] text-tn-muted leading-relaxed">
                <div className="flex items-start gap-1.5">
                  <Info size={13} className="shrink-0 text-tn-info mt-0.5" />
                  <span>
                    <strong className="text-tn-text font-medium">Approximate Geolocation:</strong> IP geolocation reflects upstream routing and infrastructure information. It does not identify a person&apos;s exact physical location.
                  </span>
                </div>
              </div>
            </div>
          </div>
        ) : (
          /* Location Unavailable View */
          <div className="flex min-h-[260px] flex-col items-center justify-center rounded-lg border border-dashed border-tn-border/70 bg-tn-card/20 p-6 text-center">
            <div className="flex h-11 w-11 items-center justify-center rounded-full border border-tn-border bg-tn-surface text-tn-muted mb-2.5">
              <MapPinOff size={20} />
            </div>
            <h4 className="text-sm font-semibold text-tn-text">No infrastructure location resolved for this investigation.</h4>
            <p className="mt-1 text-xs text-tn-muted max-w-md">
              No public routable IP address or geographic coordinates could be confirmed for &ldquo;
              <span className="font-mono text-tn-text">{investigation?.query || 'selected indicator'}</span>
              &rdquo; ({investigation ? indicatorTypeLabel(investigation.type) : 'non-IP'}).
            </p>
            <div className="mt-3 flex items-center gap-2">
              <span className="text-[10px] font-mono rounded bg-tn-card border border-tn-border px-2 py-0.5 text-tn-muted font-semibold">
                UNAVAILABLE
              </span>
            </div>
            <p className="mt-2 text-[11px] font-mono text-tn-muted/80">
              Tip: Select an IP address or resolved domain row in Recent Investigations above to update the map.
            </p>
            <div className="mt-4 rounded border border-tn-border/40 bg-tn-surface/40 p-2 text-[10px] text-tn-muted max-w-md text-left">
              <span className="flex items-center gap-1 text-[10px] text-tn-muted">
                <Info size={11} className="shrink-0 text-tn-muted" />
                <span>
                  <strong className="text-tn-text font-medium">Approximate Geolocation:</strong> IP geolocation reflects upstream routing and infrastructure information. It does not identify a person&apos;s exact physical location.
                </span>
              </span>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
