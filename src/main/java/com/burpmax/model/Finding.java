package com.burpmax.model;

import org.json.JSONArray;
import org.json.JSONObject;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Represents a single passive scan finding.
 * Thread-safety: affected_endpoints is only mutated from the Burp listener thread
 * (single-threaded per IHttpListener contract), so no locking needed there.
 * Analyst fields (suppressed, severityOverride, analystNote) are written from the
 * EDT only and read on background export threads — reads are safe because Strings
 * and booleans are either immutable or atomically readable on the JVM.
 */
public class Finding {

    // ── Severity constants ────────────────────────────────────────────────────
    public static final String SEV_CRITICAL     = "Critical";
    public static final String SEV_HIGH         = "High";
    public static final String SEV_MEDIUM       = "Medium";
    public static final String SEV_LOW          = "Low";
    public static final String SEV_INFO         = "Informational";

    private static final Set<String> VALID_SEVERITIES = Set.of(
            SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO);

    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // ── Core fields ───────────────────────────────────────────────────────────
    public final String name;
    public final String severity;
    public final String description;
    public final String evidence;
    public final String remediation;
    public final String cwe;
    public final String host;
    public final String url;
    public final int    statusCode;
    public final String endpoint;   // url stripped of query string + fragment
    public       String timestamp;

    // ── Analyst workflow ──────────────────────────────────────────────────────
    public volatile boolean suppressed        = false;
    public volatile String  severityOverride  = null;   // null = no override
    public volatile String  analystNote       = "";
    /** Where the finding came from: {@link #SOURCE_BURPMAX} or {@link #SOURCE_NUCLEI}. */
    public volatile String  source            = SOURCE_BURPMAX;
    public static final String SOURCE_BURPMAX = "BurpMax";
    public static final String SOURCE_NUCLEI  = "Nuclei";
    public volatile double  cvssScore         = -1;     // -1 = not set
    public volatile String  cvssVector        = "";     // e.g. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

    // ── Remediation status ────────────────────────────────────────────────────
    public static final String STATUS_OPEN      = "Open";
    public static final String STATUS_CONFIRMED = "Confirmed";
    public static final String STATUS_REMEDIATED= "Remediated";
    public static final String STATUS_ACCEPTED  = "Accepted Risk";
    public static final String STATUS_FP        = "False Positive";
    public static final String[] ALL_STATUSES   = {
        STATUS_OPEN, STATUS_CONFIRMED, STATUS_REMEDIATED, STATUS_ACCEPTED, STATUS_FP
    };
    public volatile String remediationStatus = STATUS_OPEN;

    /** Default CVSS base score ranges by severity (used when not explicitly set). */
    public static double defaultCvssScore(String severity) {
        return switch (severity) {
            case SEV_CRITICAL -> 9.0;
            case SEV_HIGH     -> 7.5;
            case SEV_MEDIUM   -> 5.0;
            case SEV_LOW      -> 3.0;
            default           -> 0.0;
        };
    }

    /** Returns the effective CVSS score — analyst-set or severity default. */
    public double effectiveCvssScore() {
        return cvssScore >= 0 ? cvssScore : defaultCvssScore(effectiveSeverity());
    }

    // ── Per-endpoint occurrences ──────────────────────────────────────────────
    /**
     * Each entry holds one unique endpoint this finding was seen on.
     *
     * CopyOnWriteArrayList: mergeEndpoint()/mergeEndpointFull() are called from the
     * Burp listener thread (under the FindingStore lock), while toJson() iterates this
     * list from the session/export background thread WITHOUT that lock (serialize()
     * only holds the store lock for the list snapshot, not the per-finding iteration).
     * COW makes that cross-thread iteration safe from ConcurrentModificationException;
     * the per-finding endpoint count is small so copy-on-write overhead is negligible.
     */
    public final List<EndpointEntry> affectedEndpoints = new java.util.concurrent.CopyOnWriteArrayList<>();

    // ─────────────────────────────────────────────────────────────────────────
    public Finding(String name, String severity, String description,
                   String evidence, String remediation, String cwe,
                   String host, String url, int statusCode,
                   byte[] rawRequest, byte[] rawResponse, Object httpService) {

        this.name        = name;
        this.severity    = severity;
        this.description = description;
        this.evidence    = evidence;
        this.remediation = remediation;
        this.cwe         = cwe;
        this.host        = host;
        this.url         = url;
        this.statusCode  = statusCode;
        this.endpoint    = stripQuery(url);
        this.timestamp   = LocalDateTime.now().format(FMT);

        // Auto-populate CVSS 4.0 score and vector from the vulnerability lookup table.
        // Analysts can override these via the UI after the finding is created.
        com.burpmax.model.Cvss4Calculator.CvssResult cvss =
                com.burpmax.model.Cvss4Calculator.calculate(name);
        if (cvss != null) {
            this.cvssScore  = cvss.score();
            this.cvssVector = cvss.vector();
        }

        affectedEndpoints.add(new EndpointEntry(
                this.endpoint, statusCode, rawRequest, rawResponse, httpService));
    }

    // ── Computed ──────────────────────────────────────────────────────────────
    public String effectiveSeverity() {
        return severityOverride != null ? severityOverride : severity;
    }

    /**
     * Dedup key for finding storage and merging.
     * Passive findings: one per (host, name) — passive findings aggregate all endpoints.
     * Active findings: one per (host, name, endpoint) — active findings carry per-endpoint
     * probe data (payload, parameter, probe request/response) that differs per endpoint,
     * so they must be stored separately to preserve evidence fidelity.
     */
    public String dedupKey() {
        if (SOURCE_NUCLEI.equals(source)) return "nuclei|" + host + "|" + name;
        if (name.startsWith("[ACTIVE]")) {
            return host + "|" + name + "|" + endpoint;
        }
        return host + "|" + name;
    }

    public byte[] primaryRawRequest() {
        return affectedEndpoints.isEmpty() ? null : affectedEndpoints.get(0).rawRequest;
    }

    public byte[] primaryRawResponse() {
        return affectedEndpoints.isEmpty() ? null : affectedEndpoints.get(0).rawResponse;
    }

    public Object primaryHttpService() {
        return affectedEndpoints.isEmpty() ? null : affectedEndpoints.get(0).httpService;
    }

    /** The mutated probe request for active findings, or null for passive. */
    public byte[] primaryProbeRequest() {
        return affectedEndpoints.isEmpty() ? null : affectedEndpoints.get(0).probeRequest;
    }

    /** The probe response confirming an active finding, or null for passive. */
    public byte[] primaryProbeResponse() {
        return affectedEndpoints.isEmpty() ? null : affectedEndpoints.get(0).probeResponse;
    }

    /** Payload string for active findings. */
    public String primaryPayload() {
        return affectedEndpoints.isEmpty() ? null : affectedEndpoints.get(0).payload;
    }

    /** Injection point name for active findings. */
    public String primaryParameter() {
        return affectedEndpoints.isEmpty() ? null : affectedEndpoints.get(0).parameter;
    }

    /**
     * Which substring triggered this finding and why. Computed once and cached on the primary
     * endpoint entry. Active findings use the probe request/response; passive findings and
     * findings restored from a session fall back to the captured traffic / saved probe pair.
     */
    public com.burpmax.evidence.Evidence primaryEvidence() {
        if (affectedEndpoints.isEmpty()) return com.burpmax.evidence.Evidence.EMPTY;
        EndpointEntry e = affectedEndpoints.get(0);
        com.burpmax.evidence.Evidence ev = e.evidence;
        // Older builds highlighted just the HTTP status line for passive findings; recompute those.
        if (ev != null && e.probeRequest == null && e.probeResponse == null && ev.responseMatches().size() == 1
                && ev.responseMatches().get(0).startsWith("HTTP/") && e.rawResponse != null) {
            ev = null;
        }
        if (ev == null) {
            if (e.probeRequest != null || e.probeResponse != null) {
                ev = com.burpmax.evidence.EvidenceExtractor.compute(
                        name, e.payload, e.timingMs, e.probeRequest, e.probeResponse,
                        e.rawResponse, this.evidence);
            } else {
                ev = com.burpmax.evidence.EvidenceExtractor.computePassive(
                        name, this.evidence, e.rawRequest, e.rawResponse);
            }
            e.evidence = ev;
        }
        return ev;
    }

    /** Observed timing delay for time-based findings, or -1. */
    public long primaryTimingMs() {
        return affectedEndpoints.isEmpty() ? -1L : affectedEndpoints.get(0).timingMs;
    }

    // ── Endpoint merge ────────────────────────────────────────────────────────
    public void mergeEndpoint(String url, int statusCode,
                              byte[] rawRequest, byte[] rawResponse, Object httpService) {
        String ep = stripQuery(url);
        for (EndpointEntry e : affectedEndpoints) {
            if (e.endpoint.equals(ep)) return;
        }
        // Store byte arrays only on the primary (first) endpoint to limit memory usage.
        // Subsequent endpoints record metadata only — PoC is always rendered from primary.
        affectedEndpoints.add(new EndpointEntry(ep, statusCode, null, null, null));
    }

    /** Merge preserving full probe/PoC data — used for active finding dedup. */
    public void mergeEndpointFull(String url, int statusCode,
                                   byte[] rawRequest, byte[] rawResponse, Object httpService,
                                   byte[] probeRequest, byte[] probeResponse,
                                   String payload, String parameter, long timingMs) {
        String ep = stripQuery(url);
        for (EndpointEntry e : affectedEndpoints) {
            if (e.endpoint.equals(ep)) return;
        }
        affectedEndpoints.add(new EndpointEntry(ep, statusCode,
                rawRequest, rawResponse, httpService,
                probeRequest, probeResponse, payload, parameter, timingMs));
    }

    // ── Serialization ─────────────────────────────────────────────────────────
    public JSONObject toJson() {
        primaryEvidence();   // make sure the "why flagged" data is computed so it is saved
        JSONObject o = new JSONObject();
        o.put("name",             name);
        o.put("severity",         severity);
        o.put("description",      description);
        o.put("evidence",         evidence);
        o.put("remediation",      remediation);
        o.put("cwe",              cwe);
        o.put("host",             host);
        o.put("url",              url);
        o.put("status_code",      statusCode);
        o.put("timestamp",        timestamp);
        o.put("endpoint",         endpoint);
        o.put("severity_override", severityOverride != null ? severityOverride : JSONObject.NULL);
        o.put("suppressed",        suppressed);
        o.put("analyst_note",      analystNote);
        o.put("source",            source);
        o.put("cvss_score",        cvssScore);
        o.put("cvss_vector",       cvssVector != null ? cvssVector : "");
        o.put("remediation_status", remediationStatus);

        JSONArray eps = new JSONArray();
        int epIdx = 0;
        for (EndpointEntry e : affectedEndpoints) {
            JSONObject ej = new JSONObject();
            // Keep the captured traffic too, so evidence, Repeater, re-verify and curl still work
            // after a session is loaded. Capped, and only for the first few endpoints of a finding,
            // to keep session files a sensible size.
            if (epIdx++ < RAW_ENDPOINTS) {
                java.util.List<String> hits = e.evidence != null ? e.evidence.responseMatches() : java.util.List.of();
                if (e.rawRequest  != null) ej.put("raw_req",  java.util.Base64.getEncoder().encodeToString(compact(e.rawRequest,  java.util.List.of(), RAW_REQ_CAP)));
                if (e.rawResponse != null) ej.put("raw_resp", java.util.Base64.getEncoder().encodeToString(compact(e.rawResponse, hits, RAW_RESP_CAP)));
            }
            ej.put("endpoint",    e.endpoint);
            ej.put("status_code", e.statusCode);
            // Serialize probe PoC data as Base64 so highlights survive session save/load
            {
                java.util.List<String> ph = e.evidence != null ? e.evidence.responseMatches() : java.util.List.of();
                if (e.probeRequest  != null) ej.put("probe_req",  java.util.Base64.getEncoder().encodeToString(compact(e.probeRequest, java.util.List.of(), RAW_REQ_CAP)));
                if (e.probeResponse != null) ej.put("probe_resp", java.util.Base64.getEncoder().encodeToString(compact(e.probeResponse, ph, RAW_RESP_CAP)));
            }
            if (e.payload   != null)     ej.put("payload",    e.payload);
            if (e.parameter != null)     ej.put("parameter",  e.parameter);
            if (e.timingMs  > 0)         ej.put("timing_ms",  e.timingMs);
            com.burpmax.evidence.Evidence ev = e.evidence;
            if (ev != null) {
                JSONArray ra = new JSONArray(), qa = new JSONArray();
                for (String m : ev.responseMatches()) ra.put(m);
                for (String m : ev.requestMatches())  qa.put(m);
                ej.put("ev_resp",  ra);
                ej.put("ev_req",   qa);
                ej.put("ev_logic", ev.logic());
            }
            eps.put(ej);
        }
        o.put("affected_endpoints", eps);
        return o;
    }

    public static Finding fromJson(JSONObject d) {
        String name = d.optString("name", "").trim();
        String host = d.optString("host", "").trim();
        String url  = d.optString("url",  "").trim();
        if (name.isEmpty() || host.isEmpty() || url.isEmpty())
            throw new IllegalArgumentException("Missing required field: name/host/url");

        String severity = d.optString("severity", SEV_INFO);
        if (!VALID_SEVERITIES.contains(severity)) severity = SEV_INFO;

        Finding f = new Finding(
                name,
                severity,
                d.optString("description", ""),
                d.optString("evidence",    ""),
                d.optString("remediation", ""),
                d.optString("cwe",         ""),
                host, url,
                d.optInt("status_code", 0),
                null, null, null);

        String override = d.isNull("severity_override") ? null : d.optString("severity_override", null);
        f.severityOverride = (override != null && VALID_SEVERITIES.contains(override)) ? override : null;
        f.source       = SOURCE_NUCLEI.equals(d.optString("source", "")) ? SOURCE_NUCLEI : SOURCE_BURPMAX;
        f.suppressed   = d.optBoolean("suppressed", false);
        String note    = d.optString("analyst_note", "");
        f.analystNote  = note.length() > 4096 ? note.substring(0, 4096) : note;
        double rawScore = d.optDouble("cvss_score", -1.0);
        f.cvssScore    = (rawScore >= 0.0 && rawScore <= 10.0) ? rawScore : -1.0;
        f.cvssVector   = d.optString("cvss_vector", "");
        f.timestamp    = d.optString("timestamp", f.timestamp);
        String rs = d.optString("remediation_status", STATUS_OPEN);
        f.remediationStatus = java.util.Arrays.asList(ALL_STATUSES).contains(rs) ? rs : STATUS_OPEN;

        // Restore affected_endpoints (no raw bytes available after restore)
        JSONArray eps = d.optJSONArray("affected_endpoints");
        if (eps != null && eps.length() > 0) {
            f.affectedEndpoints.clear();
            for (int i = 0; i < eps.length(); i++) {
                JSONObject ej = eps.optJSONObject(i);
                if (ej == null) continue;
                String ep = ej.optString("endpoint", "");
                if (ep.isEmpty()) continue;
                // Restore probe PoC data from Base64 if present
                byte[] probeReq  = null, probeResp = null;
                try {
                    if (ej.has("probe_req"))  probeReq  = java.util.Base64.getDecoder().decode(ej.optString("probe_req",  ""));
                    if (ej.has("probe_resp")) probeResp = java.util.Base64.getDecoder().decode(ej.optString("probe_resp", ""));
                } catch (Exception ignored) {}
                byte[] rawReq = null, rawResp = null;
                try {
                    if (ej.has("raw_req"))  rawReq  = java.util.Base64.getDecoder().decode(ej.optString("raw_req",  ""));
                    if (ej.has("raw_resp")) rawResp = java.util.Base64.getDecoder().decode(ej.optString("raw_resp", ""));
                } catch (Exception ignored) {}
                {   // shrink oversized traffic from older/larger session files so memory and the next save stay small
                    java.util.List<String> lh = new java.util.ArrayList<>();
                    JSONArray la = ej.optJSONArray("ev_resp");
                    if (la != null) for (int k = 0; k < la.length(); k++) lh.add(String.valueOf(la.get(k)));
                    if (rawReq    != null) rawReq    = compact(rawReq,    java.util.List.of(), RAW_REQ_CAP);
                    if (rawResp   != null) rawResp   = compact(rawResp,   lh, RAW_RESP_CAP);
                    if (probeReq  != null) probeReq  = compact(probeReq,  java.util.List.of(), RAW_REQ_CAP);
                    if (probeResp != null) probeResp = compact(probeResp, lh, RAW_RESP_CAP);
                }
                String pl    = ej.has("payload")   ? ej.optString("payload",   null) : null;
                String param = ej.has("parameter") ? ej.optString("parameter", null) : null;
                long   tms   = ej.has("timing_ms") ? ej.optLong("timing_ms", -1L) : -1L;
                EndpointEntry entry = new EndpointEntry(
                        ep, ej.optInt("status_code", 0), rawReq, rawResp, null,
                        probeReq, probeResp, pl, param, tms);
                if (ej.has("ev_logic")) {
                    java.util.List<String> rh = new java.util.ArrayList<>(), qh = new java.util.ArrayList<>();
                    JSONArray ra = ej.optJSONArray("ev_resp"), qa = ej.optJSONArray("ev_req");
                    if (ra != null) for (int k = 0; k < ra.length(); k++) rh.add(String.valueOf(ra.get(k)));
                    if (qa != null) for (int k = 0; k < qa.length(); k++) qh.add(String.valueOf(qa.get(k)));
                    entry.evidence = new com.burpmax.evidence.Evidence(rh, qh, ej.optString("ev_logic", ""));
                }
                f.affectedEndpoints.add(entry);
            }
        }
        return f;
    }

    // ── Saved-session traffic ─────────────────────────────────────────────────
    private static final int RAW_ENDPOINTS = 1;
    private static final int RAW_REQ_CAP   = 4 * 1024;
    private static final int RAW_RESP_CAP  = 24 * 1024;

    /**
     * Shrink a message for saving. Small messages are kept whole. A big one keeps its start
     * (status line, headers, beginning of the body) plus a window around the first piece of
     * matched text, so the proof is still there with a visible "trimmed" marker.
     */
    static byte[] compact(byte[] raw, java.util.List<String> hits, int cap) {
        if (raw.length <= cap) return raw;
        String text = new String(raw, java.nio.charset.StandardCharsets.ISO_8859_1);
        int head = cap / 2;
        int at = -1;
        for (String h : hits) { int i = text.indexOf(h, head); if (i >= 0 && (at < 0 || i < at)) at = i; }
        StringBuilder sb = new StringBuilder(cap + 100);
        sb.append(text, 0, head);
        sb.append("\r\n[... trimmed to keep the saved session small ...]\r\n");
        if (at >= 0) {
            int from = Math.max(head, at - head / 2), to = Math.min(text.length(), from + (cap - head));
            sb.append(text, from, to);
        } else {
            sb.append(text, head, Math.min(text.length(), cap));
        }
        return sb.toString().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    // ── Utilities ─────────────────────────────────────────────────────────────
    private static String stripQuery(String url) {
        if (url == null) return "";
        int q = url.indexOf('?');
        int h = url.indexOf('#');
        int cut = url.length();
        if (q >= 0) cut = Math.min(cut, q);
        if (h >= 0) cut = Math.min(cut, h);
        return url.substring(0, cut);
    }

    // ── Inner class ───────────────────────────────────────────────────────────
    public static class EndpointEntry {
        public final String endpoint;
        public final int    statusCode;
        public final byte[] rawRequest;       // original request (proxy traffic)
        public final byte[] rawResponse;      // original response
        public final Object httpService;
        // PoC-specific fields — set for active findings, null for passive
        public final byte[] probeRequest;     // mutated probe request that confirmed the finding
        public final byte[] probeResponse;    // probe response confirming the finding
        public final String payload;          // injected payload string
        public final String parameter;        // injection point name
        public final long   timingMs;         // observed delay for time-based findings (-1 = N/A)
        /** Matched substrings + detection logic. Computed lazily when absent (passive / loaded). */
        public volatile com.burpmax.evidence.Evidence evidence;

        /** Passive finding constructor — no probe-specific data. */
        public EndpointEntry(String endpoint, int statusCode,
                              byte[] rawRequest, byte[] rawResponse, Object httpService) {
            this(endpoint, statusCode, rawRequest, rawResponse, httpService,
                 null, null, null, null, -1L);
        }

        /** Active finding constructor — carries full PoC context. */
        public EndpointEntry(String endpoint, int statusCode,
                              byte[] rawRequest, byte[] rawResponse, Object httpService,
                              byte[] probeRequest, byte[] probeResponse,
                              String payload, String parameter, long timingMs) {
            this.endpoint      = endpoint;
            this.statusCode    = statusCode;
            this.rawRequest    = rawRequest;
            this.rawResponse   = rawResponse;
            this.httpService   = httpService;
            this.probeRequest  = probeRequest;
            this.probeResponse = probeResponse;
            this.payload       = payload;
            this.parameter     = parameter;
            this.timingMs      = timingMs;
        }
    }
}
