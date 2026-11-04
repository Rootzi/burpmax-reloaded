package com.burpmax.export;

import com.burpmax.evidence.Evidence;
import com.burpmax.evidence.Snippet;
import com.burpmax.model.Finding;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Markdown (human, paste into a ticket or wiki) and JSON (machine, feed another tool) exports. */
public final class StructuredExporter {

    private StructuredExporter() { }

    private static final Map<String, Integer> SEV_ORDER = Map.of(
            "Critical", 0, "High", 1, "Medium", 2, "Low", 3, "Informational", 4);

    private static List<Finding> sorted(List<Finding> in) {
        List<Finding> s = new ArrayList<>(in);
        s.sort(Comparator.comparingInt((Finding f) -> SEV_ORDER.getOrDefault(f.effectiveSeverity(), 99))
                .thenComparing(f -> f.name == null ? "" : f.name));
        return s;
    }

    private static File target(String path, String ext) throws IOException {
        if (!path.toLowerCase().endsWith(ext)) path += ext;
        File f = new File(path).getCanonicalFile();
        if (f.getAbsolutePath().contains("..")) throw new SecurityException("Invalid export path: " + path);
        return f;
    }

    /** What the finding is proven by: the probe's own traffic when it has any, else captured traffic. */
    private record Proof(byte[] req, byte[] resp, Evidence ev, String curl) { }

    private static Proof proof(Finding f) {
        boolean probe = f.primaryProbeRequest() != null || f.primaryProbeResponse() != null;
        byte[] rq = probe ? f.primaryProbeRequest() : f.primaryRawRequest();
        byte[] rs = probe ? f.primaryProbeResponse() : f.primaryRawResponse();
        String curl = "";
        if (rq != null) {
            try {
                java.net.URL u = new java.net.URL(f.url);
                int port = u.getPort() > 0 ? u.getPort() : u.getDefaultPort();
                curl = com.burpmax.util.CurlBuilder.build(rq, u.getHost(), port, u.getProtocol().equalsIgnoreCase("https"));
            } catch (Exception ignored) { }
        }
        return new Proof(rq, rs, f.primaryEvidence(), curl);
    }

    // ── Markdown ──────────────────────────────────────────────────────────────

    public static void markdown(List<Finding> findings, String path) throws Exception {
        File out = target(path, ".md");
        List<Finding> fs = sorted(findings);
        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8))) {
            w.println("# BurpMax findings");
            w.println();
            w.println("_" + fs.size() + " findings, generated " + java.time.LocalDateTime.now().withNano(0) + "_");
            w.println();
            Map<String, Integer> counts = new LinkedHashMap<>();
            for (Finding f : fs) counts.merge(f.effectiveSeverity(), 1, Integer::sum);
            w.println("| Severity | Count |");
            w.println("|---|---|");
            counts.forEach((k, v) -> w.println("| " + k + " | " + v + " |"));
            w.println();

            int n = 1;
            for (Finding f : fs) {
                Proof p = proof(f);
                w.println("## " + n++ + ". " + md(f.name) + " (" + f.effectiveSeverity() + ")");
                w.println();
                w.println("- **Host:** " + md(f.host));
                w.println("- **URL:** `" + f.url + "`");
                if (f.cwe != null && !f.cwe.isBlank()) w.println("- **CWE:** " + md(f.cwe));
                w.println("- **Status:** " + f.remediationStatus);
                if (f.affectedEndpoints.size() > 1) {
                    w.println("- **Affected endpoints (" + f.affectedEndpoints.size() + "):**");
                    for (Finding.EndpointEntry e : f.affectedEndpoints) w.println("  - `" + e.endpoint + "`");
                }
                w.println();
                if (f.description != null && !f.description.isBlank()) { w.println("**Description**"); w.println(); w.println(f.description.strip()); w.println(); }
                if (!p.ev().logic().isEmpty()) { w.println("**Why it was flagged:** " + p.ev().logic()); w.println(); }
                if (p.ev().hasMatches()) {
                    w.println("**Matched text:**");
                    for (String m : p.ev().responseMatches()) w.println("- `" + oneLine(m) + "` (in response)");
                    for (String m : p.ev().requestMatches())  w.println("- `" + oneLine(m) + "` (in request)");
                    w.println();
                }
                if (p.req() != null) {
                    w.println("**Request**"); w.println();
                    fence(w, Snippet.toPlain(Snippet.request(p.req(), p.ev().requestMatches()), ">>", "<<"));
                }
                if (p.resp() != null) {
                    w.println("**Response**"); w.println();
                    fence(w, Snippet.toPlain(Snippet.response(p.resp(), p.ev().responseMatches()), ">>", "<<"));
                }
                if (!p.curl().isEmpty()) { w.println("**Reproduce**"); w.println(); fence(w, p.curl()); }
                if (f.remediation != null && !f.remediation.isBlank()) { w.println("**Remediation**"); w.println(); w.println(f.remediation.strip()); w.println(); }
                if (f.analystNote != null && !f.analystNote.isBlank()) { w.println("**Analyst note**"); w.println(); w.println("> " + f.analystNote.strip().replace("\n", "\n> ")); w.println(); }
                w.println("---");
                w.println();
            }
            w.println("_`>>` and `<<` mark the exact text that triggered detection._");
        }
    }

    private static void fence(PrintWriter w, String body) {
        String fence = "```";
        while (body.contains(fence)) fence += "`";
        w.println(fence);
        w.println(body);
        w.println(fence);
        w.println();
    }

    private static String md(String s) { return s == null ? "" : s.replace("|", "\\|").replace("\n", " "); }
    private static String oneLine(String s) { return s.replace("`", "'").replace("\r", "").replace("\n", " \u21B5 "); }

    // ── JSON ──────────────────────────────────────────────────────────────────

    public static void json(List<Finding> findings, String path) throws Exception {
        File out = target(path, ".json");
        List<Finding> fs = sorted(findings);
        StringBuilder sb = new StringBuilder(64 * 1024);
        sb.append("{\n  \"tool\": \"BurpMax\",\n  \"generated\": ").append(q(java.time.Instant.now().toString()))
          .append(",\n  \"count\": ").append(fs.size()).append(",\n  \"findings\": [");
        boolean first = true;
        for (Finding f : fs) {
            Proof p = proof(f);
            sb.append(first ? "\n" : ",\n").append("    {");
            first = false;
            kv(sb, "name", f.name, true);
            kv(sb, "severity", f.effectiveSeverity(), false);
            kv(sb, "original_severity", f.severity, false);
            kv(sb, "status", f.remediationStatus, false);
            sb.append(",\"false_positive\":").append(f.suppressed);
            kv(sb, "host", f.host, false);
            kv(sb, "url", f.url, false);
            kv(sb, "cwe", f.cwe, false);
            sb.append(",\"cvss\":").append(f.cvssScore >= 0 ? String.valueOf(f.cvssScore) : "null");
            kv(sb, "cvss_vector", f.cvssVector, false);
            sb.append(",\"endpoints\":[");
            for (int i = 0; i < f.affectedEndpoints.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append(q(f.affectedEndpoints.get(i).endpoint));
            }
            sb.append(']');
            kv(sb, "description", f.description, false);
            kv(sb, "remediation", f.remediation, false);
            kv(sb, "analyst_note", f.analystNote, false);
            sb.append(",\"evidence\":{");
            kv(sb, "logic", p.ev().logic(), true);
            sb.append(",\"matched_in_response\":").append(arr(p.ev().responseMatches()));
            sb.append(",\"matched_in_request\":").append(arr(p.ev().requestMatches()));
            kv(sb, "request_snippet", p.req() == null ? null : Snippet.toPlain(Snippet.request(p.req(), p.ev().requestMatches())), false);
            kv(sb, "response_snippet", p.resp() == null ? null : Snippet.toPlain(Snippet.response(p.resp(), p.ev().responseMatches())), false);
            kv(sb, "curl", p.curl().isEmpty() ? null : p.curl(), false);
            sb.append("}}");
        }
        sb.append("\n  ]\n}\n");
        try (Writer w = new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8)) {
            w.write(sb.toString());
        }
    }

    private static void kv(StringBuilder sb, String k, String v, boolean first) {
        if (!first) sb.append(',');
        sb.append(q(k)).append(':').append(v == null ? "null" : q(v));
    }

    private static String arr(List<String> l) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < l.size(); i++) { if (i > 0) sb.append(','); sb.append(q(l.get(i))); }
        return sb.append(']').toString();
    }

    static String q(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> { if (c < 0x20) sb.append(String.format("\\u%04x", (int) c)); else sb.append(c); }
            }
        }
        return sb.append('"').toString();
    }
}
