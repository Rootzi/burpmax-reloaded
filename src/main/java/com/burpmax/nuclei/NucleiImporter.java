package com.burpmax.nuclei;

import com.burpmax.evidence.Evidence;
import com.burpmax.model.Finding;
import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Turns one line of {@code nuclei -jsonl -irr} output into a normal BurpMax {@link Finding}. */
public final class NucleiImporter {

    private NucleiImporter() { }

    /** Returns null for lines that aren't a result. {@code templates} maps template id to its file (may be empty). */
    public static Finding fromJsonLine(String line, Map<String, Path> templates) {
        if (line == null) return null;
        line = line.trim();
        if (!line.startsWith("{")) return null;
        JSONObject o;
        try { o = new JSONObject(line); } catch (Exception e) { return null; }
        String tid = o.optString("template-id", "");
        JSONObject info = o.optJSONObject("info");
        if (tid.isEmpty() || info == null) return null;

        String name = info.optString("name", tid);
        String sev = mapSeverity(info.optString("severity", "info"));
        String matchedAt = o.optString("matched-at", o.optString("host", ""));
        String host = o.optString("host", "");
        String url = toUrl(matchedAt, host);
        String hostName = hostOf(url, host);

        byte[] req = bytes(o.optString("request", ""));
        byte[] resp = bytes(o.optString("response", ""));
        int status = statusOf(resp);

        StringBuilder desc = new StringBuilder();
        String d = info.optString("description", "").strip();
        if (!d.isEmpty()) desc.append(d).append("\n\n");
        desc.append("Detected by Nuclei template ").append(tid);
        List<String> tags = strings(info.opt("tags"));
        if (!tags.isEmpty()) desc.append("\nTags: ").append(String.join(", ", tags));
        List<String> refs = strings(info.opt("reference"));
        if (!refs.isEmpty()) desc.append("\nReferences:\n  ").append(String.join("\n  ", refs));

        String matcher = o.optString("matcher-name", "");
        List<String> extracted = strings(o.opt("extracted-results"));
        StringBuilder evid = new StringBuilder("Nuclei template: ").append(tid);
        if (!matcher.isEmpty()) evid.append("\nMatcher: ").append(matcher);
        if (!extracted.isEmpty()) evid.append("\nExtracted: ").append(String.join(", ", extracted));

        String remediation = info.optString("remediation", "").strip();
        if (remediation.isEmpty()) remediation = "Review the Nuclei template and its references for the recommended fix.";

        String cwe = "";
        double cvss = -1;
        String vector = "";
        JSONObject cls = info.optJSONObject("classification");
        if (cls != null) {
            List<String> cwes = strings(cls.opt("cwe-id"));
            if (!cwes.isEmpty()) cwe = cwes.get(0).toUpperCase(Locale.ROOT);
            cvss = cls.optDouble("cvss-score", -1);
            vector = cls.optString("cvss-metrics", "");
        }

        Finding f = new Finding(name, sev, desc.toString(), evid.toString(), remediation, cwe,
                hostName, url, status, req.length == 0 ? null : req, resp.length == 0 ? null : resp, null);
        f.source = Finding.SOURCE_NUCLEI;
        if (cvss >= 0 && cvss <= 10) f.cvssScore = cvss;
        if (!vector.isEmpty()) f.cvssVector = vector;

        // The request Nuclei sent is the proof, so attach it as the probe traffic too.
        if (!f.affectedEndpoints.isEmpty()) {
            Finding.EndpointEntry e0 = f.affectedEndpoints.get(0);
            Finding.EndpointEntry e1 = new Finding.EndpointEntry(e0.endpoint, e0.statusCode, e0.rawRequest, e0.rawResponse,
                    e0.httpService, req.length == 0 ? null : req, resp.length == 0 ? null : resp, "", "", -1L);
            e1.evidence = evidenceFor(tid, matcher, extracted, resp, templates);
            f.affectedEndpoints.set(0, e1);
        }
        return f;
    }

    // ── Evidence: which exact text made the template match ────────────────────

    static Evidence evidenceFor(String tid, String matcher, List<String> extracted, byte[] resp, Map<String, Path> templates) {
        String text = new String(resp, StandardCharsets.ISO_8859_1);
        List<String> hits = new ArrayList<>();
        Path p = templates == null ? null : templates.get(tid);
        List<String> words = new ArrayList<>(), regexes = new ArrayList<>();
        if (p != null) {
            try { collect(new String(Files.readAllBytes(p), StandardCharsets.UTF_8), words, regexes); } catch (Exception ignored) { }
        }
        String lower = text.toLowerCase(Locale.ROOT);
        for (String w : words) {
            if (w.length() < 3 || w.contains("{{")) continue;
            int i = text.indexOf(w);
            if (i < 0) { i = lower.indexOf(w.toLowerCase(Locale.ROOT)); if (i >= 0) w = text.substring(i, i + w.length()); }
            if (i >= 0) addHit(hits, w);
            if (hits.size() >= 6) break;
        }
        for (String r : regexes) {
            if (hits.size() >= 6) break;
            try {
                Matcher m = Pattern.compile(r).matcher(text);
                if (m.find()) addHit(hits, m.group().length() > 200 ? m.group().substring(0, 200) : m.group());
            } catch (Exception ignored) { /* Go regex syntax that Java rejects: skip */ }
        }
        for (String x : extracted) if (!x.isBlank() && text.contains(x)) addHit(hits, x);

        StringBuilder logic = new StringBuilder("The response satisfied the matcher");
        if (!matcher.isEmpty()) logic.append(" '").append(matcher).append("'");
        logic.append(" of Nuclei template ").append(tid).append('.');
        if (hits.isEmpty()) logic.append(" It matched on a status code, header or computed (DSL) condition rather than a single piece of text; compare the response with the template.");
        else logic.append(" The highlighted text is what the template looks for.");
        return new Evidence(hits, List.of(), logic.toString());
    }

    private static void addHit(List<String> hits, String h) { if (!hits.contains(h)) hits.add(h); }

    /** Best-effort pull of the {@code words:} and {@code regex:} lists out of a template. */
    static void collect(String yaml, List<String> words, List<String> regexes) {
        String[] lines = yaml.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String l = lines[i];
            String t = l.strip();
            boolean w = t.equals("words:"), r = t.equals("regex:");
            if (!w && !r) continue;
            int indent = l.length() - l.stripLeading().length();
            for (int j = i + 1; j < lines.length; j++) {
                String lj = lines[j];
                if (lj.isBlank()) continue;
                int ind = lj.length() - lj.stripLeading().length();
                String tj = lj.strip();
                if (ind < indent || !tj.startsWith("- ") ) {
                    if (ind <= indent) break; else continue;
                }
                String v = unquote(tj.substring(2).strip());
                if (!v.isEmpty()) (w ? words : regexes).add(v);
            }
        }
    }

    private static String unquote(String v) {
        if (v.length() >= 2 && ((v.startsWith("\"") && v.endsWith("\"")) || (v.startsWith("'") && v.endsWith("'")))) {
            String in = v.substring(1, v.length() - 1);
            return v.startsWith("\"") ? in.replace("\\\"", "\"").replace("\\\\", "\\") : in.replace("''", "'");
        }
        return v;
    }

    // ── Small helpers ─────────────────────────────────────────────────────────

    static String mapSeverity(String s) {
        return switch (s == null ? "" : s.toLowerCase(Locale.ROOT)) {
            case "critical" -> Finding.SEV_CRITICAL;
            case "high" -> Finding.SEV_HIGH;
            case "medium" -> Finding.SEV_MEDIUM;
            case "low" -> Finding.SEV_LOW;
            default -> Finding.SEV_INFO;
        };
    }

    static String toUrl(String matchedAt, String host) {
        String m = matchedAt == null ? "" : matchedAt.trim();
        if (m.startsWith("http://") || m.startsWith("https://")) return m;
        String h = (m.isEmpty() ? host : m);
        return h.contains("://") ? h : "http://" + h;
    }

    static String hostOf(String url, String fallback) {
        try {
            String h = new URI(url).getHost();
            if (h != null) return h;
        } catch (Exception ignored) { }
        return fallback == null || fallback.isBlank() ? "unknown" : fallback.replaceAll("^[a-z]+://", "").replaceAll("[:/].*$", "");
    }

    /** Nuclei writes messages with \n; HTTP messages need CRLF so the viewers and curl export parse them. */
    static byte[] bytes(String s) {
        if (s == null || s.isEmpty()) return new byte[0];
        return s.replace("\r\n", "\n").replace("\n", "\r\n").getBytes(StandardCharsets.ISO_8859_1);
    }

    static int statusOf(byte[] resp) {
        if (resp == null || resp.length < 12) return 0;
        try {
            String[] p = new String(resp, 0, Math.min(20, resp.length), StandardCharsets.ISO_8859_1).split(" ", 3);
            return p.length > 1 ? Integer.parseInt(p[1].trim()) : 0;
        } catch (Exception e) { return 0; }
    }

    static List<String> strings(Object o) {
        List<String> out = new ArrayList<>();
        if (o instanceof JSONArray a) { for (int i = 0; i < a.length(); i++) { Object v = a.get(i); if (v != null) out.add(v.toString()); } }
        else if (o != null && o != JSONObject.NULL && !o.toString().isEmpty()) {
            for (String s : o.toString().split(",")) if (!s.isBlank()) out.add(s.trim());
        }
        return out;
    }
}
