package com.burpmax.export;

import com.burpmax.model.Finding;

import java.io.*;
import java.util.*;

public class CsvExporter {

    private static final Map<String, Integer> SEV_ORDER = Map.of(
            "Critical", 0, "High", 1, "Medium", 2, "Low", 3, "Informational", 4);

    public static void export(List<Finding> findings, String filepath) throws Exception {
        // Enforce .csv extension and canonicalize path — canonicalization resolves
        // any ".." components, preventing directory traversal via crafted save paths.
        if (!filepath.toLowerCase().endsWith(".csv")) filepath += ".csv";
        java.io.File outFile = new java.io.File(filepath).getCanonicalFile();
        if (outFile.getAbsolutePath().contains(".."))
            throw new SecurityException("Invalid export path: " + filepath);

        // Sort by severity
        List<Finding> sorted = new ArrayList<>(findings);
        sorted.sort((a, b) -> Integer.compare(
                SEV_ORDER.getOrDefault(a.effectiveSeverity(), 99),
                SEV_ORDER.getOrDefault(b.effectiveSeverity(), 99)));

        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(outFile), "UTF-8"))) {
            w.print("\uFEFF");
            // New columns are APPENDED so existing import mappings keep working.
            w.println("No,Severity,Name,Host,Endpoint,HTTP Status,CWE,Evidence,Description,Remediation,Timestamp,"
                    + "Detection Logic,Matched Text,Request Snippet,Response Snippet,Reproduce (curl)");
            int i = 1;
            for (Finding f : sorted) {
                String ep = f.affectedEndpoints.isEmpty() ? f.url
                        : f.affectedEndpoints.get(0).endpoint;
                int sc = f.affectedEndpoints.isEmpty() ? f.statusCode
                        : f.affectedEndpoints.get(0).statusCode;

                com.burpmax.evidence.Evidence ev = f.primaryEvidence();
                boolean probe = f.primaryProbeRequest() != null || f.primaryProbeResponse() != null;
                byte[] rq = probe ? f.primaryProbeRequest()  : f.primaryRawRequest();
                byte[] rs = probe ? f.primaryProbeResponse() : f.primaryRawResponse();
                java.util.List<String> matched = new java.util.ArrayList<>(ev.responseMatches());
                matched.addAll(ev.requestMatches());

                w.printf("%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s%n",
                        i++,
                        csv(f.effectiveSeverity()),
                        csv(f.name),
                        csv(f.host),
                        csv(ep),
                        sc > 0 ? sc : "",
                        csv(f.cwe),
                        csv(f.evidence),
                        csv(f.description),
                        csv(f.remediation),
                        csv(f.timestamp),
                        csv(ev.logic()),
                        csv(String.join(" | ", matched)),
                        csvMulti(rq == null ? "" : com.burpmax.evidence.Snippet.toPlain(
                                com.burpmax.evidence.Snippet.request(rq, ev.requestMatches()), ">>", "<<")),
                        csvMulti(rs == null ? "" : com.burpmax.evidence.Snippet.toPlain(
                                com.burpmax.evidence.Snippet.response(rs, ev.responseMatches()), ">>", "<<")),
                        csv(curlFor(f, rq)));
            }
        }
    }

    /** Reproduce command built from the stored request; empty when there is none. */
    private static String curlFor(Finding f, byte[] req) {
        if (req == null) return "";
        try {
            java.net.URL u = new java.net.URL(f.url);
            boolean https = u.getProtocol().equalsIgnoreCase("https");
            int port = u.getPort() > 0 ? u.getPort() : u.getDefaultPort();
            return com.burpmax.util.CurlBuilder.build(req, u.getHost(), port, https);
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Like csv() but keeps line breaks, so a request/response snippet stays readable inside one
     * (quoted) cell. Quoting means embedded newlines cannot start a new row; the formula-injection
     * guard still applies to the first character.
     */
    private static String csvMulti(String s) {
        if (s == null) return "\"\"";
        String clean = s.replace("\r\n", "\n").replace("\r", "\n");
        if (!clean.isEmpty() && "=+-@|\t".indexOf(clean.charAt(0)) >= 0) clean = "'" + clean;
        return "\"" + clean.replace("\"", "\"\"") + "\"";
    }

    private static String csv(String s) {
        if (s == null) return "\"\"";
        // Sanitize CRLF to prevent row injection
        String clean = s.replace("\r\n", " ").replace("\n", " ").replace("\r", "");
        // Prevent CSV formula injection (Excel/LibreOffice execute cells starting with =, +, -, @, |, \t)
        if (!clean.isEmpty() && "=+-@|\t".indexOf(clean.charAt(0)) >= 0) {
            clean = "'" + clean;
        }
        return "\"" + clean.replace("\"", "\"\"") + "\"";
    }
}
