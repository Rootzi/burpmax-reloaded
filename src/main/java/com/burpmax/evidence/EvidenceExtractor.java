package com.burpmax.evidence;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Works out WHICH substring of a response (and which part of the request) made a detection fire,
 * and writes the plain-English reason. It mirrors the confirmation logic the probes use
 * (error fingerprints, file-content signatures, canary reflection, SSTI arithmetic, header
 * reflection, timing) so the evidence shown to an analyst is what actually tripped the check.
 *
 * When no single substring exists (differential / timing findings) it says so honestly and
 * points at the observable difference (status line, length, elapsed time) instead of inventing one.
 */
public final class EvidenceExtractor {

    private EvidenceExtractor() { }

    private static final int CI = Pattern.CASE_INSENSITIVE;

    /** name -> pattern; the first hit of each is reported. Order = priority. */
    private record Sig(String family, Pattern p) { }

    private static final List<Sig> SIGNATURES = List.of(
        // SQL error fingerprints (same family SqliProbe confirms on)
        new Sig("SQL error message", Pattern.compile("you have an error in your sql syntax[^\\n<]{0,80}", CI)),
        new Sig("SQL error message", Pattern.compile("warning:\\s*mysql[^\\n<]{0,80}", CI)),
        new Sig("SQL error message", Pattern.compile("unclosed quotation mark after the character string[^\\n<]{0,40}", CI)),
        new Sig("SQL error message", Pattern.compile("quoted string not properly terminated", CI)),
        new Sig("SQL error message", Pattern.compile("ORA-\\d{5}[^\\n<]{0,60}", CI)),
        new Sig("SQL error message", Pattern.compile("Microsoft OLE DB Provider for SQL Server[^\\n<]{0,60}", CI)),
        new Sig("SQL error message", Pattern.compile("PSQLException[^\\n<]{0,60}", CI)),
        new Sig("SQL error message", Pattern.compile("SQLiteException[^\\n<]{0,60}", CI)),
        new Sig("SQL error message", Pattern.compile("com\\.mysql\\.jdbc[^\\n<]{0,60}", CI)),
        new Sig("SQL error message", Pattern.compile("org\\.hibernate\\.exception[^\\n<]{0,60}", CI)),
        new Sig("SQL error message", Pattern.compile("SQLSTATE\\[[^\\]]{1,12}\\][^\\n<]{0,60}", CI)),
        new Sig("SQL error message", Pattern.compile("Incorrect syntax near[^\\n<]{0,40}", CI)),
        // File-content signatures (path traversal / XXE / exposed files)
        new Sig("/etc/passwd contents", Pattern.compile("root:[x*!]?:\\d+:\\d+:[^\\n]{0,40}", CI)),
        new Sig("Windows win.ini contents", Pattern.compile("\\[(extensions|fonts|mci extensions)\\]", CI)),
        new Sig("git config contents", Pattern.compile("\\[core\\]\\s*\\n\\s*repositoryformatversion", CI)),
        new Sig("git HEAD contents", Pattern.compile("ref:\\s*refs/heads/[\\w./-]+", CI)),
        new Sig("private key material", Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
        new Sig("credential in config", Pattern.compile("(?:DB_PASSWORD|APP_KEY|SECRET_KEY|aws_secret_access_key|aws_access_key_id)\\s*[=:][^\\n]{0,40}", CI)),
        new Sig("PHP source / phpinfo", Pattern.compile("<\\?php|PHP Version\\s+[\\d.]+", CI)),
        new Sig("directory listing", Pattern.compile("<title>Index of /[^<]{0,60}</title>|Directory listing for [^<\\n]{0,60}", CI)),
        new Sig("GraphQL introspection", Pattern.compile("\"__schema\"\\s*:\\s*\\{", CI)),
        new Sig("stack trace", Pattern.compile("(?:Exception in thread|Traceback \\(most recent call last\\)|at [\\w.$]+\\([\\w.]+:\\d+\\))[^\\n]{0,80}", CI))
    );

    private static final Pattern CANARY = Pattern.compile("[A-Za-z0-9._-]*burpmax[A-Za-z0-9._-]*");
    private static final Pattern MATH   = Pattern.compile("(\\d+)\\s*\\*\\s*(')?(\\d+)(')?");

    // ── Public entry points ───────────────────────────────────────────────────

    /**
     * @param name         finding name (used only to pick sensible heuristics)
     * @param payload      injected payload, or null
     * @param timingMs     observed delay for time-based findings, or &lt;= 0
     * @param probeReq     request that triggered the finding
     * @param probeResp    response that confirmed it (may be null for OOB findings)
     * @param baselineResp the unmodified response for comparison (may be null)
     * @param probeEvidence the probe's own free-text evidence line (used as the explanation fallback)
     */
    public static Evidence compute(String name, String payload, long timingMs,
                                   byte[] probeReq, byte[] probeResp, byte[] baselineResp,
                                   String probeEvidence) {

        String lname = name == null ? "" : name.toLowerCase();
        String req   = probeReq  == null ? "" : new String(probeReq,  StandardCharsets.ISO_8859_1);
        String resp  = probeResp == null ? "" : new String(probeResp, StandardCharsets.ISO_8859_1);
        String base  = baselineResp == null ? "" : new String(baselineResp, StandardCharsets.ISO_8859_1);

        Set<String> respHits = new LinkedHashSet<>();
        List<String> reasons = new ArrayList<>();

        // Classify from the real finding names: "(Time-Based Blind)" and "(Boolean-Based Blind)" are NOT
        // out-of-band; "(OOB DNS)", "(Blind OOB)", "Out-of-Band", Log4Shell and URLDNS are.
        boolean isTime = lname.contains("time-based") || lname.contains("time based");
        boolean isBool = lname.contains("boolean");
        boolean isOob  = !isTime && !isBool
                && (lname.contains("oob") || lname.contains("out-of-band") || lname.contains("log4shell")
                    || lname.contains("log4j") || lname.contains("urldns") || lname.contains("blind"));

        // ── Out-of-band: there is no response substring; the proof is the callback itself ──
        if (isOob) {
            String callback = findCallbackHost(req, payload);
            List<String> reqHits = new ArrayList<>();
            if (callback != null) reqHits.add(callback);
            String why = "Confirmed out of band: the target (or a server it uses) made a DNS/HTTP "
                    + "request to the unique callback host embedded in the payload"
                    + (callback != null ? " (" + callback + ")" : "")
                    + ". A callback to a host only this probe knew about cannot be a coincidence.";
            return new Evidence(List.of(), reqHits, why);
        }

        // ── Time-based: the evidence is the delay, not text ─────────────────────────────────
        if (isTime || (timingMs > 0 && (lname.contains("sleep") || lname.contains("delay")))) {
            List<String> reqHits = requestHits(req, payload);
            String why = "Time-based: the injected payload asks the backend to pause."
                    + (timingMs > 0 ? " The response took " + timingMs + " ms" : " The response was delayed")
                    + "; confirmed by repeating the delay and comparing with a normal request. "
                    + "No response text proves this - re-verify by timing the request in Repeater.";
            return new Evidence(List.of(), reqHits, why);
        }

        // ── 1. Signature families ──────────────────────────────────────────────────────────
        String respBody = resp;
        for (Sig s : SIGNATURES) {
            Matcher m = s.p().matcher(respBody);
            if (m.find()) {
                // Ignore if the baseline already contained the same text (not caused by the probe).
                if (!base.isEmpty() && s.p().matcher(base).find()
                        && base.contains(m.group())) continue;
                if (respHits.add(trimHit(m.group()))) {
                    reasons.add("Response contains a " + s.family() + " that the unmodified request does not produce");
                }
                if (respHits.size() >= 3) break;
            }
        }

        // ── 2. Canary / payload reflection ─────────────────────────────────────────────────
        if (respHits.isEmpty()) {
            Matcher cm = CANARY.matcher(resp);
            while (cm.find() && respHits.size() < 3) {
                if (base.contains(cm.group())) continue;
                respHits.add(cm.group());
                reasons.add("The probe's unique canary value came back in the response");
            }
        }
        if (respHits.isEmpty() && payload != null && payload.length() >= 3) {
            String found = findReflection(resp, payload);
            if (found != null && !base.contains(found)) {
                respHits.add(found);
                reasons.add(lname.contains("xss")
                        ? "The injected payload is reflected back unescaped (angle brackets/quotes intact), so a browser would parse it as markup"
                        : "The injected payload is reflected in the response");
            }
        }

        // ── 3. SSTI arithmetic ─────────────────────────────────────────────────────────────
        if (respHits.isEmpty() && payload != null && (lname.contains("ssti") || lname.contains("template"))) {
            Matcher m = MATH.matcher(payload);
            if (m.find()) {
                String result = m.group(2) != null || m.group(4) != null
                        ? m.group(1).repeat(Math.min(20, Integer.parseInt(m.group(3))))
                        : String.valueOf(Long.parseLong(m.group(1)) * Long.parseLong(m.group(3)));
                Matcher rm = Pattern.compile("(?<![\\d])" + Pattern.quote(result) + "(?![\\d])").matcher(resp);
                if (rm.find() && !Pattern.compile("(?<![\\d])" + Pattern.quote(result) + "(?![\\d])").matcher(base).find()) {
                    respHits.add(rm.group());
                    reasons.add("The template expression '" + m.group() + "' was evaluated by the server: the result '"
                            + result + "' appears in the response but not in the unmodified page");
                }
            }
        }

        // ── 4. Header-driven findings ──────────────────────────────────────────────────────
        if (respHits.isEmpty()) {
            for (String hdr : new String[]{"access-control-allow-origin", "access-control-allow-credentials", "location"}) {
                String line = headerLine(resp, hdr);
                if (line != null && headerRelevant(lname, hdr)) {
                    respHits.add(line);
                }
            }
            if (!respHits.isEmpty()) {
                reasons.add(lname.contains("cors")
                        ? "The server echoed the attacker-controlled Origin and allowed credentials"
                        : "The response header carries the attacker-controlled value");
            }
        }

        // ── 5. Differential fallback — say so honestly ─────────────────────────────────────
        String logic;
        if (!respHits.isEmpty()) {
            logic = String.join(". ", new LinkedHashSet<>(reasons)) + ".";
        } else {
            String sl = startLine(resp);
            String bsl = startLine(base);
            if (!sl.isEmpty()) {
                respHits.add(sl);
                logic = "Differential detection: no single response substring triggered this. "
                        + "The probe response was '" + sl + "' (" + bodyLen(resp) + " body bytes)"
                        + (bsl.isEmpty() ? "" : " versus '" + bsl + "' (" + bodyLen(base) + " body bytes) for the original request")
                        + ". Compare the two in Repeater."
                        + (probeEvidence != null && !probeEvidence.isBlank()
                            ? " Probe note: " + probeEvidence : "");
            } else {
                logic = probeEvidence != null && !probeEvidence.isBlank()
                        ? "Detected by probe: " + probeEvidence
                        : "Detected by the probe's own confirmation logic; no response text was captured.";
            }
        }

        return new Evidence(new ArrayList<>(respHits), requestHits(req, payload), logic);
    }

    /**
     * Evidence for a finding that carries only the original traffic (passive findings, loaded sessions).
     * The probe's free-text evidence string is searched for quoted fragments that also occur in the response.
     */
    public static Evidence computePassive(String name, String evidenceText,
                                          byte[] rawReq, byte[] rawResp) {
        String resp = rawResp == null ? "" : new String(rawResp, StandardCharsets.ISO_8859_1);
        Set<String> hits = new LinkedHashSet<>();
        if (evidenceText != null && !resp.isEmpty()) {
            // Quoted or `backticked` tokens, then long-ish words, that really occur in the response.
            Matcher q = Pattern.compile("['\"`]([^'\"`\\n]{3,80})['\"`]").matcher(evidenceText);
            while (q.find() && hits.size() < 3) {
                if (resp.contains(q.group(1))) hits.add(q.group(1));
            }
            Matcher hm = Pattern.compile("(?i)([a-z-]+:\\s*[^\\n|]{2,80})").matcher(evidenceText);
            while (hm.find() && hits.size() < 3) {
                String cand = hm.group(1).trim();
                if (resp.contains(cand)) hits.add(cand);
            }
        }
        String why = evidenceText == null || evidenceText.isBlank()
                ? "Observed in captured traffic; no probe was sent."
                : "Observed in captured traffic (no probe was sent): " + evidenceText;
        if (hits.isEmpty() && evidenceText != null && !resp.isEmpty()) {
            // Prose evidence such as "Magento 2.3 detected in response.": find the product and
            // version where they really appear instead of highlighting the status line.
            String found = findProductVersion(resp, evidenceText);
            if (found != null) hits.add(found);
        }
        return new Evidence(new ArrayList<>(hits), List.of(), why);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static final Set<String> STOP = Set.of("detected", "response", "version", "versions", "header", "found",
            "disclosed", "this", "that", "with", "from", "body", "the", "and", "for", "present", "missing");

    /** Locates "<Product> ... <version>" (or just the product / version) in the response text. */
    private static String findProductVersion(String resp, String evidenceText) {
        Matcher vm = Pattern.compile("\\d+(?:\\.\\d+)+").matcher(evidenceText);
        String ver = vm.find() ? vm.group() : null;
        String word = null;
        Matcher wm = Pattern.compile("[A-Za-z][A-Za-z0-9._+-]{3,}").matcher(evidenceText);
        while (wm.find()) {
            String w = wm.group();
            if (!STOP.contains(w.toLowerCase())) { word = w; break; }
        }
        if (word != null && ver != null) {
            Matcher m = Pattern.compile("(?i)" + Pattern.quote(word) + "[^\\n<>\"']{0,40}?" + Pattern.quote(ver) + "[\\w.-]{0,8}").matcher(resp);
            if (m.find()) return trimHit(m.group());
        }
        if (ver != null) {
            Matcher m = Pattern.compile("[\\w/.-]{0,20}" + Pattern.quote(ver) + "[\\w.-]{0,8}").matcher(resp);
            if (m.find() && m.group().length() > ver.length()) return trimHit(m.group());
        }
        if (word != null) {
            Matcher m = Pattern.compile("(?i)" + Pattern.quote(word)).matcher(resp);
            if (m.find()) return m.group();
        }
        return null;
    }

    private static String trimHit(String s) {
        String t = s.strip();
        return t.length() > 200 ? t.substring(0, 200) : t;
    }

    private static boolean headerRelevant(String lname, String hdr) {
        if (hdr.startsWith("access-control")) return lname.contains("cors");
        if (hdr.equals("location")) return lname.contains("redirect") || lname.contains("host header");
        return false;
    }

    /** Where the payload appears in the request: raw, then URL-encoded forms. */
    private static List<String> requestHits(String req, String payload) {
        if (payload == null || payload.isEmpty() || req.isEmpty()) return List.of();
        if (req.contains(payload)) return List.of(payload);
        String enc = URLEncoder.encode(payload, StandardCharsets.UTF_8);
        if (req.contains(enc)) return List.of(enc);
        String encSpace = enc.replace("+", "%20");
        if (req.contains(encSpace)) return List.of(encSpace);
        // Last resort: a distinctive leading slice of the payload.
        int n = Math.min(payload.length(), 12);
        String head = payload.substring(0, n);
        if (n >= 4 && req.contains(head)) return List.of(head);
        return List.of();
    }

    /** Exact reflected text. Case-insensitive match returns the text as it appears in the response. */
    private static String findReflection(String resp, String payload) {
        int i = resp.indexOf(payload);
        if (i >= 0) return payload;
        Matcher m = Pattern.compile(Pattern.quote(payload), CI).matcher(resp);
        return m.find() ? m.group() : null;
    }

    private static String findCallbackHost(String req, String payload) {
        Matcher m = Pattern.compile("[a-z0-9]{8,}\\.[a-z0-9.-]*(?:oast|interact|burpcollaborator)[a-z0-9.-]*", CI).matcher(req);
        if (m.find()) return m.group();
        if (payload != null) {
            Matcher p = Pattern.compile("[a-z0-9]{8,}\\.[a-z0-9-]+\\.[a-z]{2,}", CI).matcher(payload);
            if (p.find()) return p.group();
        }
        return null;
    }

    private static String headerLine(String resp, String name) {
        int end = resp.indexOf("\r\n\r\n");
        String head = end >= 0 ? resp.substring(0, end) : resp;
        for (String line : head.split("\r?\n")) {
            if (line.toLowerCase().startsWith(name + ":")) return line.trim();
        }
        return null;
    }

    private static String startLine(String msg) {
        if (msg == null || msg.isEmpty()) return "";
        int e = msg.indexOf('\n');
        String l = e >= 0 ? msg.substring(0, e) : msg;
        return l.replace("\r", "").trim();
    }

    private static int bodyLen(String msg) {
        int i = msg.indexOf("\r\n\r\n");
        if (i >= 0) return msg.length() - i - 4;
        int j = msg.indexOf("\n\n");
        return j >= 0 ? msg.length() - j - 2 : 0;
    }
}
