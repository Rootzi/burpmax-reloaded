package com.burpmax.evidence;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds trimmed, highlighted views of a raw HTTP message.
 *
 * Rules (so a reader can re-verify without opening Repeater):
 *   - the start line (request line / status line) is ALWAYS included;
 *   - headers are included only when they matter (Host, Content-Type, Location,
 *     CORS headers, or any header line containing a match);
 *   - body text is cut to a window around each match, with explicit omission markers;
 *   - nothing is silently dropped: every cut is marked.
 */
public final class Snippet {

    /** A run of text; hit==true means it is the substring that triggered the finding. */
    public record Segment(String text, boolean hit) { }

    private static final int  DEFAULT_CTX    = 140;
    private static final int  MAX_WINDOWS    = 3;
    private static final int  NO_MATCH_BODY  = 220;

    private Snippet() { }

    // ── Public API ────────────────────────────────────────────────────────────

    public static List<Segment> request(byte[] raw, List<String> hits) {
        return build(raw, hits, true, DEFAULT_CTX);
    }

    public static List<Segment> response(byte[] raw, List<String> hits) {
        return build(raw, hits, false, DEFAULT_CTX);
    }

    /** Plain text with hits wrapped in the given markers (e.g. ">>" and "<<"). */
    public static String toPlain(List<Segment> segs, String open, String close) {
        StringBuilder sb = new StringBuilder();
        for (Segment s : segs) {
            if (s.hit()) sb.append(open).append(s.text()).append(close);
            else sb.append(s.text());
        }
        return sb.toString();
    }

    public static String toPlain(List<Segment> segs) { return toPlain(segs, "", ""); }

    /** Full message as printable text (binary bytes shown as '.'), for the "full response" view. */
    public static String full(byte[] raw) {
        if (raw == null) return "";
        StringBuilder sb = new StringBuilder(raw.length);
        for (byte b : raw) {
            int c = b & 0xFF;
            if (c == '\r') continue;
            if (c == '\n' || c == '\t' || (c >= 32 && c < 127)) sb.append((char) c);
            else if (c >= 128) sb.append((char) c);   // keep latin-1 / utf-8 bytes readable-ish
            else sb.append('.');
        }
        return sb.toString();
    }

    // ── Implementation ────────────────────────────────────────────────────────

    private static List<Segment> build(byte[] raw, List<String> hits, boolean isRequest, int ctx) {
        List<Segment> out = new ArrayList<>();
        if (raw == null || raw.length == 0) {
            out.add(new Segment("(not captured)", false));
            return out;
        }
        String msg = new String(raw, StandardCharsets.ISO_8859_1).replace("\r\n", "\n");
        int hdrEnd = msg.indexOf("\n\n");
        String head = hdrEnd >= 0 ? msg.substring(0, hdrEnd) : msg;
        String body = hdrEnd >= 0 ? msg.substring(hdrEnd + 2) : "";
        String[] hl = hits == null ? new String[0] : hits.stream()
                .filter(h -> h != null && !h.isEmpty()).toArray(String[]::new);

        String[] headLines = head.split("\n", -1);

        // 1. Start line — always.
        addHighlighted(out, headLines[0], hl);
        out.add(new Segment("\n", false));

        // 2. Relevant header lines.
        boolean droppedHeaders = false;
        for (int i = 1; i < headLines.length; i++) {
            String line = headLines[i];
            if (isInterestingHeader(line, isRequest) || containsAny(line, hl)) {
                addHighlighted(out, line, hl);
                out.add(new Segment("\n", false));
            } else {
                droppedHeaders = true;
            }
        }
        if (droppedHeaders) out.add(new Segment("[… other headers omitted …]\n", false));

        // 3. Body.
        if (!body.isEmpty()) {
            out.add(new Segment("\n", false));
            List<int[]> windows = bodyWindows(body, hl, ctx);
            if (windows.isEmpty()) {
                int end = Math.min(body.length(), NO_MATCH_BODY);
                out.add(new Segment(body.substring(0, end), false));
                if (end < body.length())
                    out.add(new Segment("\n[… " + (body.length() - end) + " more characters omitted …]", false));
            } else {
                int cursor = 0;
                for (int[] w : windows) {
                    if (w[0] > cursor)
                        out.add(new Segment("[… " + (w[0] - cursor) + " characters omitted …]\n", false));
                    addHighlighted(out, body.substring(w[0], w[1]), hl);
                    out.add(new Segment("\n", false));
                    cursor = w[1];
                }
                if (cursor < body.length())
                    out.add(new Segment("[… " + (body.length() - cursor) + " characters omitted …]", false));
            }
        }
        return trimTrailingNewline(out);
    }

    /** Merged [start,end) windows around up to MAX_WINDOWS match locations in the body. */
    private static List<int[]> bodyWindows(String body, String[] hl, int ctx) {
        List<int[]> raw = new ArrayList<>();
        for (String h : hl) {
            int from = 0, found = 0;
            while (found < MAX_WINDOWS && (from = body.indexOf(h, from)) >= 0) {
                int s = Math.max(0, from - ctx);
                int e = Math.min(body.length(), from + h.length() + ctx);
                // snap to line boundaries when a boundary is close, for readability
                int nl = body.lastIndexOf('\n', from);
                if (nl >= s - 40 && nl >= 0 && from - nl <= ctx + 40) s = Math.max(s, nl + 1);
                raw.add(new int[]{s, e});
                from += Math.max(1, h.length());
                found++;
            }
        }
        raw.sort((a, b) -> Integer.compare(a[0], b[0]));
        List<int[]> merged = new ArrayList<>();
        for (int[] w : raw) {
            if (!merged.isEmpty() && w[0] <= merged.get(merged.size() - 1)[1]) {
                merged.get(merged.size() - 1)[1] = Math.max(merged.get(merged.size() - 1)[1], w[1]);
            } else {
                merged.add(w);
            }
            if (merged.size() >= MAX_WINDOWS) break;
        }
        return merged;
    }

    private static boolean isInterestingHeader(String line, boolean isRequest) {
        String l = line.toLowerCase();
        if (isRequest) {
            return l.startsWith("host:") || l.startsWith("content-type:") || l.startsWith("origin:")
                    || l.startsWith("authorization:") || l.startsWith("x-forwarded-host:");
        }
        return l.startsWith("content-type:") || l.startsWith("location:")
                || l.startsWith("access-control-") || l.startsWith("set-cookie:")
                || l.startsWith("www-authenticate:") || l.startsWith("server:")
                || l.startsWith("x-powered-by:");
    }

    private static boolean containsAny(String s, String[] hl) {
        for (String h : hl) if (s.contains(h)) return true;
        return false;
    }

    /** Split text around every occurrence of any hit (leftmost, longest first). */
    private static void addHighlighted(List<Segment> out, String text, String[] hl) {
        int pos = 0;
        while (pos < text.length()) {
            int bestStart = -1, bestLen = 0;
            for (String h : hl) {
                int i = text.indexOf(h, pos);
                if (i >= 0 && (bestStart < 0 || i < bestStart || (i == bestStart && h.length() > bestLen))) {
                    bestStart = i; bestLen = h.length();
                }
            }
            if (bestStart < 0) break;
            if (bestStart > pos) out.add(new Segment(text.substring(pos, bestStart), false));
            out.add(new Segment(text.substring(bestStart, bestStart + bestLen), true));
            pos = bestStart + bestLen;
        }
        if (pos < text.length()) out.add(new Segment(text.substring(pos), false));
    }

    private static List<Segment> trimTrailingNewline(List<Segment> segs) {
        if (!segs.isEmpty()) {
            Segment last = segs.get(segs.size() - 1);
            if (!last.hit() && last.text().endsWith("\n")) {
                segs.set(segs.size() - 1, new Segment(last.text().substring(0, last.text().length() - 1), false));
            }
        }
        return segs;
    }
}
