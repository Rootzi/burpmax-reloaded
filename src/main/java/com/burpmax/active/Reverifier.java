package com.burpmax.active;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import com.burpmax.evidence.Evidence;
import com.burpmax.model.Finding;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Replays the request that proved a finding and checks the same proof again.
 * One request is sent, and it still passes through {@link RiskGuard}, so a re-verify can never send
 * anything the scanner itself would have refused.
 */
public final class Reverifier {

    public enum Verdict { STILL_PRESENT, NOT_REPRODUCED, INCONCLUSIVE }

    public record Result(Verdict verdict, String summary, long elapsedMs, int status,
                         byte[] request, byte[] response, List<String> found, List<String> missing) { }

    private Reverifier() { }

    public static Result run(IBurpExtenderCallbacks cb, IHttpService svc, byte[] request, Finding f) {
        if (request == null || svc == null) {
            return new Result(Verdict.INCONCLUSIVE, "No stored request to replay for this finding.",
                    0, -1, request, null, List.of(), List.of());
        }
        RiskGuard.Verdict g = new RiskGuard().check(svc.getHost(), svc.getPort(), request);
        if (!g.allowed()) {
            return new Result(Verdict.INCONCLUSIVE, "Not sent: blocked by safety rules (" + g.reason() + ").",
                    0, -1, request, null, List.of(), List.of());
        }
        long t0 = System.nanoTime();
        byte[] resp;
        try {
            IHttpRequestResponse rr = cb.makeHttpRequest(svc, request);
            resp = rr == null ? null : rr.getResponse();
        } catch (Exception e) {
            return new Result(Verdict.INCONCLUSIVE, "Request failed: " + e.getMessage(),
                    0, -1, request, null, List.of(), List.of());
        }
        long ms = (System.nanoTime() - t0) / 1_000_000L;
        if (resp == null || resp.length == 0) {
            return new Result(Verdict.NOT_REPRODUCED, "No response received (" + ms + " ms) — target down, filtered, or the request timed out.",
                    ms, -1, request, resp, List.of(), List.of());
        }
        String text = new String(resp, StandardCharsets.ISO_8859_1);
        int status = statusOf(text);

        Evidence ev = f.primaryEvidence();
        List<String> found = new ArrayList<>(), missing = new ArrayList<>();
        for (String m : ev.responseMatches()) (text.contains(m) ? found : missing).add(m);

        String logic = ev.logic() == null ? "" : ev.logic().toLowerCase();
        if (!ev.responseMatches().isEmpty()) {
            if (!found.isEmpty()) {
                return new Result(Verdict.STILL_PRESENT, "The proof text is still in the response (" + found.size()
                        + " of " + ev.responseMatches().size() + " matches, HTTP " + status + ", " + ms + " ms).",
                        ms, status, request, resp, found, missing);
            }
            return new Result(Verdict.NOT_REPRODUCED, "The proof text did not appear (HTTP " + status + ", " + ms
                    + " ms). It may be fixed, or the behaviour depends on state/session.",
                    ms, status, request, resp, found, missing);
        }
        String why = logic.contains("out-of-band") || logic.contains("callback") || logic.contains("oob")
                ? "This finding was proven by an out-of-band callback, which a replay can't judge here. Check your collaborator/interactsh log."
                : logic.contains("time") || logic.contains("delay") || logic.contains("sleep")
                ? "This finding is time-based. The replay took " + ms + " ms — compare it with a normal request to the same endpoint."
                : "This finding was proven by a difference between responses, not a single string. Replay returned HTTP "
                  + status + " (" + resp.length + " bytes) — compare with the stored response.";
        return new Result(Verdict.INCONCLUSIVE, why, ms, status, request, resp, found, missing);
    }

    private static int statusOf(String text) {
        int sp = text.indexOf(' ');
        if (sp < 0 || sp + 4 > text.length()) return -1;
        try { return Integer.parseInt(text.substring(sp + 1, sp + 4)); } catch (NumberFormatException e) { return -1; }
    }
}
