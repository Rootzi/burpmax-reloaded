package com.burpmax.evidence;

import java.util.List;

/**
 * Why a finding was flagged, in terms an analyst can verify by eye.
 *
 * @param responseMatches exact substrings of the response that triggered the detection
 * @param requestMatches  exact substrings of the request (usually the injected payload)
 * @param logic           one or two plain-English sentences describing the detection logic
 */
public record Evidence(List<String> responseMatches, List<String> requestMatches, String logic) {

    public static final Evidence EMPTY = new Evidence(List.of(), List.of(), "");

    public Evidence {
        responseMatches = responseMatches == null ? List.of() : List.copyOf(responseMatches);
        requestMatches  = requestMatches  == null ? List.of() : List.copyOf(requestMatches);
        logic           = logic == null ? "" : logic;
    }

    public boolean hasMatches() { return !responseMatches.isEmpty() || !requestMatches.isEmpty(); }

    public String[] responseArray() { return responseMatches.toArray(new String[0]); }
    public String[] requestArray()  { return requestMatches.toArray(new String[0]); }
}
