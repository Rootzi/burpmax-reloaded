package com.burpmax.util;

import java.nio.charset.StandardCharsets;

/** Turns a raw HTTP request into an equivalent, copy-pasteable curl command. */
public final class CurlBuilder {

    private CurlBuilder() { }

    /**
     * @param raw       full raw request bytes
     * @param host      target host
     * @param port      target port
     * @param https     true for https
     */
    public static String build(byte[] raw, String host, int port, boolean https) {
        if (raw == null) return "";
        String msg = new String(raw, StandardCharsets.ISO_8859_1).replace("\r\n", "\n");
        int hdrEnd = msg.indexOf("\n\n");
        String head = hdrEnd >= 0 ? msg.substring(0, hdrEnd) : msg;
        String body = hdrEnd >= 0 ? msg.substring(hdrEnd + 2) : "";

        String[] lines = head.split("\n");
        String[] rl = lines[0].split(" ");
        String method = rl.length > 0 ? rl[0] : "GET";
        String target = rl.length > 1 ? rl[1] : "/";

        boolean defaultPort = (https && port == 443) || (!https && port == 80);
        String hostHdr = host;
        for (int i = 1; i < lines.length; i++) {
            if (lines[i].toLowerCase().startsWith("host:")) { hostHdr = lines[i].substring(5).trim(); break; }
        }
        String base = (https ? "https://" : "http://") + host + (defaultPort ? "" : ":" + port);
        String url = target.startsWith("http") ? target : base + target;

        StringBuilder sb = new StringBuilder("curl -i -s -k");
        sb.append(" -X ").append(method);
        sb.append(" ").append(q(url));
        for (int i = 1; i < lines.length; i++) {
            String h = lines[i];
            int c = h.indexOf(':');
            if (c <= 0) continue;
            String name = h.substring(0, c).trim();
            String lname = name.toLowerCase();
            // curl sets these itself / they would be wrong when re-sent.
            if (lname.equals("content-length") || lname.equals("connection")) continue;
            if (lname.equals("host") && hostHdr.equalsIgnoreCase(host + (defaultPort ? "" : ":" + port))) continue;
            sb.append(" -H ").append(q(h.trim()));
        }
        if (!body.isEmpty()) {
            sb.append(" --data-binary ").append(q(body));
        }
        return sb.toString();
    }

    /** POSIX single-quote escaping. */
    private static String q(String s) {
        return "'" + s.replace("'", "'\\''") + "'";
    }
}
