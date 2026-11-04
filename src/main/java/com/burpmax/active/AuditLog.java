package com.burpmax.active;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Compact record of every request the active scan sent (or refused to send), so an engagement
 * can show exactly what touched the client's system. Only the request line is kept, never bodies
 * or headers, so it stays small: roughly 100 bytes per entry, capped at {@value #CAP} entries
 * (oldest dropped first, and counted).
 */
public final class AuditLog {

    private static final int CAP = 50_000;

    private record Entry(long t, String method, String hostPort, String target, int status, int ms, String outcome) { }

    private final ArrayDeque<Entry> entries = new ArrayDeque<>();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong sent = new AtomicLong();
    private final AtomicLong refused = new AtomicLong();

    public void clear() {
        synchronized (entries) { entries.clear(); }
        dropped.set(0); sent.set(0); refused.set(0);
    }

    /** A request went out (status &lt; 0: no response). */
    public void sent(String host, int port, byte[] request, int status, long ms) {
        sent.incrementAndGet();
        add(host, port, request, status, (int) Math.min(ms, Integer.MAX_VALUE), status < 0 ? "no-response" : "sent", "");
    }

    /** A request was stopped by the safety rules. */
    public void refused(String host, int port, byte[] request, String reason) {
        refused.incrementAndGet();
        add(host, port, request, 0, 0, "BLOCKED", reason);
    }

    private void add(String host, int port, byte[] req, int status, int ms, String outcome, String note) {
        String method = "?", target = "";
        if (req != null) {
            int end = 0;
            while (end < req.length && end < 400 && req[end] != '\r' && req[end] != '\n') end++;
            String line = new String(req, 0, end, StandardCharsets.ISO_8859_1);
            int a = line.indexOf(' '), b = line.lastIndexOf(" HTTP/");
            if (a > 0) {
                method = line.substring(0, a).intern();
                target = line.substring(a + 1, b > a ? b : line.length());
            }
        }
        if (target.length() > 300) target = target.substring(0, 300) + "…";
        Entry e = new Entry(System.currentTimeMillis(), method, host + ":" + port, target, status, ms, outcome + (note.isEmpty() ? "" : ": " + note));
        synchronized (entries) {
            entries.addLast(e);
            if (entries.size() > CAP) { entries.removeFirst(); dropped.incrementAndGet(); }
        }
    }

    public long sentCount()    { return sent.get(); }
    public long refusedCount() { return refused.get(); }
    public long droppedCount() { return dropped.get(); }
    public int  size()         { synchronized (entries) { return entries.size(); } }

    /** One-line summary for the UI. */
    public String summary() {
        return sent.get() + " requests sent, " + refused.get() + " blocked by safety rules"
                + (dropped.get() > 0 ? ", oldest " + dropped.get() + " entries trimmed" : "");
    }

    public void exportCsv(String path) throws IOException {
        if (!path.toLowerCase().endsWith(".csv")) path += ".csv";
        java.io.File f = new java.io.File(path).getCanonicalFile();
        List<Entry> snap;
        synchronized (entries) { snap = new ArrayList<>(entries); }
        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(new java.io.FileOutputStream(f), StandardCharsets.UTF_8))) {
            w.print("﻿");
            w.println("Time (UTC),Method,Host:Port,Target,HTTP Status,Duration (ms),Outcome");
            java.time.format.DateTimeFormatter fmt = java.time.format.DateTimeFormatter.ISO_INSTANT;
            for (Entry e : snap) {
                w.println(String.join(",",
                        fmt.format(java.time.Instant.ofEpochMilli(e.t())), e.method(), csv(e.hostPort()), csv(e.target()),
                        e.status() > 0 ? String.valueOf(e.status()) : "", String.valueOf(e.ms()), csv(e.outcome())));
            }
        }
    }

    private static String csv(String s) {
        String c = s.replace("\"", "\"\"");
        if (!c.isEmpty() && "=+-@\t".indexOf(c.charAt(0)) >= 0) c = "'" + c;
        return "\"" + c + "\"";
    }
}
