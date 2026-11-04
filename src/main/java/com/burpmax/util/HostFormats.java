package com.burpmax.util;

import com.burpmax.model.Finding;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Turns the affected endpoints of one or more findings into clipboard-ready host lists.
 *
 * Formats:
 *   URLS       https://youtube.com / https://goooogle.com:8080 / http://goooogle.com:3200
 *              (default ports omitted; one line per distinct scheme+host+port)
 *   HOSTNAMES  youtube.com / goooogle.com          (deduplicated across ports and schemes)
 *   HOST_PORTS youtube.com:443 / goooogle.com:8080 (handy for scanners)
 *   IPS        resolved IPv4 addresses, falling back to IPv6 only when a host has no IPv4
 *
 * Targets that are already IP addresses (hostname-less apps) are never dropped: they appear
 * in every format exactly as they are.
 */
public final class HostFormats {

    private HostFormats() { }

    public enum Format { URLS, HOSTNAMES, HOST_PORTS, IPS }

    /** One distinct scheme+host+port. */
    public record Target(String scheme, String host, int port) {
        public boolean isIpLiteral() { return HostFormats.isIpLiteral(host); }
    }

    /** Result of IP resolution. */
    public record IpResult(List<String> ips, List<String> unresolved) { }

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    // ── Collect ───────────────────────────────────────────────────────────────

    /** Distinct targets in first-seen order across every affected endpoint of every finding. */
    public static List<Target> targets(Collection<Finding> findings) {
        LinkedHashMap<String, Target> out = new LinkedHashMap<>();
        for (Finding f : findings) {
            addUrl(out, f.url);
            for (Finding.EndpointEntry e : f.affectedEndpoints) addUrl(out, e.endpoint);
        }
        return new ArrayList<>(out.values());
    }

    private static void addUrl(Map<String, Target> out, String url) {
        Target t = parse(url);
        if (t == null) return;
        out.putIfAbsent(t.scheme() + "://" + t.host().toLowerCase(Locale.ROOT) + ":" + t.port(), t);
    }

    static Target parse(String url) {
        if (url == null || url.isBlank()) return null;
        try {
            URI u = new URI(url.trim());
            String host = u.getHost();
            if (host == null) throw new IllegalArgumentException();
            String scheme = u.getScheme() == null ? "http" : u.getScheme().toLowerCase(Locale.ROOT);
            int port = u.getPort() > 0 ? u.getPort() : ("https".equals(scheme) ? 443 : 80);
            if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
            return new Target(scheme, host, port);
        } catch (Exception e) {
            // Fallback for odd URLs URI refuses (e.g. unescaped characters): scheme://host[:port]/...
            java.util.regex.Matcher m = Pattern.compile("^(?i)(https?)://(\\[[^\\]]+\\]|[^/:?#]+)(?::(\\d+))?").matcher(url.trim());
            if (!m.find()) return null;
            String scheme = m.group(1).toLowerCase(Locale.ROOT);
            String host = m.group(2);
            if (host.startsWith("[")) host = host.substring(1, host.length() - 1);
            int port = m.group(3) != null ? Integer.parseInt(m.group(3)) : ("https".equals(scheme) ? 443 : 80);
            return new Target(scheme, host, port);
        }
    }

    // ── Render (no network) ───────────────────────────────────────────────────

    public static String render(Collection<Finding> findings, Format format) {
        List<Target> ts = targets(findings);
        return switch (format) {
            case URLS       -> urls(ts);
            case HOSTNAMES  -> hostnames(ts);
            case HOST_PORTS -> hostPorts(ts);
            case IPS        -> throw new IllegalArgumentException("IPS needs resolve(); use renderIps()");
        };
    }

    public static String urls(List<Target> ts) {
        LinkedHashSet<String> lines = new LinkedHashSet<>();
        for (Target t : ts) {
            boolean def = ("https".equals(t.scheme()) && t.port() == 443)
                       || ("http".equals(t.scheme())  && t.port() == 80);
            lines.add(t.scheme() + "://" + bracket(t.host()) + (def ? "" : ":" + t.port()));
        }
        return String.join("\n", lines);
    }

    public static String hostnames(List<Target> ts) {
        LinkedHashMap<String, String> seen = new LinkedHashMap<>();
        for (Target t : ts) seen.putIfAbsent(t.host().toLowerCase(Locale.ROOT), t.host());
        return String.join("\n", seen.values());
    }

    public static String hostPorts(List<Target> ts) {
        LinkedHashSet<String> lines = new LinkedHashSet<>();
        for (Target t : ts) lines.add(bracket(t.host()) + ":" + t.port());
        return String.join("\n", lines);
    }

    // ── IP resolution (does DNS lookups - call off the UI thread) ─────────────

    /**
     * IPv4 preferred. A host only yields an IPv6 address when it has no IPv4 at all.
     * IP-literal targets pass through unchanged. Hosts that cannot be resolved are reported
     * separately rather than being silently dropped.
     */
    public static IpResult resolve(List<Target> ts) {
        LinkedHashSet<String> ips = new LinkedHashSet<>();
        LinkedHashSet<String> bad = new LinkedHashSet<>();
        Set<String> doneHosts = new HashSet<>();
        for (Target t : ts) {
            String h = t.host();
            if (!doneHosts.add(h.toLowerCase(Locale.ROOT))) continue;
            if (isIpLiteral(h)) { ips.add(stripScope(h)); continue; }
            try {
                InetAddress[] all = InetAddress.getAllByName(h);
                String v4 = null, v6 = null;
                for (InetAddress a : all) {
                    if (a instanceof Inet4Address && v4 == null) v4 = a.getHostAddress();
                    else if (a instanceof Inet6Address && v6 == null) v6 = stripScope(a.getHostAddress());
                }
                if (v4 != null) ips.add(v4);
                else if (v6 != null) ips.add(v6);
                else bad.add(h);
            } catch (Exception e) {
                bad.add(h);
            }
        }
        return new IpResult(new ArrayList<>(ips), new ArrayList<>(bad));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    public static boolean isIpLiteral(String host) {
        if (host == null) return false;
        if (IPV4.matcher(host).matches()) return true;
        return host.indexOf(':') >= 0 && host.matches("^[0-9a-fA-F:.%\\w]+$");
    }

    private static String bracket(String host) {
        return host.indexOf(':') >= 0 && !host.startsWith("[") ? "[" + host + "]" : host;
    }

    private static String stripScope(String ip) {
        int p = ip.indexOf('%');
        return p >= 0 ? ip.substring(0, p) : ip;
    }
}
