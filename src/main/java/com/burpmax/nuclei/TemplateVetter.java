package com.burpmax.nuclei;

import com.burpmax.active.RiskGuard;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Decides which Nuclei templates are allowed to run. Everything is judged from the template file
 * itself, before anything is sent:
 *   - HTTP templates only (no DNS, TCP, headless, code, JavaScript, SSL, file or flow templates);
 *   - read-only: no POST/PUT/PATCH/DELETE (declared or inside raw requests);
 *   - no brute-force style payload attacks;
 *   - none of the destructive payloads that BurpMax's own scanner refuses (same RiskGuard rules);
 *   - none of the always-excluded tags, and "oast" templates only when out-of-band is on.
 */
public final class TemplateVetter {

    private TemplateVetter() { }

    /** One template that passed. */
    public record Template(String id, String name, String severity, Set<String> tags, Path path) { }

    private static final int MAX_BYTES = 256 * 1024;
    private static final Pattern ID = Pattern.compile("(?m)^id:\\s*[\"']?([^\\s\"']+)");
    private static final Pattern NAME = Pattern.compile("(?m)^\\s{2}name:\\s*[\"']?(.+?)[\"']?\\s*$");
    private static final Pattern SEV = Pattern.compile("(?m)^\\s{2}severity:\\s*(\\w+)");
    private static final Pattern TAGS = Pattern.compile("(?m)^\\s{2}tags:\\s*(.+)$");
    private static final Pattern OTHER_PROTOCOL = Pattern.compile(
            "(?m)^(dns|tcp|network|file|headless|code|ssl|javascript|whois|websocket|flow|workflows):");
    private static final Pattern HAS_HTTP = Pattern.compile("(?m)^(http|requests):");
    private static final Pattern WRITE_METHOD = Pattern.compile(
            "(?mi)(^\\s*-?\\s*method:\\s*[\"']?(POST|PUT|PATCH|DELETE|TRACE|CONNECT)\\b)|(^\\s+(POST|PUT|PATCH|DELETE) \\S+ HTTP/)");
    private static final Pattern BRUTE = Pattern.compile("(?m)^\\s*attack:\\s*(clusterbomb|pitchfork|batteringram)");

    public record Verdict(boolean ok, String reason, Template template) { }

    /** Vet one template's text. {@code path} may be null in tests. */
    public static Verdict vet(String text, Path path, boolean allowOob) {
        if (text == null || text.length() > MAX_BYTES) return no("too large");
        Matcher id = ID.matcher(text);
        if (!id.find()) return no("no id");
        if (OTHER_PROTOCOL.matcher(text).find()) return no("not a plain HTTP template");
        if (!HAS_HTTP.matcher(text).find()) return no("no http section");
        if (WRITE_METHOD.matcher(text).find()) return no("sends write requests");
        if (BRUTE.matcher(text).find()) return no("brute-force payload attack");

        Set<String> tags = new LinkedHashSet<>();
        Matcher t = TAGS.matcher(text);
        if (t.find()) for (String x : t.group(1).split(",")) { String v = x.trim().toLowerCase(Locale.ROOT); if (!v.isEmpty()) tags.add(v); }
        for (String x : tags) if (NucleiGroups.ALWAYS_EXCLUDED_TAGS.contains(x)) return no("tag '" + x + "'");
        if (!allowOob && (tags.contains(NucleiGroups.OOB_TAG) || text.contains("interactsh"))) return no("needs out-of-band server");

        // Same destructive-payload rules the built-in scanner enforces.
        byte[] probe = ("GET / HTTP/1.1\r\nHost: x\r\n\r\n" + text).getBytes(StandardCharsets.ISO_8859_1);
        RiskGuard.Verdict g = new RiskGuard().check("x", 80, probe);
        if (!g.allowed()) return no("destructive content (" + g.reason() + ")");

        Matcher n = NAME.matcher(text), s = SEV.matcher(text);
        return new Verdict(true, "", new Template(id.group(1), n.find() ? n.group(1) : id.group(1),
                s.find() ? s.group(1).toLowerCase(Locale.ROOT) : "info", tags, path));
    }

    private static Verdict no(String why) { return new Verdict(false, why, null); }

    /** Result of walking a templates folder. */
    public record Scan(List<Template> allowed, int rejected, Map<String, Integer> rejectReasons) { }

    /** Vet every .yaml/.yml file under a folder. Skips dot-folders and helper folders. */
    public static Scan scan(Path root, boolean allowOob) throws IOException {
        List<Template> ok = new ArrayList<>();
        Map<String, Integer> why = new TreeMap<>();
        int[] rej = {0};
        try (Stream<Path> walk = Files.walk(root)) {
            walk.filter(p -> {
                String n = p.getFileName().toString().toLowerCase(Locale.ROOT);
                if (!(n.endsWith(".yaml") || n.endsWith(".yml"))) return false;
                String rel = root.relativize(p).toString();
                return !rel.startsWith(".") && !rel.contains("/.") && !rel.startsWith("helpers") && !rel.contains("/helpers/");
            }).forEach(p -> {
                try {
                    if (Files.size(p) > MAX_BYTES) { rej[0]++; why.merge("too large", 1, Integer::sum); return; }
                    Verdict v = vet(new String(Files.readAllBytes(p), StandardCharsets.UTF_8), p, allowOob);
                    if (v.ok()) ok.add(v.template());
                    else { rej[0]++; why.merge(v.reason().replaceAll("\\(.*", "").trim(), 1, Integer::sum); }
                } catch (IOException e) { rej[0]++; }
            });
        }
        return new Scan(ok, rej[0], why);
    }

    /** Templates that belong to at least one of the chosen groups. */
    public static List<Template> select(List<Template> all, Set<NucleiGroups.Group> groups) {
        List<Template> out = new ArrayList<>();
        for (Template t : all) {
            for (NucleiGroups.Group g : groups) {
                if (NucleiGroups.severityRank(t.severity()) < g.minSeverity) continue;
                boolean hit = false;
                for (String tag : t.tags()) if (g.tags.contains(tag)) { hit = true; break; }
                if (hit) { out.add(t); break; }
            }
        }
        return out;
    }

    /** How many templates each group would run (a template can count toward several groups). */
    public static Map<NucleiGroups.Group, Integer> counts(List<Template> all) {
        Map<NucleiGroups.Group, Integer> m = new EnumMap<>(NucleiGroups.Group.class);
        for (NucleiGroups.Group g : NucleiGroups.Group.values()) m.put(g, select(all, EnumSet.of(g)).size());
        return m;
    }
}
