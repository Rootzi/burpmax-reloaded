package com.burpmax.nuclei;

import java.util.*;

/**
 * Goal-based template groups. A group is a purpose ("find known CVEs", "look for exposed files"),
 * mapped to Nuclei template tags. Templates carrying any tag in {@link #ALWAYS_EXCLUDED_TAGS} are
 * never run, whatever the group.
 */
public final class NucleiGroups {

    private NucleiGroups() { }

    public enum Group {
        TECH("Technology detection", "What is running (frameworks, servers, versions). Read-only.",
                Set.of("tech", "detect", "favicon"), 0),
        EXPOSURE("Exposed files & configs", "Backups, config files, logs, debug pages, listings, VCS folders.",
                Set.of("exposure", "exposures", "config", "backup", "logs", "disclosure", "listing", "git", "debug"), 0),
        MISCONFIG("Misconfigurations", "CORS, headers, unsafe defaults, open status pages.",
                Set.of("misconfig", "misconfiguration", "cors", "security-headers"), 0),
        PANELS("Admin panels & login pages", "Finds panels and consoles that shouldn't be public.",
                Set.of("panel", "admin"), 0),
        CVE("Known CVEs (medium and above)", "Version/behaviour checks for published vulnerabilities. Largest group.",
                Set.of("cve"), 2),
        REFLECTED("Reflected issues (GET only)", "Open redirects, simple XSS/LFI/SSRF reflections via fixed GET requests.",
                Set.of("xss", "redirect", "lfi", "ssrf"), 1),
        TAKEOVER("Subdomain takeover", "Dangling hostnames pointing at unclaimed services.",
                Set.of("takeover"), 0);

        public final String label, blurb;
        public final Set<String> tags;
        /** 0 = info and up, 1 = low, 2 = medium, 3 = high, 4 = critical. */
        public final int minSeverity;

        Group(String label, String blurb, Set<String> tags, int minSeverity) {
            this.label = label; this.blurb = blurb; this.tags = tags; this.minSeverity = minSeverity;
        }
    }

    /** Never run: can lock accounts, load the target, or talk to third parties. */
    public static final Set<String> ALWAYS_EXCLUDED_TAGS = Set.of(
            "intrusive", "dos", "fuzz", "fuzzing", "bruteforce", "brute-force", "default-login",
            "kev-exploit", "sqli-time", "race", "unauth-write");

    /** Excluded unless out-of-band (interactsh) is switched on, because it calls a third-party server. */
    public static final String OOB_TAG = "oast";

    public static int severityRank(String s) {
        if (s == null) return 0;
        return switch (s.toLowerCase(Locale.ROOT)) {
            case "low" -> 1; case "medium" -> 2; case "high" -> 3; case "critical" -> 4; default -> 0;
        };
    }

    /** Which groups each built-in scan profile turns on (profile names come from ProbeCatalog). */
    public static Set<Group> forProfile(String profile) {
        if (profile == null) return EnumSet.noneOf(Group.class);
        return switch (profile) {
            case "Client-safe (recommended)" -> EnumSet.of(Group.TECH, Group.EXPOSURE, Group.MISCONFIG);
            case "Standard"                  -> EnumSet.of(Group.TECH, Group.EXPOSURE, Group.MISCONFIG, Group.PANELS, Group.CVE);
            case "Recon only (read-only)"    -> EnumSet.of(Group.TECH, Group.EXPOSURE, Group.PANELS);
            case "Full (lab / CTF)"          -> EnumSet.allOf(Group.class);
            default                          -> EnumSet.noneOf(Group.class);
        };
    }

    /** Compact text form for saving inside a profile: "1|TECH,CVE". */
    public static String encode(boolean enabled, Set<Group> groups) {
        StringBuilder sb = new StringBuilder(enabled ? "1|" : "0|");
        boolean first = true;
        for (Group g : groups) { if (!first) sb.append(','); sb.append(g.name()); first = false; }
        return sb.toString();
    }

    public static Set<Group> decodeGroups(String s) {
        Set<Group> out = EnumSet.noneOf(Group.class);
        if (s == null) return out;
        int bar = s.indexOf('|');
        for (String n : (bar >= 0 ? s.substring(bar + 1) : s).split(",")) {
            try { if (!n.isBlank()) out.add(Group.valueOf(n.trim())); } catch (IllegalArgumentException ignored) { }
        }
        return out;
    }

    public static boolean decodeEnabled(String s) { return s != null && s.startsWith("1"); }
}
