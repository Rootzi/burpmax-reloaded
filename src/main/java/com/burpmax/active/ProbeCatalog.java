package com.burpmax.active;

import java.util.*;

/**
 * Single source of truth for every selectable scan module.
 *
 * Each Module maps one task in ActiveScanner.runProbes() (its "entry" name, which is also
 * what the progress bar shows) to:
 *   - skipKey   : the key stored in the scan policy when the user ticks this module
 *   - family    : the parent key; ticking the family skips every module in it
 *   - risk      : how much it can disturb a production target
 *   - effect    : plain-English description of what it actually sends
 *
 * Semantics are unchanged from earlier versions: a ticked key means SKIPPED.
 * Old saved policies ("SQLi", "XSS", ...) keep working because the family keys
 * are the original names.
 */
public final class ProbeCatalog {

    public enum Risk {
        /** Read-only or single benign request per parameter. */
        LOW,
        /** Many requests, replays your captured request, or can trigger side effects on forms. */
        MODERATE,
        /** Writes data, bursts traffic, or can disrupt shared infrastructure / other users. */
        HIGH
    }

    public record Module(String entry, String skipKey, String family, String category,
                         Risk risk, String effect) {
        public boolean isFamilyHead() { return skipKey.equals(family); }
    }

    private static final List<Module> MODULES = new ArrayList<>();

    private static void add(String entry, String skipKey, String family, String category,
                            Risk risk, String effect) {
        MODULES.add(new Module(entry, skipKey, family, category, risk, effect));
    }
    private static void add(String name, String category, Risk risk, String effect) {
        add(name, name, name, category, risk, effect);
    }

    static {
        String INJ = "Injection", AUTH = "Auth & session", CLIENT = "Client-side",
               INFRA = "Infrastructure", DISC = "Discovery", WRITE = "Writes & load";

        // ── Injection ────────────────────────────────────────────────────────
        add("SQLi-error",  "SQLi-error",  "SQLi", INJ, Risk.LOW,
            "Sends quote characters and reads database error messages. No data-changing SQL.");
        add("SQLi-OOB",    "SQLi-OOB",    "SQLi", INJ, Risk.LOW,
            "Injects a DNS-callback payload; confirms via out-of-band interaction.");
        add("SQLi-time",   "SQLi-time",   "SQLi", INJ, Risk.MODERATE,
            "Time-based: asks the database to sleep ~3s per probe. Many in parallel can tie up connections.");
        add("CmdI-output", "CmdI-output", "CmdI", INJ, Risk.LOW,
            "Appends harmless commands (id / whoami) and looks for their output.");
        add("CmdI-OOB",    "CmdI-OOB",    "CmdI", INJ, Risk.LOW,
            "Runs curl/wget to your callback host only.");
        add("CmdI-time",   "CmdI-time",   "CmdI", INJ, Risk.MODERATE,
            "Time-based: runs sleep on the target. Many in parallel can tie up workers.");
        add("SSTI",        "SSTI-inband", "SSTI", INJ, Risk.LOW,
            "Math expressions ({{7*7}}-style) compared against a baseline.");
        add("SSTI-OOB",    "SSTI-OOB",    "SSTI", INJ, Risk.LOW,
            "Template payloads that only make a DNS callback.");
        add("XXE",         "XXE", "XXE", INJ, Risk.LOW,
            "In-band file read of well-known files + out-of-band entity callback.");
        add("LDAP",        "LDAP", "LDAP", INJ, Risk.LOW,
            "Operator injection and referral callback; read-only queries.");
        add("NoSQLi",      "NoSQLi", "NoSQLi", INJ, Risk.MODERATE,
            "Mongo operators ($ne/$gt/regex). Blocked on update/delete-style requests by the safety guard.");
        add("Path Traversal", "Path Traversal", "Path Traversal", INJ, Risk.LOW,
            "Reads well-known OS files via encoded ../ variants.");
        add("Prototype Pollution", "PP-inband", "Prototype Pollution", INJ, Risk.LOW,
            "Injects __proto__ keys into JSON/params and checks reflection.");
        add("PP-OOB",      "PP-OOB", "Prototype Pollution", INJ, Risk.LOW,
            "Pollution gadget that only makes a DNS callback.");
        add("Java Deserialization", INJ, Risk.LOW,
            "URLDNS gadget chains: DNS lookup only, no code execution.");

        // ── Auth & session ───────────────────────────────────────────────────
        add("JWT",          AUTH, Risk.LOW,
            "Tampers with your JWT (alg=none, confusion, weak secret) and replays the request.");
        add("Auth Bypass",  AUTH, Risk.MODERATE,
            "Replays your request with auth headers stripped. Read methods only unless you lift that restriction.");
        add("IDOR",         AUTH, Risk.MODERATE,
            "Replays your request with neighbouring numeric IDs. Read methods only unless you lift that restriction.");
        add("OAuth/OIDC",   AUTH, Risk.LOW,
            "Mostly passive; a few redirect_uri checks on OAuth endpoints.");
        add("ViewState",    AUTH, Risk.LOW,
            "Checks ASP.NET ViewState MAC/encryption; callback-only confirmation.");
        add("CSRF",         AUTH, Risk.MODERATE,
            "Replays your POST/PUT/DELETE without cookies. If the endpoint is public, the action executes.");

        // ── Client-side ──────────────────────────────────────────────────────
        add("XSS",          "XSS-reflected", "XSS", CLIENT, Risk.LOW,
            "Canary strings reflected back in the response; nothing stored.");
        add("DOM XSS",      "DOM XSS",       "XSS", CLIENT, Risk.LOW,
            "Reads response JavaScript for dangerous sinks. No extra payloads beyond the page fetch.");
        add("Stored XSS",   "Stored XSS",    "XSS", CLIENT, Risk.HIGH,
            "Writes a canary into POST/PUT/PATCH fields and looks for it elsewhere. Persists data; "
          + "on contact/comment forms it sends e-mails or creates records.");
        add("Open Redirect", CLIENT, Risk.LOW,
            "Canary URL in redirect-style parameters; single request each.");
        add("CORS",         CLIENT, Risk.LOW,
            "One request with a fake Origin header.");

        // ── Infrastructure ───────────────────────────────────────────────────
        add("SSRF",         INFRA, Risk.LOW,
            "Callback URLs in parameters/headers; the target calls your OOB host.");
        add("Host Header",  INFRA, Risk.LOW,
            "Canary hostname in Host / X-Forwarded-Host; checks reflection.");
        add("Log4Shell",    INFRA, Risk.LOW,
            "JNDI DNS callback strings in headers and parameters; callback only.");
        add("GraphQL",      INFRA, Risk.LOW,
            "Introspection, batching and alias checks plus error-provoking quotes in arguments.");
        add("Smuggling",    INFRA, Risk.HIGH,
            "CL.TE / TE.CL desync probes. A bad desync can poison the connection and hit OTHER users' requests.");

        // ── Discovery ────────────────────────────────────────────────────────
        add("Sensitive Files", DISC, Risk.LOW,
            "GET requests for ~17 known-sensitive paths (.git, .env, backups). Read-only.");
        add("Smart Crawler",   DISC, Risk.LOW,
            "GET requests (max 120/host) for stack-specific admin/debug paths. Read-only.");
        add("Hidden Params",   DISC, Risk.MODERATE,
            "Adds ~120 guessed parameters (debug, admin, ...) to your request and diffs responses.");

        // ── Writes & load ────────────────────────────────────────────────────
        add("Mass Assignment", WRITE, Risk.HIGH,
            "Adds role/admin/price/is_active fields to POST/PUT/PATCH bodies. Can actually change data or privileges.");
        add("Race Condition",  WRITE, Risk.HIGH,
            "Fires 20 identical requests in parallel at coupon/payment-style endpoints. Can duplicate orders or redemptions.");
        add("File Upload",     WRITE, Risk.HIGH,
            "Uploads 10 variants of inert test files to the target and fetches them back. Leaves files on the server.");
        add("Rate Limit",      WRITE, Risk.HIGH,
            "Sends 6 identical copies of your request. On a form that sends e-mail that is 6 e-mails; "
          + "on a login it can lock the account.");
    }

    private ProbeCatalog() { }

    // ── Queries ───────────────────────────────────────────────────────────────

    public static List<Module> all() { return Collections.unmodifiableList(MODULES); }

    public static List<String> categories() {
        LinkedHashSet<String> cats = new LinkedHashSet<>();
        for (Module m : MODULES) cats.add(m.category());
        return new ArrayList<>(cats);
    }

    public static List<Module> inCategory(String cat) {
        List<Module> out = new ArrayList<>();
        for (Module m : MODULES) if (m.category().equals(cat)) out.add(m);
        return out;
    }

    /** Distinct family keys in catalog order. */
    public static List<String> families() {
        LinkedHashSet<String> f = new LinkedHashSet<>();
        for (Module m : MODULES) f.add(m.family());
        return new ArrayList<>(f);
    }

    public static List<Module> inFamily(String family) {
        List<Module> out = new ArrayList<>();
        for (Module m : MODULES) if (m.family().equals(family)) out.add(m);
        return out;
    }

    public static Module forEntry(String entry) {
        for (Module m : MODULES) if (m.entry().equals(entry)) return m;
        return null;
    }

    /**
     * True if the task with this runProbes() entry name must NOT run under this policy.
     * Unknown entries are never skipped here (they are infrastructure, not modules).
     */
    public static boolean isSkipped(String entry, Set<String> skip) {
        if (skip == null || skip.isEmpty()) return false;
        Module m = forEntry(entry);
        if (m == null) return skip.contains(entry);
        return skip.contains(m.skipKey()) || skip.contains(m.family()) || skip.contains(m.entry());
    }

    /** Every skip key the UI can produce (family heads + children). */
    public static Set<String> allSkipKeys() {
        Set<String> s = new LinkedHashSet<>();
        for (Module m : MODULES) { s.add(m.skipKey()); s.add(m.family()); }
        return s;
    }

    // ── Built-in profiles (read-only) ─────────────────────────────────────────

    /** Skip set for a built-in profile name, or null if the name is not built in. */
    public static Set<String> builtInSkips(String profile) {
        switch (profile) {
            case "Client-safe (recommended)": {
                // Skip everything HIGH, plus the MODERATE modules that replay or sleep.
                Set<String> s = new LinkedHashSet<>();
                for (Module m : MODULES) {
                    if (m.risk() == Risk.HIGH) s.add(m.skipKey());
                }
                // IDOR / Auth Bypass stay on: with "replay only on read methods" (default) they
                // never re-send a write. CSRF only ever applies to writes, so it is skipped.
                s.addAll(List.of("SQLi-time", "CmdI-time", "CSRF"));
                return s;
            }
            case "Standard": {
                Set<String> s = new LinkedHashSet<>();
                for (Module m : MODULES) {
                    if (m.risk() == Risk.HIGH) s.add(m.skipKey());
                }
                return s;
            }
            case "Recon only (read-only)": {
                // Only modules that never send anything but GETs/callback strings.
                Set<String> s = new LinkedHashSet<>();
                for (Module m : MODULES) {
                    if (m.risk() != Risk.LOW) s.add(m.skipKey());
                }
                return s;
            }
            case "Full (lab / CTF)":
                return new LinkedHashSet<>();
            default:
                return null;
        }
    }

    public static final List<String> BUILT_IN_PROFILES = List.of(
            "Client-safe (recommended)", "Standard", "Recon only (read-only)", "Full (lab / CTF)");
}
