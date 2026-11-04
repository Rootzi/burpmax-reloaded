package com.burpmax.active;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Central safety layer consulted by HttpSender before every probe request.
 *
 * Two independent protections:
 *
 *  1. DESTRUCTIVE PAYLOAD DENYLIST - refuses any request whose line/body contains
 *     something that could destroy or mutate data if the injection lands
 *     (DROP/DELETE/TRUNCATE/UPDATE statements, xp_cmdshell, file-writing SQL,
 *     rm -rf style shell, always-true OR tautologies, code-executing Mongo
 *     operators, ...). Detection probes never need these: they work from
 *     errors, AND-true/AND-false differentials, timing and out-of-band callbacks.
 *
 *  2. WRITE BUDGET - non-idempotent requests (anything but GET/HEAD/OPTIONS)
 *     are counted per METHOD + host + path. Once an endpoint's budget is spent
 *     further sends are refused for the rest of the scan. Budgets are tiered by
 *     what the endpoint looks like:
 *       MESSAGING   contact/feedback/subscribe/invite/... (sends e-mail or SMS)
 *       AUTH        login/token/otp/reset (lock-out risk)
 *       DESTRUCTIVE delete/remove/purge/wipe/... (budget 0 - never touched)
 *       OTHER       everything else that writes
 *
 * This is NOT a global "safe mode": GET-based probing is unaffected, and write
 * endpoints still get tested up to their budget.
 */
public final class RiskGuard {

    public enum Tier { MESSAGING, AUTH, DESTRUCTIVE, OTHER }

    /** Why a request was refused. */
    public record Verdict(boolean allowed, String reason) {
        static final Verdict OK = new Verdict(true, "");
        static Verdict deny(String why) { return new Verdict(false, why); }
    }

    // ── Tunable budgets (writes allowed per endpoint per scan) ────────────────
    private volatile int budgetMessaging = 3;
    private volatile int budgetAuth      = 15;
    private volatile int budgetOther     = 60;

    public void setBudgets(int messaging, int auth, int other) {
        this.budgetMessaging = Math.max(0, messaging);
        this.budgetAuth      = Math.max(0, auth);
        this.budgetOther     = Math.max(0, other);
    }
    public int budgetMessaging() { return budgetMessaging; }
    public int budgetAuth()      { return budgetAuth; }
    public int budgetOther()     { return budgetOther; }

    private final Map<String, AtomicInteger> used    = new ConcurrentHashMap<>();
    private final Set<String>                warned  = ConcurrentHashMap.newKeySet();
    private final AtomicInteger              blocked = new AtomicInteger();
    private volatile Consumer<String>        log     = s -> { };

    public void setLogger(Consumer<String> l) { this.log = l != null ? l : s -> { }; }
    public int  blockedCount()                { return blocked.get(); }
    public void reset()                       { used.clear(); warned.clear(); blocked.set(0); }

    // ── Patterns ──────────────────────────────────────────────────────────────

    private static final int F = Pattern.CASE_INSENSITIVE | Pattern.DOTALL;

    private record Rule(String name, Pattern pattern) { }

    private static final Rule[] DESTRUCTIVE = {
        new Rule("SQL DROP/TRUNCATE/ALTER", Pattern.compile("\\b(drop|truncate|alter)\\s+(table|database|schema|user|index|view|column)\\b", F)),
        new Rule("SQL DELETE FROM", Pattern.compile("\\bdelete\\s+from\\b", F)),
        new Rule("SQL INSERT INTO", Pattern.compile("\\binsert\\s+into\\b", F)),
        new Rule("stacked SQL UPDATE", Pattern.compile(";\\s*update\\s+[\\w.\\[\\]`\"]+\\s+set\\b", F)),
        new Rule("SQL account/schema creation", Pattern.compile("\\b(create|grant|revoke)\\s+(user|login|role|table|database)\\b", F)),
        new Rule("SQL Server admin procedure", Pattern.compile("\\bxp_cmdshell\\b|\\bsp_configure\\b|\\bsp_addlogin\\b|\\bsp_executesql\\b", F)),
        new Rule("SQL file-write", Pattern.compile("\\binto\\s+(out|dump)file\\b|\\butl_file\\b|\\bcopy\\s+\\w+\\s+to\\s+program\\b", F)),
        new Rule("SQL SHUTDOWN", Pattern.compile(";\\s*shutdown\\b|\\bshutdown\\s+with\\s+nowait\\b", F)),
        new Rule("OR tautology (widens WHERE)", Pattern.compile("['\"\\)\\s]\\s*or\\s+['\"]?\\w+['\"]?\\s*=\\s*['\"]?\\w+['\"]?\\s*(--|#|/\\*|$|['\"])", F)),
        new Rule("OR 1=1 tautology", Pattern.compile("\\bor\\s+1\\s*=\\s*1\\b|\\bor\\s+true\\b", F)),
        new Rule("shell rm -rf", Pattern.compile("\\brm\\s+-[a-z]*[rf]", F)),
        new Rule("disk-destroying command", Pattern.compile("\\b(mkfs|fdisk|wipefs|shred)\\b", F)),
        new Rule("dd if=", Pattern.compile("\\bdd\\s+if=", F)),
        new Rule("fork bomb", Pattern.compile(":\\(\\)\\s*\\{", F)),
        new Rule("host shutdown/reboot", Pattern.compile("\\b(shutdown|reboot|halt|poweroff)\\s+(-|now|/)", F)),
        new Rule("chained reboot/halt", Pattern.compile("[;&|`]\\s*(reboot|halt|poweroff)\\b", F)),
        new Rule("format drive", Pattern.compile("\\bformat\\s+[a-z]:", F)),
        new Rule("Windows recursive delete", Pattern.compile("\\bdel\\s+/[fqs]\\b|\\brmdir\\s+/s\\b", F)),
        new Rule("write to block device", Pattern.compile(">\\s*/dev/(sd|nvme|hd)", F)),
        new Rule("recursive chmod on /", Pattern.compile("\\bchmod\\s+-r\\s+[0-7]{3,4}\\s+/(\\s|$)", F)),
        new Rule("kill -9 / killall", Pattern.compile("\\bkill\\s+-9\\s+(-1|1)\\b|\\bkillall\\b", F)),
        new Rule("Mongo code-exec operator", Pattern.compile("\\$(where|function|accumulator)\\b", F)),
    };

    /** Operators that widen a filter; fine on a read, destructive on update/delete. */
    private static final Pattern WIDENING_OPS =
        Pattern.compile("\\$(ne|gt|gte|lt|lte|regex|or|nin|exists|not)\\b", F);

    private static final Pattern MESSAGING_PATH = Pattern.compile(
        "(contact|feedback|enquir|inquir|subscribe|newsletter|support|helpdesk|ticket|message|"
      + "mail|sms|notify|invite|share|refer|comment|review|testimonial|callback|call-?me|"
      + "request-?(quote|demo|info)|quote|booking|appointment|register|signup|sign-up|"
      + "forgot|recover|verify|resend)", Pattern.CASE_INSENSITIVE);

    private static final Pattern MESSAGING_PARAM = Pattern.compile(
        "(^|[?&\"'\\s;])(email|e-mail|mail|message|msg|subject|comment|enquiry|inquiry|"
      + "phone|mobile|telephone|your-?(name|email|message))(=|\"\\s*:|\\b)", Pattern.CASE_INSENSITIVE);

    private static final Pattern AUTH_PATH = Pattern.compile(
        "(login|signin|sign-in|logon|auth|token|oauth|otp|2fa|mfa|password|passwd|session)",
        Pattern.CASE_INSENSITIVE);

    private static final Pattern DESTRUCTIVE_PATH = Pattern.compile(
        "(delete|remove|destroy|purge|wipe|drop|erase|clear|truncate|terminate|"
      + "cancel|revoke|deactivate|close-?account|unsubscribe-?all|factory-?reset|reset-?all)",
        Pattern.CASE_INSENSITIVE);

    // ── Public API ────────────────────────────────────────────────────────────

    /** Evaluate a request about to be sent. Counts it against the budget if allowed. */
    public Verdict check(String host, int port, byte[] request) {
        if (request == null || request.length == 0) return Verdict.OK;
        String raw = new String(request, StandardCharsets.ISO_8859_1);

        int lineEnd = raw.indexOf("\r\n");
        String line = lineEnd > 0 ? raw.substring(0, lineEnd) : raw;
        String[] parts = line.split(" ");
        String method = parts.length > 0 ? parts[0].toUpperCase() : "GET";
        String target = parts.length > 1 ? parts[1] : "/";

        int hdrEnd = raw.indexOf("\r\n\r\n");
        String body = hdrEnd >= 0 ? raw.substring(hdrEnd + 4) : "";

        // Scan the request line + body, raw and URL-decoded (payloads are often encoded).
        String hay = line + "\n" + body;
        String dec = safeDecode(hay);
        for (Rule r : DESTRUCTIVE) {
            if (r.pattern().matcher(hay).find() || r.pattern().matcher(dec).find()) {
                return deny(method, target, "destructive payload: " + r.name());
            }
        }

        if (isSafeMethod(method)) return Verdict.OK;

        String path = stripQuery(target);

        // Widening NoSQL operators never go to update/delete style requests.
        boolean mutating = method.equals("PUT") || method.equals("PATCH") || method.equals("DELETE")
                || DESTRUCTIVE_PATH.matcher(path).find();
        if (mutating && (WIDENING_OPS.matcher(hay).find() || WIDENING_OPS.matcher(dec).find())) {
            return deny(method, target, "filter-widening operator on a mutating request");
        }

        Tier tier = classify(method, path, hay);
        int budget = switch (tier) {
            case DESTRUCTIVE -> 0;
            case MESSAGING   -> budgetMessaging;
            case AUTH        -> budgetAuth;
            case OTHER       -> budgetOther;
        };

        String key = method + " " + host + ":" + port + path;
        int n = used.computeIfAbsent(key, k -> new AtomicInteger()).incrementAndGet();
        if (n > budget) {
            used.get(key).decrementAndGet();   // don't keep counting refused sends
            return deny(method, target, "write budget reached for " + tier.name().toLowerCase()
                    + " endpoint (" + budget + ")");
        }
        return Verdict.OK;
    }

    public static Tier classify(String method, String path, String requestText) {
        if (method.equals("DELETE") || DESTRUCTIVE_PATH.matcher(path).find()) return Tier.DESTRUCTIVE;
        if (MESSAGING_PATH.matcher(path).find() || MESSAGING_PARAM.matcher(requestText).find()) {
            // A login form also has an "email" field; auth wins when the path says so.
            if (!AUTH_PATH.matcher(path).find()) return Tier.MESSAGING;
        }
        if (AUTH_PATH.matcher(path).find()) return Tier.AUTH;
        return Tier.OTHER;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Verdict deny(String method, String target, String why) {
        blocked.incrementAndGet();
        String key = method + " " + stripQuery(target) + " " + why;
        if (warned.add(key)) log.accept("RiskGuard blocked " + method + " " + stripQuery(target) + " - " + why);
        return Verdict.deny(why);
    }

    private static boolean isSafeMethod(String m) {
        return m.equals("GET") || m.equals("HEAD") || m.equals("OPTIONS");
    }

    private static String stripQuery(String t) {
        int q = t.indexOf('?');
        String p = q >= 0 ? t.substring(0, q) : t;
        int h = p.indexOf('#');
        return h >= 0 ? p.substring(0, h) : p;
    }

    /** Lenient percent-decoder (never throws on malformed %xx). Two passes catch double encoding. */
    private static String safeDecode(String s) {
        return lenientDecode(lenientDecode(s));
    }

    private static String lenientDecode(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '+') {
                sb.append(' ');
            } else if (c == '%' && i + 2 < s.length()
                    && Character.digit(s.charAt(i + 1), 16) >= 0
                    && Character.digit(s.charAt(i + 2), 16) >= 0) {
                sb.append((char) Integer.parseInt(s.substring(i + 1, i + 3), 16));
                i += 2;
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
