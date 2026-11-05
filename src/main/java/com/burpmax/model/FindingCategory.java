package com.burpmax.model;

import java.util.Locale;

/** Buckets a finding into a broad category (for the "group by category" view), from its title and CWE. */
public final class FindingCategory {
    private FindingCategory() {}

    public static final String INJECTION   = "Injection";
    public static final String CLIENT_SIDE = "Client-side";
    public static final String AUTH        = "Authentication & access control";
    public static final String SESSION     = "Cookies & sessions";
    public static final String HEADERS     = "Security headers & configuration";
    public static final String DISCLOSURE  = "Information disclosure";
    public static final String OUTDATED    = "Outdated software";
    public static final String TRANSPORT   = "Transport & cleartext";
    public static final String INFRA       = "Server & infrastructure";
    public static final String NUCLEI      = "Nuclei (other)";
    public static final String OTHER       = "Other";

    public static String of(Finding f) {
        if (f == null) return OTHER;
        String n = (f.name == null ? "" : f.name).toLowerCase(Locale.ROOT);
        String cwe = f.cwe == null ? "" : f.cwe.toLowerCase(Locale.ROOT);

        if (has(n, "sql inj", "sqli", "nosql", "command inj", "cmdi", "template inj", "ssti", "xxe", "xml external",
                "ldap", "path traversal", "directory traversal", "local file", "prototype pollution",
                "deserializ", "log4shell", "ssrf", "server-side request", "code inj", "file inclusion", "mass assignment"))
            return INJECTION;
        if (has(n, "xss", "cross-site scripting", "clickjack", "open redirect", "csrf", "cross-site request", "dom-based", "content security policy", "csp"))
            return CLIENT_SIDE;
        if (has(n, "outdated", "end-of-life", "end of life", "eol", "vulnerable version", "known vulnerab"))
            return OUTDATED;
        if (has(n, "cookie", "session"))
            return SESSION;
        if (has(n, "auth", "jwt", "oauth", "oidc", "idor", "direct object", "password", "credential", "login", "privilege", "access control", "rate limit", "brute"))
            return has(n, "cleartext") ? TRANSPORT : AUTH;
        if (has(n, "cleartext", "http strict", "hsts", "tls", "ssl", "https", "mixed content", "insecure transport"))
            return TRANSPORT;
        if (has(n, "disclos", "secret", "api key", "token exposed", "stack trace", "debug", "metadata", "directory listing",
                "backup", "sensitive", "leak", "exposed", "version", "comment", "email address", "private key"))
            return DISCLOSURE;
        if (has(n, "header", "cors", "cache-control", "cache control", "x-frame", "x-content", "referrer", "permissions-policy",
                "host header", "misconfig", "http method", "trace", "options"))
            return HEADERS;
        if (has(n, "smuggling", "race condition", "cache poison", "request splitting", "server"))
            return INFRA;
        if (cwe.contains("89") || cwe.contains("78") || cwe.contains("79") && n.contains("script")) return n.contains("script") ? CLIENT_SIDE : INJECTION;
        return Finding.SOURCE_NUCLEI.equals(f.source) ? NUCLEI : OTHER;
    }

    private static boolean has(String n, String... keys) {
        for (String k : keys) if (n.contains(k)) return true;
        return false;
    }
}
