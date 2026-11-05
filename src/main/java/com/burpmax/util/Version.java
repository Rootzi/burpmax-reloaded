package com.burpmax.util;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Build version, stamped into the jar by build.sh (VERSION file + CI build number). */
public final class Version {
    private Version() {}

    private static final String V = load();

    /** e.g. "1.1.7" from CI, or "1.1.dev" for a local build. */
    public static String get() { return V; }

    private static String load() {
        try (InputStream in = Version.class.getResourceAsStream("/burpmax-version.txt")) {
            if (in != null) {
                String s = new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();
                if (!s.isEmpty()) return s;
            }
        } catch (Exception ignored) {}
        return "dev";
    }
}
