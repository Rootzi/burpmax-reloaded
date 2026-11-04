package com.burpmax.nuclei;

import com.burpmax.active.ScanFlow;
import com.burpmax.model.Finding;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Runs the Nuclei binary on a vetted list of templates and feeds each result back as a Finding.
 *
 * Nuclei is a separate process, so BurpMax's per-request guard can't see its traffic. Safety here
 * comes from deciding up front exactly which templates run ({@link TemplateVetter}), rate limiting,
 * running with out-of-band servers off by default, and stopping when you cancel. Pause stops the
 * process in place (SIGSTOP) and resume continues it (SIGCONT), so nothing restarts.
 */
public final class NucleiRunner {

    /** Everything a run needs. */
    public static final class Config {
        public boolean enabled;
        public String binary = "nuclei";
        public String templatesDir = "";
        public Set<NucleiGroups.Group> groups = EnumSet.noneOf(NucleiGroups.Group.class);
        public boolean allowOob = false;
        public int requestsPerSecond = 10;
        public List<String> headers = new ArrayList<>();
    }

    public record Outcome(int templatesRun, int findings, String message) { }

    private static final int CHUNK = 1200;   // templates per process; keeps the command line short
    private static final int MAX_STDERR_LINES = 12;

    private NucleiRunner() { }

    // ── Locating things ───────────────────────────────────────────────────────

    /** Finds the nuclei binary: the configured path, else PATH, else common install folders. */
    public static String findBinary(String configured) {
        List<String> tries = new ArrayList<>();
        if (configured != null && !configured.isBlank()) tries.add(configured.trim());
        tries.add("nuclei");
        String home = System.getProperty("user.home", "");
        tries.add(home + "/go/bin/nuclei");
        tries.add("/usr/local/bin/nuclei");
        tries.add("/usr/bin/nuclei");
        tries.add("/opt/homebrew/bin/nuclei");
        for (String t : tries) {
            String v = version(t);
            if (v != null) return t;
        }
        return null;
    }

    /** Returns the version text if the binary runs, else null. */
    public static String version(String bin) {
        try {
            Process p = new ProcessBuilder(bin, "-version").redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (!p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS)) { p.destroyForcibly(); return null; }
            return p.exitValue() == 0 || out.toLowerCase().contains("nuclei") ? out.strip() : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** First existing templates folder: the configured one, else the usual install locations. */
    public static Path findTemplates(String configured) {
        List<String> tries = new ArrayList<>();
        if (configured != null && !configured.isBlank()) tries.add(configured.trim());
        String home = System.getProperty("user.home", "");
        tries.add(home + "/nuclei-templates");
        tries.add(home + "/.local/nuclei-templates");
        tries.add(home + "/.config/nuclei/templates");
        tries.add("/usr/share/nuclei-templates");
        for (String t : tries) {
            Path p = Paths.get(t);
            if (Files.isDirectory(p)) return p;
        }
        return null;
    }

    // ── Run ───────────────────────────────────────────────────────────────────

    public static Outcome run(Config cfg, List<String> targetOrigins, Consumer<Finding> sink,
                              Consumer<String> status, Consumer<String> log,
                              AtomicBoolean cancelled, ScanFlow flow) {
        if (targetOrigins.isEmpty()) return new Outcome(0, 0, "No targets for Nuclei.");
        if (cfg.groups.isEmpty()) return new Outcome(0, 0, "No Nuclei groups selected.");

        String bin = findBinary(cfg.binary);
        if (bin == null) {
            return new Outcome(0, 0, "Nuclei not found. Install it (e.g. 'sudo apt install nuclei') or set its path in the scan dialog.");
        }
        Path tdir = findTemplates(cfg.templatesDir);
        if (tdir == null) {
            return new Outcome(0, 0, "Nuclei templates folder not found. Run 'nuclei -update-templates' or set the folder in the scan dialog.");
        }

        status.accept("Nuclei: vetting templates in " + tdir + " ...");
        TemplateVetter.Scan scan;
        try { scan = TemplateVetter.scan(tdir, cfg.allowOob); }
        catch (IOException e) { return new Outcome(0, 0, "Could not read templates: " + e.getMessage()); }
        List<TemplateVetter.Template> chosen = TemplateVetter.select(scan.allowed(), cfg.groups);
        log.accept("Nuclei: " + scan.allowed().size() + " templates allowed, " + scan.rejected() + " rejected ("
                + scan.rejectReasons() + "); " + chosen.size() + " selected by goal.");
        if (chosen.isEmpty()) return new Outcome(0, 0, "No allowed templates match the selected goals.");

        Map<String, Path> byId = new HashMap<>();
        for (TemplateVetter.Template t : chosen) byId.put(t.id(), t.path());

        Path targets = null;
        try {
            targets = Files.createTempFile("burpmax-nuclei-targets", ".txt");
            Files.write(targets, targetOrigins, StandardCharsets.UTF_8);
            int found = 0, ran = 0;
            int chunks = (chosen.size() + CHUNK - 1) / CHUNK;
            for (int c = 0; c < chunks && !cancelled.get(); c++) {
                List<TemplateVetter.Template> part = chosen.subList(c * CHUNK, Math.min(chosen.size(), (c + 1) * CHUNK));
                final int chunkNo = c + 1;
                final int foundSoFar = found;
                int[] n = {0};
                String err = runChunk(bin, cfg, targets, part, byId, f -> {
                    n[0]++;
                    sink.accept(f);
                    status.accept("Nuclei " + chunkNo + "/" + chunks + ": " + (foundSoFar + n[0]) + " findings so far");
                }, status, log, cancelled, flow, chunkNo, chunks);
                found += n[0];
                ran += part.size();
                if (err != null) return new Outcome(ran, found, err);
            }
            return new Outcome(ran, found, cancelled.get() ? "Nuclei stopped." : "Nuclei finished: " + found + " findings from " + ran + " templates.");
        } catch (IOException e) {
            return new Outcome(0, 0, "Nuclei failed: " + e.getMessage());
        } finally {
            if (targets != null) try { Files.deleteIfExists(targets); } catch (IOException ignored) { }
        }
    }

    /** Builds the command line (public for tests). */
    public static List<String> command(String bin, Config cfg, Path targets, List<TemplateVetter.Template> part) {
        List<String> cmd = new ArrayList<>(List.of(bin,
                "-jsonl", "-irr", "-silent", "-nc", "-duc",      // JSON out with request/response, no colour, no update check
                "-l", targets.toString(),
                "-rl", String.valueOf(Math.max(1, cfg.requestsPerSecond)),
                "-c", "5", "-timeout", "10", "-retries", "1", "-mhe", "20",
                "-pt", "http"));
        if (!cfg.allowOob) cmd.add("-ni");                       // no interactsh: nothing goes to a third-party server
        for (String h : cfg.headers) { cmd.add("-H"); cmd.add(h); }
        for (TemplateVetter.Template t : part) { cmd.add("-t"); cmd.add(t.path().toString()); }
        return cmd;
    }

    private static String runChunk(String bin, Config cfg, Path targets, List<TemplateVetter.Template> part,
                                   Map<String, Path> byId, Consumer<Finding> sink, Consumer<String> status,
                                   Consumer<String> log, AtomicBoolean cancelled, ScanFlow flow,
                                   int chunkNo, int chunks) throws IOException {
        List<String> cmd = command(bin, cfg, targets, part);
        status.accept("Nuclei " + chunkNo + "/" + chunks + ": running " + part.size() + " templates ...");
        Process p = new ProcessBuilder(cmd).start();
        p.getOutputStream().close();

        Deque<String> errLines = new ArrayDeque<>();
        Thread errT = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getErrorStream(), StandardCharsets.UTF_8))) {
                String l;
                while ((l = r.readLine()) != null) {
                    synchronized (errLines) { errLines.addLast(l); if (errLines.size() > MAX_STDERR_LINES) errLines.removeFirst(); }
                }
            } catch (IOException ignored) { }
        }, "burpmax-nuclei-stderr");
        errT.setDaemon(true);
        errT.start();

        // Pause / cancel watcher: stops the process in place, or kills it.
        AtomicBoolean done = new AtomicBoolean();
        Thread watch = new Thread(() -> {
            boolean stopped = false;
            while (!done.get()) {
                try { Thread.sleep(250); } catch (InterruptedException e) { return; }
                if (cancelled.get()) { kill(p); return; }
                boolean want = flow != null && flow.isPaused();
                if (want != stopped) { signal(p, want ? "STOP" : "CONT"); stopped = want; }
            }
            if (stopped) signal(p, "CONT");
        }, "burpmax-nuclei-watch");
        watch.setDaemon(true);
        watch.start();

        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                Finding f = NucleiImporter.fromJsonLine(line, byId);
                if (f != null) sink.accept(f);
            }
        } finally {
            done.set(true);
        }
        int code;
        try { code = p.waitFor(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); kill(p); return "Interrupted"; }
        if (cancelled.get()) return null;
        if (code != 0) {
            String tail;
            synchronized (errLines) { tail = String.join(" | ", errLines); }
            log.accept("Nuclei exited with code " + code + ": " + tail);
            return "Nuclei exited with an error (code " + code + "). " + (tail.isEmpty() ? "" : tail);
        }
        return null;
    }

    private static void kill(Process p) {
        try { p.descendants().forEach(ProcessHandle::destroyForcibly); } catch (Exception ignored) { }
        p.destroyForcibly();
    }

    private static void signal(Process p, String sig) {
        try { new ProcessBuilder("kill", "-" + sig, String.valueOf(p.pid())).start().waitFor(); }
        catch (Exception ignored) { }
    }
}
