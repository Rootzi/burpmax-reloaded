package com.burpmax.active;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Pace and pause control shared by every request of one active scan.
 *
 *  - Pause/resume happens in place: request threads simply wait where they are, so nothing is
 *    restarted and no work is repeated.
 *  - Auto-throttle: when a noticeable share of recent requests fail or get rate-limited
 *    (no response, HTTP 429/502/503/504), an extra delay is added to every request; it fades
 *    again once the target looks healthy.
 *  - Circuit breaker: if the target looks to be falling over (a long run of failures, or nearly
 *    every recent request failing) the scan pauses itself, then tries again after a cool-down.
 *    After a few trips it stays paused until the user resumes.
 *
 * The waiting happens before a request is timed, so it never skews time-based detection.
 */
public final class ScanFlow {

    public enum State { RUNNING, PAUSED_BY_USER, PAUSED_AUTO }

    private static final int  WINDOW          = 20;
    private static final int  MIN_SAMPLES     = 10;
    private static final int  MAX_EXTRA_MS    = 4000;
    private static final int  TRIP_RUN        = 10;      // consecutive failures
    private static final double TRIP_RATE     = 0.8;     // share of a full window
    private static final double SLOW_RATE     = 0.3;
    private static final int  MAX_AUTO_TRIPS  = 3;
    private static final long BASE_COOLDOWN_S = 60;

    private final AtomicBoolean cancelled;
    private final Object lock = new Object();

    private volatile State state = State.RUNNING;
    private volatile String reason = "";
    private volatile int extraDelayMs = 0;
    private volatile boolean autoThrottle = true;

    private final boolean[] ring = new boolean[WINDOW];   // true = bad outcome
    private int filled = 0, pos = 0, badInWindow = 0, run = 0, sinceEval = 0;
    private int trips = 0;
    private long resumeAtMs = 0;

    private volatile Consumer<String> onStatus = s -> { };
    private volatile Consumer<State> onState = s -> { };

    public ScanFlow(AtomicBoolean cancelled) { this.cancelled = cancelled; }

    public void setOnStatus(Consumer<String> c) { this.onStatus = c == null ? s -> { } : c; }
    public void setOnState(Consumer<State> c)   { this.onState = c == null ? s -> { } : c; }
    public void setAutoThrottle(boolean on)     { this.autoThrottle = on; if (!on) extraDelayMs = 0; }

    public State  state()        { return state; }
    public String reason()       { return reason; }
    public int    extraDelayMs() { return extraDelayMs; }
    public boolean isPaused()    { return state != State.RUNNING; }

    /** Forget everything: new scan. */
    public void reset() {
        synchronized (lock) {
            filled = pos = badInWindow = run = sinceEval = trips = 0;
            java.util.Arrays.fill(ring, false);
            extraDelayMs = 0;
            state = State.RUNNING;
            reason = "";
            lock.notifyAll();
        }
        onState.accept(State.RUNNING);
    }

    // ── Pause / resume ────────────────────────────────────────────────────────

    public void pauseByUser() {
        synchronized (lock) {
            if (state != State.RUNNING) return;
            state = State.PAUSED_BY_USER;
            reason = "Paused by you";
            resumeAtMs = 0;
        }
        onStatus.accept("Scan paused — requests already in flight will finish, nothing new is sent.");
        onState.accept(State.PAUSED_BY_USER);
    }

    /** Resume where the scan stopped. */
    public void resume() {
        boolean was;
        synchronized (lock) {
            was = state != State.RUNNING;
            state = State.RUNNING;
            reason = "";
            resumeAtMs = 0;
            clearWindow();
            lock.notifyAll();
        }
        if (was) {
            onStatus.accept("Scan resumed" + (extraDelayMs > 0 ? " (throttled: +" + extraDelayMs + " ms per request)" : "") + ".");
            onState.accept(State.RUNNING);
        }
    }

    /** Wake everything that is waiting (used on cancel). */
    public void release() {
        synchronized (lock) { lock.notifyAll(); }
    }

    /**
     * Block while paused. Returns false if the scan was cancelled while waiting.
     * Also handles the timed auto-resume after a circuit-breaker pause.
     */
    public boolean await() {
        if (state == State.RUNNING) return !cancelled.get();
        synchronized (lock) {
            while (state != State.RUNNING && !cancelled.get()) {
                if (state == State.PAUSED_AUTO && resumeAtMs > 0) {
                    long left = resumeAtMs - System.currentTimeMillis();
                    if (left <= 0) {
                        state = State.RUNNING;
                        reason = "";
                        resumeAtMs = 0;
                        extraDelayMs = MAX_EXTRA_MS;   // come back slowly
                        clearWindow();
                        onStatus.accept("Cool-down over — resuming slowly (+" + MAX_EXTRA_MS + " ms per request).");
                        onState.accept(State.RUNNING);
                        break;
                    }
                    try { lock.wait(Math.min(left, 500)); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return false; }
                } else {
                    try { lock.wait(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return false; }
                }
            }
        }
        return !cancelled.get();
    }

    // ── Health tracking ───────────────────────────────────────────────────────

    /** Feed the outcome of one finished request. status < 0 means no response at all. */
    public void record(int status) {
        if (!autoThrottle) return;
        boolean bad = status < 0 || status == 429 || status == 502 || status == 503 || status == 504;
        String tripReason = null;
        int newExtra = -1;
        synchronized (lock) {
            if (state != State.RUNNING) return;
            if (filled == WINDOW && ring[pos]) badInWindow--;
            ring[pos] = bad;
            if (bad) badInWindow++;
            pos = (pos + 1) % WINDOW;
            if (filled < WINDOW) filled++;
            run = bad ? run + 1 : 0;
            sinceEval++;

            if (run >= TRIP_RUN) {
                tripReason = run + " requests in a row got no response or were rate-limited (HTTP 429/502/503/504)";
            } else if (filled == WINDOW && badInWindow >= WINDOW * TRIP_RATE) {
                tripReason = badInWindow + " of the last " + WINDOW + " requests failed or were rate-limited";
            } else if (filled >= MIN_SAMPLES && sinceEval >= MIN_SAMPLES / 2) {
                sinceEval = 0;
                double rate = (double) badInWindow / filled;
                int cur = extraDelayMs;
                if (rate >= SLOW_RATE)          newExtra = Math.min(MAX_EXTRA_MS, Math.max(250, cur * 2));
                else if (badInWindow == 0 && cur > 0) newExtra = cur < 100 ? 0 : cur / 2;
            }
            if (tripReason != null) trip(tripReason);
            else if (newExtra >= 0 && newExtra != extraDelayMs) extraDelayMs = newExtra;
        }
        if (tripReason != null) return;   // trip() already reported
        if (newExtra >= 0) {
            onStatus.accept(newExtra == 0 ? "Target looks healthy again — throttle removed."
                    : "Target is struggling — slowing down (+" + newExtra + " ms per request).");
        }
    }

    // caller holds lock
    private void trip(String why) {
        trips++;
        state = State.PAUSED_AUTO;
        extraDelayMs = Math.max(extraDelayMs, 1000);
        boolean auto = trips <= MAX_AUTO_TRIPS;
        long cool = BASE_COOLDOWN_S * trips;
        resumeAtMs = auto ? System.currentTimeMillis() + cool * 1000L : 0;
        reason = why;
        final String msg = "⚠ Auto-paused: " + why + ". "
                + (auto ? "Retrying in " + cool + " s, or press Resume to continue now."
                        : "Press Resume when the target is back.");
        // notify outside the monitor's critical path where possible
        new Thread(() -> { onStatus.accept(msg); onState.accept(State.PAUSED_AUTO); }, "burpmax-flow-notify").start();
    }

    private void clearWindow() {
        filled = pos = badInWindow = run = sinceEval = 0;
        java.util.Arrays.fill(ring, false);
    }
}
