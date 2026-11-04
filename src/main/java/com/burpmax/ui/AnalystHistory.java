package com.burpmax.ui;

import com.burpmax.model.Finding;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * Undo/redo for analyst actions on findings (false-positive flag, severity override, status,
 * notes), including bulk changes, which undo as a single step.
 *
 * It is snapshot based: each step stores the analyst fields of every finding it touched, before and
 * after. Undo restores "before", redo restores "after". Findings are held by reference, so a step
 * stays valid after the table is re-filtered or re-sorted.
 */
final class AnalystHistory {

    private static final int LIMIT = 200;

    /** The analyst-editable state of one finding. */
    record Snap(boolean suppressed, String severityOverride, String status, String note) {
        static Snap of(Finding f) {
            return new Snap(f.suppressed, f.severityOverride, f.remediationStatus, f.analystNote);
        }
        void applyTo(Finding f) {
            f.suppressed = suppressed;
            f.severityOverride = severityOverride;
            f.remediationStatus = status;
            f.analystNote = note;
        }
    }

    private record Step(String label, List<Finding> findings, List<Snap> before, List<Snap> after) { }

    private final Deque<Step> undo = new ArrayDeque<>();
    private final Deque<Step> redo = new ArrayDeque<>();
    private final Runnable onChange;

    AnalystHistory(Runnable onChange) { this.onChange = onChange; }

    /** Capture the state of these findings before a change. */
    List<Snap> snapshot(List<Finding> fs) {
        List<Snap> out = new ArrayList<>(fs.size());
        for (Finding f : fs) out.add(Snap.of(f));
        return out;
    }

    /** Record a change that has just been applied. {@code before} is from {@link #snapshot}. */
    void record(String label, List<Finding> fs, List<Snap> before) {
        List<Snap> after = snapshot(fs);
        if (after.equals(before)) return;   // nothing really changed
        undo.push(new Step(label, new ArrayList<>(fs), before, after));
        if (undo.size() > LIMIT) undo.removeLast();
        redo.clear();
        onChange.run();
    }

    /** Run {@code change} on these findings and record it as one undoable step. */
    void apply(String label, List<Finding> fs, Runnable change) {
        List<Snap> before = snapshot(fs);
        change.run();
        record(label, fs, before);
    }

    boolean canUndo() { return !undo.isEmpty(); }
    boolean canRedo() { return !redo.isEmpty(); }
    String undoLabel() { return undo.isEmpty() ? null : undo.peek().label(); }
    String redoLabel() { return redo.isEmpty() ? null : redo.peek().label(); }

    String undo() {
        if (undo.isEmpty()) return null;
        Step s = undo.pop();
        restore(s.findings(), s.before());
        redo.push(s);
        onChange.run();
        return s.label();
    }

    String redo() {
        if (redo.isEmpty()) return null;
        Step s = redo.pop();
        restore(s.findings(), s.after());
        undo.push(s);
        onChange.run();
        return s.label();
    }

    void clear() { undo.clear(); redo.clear(); onChange.run(); }

    private static void restore(List<Finding> fs, List<Snap> snaps) {
        for (int i = 0; i < fs.size(); i++) snaps.get(i).applyTo(fs.get(i));
    }
}
