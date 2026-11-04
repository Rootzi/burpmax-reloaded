package com.burpmax.ui;

import burp.IBurpExtenderCallbacks;
import com.burpmax.nuclei.NucleiGroups;
import com.burpmax.nuclei.NucleiRunner;
import com.burpmax.nuclei.TemplateVetter;

import javax.swing.*;
import java.awt.*;
import java.nio.file.Path;
import java.util.*;
import java.util.List;

import static com.burpmax.ui.Theme.*;

/**
 * Scan-dialog section for Nuclei: on/off, goal groups, binary and template folder, out-of-band switch.
 * Its state is part of a scan profile, so each profile can carry its own set of goals.
 */
final class NucleiPanel extends JPanel {

    @java.io.Serial
    private static final long serialVersionUID = 1L;

    private static final String S_BIN = "burpmax.nuclei.bin", S_TPL = "burpmax.nuclei.templates";

    private final transient IBurpExtenderCallbacks callbacks;
    private final JCheckBox enabled = new JCheckBox("Run Nuclei templates after the BurpMax modules");
    private final JCheckBox runNative = new JCheckBox("Run BurpMax's own modules (untick for a Nuclei-only scan)");
    private final Map<NucleiGroups.Group, JCheckBox> groupBoxes = new EnumMap<>(NucleiGroups.Group.class);
    private final Map<NucleiGroups.Group, JLabel> countLbls = new EnumMap<>(NucleiGroups.Group.class);
    private final JTextField bin = new JTextField();
    private final JTextField tpl = new JTextField();
    private final JCheckBox oob = new JCheckBox("Allow out-of-band templates (uses a public interactsh server)");
    private final JSpinner rps = new JSpinner(new SpinnerNumberModel(10, 1, 200, 1));
    private final JLabel info = new JLabel(" ");
    private final JPanel groupsPanel = new JPanel();
    private final Runnable relayout;
    private boolean adjusting;

    NucleiPanel(IBurpExtenderCallbacks callbacks, Runnable relayout) {
        this.callbacks = callbacks;
        this.relayout = relayout;
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBackground(C_SURFACE);
        setAlignmentX(LEFT_ALIGNMENT);

        style(enabled, true); style(runNative, false); style(oob, false);
        runNative.setSelected(true);
        enabled.addActionListener(e -> sync());
        add(enabled);
        add(runNative);
        add(Box.createVerticalStrut(6));

        JLabel hint = small("<html><div style='width:430px'>Pick goals. Each goal is a set of Nuclei template tags. "
                + "Only read-only HTTP templates are ever run: nothing that sends POST/PUT/DELETE, brute-forces logins, "
                + "uses destructive payloads, or is tagged intrusive/dos/fuzzing.</div></html>");
        add(hint);
        add(Box.createVerticalStrut(4));

        groupsPanel.setLayout(new BoxLayout(groupsPanel, BoxLayout.Y_AXIS));
        groupsPanel.setOpaque(false);
        groupsPanel.setAlignmentX(LEFT_ALIGNMENT);
        for (NucleiGroups.Group g : NucleiGroups.Group.values()) {
            JCheckBox cb = new JCheckBox(g.label);
            style(cb, false);
            cb.setToolTipText("<html><div style='width:300px'>" + g.blurb + "<br>Tags: " + String.join(", ", new TreeSet<>(g.tags)) + "</div></html>");
            cb.addActionListener(e -> refreshInfo());
            JLabel cnt = small(" ");
            JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
            row.setOpaque(false);
            row.setAlignmentX(LEFT_ALIGNMENT);
            row.add(cb);
            row.add(cnt);
            groupsPanel.add(row);
            groupBoxes.put(g, cb);
            countLbls.put(g, cnt);
        }
        add(groupsPanel);
        add(Box.createVerticalStrut(8));

        add(labeled("Nuclei binary", bin, "Detect", this::detect));
        add(Box.createVerticalStrut(4));
        add(labeled("Templates folder", tpl, "Count", this::countTemplates));
        add(Box.createVerticalStrut(4));
        JPanel r = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        r.setOpaque(false);
        r.setAlignmentX(LEFT_ALIGNMENT);
        r.add(rps);
        r.add(small("requests per second (Nuclei's own rate limit)"));
        add(r);
        add(oob);
        add(Box.createVerticalStrut(4));
        info.setFont(Widgets.UI_SMALL);
        info.setForeground(C_TEXT_MUTED);
        info.setAlignmentX(LEFT_ALIGNMENT);
        add(info);

        try {
            String b = callbacks == null ? null : callbacks.loadExtensionSetting(S_BIN);
            String t = callbacks == null ? null : callbacks.loadExtensionSetting(S_TPL);
            bin.setText(b == null ? "" : b);
            tpl.setText(t == null ? "" : t);
        } catch (Exception ignored) { }
        bin.setToolTipText("Leave empty to find 'nuclei' on your PATH");
        tpl.setToolTipText("Leave empty to use ~/nuclei-templates");
        sync();
    }

    // ── Profile hooks ─────────────────────────────────────────────────────────

    String encode() { return NucleiGroups.encode(enabled.isSelected(), selectedGroups()) + "|" + (runNative.isSelected() ? "1" : "0"); }

    void applyEncoded(String s) {
        if (s == null) return;
        String[] parts = s.split("\\|", -1);
        // format: "1|TECH,CVE|1"
        enabled.setSelected(NucleiGroups.decodeEnabled(s));
        Set<NucleiGroups.Group> gs = parts.length > 1 ? NucleiGroups.decodeGroups(parts[1]) : EnumSet.noneOf(NucleiGroups.Group.class);
        for (Map.Entry<NucleiGroups.Group, JCheckBox> e : groupBoxes.entrySet()) e.getValue().setSelected(gs.contains(e.getKey()));
        runNative.setSelected(parts.length < 3 || !"0".equals(parts[2]));
        sync();
    }

    /** Settings a built-in profile uses. */
    void applyBuiltIn(String profile) {
        Set<NucleiGroups.Group> gs = NucleiGroups.forProfile(profile);
        enabled.setSelected(!gs.isEmpty());
        runNative.setSelected(true);
        for (Map.Entry<NucleiGroups.Group, JCheckBox> e : groupBoxes.entrySet()) e.getValue().setSelected(gs.contains(e.getKey()));
        sync();
    }

    // ── Results ───────────────────────────────────────────────────────────────

    boolean runNative() { return runNative.isSelected(); }

    Set<NucleiGroups.Group> selectedGroups() {
        Set<NucleiGroups.Group> s = EnumSet.noneOf(NucleiGroups.Group.class);
        for (Map.Entry<NucleiGroups.Group, JCheckBox> e : groupBoxes.entrySet()) if (e.getValue().isSelected()) s.add(e.getKey());
        return s;
    }

    NucleiRunner.Config config(int delayMs, List<String> headers) {
        NucleiRunner.Config c = new NucleiRunner.Config();
        c.enabled = enabled.isSelected() && !selectedGroups().isEmpty();
        c.binary = bin.getText().trim().isEmpty() ? "nuclei" : bin.getText().trim();
        c.templatesDir = tpl.getText().trim();
        c.groups = selectedGroups();
        c.allowOob = oob.isSelected();
        int userRps = (Integer) rps.getValue();
        // honour a slow scan: a 500 ms delay setting means at most ~2 requests/s
        c.requestsPerSecond = delayMs > 0 ? Math.max(1, Math.min(userRps, 1000 / Math.max(1, delayMs))) : userRps;
        c.headers = new ArrayList<>(headers);
        try {
            if (callbacks != null) {
                callbacks.saveExtensionSetting(S_BIN, bin.getText().trim());
                callbacks.saveExtensionSetting(S_TPL, tpl.getText().trim());
            }
        } catch (Exception ignored) { }
        return c;
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    private void sync() {
        boolean on = enabled.isSelected();
        for (JCheckBox cb : groupBoxes.values()) cb.setEnabled(on);
        bin.setEnabled(on); tpl.setEnabled(on); rps.setEnabled(on); oob.setEnabled(on);
        refreshInfo();
    }

    private void refreshInfo() {
        int n = selectedGroups().size();
        info.setText(enabled.isSelected()
                ? (n == 0 ? "Pick at least one goal." : n + " goal" + (n == 1 ? "" : "s") + " selected. Findings appear in the same table, tagged Nuclei.")
                : "Nuclei is off for this scan.");
        if (relayout != null) relayout.run();
    }

    private void detect() {
        info.setText("Looking for nuclei ...");
        new SwingWorker<String, Void>() {
            @Override protected String doInBackground() {
                String b = NucleiRunner.findBinary(bin.getText());
                Path t = NucleiRunner.findTemplates(tpl.getText());
                if (b == null) return "Nuclei not found. Install it (sudo apt install nuclei) or type its full path.";
                String v = NucleiRunner.version(b);
                SwingUtilities.invokeLater(() -> { if (bin.getText().isBlank()) bin.setText(b); if (t != null && tpl.getText().isBlank()) tpl.setText(t.toString()); });
                return "Found " + b + (v == null ? "" : " — " + v.replaceAll("\\s+", " ").replaceAll("^.*Version: ?", "v")) + (t == null ? "  (templates folder not found)" : "  templates: " + t);
            }
            @Override protected void done() {
                try { info.setText(get()); } catch (Exception e) { info.setText("Detect failed: " + e.getMessage()); }
                if (relayout != null) relayout.run();
            }
        }.execute();
    }

    private void countTemplates() {
        info.setText("Reading templates ...");
        final boolean allowOob = oob.isSelected();
        new SwingWorker<Map<NucleiGroups.Group, Integer>, Void>() {
            private String note = "";
            @Override protected Map<NucleiGroups.Group, Integer> doInBackground() throws Exception {
                Path t = NucleiRunner.findTemplates(tpl.getText());
                if (t == null) { note = "Templates folder not found. Run 'nuclei -update-templates' or set the folder."; return Map.of(); }
                TemplateVetter.Scan sc = TemplateVetter.scan(t, allowOob);
                note = sc.allowed().size() + " templates are allowed to run, " + sc.rejected() + " were rejected as unsafe or unsupported.";
                return TemplateVetter.counts(sc.allowed());
            }
            @Override protected void done() {
                try {
                    Map<NucleiGroups.Group, Integer> m = get();
                    for (Map.Entry<NucleiGroups.Group, JLabel> e : countLbls.entrySet()) {
                        Integer c = m.get(e.getKey());
                        e.getValue().setText(c == null ? " " : "(" + c + " templates)");
                    }
                    info.setText(note);
                } catch (Exception ex) { info.setText("Could not read templates: " + ex.getMessage()); }
                if (relayout != null) relayout.run();
            }
        }.execute();
    }

    private JComponent labeled(String label, JTextField field, String btnText, Runnable action) {
        JPanel p = new JPanel(new BorderLayout(6, 0));
        p.setOpaque(false);
        p.setAlignmentX(LEFT_ALIGNMENT);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        JLabel l = small(label);
        l.setPreferredSize(new Dimension(100, 20));
        field.setFont(FONT_MONO);
        field.setBackground(C_HEADER_BG);
        field.setForeground(C_TEXT_HEAD);
        field.setCaretColor(C_TEXT_HEAD);
        JButton b = Widgets.ghost(btnText);
        b.addActionListener(e -> action.run());
        p.add(l, BorderLayout.WEST);
        p.add(field, BorderLayout.CENTER);
        p.add(b, BorderLayout.EAST);
        return p;
    }

    private static void style(JCheckBox cb, boolean bold) {
        cb.setFont(bold ? FONT_UI_B : FONT_UI);
        cb.setForeground(C_TEXT_HEAD);
        cb.setBackground(C_SURFACE);
        cb.setAlignmentX(LEFT_ALIGNMENT);
    }

    private static JLabel small(String t) {
        JLabel l = new JLabel(t);
        l.setFont(Widgets.UI_SMALL);
        l.setForeground(C_TEXT_MUTED);
        l.setAlignmentX(LEFT_ALIGNMENT);
        return l;
    }
}
