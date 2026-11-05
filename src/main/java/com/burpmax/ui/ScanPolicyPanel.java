package com.burpmax.ui;

import com.burpmax.active.ProbeCatalog;
import com.burpmax.active.ProbeCatalog.Module;
import com.burpmax.active.ProbeCatalog.Risk;
import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.function.IntSupplier;

import static com.burpmax.ui.Theme.*;

/**
 * Scan-policy picker for the Active Scan dialog.
 *
 * Semantics are unchanged: a TICKED box means that module is SKIPPED.
 * Modules are grouped by category (collapsible) and carry a risk badge; families such as
 * SQLi have a header box that ticks every member. Profiles bundle the ticked set with the
 * write-budget and replay settings. Built-in profiles can never be overwritten: type a new name
 * into the profile box and press "Save config" to keep your own.
 */
final class ScanPolicyPanel extends JPanel {

    @java.io.Serial
    private static final long serialVersionUID = 1L;

    private static final String SETTING = "burpmax.scanprofiles.v1";
    private static final Color RISK_LOW  = new Color(0x34, 0xD3, 0x99);
    private static final Color RISK_MOD  = new Color(0xFB, 0xBF, 0x24);
    private static final Color RISK_HIGH = new Color(0xF8, 0x71, 0x71);

    /** One saved profile. */
    private record Profile(String name, Set<String> skips, int messaging, int auth, int other,
                           boolean replayReadOnly, String nuclei) { }

    private final transient IBurpExtenderCallbacks callbacks;
    private final transient IntSupplier endpointCount;
    private final Runnable relayout;

    private final Map<String, JCheckBox> boxes = new LinkedHashMap<>();         // skipKey -> box
    private final Map<String, JCheckBox> familyBoxes = new LinkedHashMap<>();   // family  -> header box
    private final Map<String, CollapsibleSection> sections = new LinkedHashMap<>();
    private final JComboBox<String> profileBox = new JComboBox<>();
    private final JLabel profileNote = new JLabel(" ");
    private final JTextArea plan = Widgets.wrapped(" ", C_TEXT_DIM);
    private final JSpinner budMsg  = spinner(3, 0, 50);
    private final JSpinner budAuth = spinner(15, 0, 500);
    private final JSpinner budOther = spinner(60, 0, 5000);
    private final JCheckBox replayRo = new JCheckBox("Replay-style checks (IDOR, Auth Bypass, CSRF) only on GET/HEAD/OPTIONS");
    private final Map<String, Profile> custom = new LinkedHashMap<>();
    private boolean adjusting;
    private final NucleiPanel nuclei;

    ScanPolicyPanel(IBurpExtenderCallbacks callbacks, Set<String> initialSkips, int[] budgets,
                    boolean replayReadOnly, IntSupplier endpointCount, Runnable relayout, NucleiPanel nuclei) {
        this.nuclei = nuclei;
        this.callbacks = callbacks;
        this.endpointCount = endpointCount;
        this.relayout = relayout;
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBackground(C_SURFACE);
        setAlignmentX(LEFT_ALIGNMENT);

        loadCustom();
        add(profileRow());
        add(Box.createVerticalStrut(4));
        profileNote.setFont(Widgets.UI_SMALL);
        profileNote.setForeground(C_TEXT_MUTED);
        profileNote.setAlignmentX(LEFT_ALIGNMENT);
        add(profileNote);
        add(Box.createVerticalStrut(8));

        add(Widgets.wrapped("Tick a module to SKIP it. Badges: LOW = read-only, MOD = many requests or replays your request, "
                + "HIGH = writes data or bursts traffic.", C_TEXT_MUTED));
        add(Box.createVerticalStrut(6));

        for (String cat : ProbeCatalog.categories()) add(categorySection(cat));

        add(Box.createVerticalStrut(8));
        add(safetyBlock());
        add(Box.createVerticalStrut(8));
        add(plan);

        // initial state: the saved skips from the last scan, else the recommended profile
        Set<String> init = initialSkips == null ? Set.of() : initialSkips;
        if (init.isEmpty() && budgets == null) {
            profileBox.setSelectedItem(ProbeCatalog.BUILT_IN_PROFILES.get(0));
            applyProfileByName(ProbeCatalog.BUILT_IN_PROFILES.get(0));
        } else {
            applySkips(init);
            if (budgets != null) { budMsg.setValue(budgets[0]); budAuth.setValue(budgets[1]); budOther.setValue(budgets[2]); }
            replayRo.setSelected(replayReadOnly);
            adjusting = true;
            try {
                String m = matchingProfile();
                if (m != null) profileBox.setSelectedItem(m); else profileBox.setSelectedItem("Last scan settings");
            } finally { adjusting = false; }
            refresh();
        }
    }

    Map<String, CollapsibleSection> sectionsForTest() { return sections; }

    // ── Public results ────────────────────────────────────────────────────────

    /** Skip keys to hand to ActiveScanner.setSkipProbes (family key when every member is ticked). */
    Set<String> skips() {
        Set<String> out = new LinkedHashSet<>();
        for (Map.Entry<String, JCheckBox> e : boxes.entrySet()) if (e.getValue().isSelected()) out.add(e.getKey());
        for (Map.Entry<String, JCheckBox> e : familyBoxes.entrySet()) if (e.getValue().isSelected()) out.add(e.getKey());
        return out;
    }
    int[] budgets() { return new int[]{ (Integer) budMsg.getValue(), (Integer) budAuth.getValue(), (Integer) budOther.getValue() }; }
    boolean replayReadOnly() { return replayRo.isSelected(); }

    // ── Profile row ───────────────────────────────────────────────────────────

    private JComponent profileRow() {
        JPanel row = new JPanel(new BorderLayout(6, 0));
        row.setBackground(C_SURFACE);
        row.setAlignmentX(LEFT_ALIGNMENT);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));

        JLabel lbl = new JLabel("Profile");
        lbl.setFont(Widgets.UI_SMALL);
        lbl.setForeground(C_TEXT_MUTED);

        profileBox.setEditable(true);
        profileBox.setFont(Theme.FONT_UI);
        reloadProfileItems(ProbeCatalog.BUILT_IN_PROFILES.get(0));
        profileBox.addActionListener(e -> {
            if (adjusting) return;
            if ("comboBoxChanged".equals(e.getActionCommand()) && profileBox.getSelectedIndex() >= 0) {
                applyProfileByName((String) profileBox.getSelectedItem());
            }
        });

        JButton save = Widgets.ghost("Save config");
        save.setToolTipText("Type a new name in the profile box, then save. Built-in profiles can't be overwritten.");
        save.addActionListener(e -> saveProfile());
        JButton del = Widgets.ghost("Delete");
        del.addActionListener(e -> deleteProfile());

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        btns.setOpaque(false);
        btns.add(save);
        btns.add(del);

        row.add(lbl, BorderLayout.WEST);
        row.add(profileBox, BorderLayout.CENTER);
        row.add(btns, BorderLayout.EAST);
        return row;
    }

    private void reloadProfileItems(String select) {
        adjusting = true;
        try {
            profileBox.removeAllItems();
            for (String n : ProbeCatalog.BUILT_IN_PROFILES) profileBox.addItem(n);
            for (String n : custom.keySet()) profileBox.addItem(n);
            profileBox.setSelectedItem(select);
        } finally { adjusting = false; }
    }

    private void applyProfileByName(String name) {
        if (name == null) return;
        Profile p = custom.get(name);
        if (p != null) {
            apply(p);
            profileNote.setText("Custom profile — edit and press Save config to update it.");
            return;
        }
        Set<String> s = ProbeCatalog.builtInSkips(name);
        if (s == null) return;
        apply(new Profile(name, s, 3, 15, 60, !"Full (lab / CTF)".equals(name), null));
        if (nuclei != null) nuclei.applyBuiltIn(name);
        profileNote.setText("Built-in profile (read-only). Change anything, then type a new name and Save config to keep it.");
    }

    private void apply(Profile p) {
        applySkips(p.skips());
        budMsg.setValue(p.messaging());
        budAuth.setValue(p.auth());
        budOther.setValue(p.other());
        replayRo.setSelected(p.replayReadOnly());
        if (nuclei != null && p.nuclei() != null) nuclei.applyEncoded(p.nuclei());
        refresh();
    }

    private void saveProfile() {
        Object sel = profileBox.getEditor().getItem();
        String name = sel == null ? "" : sel.toString().trim().replaceAll("[\\t\\r\\n|]", " ");
        if (name.isEmpty()) { toast("Type a name for the profile first."); return; }
        if (ProbeCatalog.BUILT_IN_PROFILES.contains(name)) {
            toast("\"" + name + "\" is built in and can't be overwritten. Type a new name.");
            return;
        }
        int[] b = budgets();
        custom.put(name, new Profile(name, skips(), b[0], b[1], b[2], replayReadOnly(), nuclei == null ? null : nuclei.encode()));
        persistCustom();
        reloadProfileItems(name);
        profileNote.setText("Saved \"" + name + "\".");
    }

    private void deleteProfile() {
        Object sel = profileBox.getSelectedItem();
        String name = sel == null ? "" : sel.toString();
        if (!custom.containsKey(name)) { toast("Only your own profiles can be deleted."); return; }
        custom.remove(name);
        persistCustom();
        reloadProfileItems(ProbeCatalog.BUILT_IN_PROFILES.get(0));
        applyProfileByName(ProbeCatalog.BUILT_IN_PROFILES.get(0));
    }

    private void toast(String msg) {
        profileNote.setForeground(RISK_MOD);
        profileNote.setText(msg);
        javax.swing.Timer t = new javax.swing.Timer(3500, e -> profileNote.setForeground(C_TEXT_MUTED));
        t.setRepeats(false);
        t.start();
    }

    private String matchingProfile() {
        Set<String> cur = skips();
        for (String n : ProbeCatalog.BUILT_IN_PROFILES) {
            Set<String> b = ProbeCatalog.builtInSkips(n);
            if (b != null && expand(b).equals(expand(cur))) return n;
        }
        return null;
    }

    private static Set<String> expand(Set<String> s) {
        Set<String> out = new TreeSet<>();
        for (Module m : ProbeCatalog.all()) if (ProbeCatalog.isSkipped(m.entry(), s)) out.add(m.entry());
        return out;
    }

    // ── Persistence (plain text, one profile per line) ────────────────────────

    private void loadCustom() {
        try {
            String raw = callbacks == null ? null : callbacks.loadExtensionSetting(SETTING);
            if (raw == null || raw.isBlank()) return;
            for (String line : raw.split("\n")) {
                String[] f = line.split("\t", -1);
                if (f.length < 5 || f[0].isBlank() || ProbeCatalog.BUILT_IN_PROFILES.contains(f[0])) continue;
                Set<String> skips = new LinkedHashSet<>();
                for (String k : f[4].split(",")) if (!k.isBlank()) skips.add(k);
                String[] b = f[1].split(",");
                custom.put(f[0], new Profile(f[0], skips, Integer.parseInt(b[0]), Integer.parseInt(b[1]),
                        Integer.parseInt(b[2]), "1".equals(f[3]), f.length > 5 && !f[5].isEmpty() ? f[5] : null));
            }
        } catch (Exception ignored) { /* corrupt setting: start with built-ins only */ }
    }

    private void persistCustom() {
        if (callbacks == null) return;
        StringBuilder sb = new StringBuilder();
        for (Profile p : custom.values()) {
            sb.append(p.name()).append('\t').append(p.messaging()).append(',').append(p.auth()).append(',').append(p.other())
              .append('\t').append("").append('\t').append(p.replayReadOnly() ? "1" : "0")
              .append('\t').append(String.join(",", p.skips()))
              .append('\t').append(p.nuclei() == null ? "" : p.nuclei()).append('\n');
        }
        try { callbacks.saveExtensionSetting(SETTING, sb.toString()); } catch (Exception ignored) { }
    }

    // ── Module grid ───────────────────────────────────────────────────────────

    private CollapsibleSection categorySection(String cat) {
        JPanel body = new JPanel();
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        body.setBackground(C_SURFACE);

        // group by family, keeping catalog order
        LinkedHashMap<String, List<Module>> byFam = new LinkedHashMap<>();
        for (Module m : ProbeCatalog.inCategory(cat)) byFam.computeIfAbsent(m.family(), k -> new ArrayList<>()).add(m);

        for (Map.Entry<String, List<Module>> fe : byFam.entrySet()) {
            List<Module> mods = fe.getValue();
            boolean grouped = mods.size() > 1;
            if (grouped) {
                JCheckBox head = box(fe.getKey() + "  (all)", Risk.LOW, "Skip every " + fe.getKey() + " module", true);
                familyBoxes.put(fe.getKey(), head);
                head.addActionListener(e -> {
                    for (Module m : mods) boxes.get(m.skipKey()).setSelected(head.isSelected());
                    refresh();
                });
                body.add(head);
            }
            for (Module m : mods) {
                JCheckBox cb = box(m.entry(), m.risk(), m.effect(), false);
                if (grouped) cb.setBorder(BorderFactory.createEmptyBorder(0, 22, 0, 0));
                boxes.put(m.skipKey(), cb);
                cb.addActionListener(e -> {
                    if (grouped) {
                        boolean all = true;
                        for (Module x : mods) all &= boxes.get(x.skipKey()).isSelected();
                        familyBoxes.get(fe.getKey()).setSelected(all);
                    }
                    refresh();
                });
                body.add(cb);
            }
        }

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        btns.setOpaque(false);
        btns.setAlignmentX(LEFT_ALIGNMENT);
        JButton none = Widgets.ghost("Skip none");
        JButton all = Widgets.ghost("Skip all");
        none.addActionListener(e -> setCategory(cat, false));
        all.addActionListener(e -> setCategory(cat, true));
        btns.add(none);
        btns.add(all);
        body.add(Box.createVerticalStrut(4));
        body.add(btns);

        CollapsibleSection sec = new CollapsibleSection(cat, body, false);
        sec.onToggle(open -> relayout.run());
        sections.put(cat, sec);
        return sec;
    }

    private void setCategory(String cat, boolean skip) {
        for (Module m : ProbeCatalog.inCategory(cat)) boxes.get(m.skipKey()).setSelected(skip);
        for (JCheckBox fb : familyBoxes.values()) fb.setSelected(false);
        syncFamilies();
        refresh();
    }

    private JCheckBox box(String label, Risk risk, String effect, boolean head) {
        JCheckBox cb = new JCheckBox(label + (head ? "" : "  [" + (risk == Risk.HIGH ? "HIGH" : risk == Risk.MODERATE ? "MOD" : "LOW") + "]"));
        cb.setFont(head ? Theme.FONT_UI_B : Theme.FONT_UI);
        // The risk shows in the label text; colour the whole label so it is scannable.
        cb.setForeground(head ? C_TEXT_HEAD : risk == Risk.HIGH ? RISK_HIGH : risk == Risk.MODERATE ? RISK_MOD : C_TEXT_HEAD);
        cb.setBackground(C_SURFACE);
        cb.setAlignmentX(LEFT_ALIGNMENT);
        cb.setToolTipText("<html><div style='width:320px'>" + escape(effect) + "</div></html>");
        return cb;
    }

    private static String escape(String s) { return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;"); }

    private void applySkips(Set<String> skip) {
        for (Module m : ProbeCatalog.all()) boxes.get(m.skipKey()).setSelected(ProbeCatalog.isSkipped(m.entry(), skip));
        syncFamilies();
    }

    private void syncFamilies() {
        for (Map.Entry<String, JCheckBox> fe : familyBoxes.entrySet()) {
            boolean all = true;
            for (Module m : ProbeCatalog.inFamily(fe.getKey())) all &= boxes.get(m.skipKey()).isSelected();
            fe.getValue().setSelected(all);
        }
    }

    // ── Safety block + plan preview ───────────────────────────────────────────

    private JComponent safetyBlock() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBackground(C_SURFACE);

        JTextArea rules = new JTextArea(
                "Always on, cannot be switched off:\n"
              + " • Payloads that delete, drop, truncate, shut down or write files are never sent.\n"
              + " • Boolean/OR tautologies and NoSQL widening operators are never sent on write requests.\n"
              + " • DELETE and destructive-named endpoints are never replayed.\n"
              + " • Writes per endpoint are capped (below), so a contact form can't be flooded.");
        rules.setEditable(false);
        rules.setOpaque(false);
        rules.setLineWrap(true);
        rules.setWrapStyleWord(true);
        rules.setColumns(44);
        rules.setFont(Widgets.UI_SMALL);
        rules.setForeground(C_TEXT_MUTED);
        rules.setAlignmentX(LEFT_ALIGNMENT);
        p.add(rules);
        p.add(Box.createVerticalStrut(6));

        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        row.setOpaque(false);
        row.setAlignmentX(LEFT_ALIGNMENT);
        row.add(small("Max writes per endpoint — contact/comment forms"));
        row.add(budMsg);
        row.add(small("login/auth"));
        row.add(budAuth);
        row.add(small("other"));
        row.add(budOther);
        p.add(row);
        p.add(Box.createVerticalStrut(4));

        replayRo.setFont(Widgets.UI_SMALL);
        replayRo.setForeground(C_TEXT_HEAD);
        replayRo.setBackground(C_SURFACE);
        replayRo.setAlignmentX(LEFT_ALIGNMENT);
        replayRo.setToolTipText("Untick to let these modules re-send your captured POST/PUT requests with changes.");
        replayRo.addActionListener(e -> refresh());
        p.add(replayRo);

        for (JSpinner s : List.of(budMsg, budAuth, budOther)) s.addChangeListener(e -> refresh());
        return new CollapsibleSection("Safety limits", p, false);
    }

    private static JComponent budgetRow(String label, JSpinner sp) {
        JPanel r = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 1));
        r.setOpaque(false);
        r.setAlignmentX(LEFT_ALIGNMENT);
        r.add(sp);
        r.add(small(label));
        return r;
    }

    private static JLabel small(String t) {
        JLabel l = new JLabel(t);
        l.setFont(Widgets.UI_SMALL);
        l.setForeground(C_TEXT_MUTED);
        return l;
    }

    private static JSpinner spinner(int v, int lo, int hi) {
        JSpinner s = new JSpinner(new SpinnerNumberModel(v, lo, hi, 1));
        s.setPreferredSize(new Dimension(62, 22));
        return s;
    }

    /** Update per-category summaries and the "what will run" line. */
    private void refresh() {
        int run = 0, total = 0, high = 0, mod = 0;
        for (String cat : ProbeCatalog.categories()) {
            int skipped = 0, n = 0;
            for (Module m : ProbeCatalog.inCategory(cat)) {
                n++; total++;
                boolean sk = boxes.get(m.skipKey()).isSelected();
                if (sk) skipped++; else {
                    run++;
                    if (m.risk() == Risk.HIGH) high++; else if (m.risk() == Risk.MODERATE) mod++;
                }
            }
            sections.get(cat).setSummary((n - skipped) + " of " + n + " run" + (skipped > 0 ? "  ·  " + skipped + " skipped" : ""));
        }
        int eps = 0;
        try { eps = endpointCount == null ? 0 : endpointCount.getAsInt(); } catch (Exception ignored) { }
        plan.setText("Scan plan: " + run + " of " + total + " modules x "
                + (eps > 0 ? eps + " endpoints" : "all in-scope endpoints")
                + (eps > 0 ? " (up to " + (run * eps) + " module runs, each sending several requests)" : "")
                + "\nIncludes " + high + " high-risk and " + mod + " moderate-risk modules."
                + (replayRo.isSelected() ? " Replay checks stay read-only." : " Replay checks may re-send writes."));
        relayout.run();
    }
}
