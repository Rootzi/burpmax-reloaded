package com.burpmax.ui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;

/** Scan-dialog section: limit the active scan to chosen hosts (default: every in-scope host). */
final class HostScopePanel extends JPanel {

    private static final long serialVersionUID = 1L;
    private final transient Map<String, JCheckBox> boxes = new LinkedHashMap<>();
    private final JTextField extra = new JTextField();

    HostScopePanel(IBurpExtenderCallbacks cb, Runnable relayout) {
        super();
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setOpaque(false);

        Map<String, Integer> counts = new TreeMap<>();
        try {
            IHttpRequestResponse[] items = cb.getSiteMap(null);
            if (items != null) {
                int n = 0;
                for (IHttpRequestResponse it : items) {
                    if (++n > 100_000) break;
                    try {
                        java.net.URL u = cb.getHelpers().analyzeRequest(it).getUrl();
                        if (u == null || !cb.isInScope(u)) continue;
                        String h = u.getHost() + (u.getPort() > 0 && u.getPort() != u.getDefaultPort() ? ":" + u.getPort() : "");
                        counts.merge(h.toLowerCase(), 1, Integer::sum);
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception ignored) {}

        JTextArea hint = Widgets.wrapped("Untick a host to leave it out of this scan. Leave everything ticked to scan the whole scope.", new Color(0x94, 0xA3, 0xB8));
        hint.setAlignmentX(LEFT_ALIGNMENT);
        add(hint);
        add(Box.createVerticalStrut(6));

        JPanel list = new JPanel();
        list.setLayout(new BoxLayout(list, BoxLayout.Y_AXIS));
        list.setOpaque(false);
        if (counts.isEmpty()) {
            JLabel none = new JLabel("No in-scope hosts in the site map yet. Add hosts manually below, or browse the target first.");
            none.setAlignmentX(LEFT_ALIGNMENT);
            list.add(none);
        }
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            JCheckBox b = new JCheckBox(e.getKey() + "   (" + e.getValue() + " URL" + (e.getValue() == 1 ? "" : "s") + ")", true);
            b.setOpaque(false);
            b.setAlignmentX(LEFT_ALIGNMENT);
            boxes.put(e.getKey(), b);
            list.add(b);
        }
        JScrollPane sp = new JScrollPane(list);
        sp.setAlignmentX(LEFT_ALIGNMENT);
        sp.setPreferredSize(new Dimension(420, Math.min(170, 26 + 22 * Math.max(1, counts.size()))));
        sp.setMaximumSize(new Dimension(Integer.MAX_VALUE, 170));
        add(sp);
        add(Box.createVerticalStrut(6));

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        btns.setOpaque(false);
        btns.setAlignmentX(LEFT_ALIGNMENT);
        JButton all = new JButton("Select all"), none = new JButton("Select none");
        all.addActionListener(e -> boxes.values().forEach(b -> b.setSelected(true)));
        none.addActionListener(e -> boxes.values().forEach(b -> b.setSelected(false)));
        btns.add(all); btns.add(none);
        add(btns);
        add(Box.createVerticalStrut(6));

        JTextArea l2 = Widgets.wrapped("Or type hosts to scan (comma or space separated; host, host:port or *.example.com). These are added to any ticked hosts.", new Color(0x94, 0xA3, 0xB8));
        l2.setAlignmentX(LEFT_ALIGNMENT);
        add(l2);
        extra.setAlignmentX(LEFT_ALIGNMENT);
        extra.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        add(extra);
    }

    /** null = no restriction (everything ticked, nothing typed). */
    Set<String> selectedHosts() {
        Set<String> typed = typedHosts();
        boolean allTicked = !boxes.isEmpty() && boxes.values().stream().allMatch(AbstractButton::isSelected);
        if (allTicked && typed.isEmpty()) return null;
        if (boxes.isEmpty() && typed.isEmpty()) return null;   // nothing known: do not restrict
        Set<String> out = new LinkedHashSet<>();
        boxes.forEach((h, b) -> { if (b.isSelected()) out.add(h); });
        out.addAll(typed);
        return out;
    }

    /** True when the user has narrowed the list to nothing. */
    boolean nothingChosen() {
        Set<String> s = selectedHosts();
        return s != null && s.isEmpty();
    }

    private Set<String> typedHosts() {
        Set<String> out = new LinkedHashSet<>();
        for (String t : extra.getText().split("[,\\s]+")) {
            String h = t.trim().toLowerCase().replaceFirst("^https?://", "").replaceAll("/.*$", "");
            if (!h.isEmpty()) out.add(h);
        }
        return out;
    }
}
