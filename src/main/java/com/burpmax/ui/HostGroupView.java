package com.burpmax.ui;

import com.burpmax.model.Finding;
import com.burpmax.util.HostFormats;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;

import static com.burpmax.ui.Theme.*;

/**
 * Host-centric view of the findings (like a vulnerability scanner's "by host" report).
 * Hosts are ordered worst-first and show per-severity counts; expanding one lists its findings.
 * Hostname-less applications (plain IP addresses) get their own entry like any other host.
 * A finding that affects several hosts appears under each of them.
 */
final class HostGroupView extends JPanel {

    @java.io.Serial
    private static final long serialVersionUID = 1L;

    @FunctionalInterface
    interface ContextHandler { void show(Component invoker, int x, int y, List<Finding> findings); }

    private static final List<String> SEV_ORDER = List.of(
            Finding.SEV_CRITICAL, Finding.SEV_HIGH, Finding.SEV_MEDIUM, Finding.SEV_LOW, Finding.SEV_INFO);

    /** Tree node payload for a host. */
    private record HostNode(String label, boolean ip, List<Finding> findings, int[] counts) {
        @Override public String toString() { return label; }
    }

    private final JTree tree = new JTree();
    private final JTextField search = new JTextField();
    private final JLabel summary = new JLabel(" ");
    private final Consumer<Finding> onSelect;
    private final ContextHandler onContext;
    private transient List<Finding> source = List.of();

    HostGroupView(Consumer<Finding> onSelect, ContextHandler onContext) {
        super(new BorderLayout());
        this.onSelect = onSelect;
        this.onContext = onContext;
        setBackground(C_ROOT);

        search.setFont(FONT_UI);
        search.setBackground(C_SURFACE);
        search.setForeground(C_TEXT);
        search.setCaretColor(C_TEXT);
        search.setToolTipText("Filter hosts: hostname, IP, port or finding name");
        search.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(C_BORDER, 1), BorderFactory.createEmptyBorder(3, 6, 3, 6)));
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e)  { rebuild(); }
            public void removeUpdate(DocumentEvent e)  { rebuild(); }
            public void changedUpdate(DocumentEvent e) { rebuild(); }
        });

        summary.setFont(Widgets.UI_SMALL);
        summary.setForeground(C_TEXT_MUTED);
        JPanel top = new JPanel(new BorderLayout(0, 4));
        top.setOpaque(false);
        top.setBorder(BorderFactory.createEmptyBorder(8, 10, 6, 10));
        top.add(search, BorderLayout.NORTH);
        top.add(summary, BorderLayout.SOUTH);
        add(top, BorderLayout.NORTH);

        tree.setRootVisible(false);
        tree.setShowsRootHandles(true);
        tree.setBackground(C_ROOT);
        tree.setRowHeight(24);
        tree.setCellRenderer(new Renderer());
        tree.getSelectionModel().setSelectionMode(TreeSelectionModel.DISCONTIGUOUS_TREE_SELECTION);
        tree.addTreeSelectionListener(e -> {
            TreePath p = e.getNewLeadSelectionPath();
            if (p != null && ((DefaultMutableTreeNode) p.getLastPathComponent()).getUserObject() instanceof Finding f) {
                onSelect.accept(f);
            }
        });
        tree.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e)  { popup(e); }
            @Override public void mouseReleased(MouseEvent e) { popup(e); }
        });
        JScrollPane sp = new JScrollPane(tree);
        sp.setBorder(BorderFactory.createEmptyBorder());
        sp.getViewport().setBackground(C_ROOT);
        add(sp, BorderLayout.CENTER);
    }

    void expandAllForTest() { for (int i = 0; i < tree.getRowCount(); i++) tree.expandRow(i); }

    void setFindings(List<Finding> findings) {
        this.source = findings == null ? List.of() : findings;
        rebuild();
    }

    // ── Build ─────────────────────────────────────────────────────────────────

    private void rebuild() {
        String q = search.getText().trim().toLowerCase(Locale.ROOT);

        // host label -> findings (LinkedHashMap keeps insertion order before we sort)
        Map<String, List<Finding>> byHost = new LinkedHashMap<>();
        Map<String, Boolean> isIp = new HashMap<>();
        for (Finding f : source) {
            Set<String> seen = new LinkedHashSet<>();
            for (HostFormats.Target t : HostFormats.targets(List.of(f))) {
                boolean def = ("https".equals(t.scheme()) && t.port() == 443) || ("http".equals(t.scheme()) && t.port() == 80);
                String label = t.host() + (def ? "" : ":" + t.port());
                if (seen.add(label)) { byHost.computeIfAbsent(label, k -> new ArrayList<>()).add(f); isIp.put(label, t.isIpLiteral()); }
            }
            if (seen.isEmpty()) {
                // No parsable URL at all: fall back to the stored host so nothing is silently dropped.
                String h = f.host == null || f.host.isBlank() ? "(unknown host)" : f.host;
                byHost.computeIfAbsent(h, k -> new ArrayList<>()).add(f);
                isIp.put(h, HostFormats.isIpLiteral(h));
            }
        }

        List<HostNode> hosts = new ArrayList<>();
        for (Map.Entry<String, List<Finding>> e : byHost.entrySet()) {
            List<Finding> fs = e.getValue();
            if (!q.isEmpty() && !e.getKey().toLowerCase(Locale.ROOT).contains(q)) {
                fs = fs.stream().filter(f -> f.name != null && f.name.toLowerCase(Locale.ROOT).contains(q)).toList();
                if (fs.isEmpty()) continue;
            }
            int[] c = new int[SEV_ORDER.size()];
            for (Finding f : fs) { int i = SEV_ORDER.indexOf(f.effectiveSeverity()); if (i >= 0) c[i]++; }
            hosts.add(new HostNode(e.getKey(), isIp.getOrDefault(e.getKey(), false), new ArrayList<>(fs), c));
        }
        hosts.sort(Comparator
                .comparing((HostNode h) -> worst(h)).thenComparing(h -> -h.findings().size())
                .thenComparing(HostNode::label, String.CASE_INSENSITIVE_ORDER));

        // remember expanded hosts across rebuilds
        Set<String> open = new HashSet<>();
        DefaultMutableTreeNode oldRoot = tree.getModel().getRoot() instanceof DefaultMutableTreeNode r ? r : null;
        if (oldRoot != null) for (int i = 0; i < oldRoot.getChildCount(); i++) {
            DefaultMutableTreeNode n = (DefaultMutableTreeNode) oldRoot.getChildAt(i);
            if (tree.isExpanded(new TreePath(n.getPath()))) open.add(n.getUserObject().toString());
        }

        DefaultMutableTreeNode root = new DefaultMutableTreeNode("hosts");
        for (HostNode h : hosts) {
            DefaultMutableTreeNode hn = new DefaultMutableTreeNode(h);
            List<Finding> sorted = new ArrayList<>(h.findings());
            sorted.sort(Comparator.comparingInt((Finding f) -> SEV_ORDER.indexOf(f.effectiveSeverity()))
                    .thenComparing(f -> f.name == null ? "" : f.name));
            for (Finding f : sorted) hn.add(new DefaultMutableTreeNode(f));
            root.add(hn);
        }
        tree.setModel(new DefaultTreeModel(root));
        for (int i = 0; i < root.getChildCount(); i++) {
            DefaultMutableTreeNode n = (DefaultMutableTreeNode) root.getChildAt(i);
            if (open.contains(n.getUserObject().toString()) || (!q.isEmpty() && hosts.size() <= 8)) {
                tree.expandPath(new TreePath(n.getPath()));
            }
        }
        int total = hosts.stream().mapToInt(h -> h.findings().size()).sum();
        summary.setText(hosts.size() + (hosts.size() == 1 ? " host" : " hosts") + "  ·  " + total + " findings");
    }

    private static int worst(HostNode h) {
        for (int i = 0; i < h.counts().length; i++) if (h.counts()[i] > 0) return i;
        return SEV_ORDER.size();
    }

    // ── Interaction ───────────────────────────────────────────────────────────

    private void popup(MouseEvent e) {
        if (!e.isPopupTrigger()) return;
        TreePath at = tree.getPathForLocation(e.getX(), e.getY());
        if (at == null) return;
        if (!tree.isPathSelected(at)) tree.setSelectionPath(at);
        LinkedHashSet<Finding> picked = new LinkedHashSet<>();
        TreePath[] paths = tree.getSelectionPaths();
        if (paths != null) for (TreePath p : paths) {
            Object o = ((DefaultMutableTreeNode) p.getLastPathComponent()).getUserObject();
            if (o instanceof HostNode h) picked.addAll(h.findings());
            else if (o instanceof Finding f) picked.add(f);
        }
        if (!picked.isEmpty()) onContext.show(tree, e.getX(), e.getY(), new ArrayList<>(picked));
    }

    // ── Rendering ─────────────────────────────────────────────────────────────

    private static Color sevColor(String sev) {
        if (sev == null) return C_TEXT_MUTED;
        return switch (sev) {
            case Finding.SEV_CRITICAL -> C_CRITICAL;
            case Finding.SEV_HIGH -> C_HIGH;
            case Finding.SEV_MEDIUM -> C_MEDIUM;
            case Finding.SEV_LOW -> C_LOW;
            default -> C_INFO;
        };
    }

    /**
     * Draws coloured text segments itself: no HTML (Burp's look and feel can show HTML as raw text)
     * and no nested components.
     */
    private static final class SegRow extends JComponent {
        @java.io.Serial private static final long serialVersionUID = 1L;
        private final transient List<Object[]> segs = new ArrayList<>();   // {String text, Font font, Color color}
        private boolean selected;

        SegRow add(String text, Font f, Color c) { segs.add(new Object[]{text, f, c}); return this; }
        SegRow selected(boolean s) { selected = s; return this; }

        @Override public Dimension getPreferredSize() {
            int w = 6, h = 20;
            for (Object[] s : segs) {
                FontMetrics fm = getFontMetrics((Font) s[1]);
                w += fm.stringWidth((String) s[0]) + 8;
                h = Math.max(h, fm.getHeight() + 6);
            }
            return new Dimension(w, h);
        }

        @Override protected void paintComponent(Graphics g0) {
            Graphics2D g = (Graphics2D) g0.create();
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            g.setColor(selected ? C_SEL_ROW : C_ROOT);
            g.fillRect(0, 0, getWidth(), getHeight());
            int x = 3;
            for (Object[] s : segs) {
                Font f = (Font) s[1];
                g.setFont(f);
                g.setColor((Color) s[2]);
                FontMetrics fm = g.getFontMetrics();
                g.drawString((String) s[0], x, (getHeight() - fm.getHeight()) / 2 + fm.getAscent());
                x += fm.stringWidth((String) s[0]) + 8;
            }
            g.dispose();
        }
    }

    private static final class Renderer implements javax.swing.tree.TreeCellRenderer {
        private static final String[] AB = {"C", "H", "M", "L", "I"};

        @Override public Component getTreeCellRendererComponent(JTree t, Object value, boolean sel,
                boolean exp, boolean leaf, int row, boolean focus) {
            SegRow r = new SegRow().selected(sel);
            Object o = ((DefaultMutableTreeNode) value).getUserObject();
            if (o instanceof HostNode h) {
                r.add(h.label(), new Font("Arial", Font.BOLD, 12), C_TEXT_HEAD);
                if (h.ip()) r.add("IP", Widgets.UI_TINY, C_TEXT_MUTED);
                for (int i = 0; i < h.counts().length; i++) {
                    if (h.counts()[i] > 0) r.add(AB[i] + " " + h.counts()[i], Widgets.UI_TINY, sevColor(SEV_ORDER.get(i)));
                }
            } else if (o instanceof Finding f) {
                r.add("\u25CF", FONT_UI, sevColor(f.effectiveSeverity()));
                r.add((f.name == null ? "" : f.name) + (f.suppressed ? "  (FP)" : ""), FONT_UI, f.suppressed ? C_TEXT_MUTED : C_TEXT);
            } else {
                r.add(String.valueOf(o), FONT_UI, C_TEXT);
            }
            return r;
        }
    }
}
