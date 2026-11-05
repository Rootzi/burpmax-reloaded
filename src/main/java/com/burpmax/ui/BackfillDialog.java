package com.burpmax.ui;

import burp.IBurpExtenderCallbacks;
import com.burpmax.active.ActiveScanner;
import com.burpmax.active.ActiveScanner.BackfillOutcome;
import com.burpmax.active.ActiveScanner.BackfillStatus;
import com.burpmax.model.Finding;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/** "Backfill evidence": re-checks only the findings that have no captured traffic, then shows a results table. */
final class BackfillDialog {

    private BackfillDialog() {}

    private record Row(Finding f, String url, BackfillOutcome o) {}

    static String label(BackfillStatus s) {
        return switch (s) {
            case VALIDATED      -> "Evidence captured";
            case NOT_REPRODUCED -> "Could not reproduce";
            case FAILED         -> "Request failed";
            case BLOCKED        -> "Not run (scope/safety)";
            case UNSUPPORTED    -> "Skipped";
        };
    }

    static void start(Component parent, IBurpExtenderCallbacks callbacks, List<Finding> all,
                      java.util.Set<String> skips, boolean busy, Runnable onChanged) {
        if (busy) {
            JOptionPane.showMessageDialog(parent, "A scan is running. Cancel or wait for it to finish first.",
                    "Backfill evidence", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        List<Finding> todo = new ArrayList<>();
        for (Finding f : all) if (ActiveScanner.lacksEvidence(f)) todo.add(f);
        if (todo.isEmpty()) {
            JOptionPane.showMessageDialog(parent, "Every finding already has captured traffic. Nothing to backfill.",
                    "Backfill evidence", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JCheckBox active = new JCheckBox("Also re-probe injection-type findings (low-risk modules only)", true);
        JSpinner delay = new JSpinner(new SpinnerNumberModel(300, 0, 10000, 100));
        JTextArea info = new JTextArea(
                todo.size() + " of " + all.size() + " findings have no captured request/response.\n\n"
              + "Each one is re-fetched once with a plain GET of its URL (in-scope only) and checked again.\n"
              + "Evidence is attached only if the issue shows up again; nothing new is added to your findings.\n"
              + "Safety rules and your ticked skips still apply; time-based and replay modules never run here.");
        info.setEditable(false); info.setOpaque(false); info.setLineWrap(true); info.setWrapStyleWord(true);
        info.setColumns(52);
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        for (JComponent c : new JComponent[]{info, active}) { c.setAlignmentX(Component.LEFT_ALIGNMENT); p.add(c); p.add(Box.createVerticalStrut(8)); }
        JPanel dr = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        dr.setAlignmentX(Component.LEFT_ALIGNMENT);
        dr.add(new JLabel("Delay between requests (ms):  ")); dr.add(delay);
        p.add(dr);
        if (JOptionPane.showConfirmDialog(parent, p, "Backfill evidence",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION) return;

        final boolean allowActive = active.isSelected();
        final ActiveScanner sc = new ActiveScanner(callbacks, callbacks.getHelpers(), new com.burpmax.store.FindingStore());
        sc.setRequestDelayMs((Integer) delay.getValue());
        sc.setSkipProbes(skips);
        if (!sc.beginBackfill()) return;

        JDialog prog = new JDialog(SwingUtilities.getWindowAncestor(parent), "Backfilling evidence", Dialog.ModalityType.MODELESS);
        JProgressBar bar = new JProgressBar(0, todo.size());
        bar.setStringPainted(true);
        JLabel now = new JLabel(" ");
        JButton cancel = new JButton("Cancel");
        JPanel pp = new JPanel(new BorderLayout(6, 6));
        pp.setBorder(BorderFactory.createEmptyBorder(12, 14, 12, 14));
        pp.add(now, BorderLayout.NORTH); pp.add(bar, BorderLayout.CENTER); pp.add(cancel, BorderLayout.SOUTH);
        prog.setContentPane(pp); prog.setSize(480, 140); prog.setLocationRelativeTo(parent);
        cancel.addActionListener(e -> { sc.cancel(); cancel.setEnabled(false); now.setText("Cancelling..."); });
        prog.setVisible(true);

        List<Row> rows = new ArrayList<>();
        Thread t = new Thread(() -> {
            int i = 0;
            try {
                for (Finding f : todo) {
                    if (Thread.currentThread().isInterrupted()) break;
                    final int idx = ++i;
                    final String nm = f.name;
                    SwingUtilities.invokeLater(() -> { now.setText(idx + "/" + todo.size() + "  " + nm); bar.setValue(idx - 1); });
                    BackfillOutcome o = sc.backfillOne(f, allowActive);
                    rows.add(new Row(f, f.affectedEndpoints.isEmpty() ? f.url : f.affectedEndpoints.get(0).endpoint, o));
                    if (!sc.isRunning()) break;
                    if (o.status == BackfillStatus.FAILED && "Cancelled".equals(o.detail)) {
                        for (Finding rest : todo.subList(idx, todo.size()))
                            rows.add(new Row(rest, rest.url, new BackfillOutcome(BackfillStatus.UNSUPPORTED, "-", "Cancelled before it ran")));
                        break;
                    }
                }
            } finally {
                sc.endBackfill();
                SwingUtilities.invokeLater(() -> {
                    prog.dispose();
                    onChanged.run();
                    showResults(parent, rows);
                });
            }
        }, "burpmax-backfill");
        t.setDaemon(true);
        t.start();
    }

    private static void showResults(Component parent, List<Row> rows) {
        long ok = rows.stream().filter(r -> r.o().status == BackfillStatus.VALIDATED).count();
        String[] cols = {"Finding", "Severity", "URL", "Method", "Outcome", "Detail"};
        AbstractTableModel m = new AbstractTableModel() {
            public int getRowCount() { return rows.size(); }
            public int getColumnCount() { return cols.length; }
            public String getColumnName(int c) { return cols[c]; }
            public Object getValueAt(int r, int c) {
                Row x = rows.get(r);
                return switch (c) {
                    case 0 -> x.f().name;
                    case 1 -> x.f().effectiveSeverity();
                    case 2 -> x.url();
                    case 3 -> x.o().method;
                    case 4 -> label(x.o().status);
                    default -> x.o().detail;
                };
            }
        };
        JTable tbl = new JTable(m);
        tbl.setAutoCreateRowSorter(false);
        tbl.setRowSorter(new TableRowSorter<>(m));
        tbl.setRowHeight(22);
        int[] w = {200, 70, 260, 110, 150, 320};
        for (int i = 0; i < w.length; i++) tbl.getColumnModel().getColumn(i).setPreferredWidth(w[i]);
        tbl.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        tbl.getColumnModel().getColumn(4).setCellRenderer(new javax.swing.table.DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean foc, int r, int c) {
                Component comp = super.getTableCellRendererComponent(t, v, sel, foc, r, c);
                if (!sel) {
                    boolean good = "Evidence captured".equals(v);
                    comp.setForeground(good ? new Color(0x16, 0x8A, 0x3C) : new Color(0xC0, 0x39, 0x2B));
                }
                return comp;
            }
        });

        String summary = ok + " of " + rows.size() + " findings now have evidence; "
                + (rows.size() - ok) + " did not (see Outcome and Detail).";
        JDialog d = new JDialog(SwingUtilities.getWindowAncestor(parent), "Backfill results", Dialog.ModalityType.MODELESS);
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(new JLabel(summary));
        JButton copy = new JButton("Copy table"), csv = new JButton("Export CSV"), close = new JButton("Close");
        copy.addActionListener(e -> Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(toText(rows, "\t")), null));
        csv.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setSelectedFile(new File("burpmax-backfill-results.csv"));
            if (fc.showSaveDialog(d) != JFileChooser.APPROVE_OPTION) return;
            try { Files.write(fc.getSelectedFile().toPath(), toCsv(rows).getBytes(StandardCharsets.UTF_8)); }
            catch (Exception ex) { JOptionPane.showMessageDialog(d, "Could not save: " + ex.getMessage()); }
        });
        close.addActionListener(e -> d.dispose());
        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        bottom.add(copy); bottom.add(csv); bottom.add(close);
        d.getContentPane().add(top, BorderLayout.NORTH);
        d.getContentPane().add(Widgets.contrast(new JScrollPane(tbl)), BorderLayout.CENTER);
        d.getContentPane().add(bottom, BorderLayout.SOUTH);
        d.setSize(1000, 460);
        d.setLocationRelativeTo(parent);
        d.setVisible(true);
    }

    private static String toText(List<Row> rows, String sep) {
        StringBuilder sb = new StringBuilder("Finding" + sep + "Severity" + sep + "URL" + sep + "Method" + sep + "Outcome" + sep + "Detail\n");
        for (Row r : rows)
            sb.append(r.f().name).append(sep).append(r.f().effectiveSeverity()).append(sep).append(r.url()).append(sep)
              .append(r.o().method).append(sep).append(label(r.o().status)).append(sep).append(r.o().detail).append('\n');
        return sb.toString();
    }

    private static String q(String s) {
        String v = s == null ? "" : s;
        if (!v.isEmpty() && "=+-@".indexOf(v.charAt(0)) >= 0) v = "'" + v;   // spreadsheet formula guard
        return "\"" + v.replace("\"", "\"\"") + "\"";
    }

    private static String toCsv(List<Row> rows) {
        StringBuilder sb = new StringBuilder("Finding,Severity,URL,Method,Outcome,Detail\r\n");
        for (Row r : rows)
            sb.append(q(r.f().name)).append(',').append(q(r.f().effectiveSeverity())).append(',').append(q(r.url())).append(',')
              .append(q(r.o().method)).append(',').append(q(label(r.o().status))).append(',').append(q(r.o().detail)).append("\r\n");
        return sb.toString();
    }
}
