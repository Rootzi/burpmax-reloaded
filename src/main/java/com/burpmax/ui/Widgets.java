package com.burpmax.ui;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

import static com.burpmax.ui.Theme.*;

/** Small shared Swing helpers so new panels match the existing look without depending on UIBuilder internals. */
final class Widgets {

    private Widgets() { }

    static final Font MONO      = new Font(Font.MONOSPACED, Font.PLAIN, 12);
    static final Font MONO_BOLD = new Font(Font.MONOSPACED, Font.BOLD, 12);
    static final Font UI_SMALL  = new Font("Arial", Font.PLAIN, 11);
    static final Font UI_TINY   = new Font("Arial", Font.BOLD, 10);

    static final Color HIT_BG = new Color(250, 204, 21);
    static final Color HIT_FG = new Color(20, 24, 33);

    static JButton ghost(String text) {
        JButton b = new JButton(text);
        b.setBackground(C_BTN_GHOST_BG);
        b.setForeground(C_BTN_GHOST_FG);
        b.setFont(UI_SMALL);
        b.setFocusPainted(false);
        b.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(C_BTN_GHOST_BD, 1),
                BorderFactory.createEmptyBorder(2, 8, 2, 8)));
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        b.setOpaque(true);
        return b;
    }

    static JLabel caption(String text) {
        JLabel l = new JLabel(text);
        l.setFont(UI_TINY);
        l.setForeground(C_TEXT_MUTED);
        return l;
    }

    static void styleScroll(JScrollPane sp) {
        sp.setBorder(BorderFactory.createLineBorder(new Color(19, 30, 46), 1));
        sp.getViewport().setBackground(C_DEEP);
        sp.setBackground(C_DEEP);
    }

    static void copy(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(text == null ? "" : text), null);
    }

    /** Briefly relabel a button ("Copied") so the user gets feedback without a dialog. */
    static void flash(JButton b, String temp) {
        String orig = b.getText();
        b.setText(temp);
        Timer t = new Timer(900, e -> b.setText(orig));
        t.setRepeats(false);
        t.start();
    }

    /** Wrapped, read-only, transparent plain text (use instead of an HTML label). */
    static JTextArea wrapped(String text, Color fg) {
        JTextArea t = new JTextArea(text);
        t.setEditable(false);
        t.setFocusable(false);
        t.setOpaque(false);
        t.setLineWrap(true);
        t.setWrapStyleWord(true);
        t.setFont(UI_SMALL);
        t.setForeground(fg);
        t.setBorder(null);
        t.setAlignmentX(Component.LEFT_ALIGNMENT);
        return t;
    }

    /** A panel that follows the width of the scroll pane it sits in, so content wraps instead of clipping. */
    static final class TrackingPanel extends JPanel implements Scrollable {
        @java.io.Serial private static final long serialVersionUID = 1L;
        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(Rectangle r, int o, int d) { return 16; }
        @Override public int getScrollableBlockIncrement(Rectangle r, int o, int d) { return Math.max(32, r.height - 32); }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() { return false; }
    }

    /**
     * Makes the mouse wheel scroll {@code outer} even when the pointer is over a nested scroll pane,
     * text area, combo box or spinner (which otherwise swallow the wheel). Components added later are
     * picked up automatically.
     */
    static void forwardWheel(Container root, JScrollPane outer) {
        java.awt.event.MouseWheelListener fwd = e -> {
            Component src = e.getComponent();
            JScrollPane inner = (JScrollPane) SwingUtilities.getAncestorOfClass(JScrollPane.class, src);
            // Inside a nested scroll pane: let that pane try first (it hands over when it cannot scroll).
            JComponent target = (inner != null && inner != outer) ? inner : outer;
            target.dispatchEvent(SwingUtilities.convertMouseEvent(src, e, target));
        };
        java.awt.event.ContainerListener adder = new java.awt.event.ContainerAdapter() {
            @Override public void componentAdded(java.awt.event.ContainerEvent ev) { hook(ev.getChild(), fwd, this, outer); }
        };
        hook(root, fwd, adder, outer);
    }

    private static void hook(Component c, java.awt.event.MouseWheelListener fwd,
                             java.awt.event.ContainerListener adder, JScrollPane outer) {
        if (c == outer) return;
        boolean isInnerScroll = c instanceof JScrollPane;
        for (java.awt.event.MouseWheelListener l : c.getMouseWheelListeners()) if (l == fwd) return;
        if (c instanceof JScrollPane sp) {
            // inner scroll panes: scroll themselves when they can, otherwise hand over to the outer pane
            sp.setWheelScrollingEnabled(false);
            sp.addMouseWheelListener(e -> {
                JScrollBar b = sp.getVerticalScrollBar();
                boolean canMove = b.isVisible()
                        && ((e.getWheelRotation() < 0 && b.getValue() > b.getMinimum())
                         || (e.getWheelRotation() > 0 && b.getValue() + b.getVisibleAmount() < b.getMaximum()));
                if (canMove) b.setValue(b.getValue() + e.getUnitsToScroll() * b.getUnitIncrement());
                else outer.dispatchEvent(SwingUtilities.convertMouseEvent(sp, e, outer));
            });
        } else if (c instanceof JTextComponent || c instanceof JComboBox || c instanceof JSpinner
                || c instanceof JSlider || c instanceof JTable || c instanceof JList) {
            c.addMouseWheelListener(fwd);
        }
        if (c instanceof Container ct) {
            ct.addContainerListener(adder);
            for (Component ch : ct.getComponents()) hook(ch, fwd, adder, outer);
        }
    }
}
