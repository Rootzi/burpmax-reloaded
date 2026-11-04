package com.burpmax.ui;

import javax.swing.*;
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

    /** A panel that follows the width of the scroll pane it sits in, so content wraps instead of clipping. */
    static final class TrackingPanel extends JPanel implements Scrollable {
        @java.io.Serial private static final long serialVersionUID = 1L;
        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(Rectangle r, int o, int d) { return 16; }
        @Override public int getScrollableBlockIncrement(Rectangle r, int o, int d) { return Math.max(32, r.height - 32); }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() { return false; }
    }
}
