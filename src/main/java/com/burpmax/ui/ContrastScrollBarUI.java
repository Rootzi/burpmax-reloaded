package com.burpmax.ui;

import javax.swing.*;
import javax.swing.plaf.basic.BasicScrollBarUI;
import java.awt.*;

/**
 * High-contrast scroll bar: wide, light thumb on a dark track, brighter on hover/drag.
 * Burp's own look and feel draws thin, low-contrast bars on this dark UI, so we paint our own.
 */
final class ContrastScrollBarUI extends BasicScrollBarUI {
    private static final Color TRACK        = new Color(0x16, 0x1F, 0x33);
    private static final Color TRACK_EDGE   = new Color(0x2A, 0x3A, 0x57);
    private static final Color THUMB        = new Color(0x7F, 0xA8, 0xD9);
    private static final Color THUMB_HOVER  = new Color(0xA9, 0xC9, 0xF0);
    private static final Color THUMB_DRAG   = new Color(0xD2, 0xE4, 0xFA);
    static final int WIDTH = 15;

    @Override protected void configureScrollBarColors() {
        thumbColor = THUMB; trackColor = TRACK;
    }

    @Override protected JButton createDecreaseButton(int o) { return zero(); }
    @Override protected JButton createIncreaseButton(int o) { return zero(); }

    private static JButton zero() {
        JButton b = new JButton();
        Dimension d = new Dimension(0, 0);
        b.setPreferredSize(d); b.setMinimumSize(d); b.setMaximumSize(d);
        b.setFocusable(false);
        return b;
    }

    @Override public Dimension getPreferredSize(JComponent c) {
        return scrollbar.getOrientation() == Adjustable.VERTICAL
                ? new Dimension(WIDTH, 48) : new Dimension(48, WIDTH);
    }

    @Override protected Dimension getMinimumThumbSize() { return new Dimension(24, 24); }

    @Override protected void paintTrack(Graphics g, JComponent c, Rectangle r) {
        g.setColor(TRACK);
        g.fillRect(r.x, r.y, r.width, r.height);
        g.setColor(TRACK_EDGE);
        if (scrollbar.getOrientation() == Adjustable.VERTICAL) g.drawLine(r.x, r.y, r.x, r.y + r.height);
        else g.drawLine(r.x, r.y, r.x + r.width, r.y);
    }

    @Override protected void paintThumb(Graphics g0, JComponent c, Rectangle r) {
        if (r.isEmpty() || !scrollbar.isEnabled()) return;
        Graphics2D g = (Graphics2D) g0.create();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(isDragging ? THUMB_DRAG : isThumbRollover() ? THUMB_HOVER : THUMB);
        g.fillRoundRect(r.x + 2, r.y + 2, r.width - 4, r.height - 4, 8, 8);
        g.dispose();
    }
}
