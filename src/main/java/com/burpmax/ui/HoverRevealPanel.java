package com.burpmax.ui;

import javax.swing.*;
import java.awt.*;

/**
 * Wraps a component and overlays a small action button in its top-right corner that only appears
 * while the mouse is over the panel. Hover is detected by polling the pointer position, which is
 * robust against child components (scroll panes, text panes) swallowing mouse events.
 */
final class HoverRevealPanel extends JPanel {

    @java.io.Serial
    private static final long serialVersionUID = 1L;

    private final transient JButton button;
    private final Timer poll;

    HoverRevealPanel(JComponent content, JButton revealButton) {
        setLayout(new OverlayLayout(this));
        setOpaque(false);
        this.button = revealButton;

        revealButton.setAlignmentX(1.0f);
        revealButton.setAlignmentY(0.0f);
        revealButton.setMaximumSize(revealButton.getPreferredSize());
        revealButton.setVisible(false);
        revealButton.setMargin(new Insets(1, 6, 1, 6));

        content.setAlignmentX(1.0f);
        content.setAlignmentY(0.0f);

        // First added = painted on top.
        add(revealButton);
        add(content);

        poll = new Timer(120, e -> update());
        poll.setRepeats(true);
    }

    private void update() {
        if (!isShowing()) { button.setVisible(false); return; }
        PointerInfo pi = MouseInfo.getPointerInfo();
        if (pi == null) return;
        Point p = pi.getLocation();
        Point origin = getLocationOnScreen();
        Rectangle r = new Rectangle(origin.x, origin.y, getWidth(), getHeight());
        boolean inside = r.contains(p);
        if (inside != button.isVisible()) button.setVisible(inside);
    }

    @Override public void addNotify()    { super.addNotify(); poll.start(); }
    @Override public void removeNotify() { poll.stop(); super.removeNotify(); }
}
