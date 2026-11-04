package com.burpmax.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Consumer;

import static com.burpmax.ui.Theme.*;

/**
 * A titled section whose body can be folded away. Used by the scan dialog and detail pane so
 * long configuration stays scannable instead of one tall wall of controls.
 */
final class CollapsibleSection extends JPanel {

    @java.io.Serial
    private static final long serialVersionUID = 1L;

    private final JLabel arrow = new JLabel();
    private final JLabel title = new JLabel();
    private final JLabel summary = new JLabel();
    private final JComponent body;
    private boolean expanded;
    private transient Consumer<Boolean> onToggle;

    CollapsibleSection(String titleText, JComponent body, boolean startExpanded) {
        super(new BorderLayout());
        this.body = body;
        this.expanded = startExpanded;
        setOpaque(false);
        setAlignmentX(LEFT_ALIGNMENT);

        JPanel header = new JPanel(new BorderLayout(6, 0));
        header.setOpaque(true);
        header.setBackground(C_HEADER_BG);
        header.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, C_BORDER2),
                BorderFactory.createEmptyBorder(7, 4, 7, 4)));
        header.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        arrow.setFont(new Font("Arial", Font.BOLD, 12));
        arrow.setForeground(C_ACCENT_BLU);
        title.setText(titleText);
        title.setFont(new Font("Arial", Font.BOLD, 12));
        title.setForeground(C_TEXT_HEAD);
        summary.setFont(Widgets.UI_SMALL);
        summary.setForeground(C_TEXT_MUTED);

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        left.setOpaque(false);
        left.add(arrow);
        left.add(title);
        header.add(left, BorderLayout.WEST);
        header.add(summary, BorderLayout.CENTER);
        summary.setHorizontalAlignment(SwingConstants.RIGHT);

        MouseAdapter click = new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) { setExpanded(!expanded); }
        };
        header.addMouseListener(click);
        left.addMouseListener(click);
        summary.addMouseListener(click);
        arrow.addMouseListener(click);
        title.addMouseListener(click);

        JPanel bodyWrap = new JPanel(new BorderLayout());
        bodyWrap.setOpaque(false);
        bodyWrap.setBorder(BorderFactory.createEmptyBorder(8, 6, 10, 6));
        bodyWrap.add(body, BorderLayout.CENTER);
        this.bodyWrap = bodyWrap;

        add(header, BorderLayout.NORTH);
        add(bodyWrap, BorderLayout.CENTER);
        apply();
    }

    private final JPanel bodyWrap;

    /** Short text shown at the right of the header, e.g. "3 modules skipped". */
    void setSummary(String s) { summary.setText(s == null ? "" : s); }

    void onToggle(Consumer<Boolean> cb) { this.onToggle = cb; }

    boolean isExpanded() { return expanded; }

    void setExpanded(boolean v) {
        if (v == expanded) return;
        expanded = v;
        apply();
        if (onToggle != null) onToggle.accept(v);
        revalidate();
        repaint();
        Window w = SwingUtilities.getWindowAncestor(this);
        if (w != null) w.validate();
    }

    private void apply() {
        arrow.setText(expanded ? "▾" : "▸");   // ▾ ▸
        bodyWrap.setVisible(expanded);
    }

    @Override public Dimension getMaximumSize() {
        return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
    }

    JComponent bodyComponent() { return body; }
}
