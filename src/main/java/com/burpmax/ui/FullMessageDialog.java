package com.burpmax.ui;

import com.burpmax.evidence.Snippet;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;

import static com.burpmax.ui.Theme.*;

/** Non-modal, resizable viewer for the complete request and response of a finding. */
final class FullMessageDialog {

    private FullMessageDialog() { }

    /** @param startOnResponse true to open on the Response tab. */
    static void show(Component parent, String title, byte[] request, byte[] response,
                     boolean startOnResponse) {
        Window owner = SwingUtilities.getWindowAncestor(parent);
        JDialog dlg = new JDialog(owner, title, Dialog.ModalityType.MODELESS);
        dlg.setSize(860, 580);
        dlg.setLocationRelativeTo(parent);

        JTabbedPane tabs = new JTabbedPane();
        JTextArea reqArea = area(Snippet.full(request), request == null ? "(not captured)" : null);
        JTextArea respArea = area(Snippet.full(response), response == null ? "(no response captured)" : null);
        tabs.addTab("Request", wrap(reqArea));
        tabs.addTab("Response", wrap(respArea));
        tabs.setSelectedIndex(startOnResponse ? 1 : 0);

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 6));
        bar.setBackground(C_HEADER_BG);
        JCheckBox wrap = new JCheckBox("Wrap lines");
        wrap.setForeground(C_TEXT_DIM);
        wrap.setBackground(C_HEADER_BG);
        wrap.addActionListener(e -> {
            reqArea.setLineWrap(wrap.isSelected());
            respArea.setLineWrap(wrap.isSelected());
        });
        JButton copy = Widgets.ghost("Copy this tab");
        copy.addActionListener(e -> {
            JTextArea a = tabs.getSelectedIndex() == 0 ? reqArea : respArea;
            Widgets.copy(a.getText());
            Widgets.flash(copy, "Copied");
        });
        JButton close = Widgets.ghost("Close");
        close.addActionListener(e -> dlg.dispose());
        bar.add(wrap);
        bar.add(copy);
        bar.add(close);

        dlg.getContentPane().setLayout(new BorderLayout());
        dlg.getContentPane().setBackground(C_ROOT);
        dlg.getContentPane().add(tabs, BorderLayout.CENTER);
        dlg.getContentPane().add(bar, BorderLayout.SOUTH);
        dlg.getRootPane().registerKeyboardAction(e -> dlg.dispose(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);
        dlg.setVisible(true);
    }

    private static JTextArea area(String text, String placeholder) {
        JTextArea a = new JTextArea(placeholder != null ? placeholder : text);
        a.setEditable(false);
        a.setFont(Widgets.MONO);
        a.setBackground(C_DEEP);
        a.setForeground(C_TEXT_DIM);
        a.setCaretColor(C_TEXT);
        a.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        a.setCaretPosition(0);
        return a;
    }

    private static JScrollPane wrap(JTextArea a) {
        JScrollPane sp = Widgets.contrast(new JScrollPane(a));
        Widgets.styleScroll(sp);
        return sp;
    }
}
