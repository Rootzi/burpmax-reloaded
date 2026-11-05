package com.burpmax.ui;

import com.burpmax.evidence.Evidence;
import com.burpmax.evidence.Snippet;
import com.burpmax.model.Finding;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.util.List;

import static com.burpmax.ui.Theme.*;

/**
 * Shows the part of the traffic that actually proves a finding:
 *   - a plain-English "why was this flagged" line,
 *   - the exact substring(s) that triggered it (click a chip to copy),
 *   - a trimmed request and response (start line always present, hit highlighted),
 *   - a hover-revealed button that opens the complete request/response.
 * All text is selectable and has a Copy button.
 */
final class EvidencePanel extends JPanel {

    @java.io.Serial
    private static final long serialVersionUID = 1L;

    private final JTextArea logic = new JTextArea();
    private final JPanel chips = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
    private final JLabel reqTitle = Widgets.caption("REQUEST");
    private final JLabel respTitle = Widgets.caption("RESPONSE");
    private final JTextPane reqPane = pane();
    private final JTextPane respPane = pane();
    private final JButton reqCopy = Widgets.ghost("Copy");
    private final JButton respCopy = Widgets.ghost("Copy");
    private final JButton fullReq = Widgets.ghost("⤢ Full request");
    private final JButton fullResp = Widgets.ghost("⤢ Full response");
    private final JLabel note = new JLabel();

    private transient byte[] curReq;
    private transient byte[] curResp;
    private transient String curTitle = "";
    private transient String reqPlain = "";
    private transient String respPlain = "";

    EvidencePanel() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setOpaque(false);

        add(sectionLabel("WHY IT WAS FLAGGED"));
        logic.setEditable(false);
        logic.setLineWrap(true);
        logic.setWrapStyleWord(true);
        logic.setFont(new Font("Arial", Font.PLAIN, 12));
        logic.setForeground(C_TEXT);
        logic.setBackground(C_DEEP);
        logic.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        JScrollPane lsp = new JScrollPane(logic);
        Widgets.styleScroll(lsp);
        lsp.setAlignmentX(LEFT_ALIGNMENT);
        lsp.setPreferredSize(new Dimension(300, 70));
        lsp.setMaximumSize(new Dimension(Integer.MAX_VALUE, 110));
        add(lsp);

        add(Box.createVerticalStrut(6));
        JLabel chipLbl = sectionLabel("MATCHED TEXT  (click to copy)");
        add(chipLbl);
        chips.setOpaque(false);
        chips.setAlignmentX(LEFT_ALIGNMENT);
        add(chips);

        add(Box.createVerticalStrut(6));
        add(block(reqTitle, reqPane, reqCopy, fullReq, false));
        add(Box.createVerticalStrut(6));
        add(block(respTitle, respPane, respCopy, fullResp, true));

        note.setFont(Widgets.UI_SMALL);
        note.setForeground(C_TEXT_MUTED);
        note.setAlignmentX(LEFT_ALIGNMENT);
        note.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
        add(note);

        reqCopy.addActionListener(e -> { Widgets.copy(reqPlain); Widgets.flash(reqCopy, "Copied"); });
        respCopy.addActionListener(e -> { Widgets.copy(respPlain); Widgets.flash(respCopy, "Copied"); });
        fullReq.addActionListener(e -> FullMessageDialog.show(this, curTitle, curReq, curResp, false));
        fullResp.addActionListener(e -> FullMessageDialog.show(this, curTitle, curReq, curResp, true));
    }

    // ── Public ────────────────────────────────────────────────────────────────

    /** Show the evidence for a finding: the probe's own request/response when it has one. */
    void show(Finding f) {
        Evidence ev = f.primaryEvidence();
        boolean probe = f.primaryProbeRequest() != null || f.primaryProbeResponse() != null;
        curReq  = probe ? f.primaryProbeRequest()  : f.primaryRawRequest();
        curResp = probe ? f.primaryProbeResponse() : f.primaryRawResponse();
        curTitle = f.name;

        logic.setText(ev.logic().isEmpty() ? "No detection detail recorded for this finding." : ev.logic());
        logic.setCaretPosition(0);

        chips.removeAll();
        for (String m : ev.responseMatches()) chips.add(chip(m, "in response"));
        for (String m : ev.requestMatches())  chips.add(chip(m, "in request"));
        if (!ev.hasMatches()) {
            JLabel none = new JLabel("No single substring — see the explanation above");
            none.setFont(Widgets.UI_SMALL);
            none.setForeground(C_TEXT_MUTED);
            chips.add(none);
        }

        reqTitle.setText(probe ? "REQUEST  —  sent by " + f.source + " (this is what reproduces it)"
                               : "REQUEST  —  captured traffic");
        respTitle.setText(probe ? "RESPONSE  —  to the request above"
                                : "RESPONSE  —  captured traffic");

        List<Snippet.Segment> rq = Snippet.request(curReq, ev.requestMatches());
        List<Snippet.Segment> rs = Snippet.response(curResp, ev.responseMatches());
        render(reqPane, rq);
        render(respPane, rs);
        reqPlain  = Snippet.toPlain(rq);
        respPlain = Snippet.toPlain(rs);

        fullReq.setEnabled(curReq != null);
        fullResp.setEnabled(curResp != null);
        note.setText(curResp == null && probe
                ? "No response body was needed: this finding is confirmed out of band or by timing."
                : (f.primaryRawRequest() == null && !probe
                    ? "This finding was saved by an older version, which did not keep its traffic. Re-scan to capture it."
                    : " "));
        revalidate();
        repaint();
    }

    void clear() {
        logic.setText("");
        chips.removeAll();
        render(reqPane, List.of());
        render(respPane, List.of());
        reqPlain = respPlain = "";
        curReq = curResp = null;
        note.setText(" ");
    }

    // ── Pieces ────────────────────────────────────────────────────────────────

    private JLabel sectionLabel(String t) {
        JLabel l = Widgets.caption(t);
        l.setAlignmentX(LEFT_ALIGNMENT);
        l.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));
        return l;
    }

    private JPanel block(JLabel title, JTextPane pane, JButton copy, JButton full, boolean isResp) {
        JPanel p = new JPanel(new BorderLayout());
        p.setOpaque(false);
        p.setAlignmentX(LEFT_ALIGNMENT);

        JPanel head = new JPanel(new BorderLayout());
        head.setOpaque(false);
        head.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));
        head.add(title, BorderLayout.CENTER);
        head.add(copy, BorderLayout.EAST);

        JScrollPane sp = new JScrollPane(pane);
        Widgets.styleScroll(sp);
        sp.setPreferredSize(new Dimension(300, isResp ? 190 : 130));
        sp.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        p.add(head, BorderLayout.NORTH);
        p.add(new HoverRevealPanel(sp, full), BorderLayout.CENTER);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, isResp ? 240 : 180));
        return p;
    }

    private JComponent chip(String text, String where) {
        String shown = text.length() > 70 ? text.substring(0, 67) + "…" : text;
        JButton b = new JButton(shown.replace("\n", " ↵ ").replace("\r", ""));
        b.setFont(Widgets.MONO_BOLD);
        b.setForeground(Widgets.HIT_FG);
        b.setBackground(Widgets.HIT_BG);
        b.setFocusPainted(false);
        b.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        b.setToolTipText("Matched " + where + " — click to copy exactly: " + text);
        b.addActionListener(e -> { Widgets.copy(text); Widgets.flash(b, "Copied"); });
        return b;
    }

    private static JTextPane pane() {
        JTextPane tp = new JTextPane();
        tp.setEditable(false);
        tp.setFont(Widgets.MONO);
        tp.setBackground(C_DEEP);
        tp.setForeground(C_TEXT_DIM);
        tp.setCaretColor(C_TEXT);
        tp.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        return tp;
    }

    private static void render(JTextPane tp, List<Snippet.Segment> segs) {
        StyledDocument doc = tp.getStyledDocument();
        SimpleAttributeSet normal = new SimpleAttributeSet();
        StyleConstants.setForeground(normal, C_TEXT_DIM);
        SimpleAttributeSet hit = new SimpleAttributeSet();
        StyleConstants.setForeground(hit, Widgets.HIT_FG);
        StyleConstants.setBackground(hit, Widgets.HIT_BG);
        StyleConstants.setBold(hit, true);
        try {
            doc.remove(0, doc.getLength());
            for (Snippet.Segment s : segs) {
                doc.insertString(doc.getLength(), s.text(), s.hit() ? hit : normal);
            }
        } catch (BadLocationException ignored) { }
        tp.setCaretPosition(0);
    }
}
