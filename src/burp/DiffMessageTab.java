package burp;

import com.github.difflib.DiffUtils;
import com.github.difflib.patch.AbstractDelta;
import com.github.difflib.patch.Patch;
import com.github.difflib.text.DiffRowGenerator;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultCaret;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class DiffMessageTab implements IMessageEditorTab {
    private final JPanel diffyContainer = new JPanel(new BorderLayout());
    private RSyntaxTextArea textEditor = new RSyntaxTextArea(20, 60);
    private RTextScrollPane scrollPane = new RTextScrollPane(textEditor);

    private String red = "#dc3545";
    private String green = "#28a745";
    private String blue = "#0d6efd";
    private Highlighter.HighlightPainter modifiedPainter = new DefaultHighlighter.DefaultHighlightPainter(Color.decode(blue));
    private byte[] currentMessage;
    private byte[] lastMessage;
    private int lastPort;
    private String lastHost;
    private String lastProtocol;
    private Boolean componentShown = false;
    private final int MAX_BYTES = 750000;
    private IMessageEditorController controller;

    public DiffMessageTab(IMessageEditorController controller) {
        this.controller = controller;
        diffyContainer.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                if(componentShown) {
                    return;
                }
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        diffyContainer.removeAll();
                        textEditor.setLineWrap(true);
                        textEditor.setEditable(false);
                        textEditor.setAntiAliasingEnabled(false);
                        scrollPane.setAutoscrolls(true);
                        DefaultCaret caret = (DefaultCaret) textEditor.getCaret();
                        caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);

                        if(UIManager.getLookAndFeel().getID().contains("Dar")) {
                            try {
                                Theme theme = Theme.load(getClass().getResourceAsStream(
                                        "/org/fife/ui/rsyntaxtextarea/themes/dark.xml"));
                                theme.apply(textEditor);
                            } catch (IOException ioe) {
                            }
                        }
                        diffyContainer.add(scrollPane);
                    }
                });
                componentShown = true;
            }
        });
    }

    @Override
    public String getTabCaption() {
        return "Diff";
    }

    @Override
    public Component getUiComponent() {
        return diffyContainer;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return !isRequest;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        if(isRequest) {
           return;
        }
        if (content != null && content.length > 0) {

            int currentPort = controller.getHttpService().getPort();
            String currentHost = controller.getHttpService().getHost();
            String currentProtocol = controller.getHttpService().getProtocol();

            if(currentMessage != content) {
                if(content.length > MAX_BYTES) {
                    textEditor.setText("Response is too large to diff");
                    return;
                }
                String contentType = Utilities.getHeader(content, "Content-Type").toLowerCase();
                if(contentType.length() == 0) {
                    contentType = Utilities.getHeader(content, "content-type").toLowerCase();
                }
                if(contentType.contains("json")) {
                    textEditor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
                } else if(contentType.contains("html")) {
                    textEditor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML);
                } else if(contentType.contains("javascript")) {
                    textEditor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
                } else if(contentType.contains("css")) {
                    textEditor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_CSS);
                } else if(contentType.contains("xml")) {
                    textEditor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_XML);
                } else {
                    textEditor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE);
                }
                textEditor.setText(Utilities.helpers.bytesToString(content));
                textEditor.removeAllLineHighlights();
                if(isLastService(currentPort, currentHost, currentProtocol) && lastMessage != null && lastMessage != content && lastMessage.length > 0) {
                    java.util.List<String> currentResponse = Arrays.asList(Utilities.helpers.bytesToString(content).split("\\n"));
                    java.util.List<String> previousResponse  = Arrays.asList(Utilities.helpers.bytesToString(lastMessage).split("\\n"));
                    Highlighter highlighter = textEditor.getHighlighter();
                    Patch<String> patch = DiffUtils.diff(previousResponse, currentResponse);
                    List<AbstractDelta<String>> deltas = patch.getDeltas();
                    for (AbstractDelta<String> delta : deltas) {
                        switch (delta.getType()) {
                            case DELETE:
                                try {
                                    textEditor.addLineHighlight(delta.getTarget().getPosition(), Color.decode(red));
                                } catch (BadLocationException e) {

                                }
                                break;
                            case INSERT:
                                try {
                                    textEditor.addLineHighlight(delta.getTarget().getPosition(), Color.decode(green));
                                } catch (BadLocationException e) {

                                }
                                break;
                            case CHANGE:
                                int linePos = delta.getTarget().getPosition();
                                int pos = 0;
                                for (int i = 0; i < linePos; i++) {
                                    pos += currentResponse.get(i).length() + 1;
                                }
                                int finalPos = pos;
                                DiffRowGenerator generator = DiffRowGenerator.create()
                                        .showInlineDiffs(true)
                                        .mergeOriginalRevised(true)
                                        .inlineDiffByWord(true)
                                        .lineNormalizer(f -> f)
                                        .processDiffs(diff-> {
                                            List<String> targetLines = delta.getTarget().getLines();
                                            int currentLinePos = finalPos;
                                            for(int i=0;i<targetLines.size();i++) {
                                                String line = targetLines.get(i);
                                                int foundPos = line.indexOf(diff);
                                                if (foundPos != -1) {
                                                    int start = currentLinePos + foundPos;
                                                    int end = start + diff.length();
                                                    addHighlight(start, end, highlighter, modifiedPainter);
                                                    break;
                                                } else {
                                                    currentLinePos += line.length() + 1;
                                                }
                                            }
                                            return diff;
                                        })
                                        .build();

                                generator.generateDiffRows(
                                        delta.getSource().getLines(),
                                        delta.getTarget().getLines());
                                int currentLine = linePos + 1;
                                for(int i=delta.getSource().getLines().size();i<delta.getTarget().getLines().size();i++){
                                    try {
                                        textEditor.addLineHighlight(currentLine, Color.decode(green));
                                    } catch (BadLocationException e) {

                                    } finally {
                                        currentLine++;
                                    }
                                }
                                break;
                        }
                    }
                }
            }
        }
        currentMessage = content;
        lastMessage = currentMessage;
        lastPort = controller.getHttpService().getPort();
        lastHost = controller.getHttpService().getHost();
        lastProtocol = controller.getHttpService().getProtocol();
    }
    @Override
    public byte[] getMessage() {
        return currentMessage;
    }

    private void addHighlight(int startPos, int endPos, Highlighter highlighter, Highlighter.HighlightPainter painter) {
        try {
            highlighter.addHighlight(startPos, endPos, painter);
        } catch (BadLocationException e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean isModified() {
        return false;
    }

    public boolean isLastService(int currentPort, String currentHost, String currentProtocol) {
        if(lastPort == 0 || lastHost == null || lastProtocol == null) {
            return true;
        }
        return currentPort == lastPort && currentHost.equals(lastHost) && currentProtocol.equals(lastProtocol);
    }

    @Override
    public byte[] getSelectedData() {
        return null;
    }
}
