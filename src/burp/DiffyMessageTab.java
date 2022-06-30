package burp;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultCaret;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;

public class DiffyMessageTab implements IMessageEditorTab {
    private final JPanel diffyContainer = new JPanel(new BorderLayout());
    private RSyntaxTextArea textEditor = new RSyntaxTextArea(20, 60);
    private RTextScrollPane scrollPane = new RTextScrollPane(textEditor);
    private String red = "#dc3545";
    private String green = "#28a745";

    private byte[] currentMessage;
    private byte[] lastMessage;
    private Boolean componentShown = false;

    public DiffyMessageTab() {
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
                        scrollPane.setAutoscrolls(true);
                        DefaultCaret caret = (DefaultCaret) textEditor.getCaret();
                        caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);
                        try {
                            Theme theme = Theme.load(getClass().getResourceAsStream(
                                    "/org/fife/ui/rsyntaxtextarea/themes/dark.xml"));
                            theme.apply(textEditor);
                        } catch (IOException ioe) {
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
        return "Diffy";
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
            if(currentMessage != content) {
                textEditor.setText(Utilities.helpers.bytesToString(content));
                textEditor.removeAllLineHighlights();
                if(lastMessage != null && lastMessage != content && lastMessage.length > 0) {
                    try {
                        BufferedReader reader1 = new BufferedReader(new StringReader(Utilities.helpers.bytesToString(content)));
                        BufferedReader reader2 = new BufferedReader(new StringReader(Utilities.helpers.bytesToString(lastMessage)));

                        String line1;
                        String line2;
                        int lineNumber = 0;
                        while ((line1 = reader1.readLine()) != null && (line2 = reader2.readLine()) != null) {
                            if (!line1.equals(line2)) {
                                textEditor.addLineHighlight(lineNumber, Color.decode(red));
                            }
                            lineNumber++;
                        }
                    } catch (BadLocationException e) {
                        Utilities.err("Bad location:" + e);
                    } catch (IOException e) {
                        Utilities.err("IO error:" + e);
                    }
                }
            }
            lastMessage = currentMessage;
        }
        currentMessage = content;
    }

    @Override
    public byte[] getMessage() {
        return currentMessage;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        return null;
    }
}
