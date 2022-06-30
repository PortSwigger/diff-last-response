package burp;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import javax.swing.text.BadLocationException;
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

    public DiffyMessageTab() {
        diffyContainer.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        diffyContainer.removeAll();
                        textEditor.setLineWrap(true);
                        textEditor.setEditable(false);
                        try {
                            Theme theme = Theme.load(getClass().getResourceAsStream(
                                    "/org/fife/ui/rsyntaxtextarea/themes/dark.xml"));
                            theme.apply(textEditor);
                        } catch (IOException ioe) {
                        }
                        diffyContainer.add(scrollPane);
                    }
                });
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
        if (content != null) {
            if(currentMessage != content) {
                byte[] lastResponse = BurpExtender.response1 == content ? BurpExtender.response2 : BurpExtender.response1;
                textEditor.setText(Utilities.helpers.bytesToString(content));
                if(lastResponse != null && lastResponse != content) {
                    try {
                        BufferedReader reader1 = new BufferedReader(new StringReader(Utilities.helpers.bytesToString(content)));
                        BufferedReader reader2 = new BufferedReader(new StringReader(Utilities.helpers.bytesToString(lastResponse)));

                        String line1;
                        String line2;
                        int lineNumber = 1;
                        while ((line1 = reader1.readLine()) != null && (line2 = reader2.readLine()) != null)
                        {
                            if (!line1.equals(line2))
                            {
                                textEditor.addLineHighlight(lineNumber, Color.decode(red));
                            }
                            lineNumber++;
                        }
                    } catch (BadLocationException e) {
                    } catch (IOException e) {
                    }
                }
            }
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
