package burp;

import com.github.difflib.DiffUtils;
import com.github.difflib.patch.AbstractDelta;
import com.github.difflib.patch.Patch;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.Theme;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultCaret;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.IOException;
import java.util.Arrays;

public class DiffyMessageTab implements IMessageEditorTab {
    private final JPanel diffyContainer = new JPanel(new BorderLayout());
    private RSyntaxTextArea textEditor = new RSyntaxTextArea(20, 60);
    private RTextScrollPane scrollPane = new RTextScrollPane(textEditor);
    private String red = "#dc3545";
    private String green = "#28a745";
    private String blue = "#0d6efd";

    private byte[] currentMessage;
    private byte[] lastMessage;
    private Boolean componentShown = false;
    private final int MAX_BYTES = 1000000;

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
                        textEditor.setAntiAliasingEnabled(false);
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

                if(content.length > MAX_BYTES) {
                    textEditor.setText("Response is too large to diff");
                    return;
                }


                textEditor.setText(Utilities.helpers.bytesToString(content));
                textEditor.removeAllLineHighlights();
                if(lastMessage != null && lastMessage != content && lastMessage.length > 0) {
                    java.util.List<String> currentResponse = Arrays.asList(Utilities.helpers.bytesToString(content).split("\\r?\\n"));
                    java.util.List<String> previousResponse  = Arrays.asList(Utilities.helpers.bytesToString(lastMessage).split("\\r?\\n"));

                    Patch<String> patch = DiffUtils.diff(previousResponse, currentResponse);
                    for (AbstractDelta<String> delta : patch.getDeltas()) {
                        switch (delta.getType()) {
                            case CHANGE:
                                try {
                                    int pos = delta.getTarget().getPosition();
                                    int size = delta.getTarget().size();
                                    textEditor.addLineHighlight(pos, Color.decode(blue));
                                    for(int i = pos; i < pos + size;i++) {
                                        textEditor.addLineHighlight(i, Color.decode(blue));
                                    }
                                } catch (BadLocationException e) {

                                }
                                break;
                            case DELETE:
                                try {
                                    int pos = delta.getTarget().getPosition();
                                    textEditor.addLineHighlight(pos, Color.decode(red));
                                } catch (BadLocationException e) {

                                }
                                break;
                            case INSERT:
                                try {
                                    int pos = delta.getTarget().getPosition();
                                    int size = delta.getTarget().size();
                                    textEditor.addLineHighlight(pos, Color.decode(green));
                                    for(int i = pos; i < pos + size;i++) {
                                        textEditor.addLineHighlight(i, Color.decode(green));
                                    }
                                } catch (BadLocationException e) {

                                }
                                break;
                        }
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
