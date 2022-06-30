package burp;

import java.util.HashMap;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, IMessageEditorTabFactory, IHttpListener {
    private static final String name = "Diffy";
    private static final String version = "1.0.0";
    static int responseCounter = 1;
    static byte[] response1 = null;
    static byte[] response2 = null;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        new Utilities(callbacks, new HashMap<>(), name);
        callbacks.setExtensionName(name);
        Utilities.callbacks.registerHttpListener(this);
        Utilities.callbacks.registerMessageEditorTabFactory(this);
        Utilities.callbacks.registerExtensionStateListener(this);
        Utilities.out("Loaded " + name + " v" + version);
    }

    @Override
    public void extensionUnloaded() {
        Utilities.out("Unloaded " + name);
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new DiffyMessageTab();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if(messageIsRequest) {
            return;
        }
        if(toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER) {
            if(responseCounter == 1) {
                response1 = messageInfo.getResponse();
                responseCounter++;
            } else {
                response2 = messageInfo.getResponse();
                responseCounter = 1;
            }
        }
    }
}
