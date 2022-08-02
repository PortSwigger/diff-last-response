package burp;

import java.util.HashMap;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, IMessageEditorTabFactory, IHttpListener {
    public static final String name = "Diff last response";
    public static final String version = "1.0.10";
    public static byte[] lastMessageFromListener;
    public static int lastPortFromListener;
    public static String lastHostFromListener;
    public static String lastProtocolFromListener;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        new Utilities(callbacks, new HashMap<>(), name);
        callbacks.setExtensionName(name);
        Utilities.callbacks.registerMessageEditorTabFactory(this);
        Utilities.callbacks.registerExtensionStateListener(this);
        Utilities.callbacks.registerHttpListener(this);
        Utilities.out("Loaded " + name + " v" + version);
    }

    @Override
    public void extensionUnloaded() {
        Utilities.out("Unloaded " + name);
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new DiffMessageTab(controller);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean isRequest, IHttpRequestResponse messageInfo) {
        if(toolFlag != IBurpExtenderCallbacks.TOOL_REPEATER || isRequest) {
            return;
        }

        lastMessageFromListener = messageInfo.getResponse();
        lastPortFromListener = messageInfo.getHttpService().getPort();
        lastHostFromListener = messageInfo.getHttpService().getHost();
        lastProtocolFromListener = messageInfo.getHttpService().getProtocol();
        return;
    }
}
