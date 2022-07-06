package burp;

import java.util.HashMap;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, IMessageEditorTabFactory {
    public static final String name = "Diff last response";
    public static final String version = "1.0.4";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        new Utilities(callbacks, new HashMap<>(), name);
        callbacks.setExtensionName(name);
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
        return new DiffMessageTab(controller);
    }
}
