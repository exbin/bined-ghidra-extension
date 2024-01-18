/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.exbin.bined.ghidra;

import docking.ActionContext;
import docking.action.DockingAction;
import static ghidra.GhidraOptions.*;

import java.awt.*;
import java.math.BigInteger;
import java.util.*;
import java.util.List;

import javax.swing.JComponent;

import generic.theme.*;
import ghidra.GhidraOptions;
import ghidra.GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES;
import ghidra.app.plugin.core.byteviewer.ByteViewerLayoutModel;
import ghidra.app.plugin.core.format.*;
import ghidra.app.services.MarkerService;
import ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.SwingUpdateManager;
import org.exbin.auxiliary.binary_data.EmptyBinaryData;
import org.exbin.bined.ghidra.action.OptionsAction;
import org.exbin.bined.ghidra.main.BinEdManager;
import org.exbin.framework.bined.BinEdEditorComponent;
import org.exbin.framework.bined.BinEdFileManager;

public abstract class BinEdComponentProvider extends ComponentProviderAdapter
        implements OptionsChangeListener {

    protected static final String BLOCK_NUM = "Block Num";
    protected static final String BLOCK_OFFSET = "Block Offset";
    protected static final String BLOCK_COLUMN = "Block Column";
    protected static final String INDEX = "Index";
    protected static final String X_OFFSET = "X Offset";
    protected static final String Y_OFFSET = "Y Offset";
    private static final String VIEW_NAMES = "View Names";
    private static final String HEX_VIEW_GROUPSIZE = "Hex view groupsize";
    private static final String BYTES_PER_LINE_NAME = "Bytes Per Line";
    private static final String OFFSET_NAME = "Offset";
    static final int DEFAULT_NUMBER_OF_CHARS = 8;

    static final String DEFAULT_FONT_ID = "font.byteviewer";
    static final int DEFAULT_BYTES_PER_LINE = 16;

    //@formatter:off
    static final String FG = "byteviewer.color.fg";
    static final String CURSOR = "byteviewer.color.cursor";

    static final GColor SEPARATOR_COLOR = new GColor("color.fg.byteviewer.separator");
    static final GColor CHANGED_VALUE_COLOR = new GColor("color.fg.byteviewer.changed");
    static final GColor CURSOR_ACTIVE_COLOR = new GColor("color.cursor.byteviewer.focused.active");
    static final GColor CURSOR_NON_ACTIVE_COLOR = new GColor("color.cursor.byteviewer.focused.not.active");
    static final GColor CURSOR_NOT_FOCUSED_COLOR = new GColor("color.cursor.byteviewer.unfocused");

    static final GColor CURRENT_LINE_COLOR = GhidraOptions.DEFAULT_CURSOR_LINE_COLOR;
    //@formatter:on

    static final String DEFAULT_INDEX_NAME = "Addresses";

    static final String OPTION_FONT = "Font";

    private static final String DEFAULT_VIEW = "BinEd";
    private static final String CURRENT_LINE_COLOR_OPTION_NAME
            = GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR_OPTION_NAME;
    private static final String OPTION_HIGHLIGHT_CURSOR_LINE
            = GhidraOptions.HIGHLIGHT_CURSOR_LINE_OPTION_NAME;

    protected BinEdEditorComponent panel;

    private int bytesPerLine;
    private int offset;
    private int hexGroupSize = 1;

    protected Map<String, BinedFieldPanel> viewMap = new HashMap<>();

//    protected ToggleDockingAction editModeAction;
	protected DockingAction optionsAction;

    protected ProgramByteBlockSet blockSet;

    protected final AbstractByteViewerPlugin<?> plugin;

    protected SwingUpdateManager updateManager;

    private Map<String, Class<? extends DataFormatModel>> dataFormatModelClassMap;

    protected BinEdComponentProvider(PluginTool tool, AbstractByteViewerPlugin<?> plugin,
            String name, Class<?> contextType) {
        super(tool, name, plugin.getName(), contextType);
        this.plugin = plugin;
        registerAdjustableFontId(DEFAULT_FONT_ID);

        initializedDataFormatModelClassMap();

        panel = new BinEdEditorComponent();
        BinEdManager binEdManager = BinEdManager.getInstance();
        BinEdFileManager fileManager = binEdManager.getFileManager();
        fileManager.initComponentPanel(panel.getComponentPanel());
        binEdManager.initEditorComponent(panel);

        bytesPerLine = DEFAULT_BYTES_PER_LINE;
        setIcon(new GIcon("icon.plugin.byteviewer.provider"));

        createActions();

        updateManager = new SwingUpdateManager(1000, 3000, () -> refreshView());

        addView(DEFAULT_VIEW);
        setWindowMenuGroup("BinEd");
    }

    private void initializedDataFormatModelClassMap() {
        dataFormatModelClassMap = new HashMap<>();
        Set<? extends DataFormatModel> models = getDataFormatModels();
        for (DataFormatModel model : models) {
            dataFormatModelClassMap.put(model.getName(), model.getClass());
        }
    }

    private void createActions() {
//		editModeAction = new ToggleEditAction(this, plugin);
		optionsAction = new DockingAction("BinEd Plugin Options", plugin.getName()) {
            @Override
            public void actionPerformed(ActionContext ac) {
                new OptionsAction(panel.getComponentPanel(), null, BinEdManager.getInstance().getPreferences()).actionPerformed(null);
            }
        };

//		addLocalAction(editModeAction);
		addLocalAction(optionsAction);
    }

    @Override
    public JComponent getComponent() {
        return panel.getComponent();
    }

    @Override
    public HelpLocation getHelpLocation() {
        return new HelpLocation("BinEdPlugin", "BinEdPlugin");
    }

    protected ByteBlock[] getByteBlocks() {
        return (blockSet == null) ? null : blockSet.getBlocks();
    }

    protected void notifyBlockSetChanged() {
        panel.getCodeArea().setContentData(blockSet == null ? EmptyBinaryData.INSTANCE : new ByteBlocksBinaryData(blockSet));
    }

    /**
     * Notification that an option changed.
     *
     * @param options options object containing the property that changed
     * @param optionName name of option that changed
     * @param oldValue old value of the option
     * @param newValue new value of the option
     */
    @Override
    public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
            Object newValue) {
        if (options.getName().equals("BinEd")) {
            if (optionName.equals(OPTION_FONT)) {
                setFont(SystemUtilities.adjustForFontSizeOverride((Font) newValue));
            }
        } else if (options.getName().equals(CATEGORY_BROWSER_FIELDS)) {
            if (optionName.equals(CURSOR_HIGHLIGHT_BUTTON_NAME)) {
                CURSOR_MOUSE_BUTTON_NAMES mouseButton = (CURSOR_MOUSE_BUTTON_NAMES) newValue;
//				panel.setHighlightButton(mouseButton.getMouseEventID());
            } else if (optionName.equals(HIGHLIGHT_COLOR_NAME)) {
//				panel.setMouseButtonHighlightColor((Color) newValue);
            }
        }
    }

    private void setFont(Font font) {
//        FontMetrics fm = panel.getFontMetrics(font);
//		panel.setFontMetrics(fm);
        tool.setConfigChanged(true);
    }

    /**
     * Set the offset that is applied to each block.
     *
     * @param blockOffset the new block offset
     */
    void setBlockOffset(int blockOffset) {
        if (blockOffset == offset) {
            return;
        }
        int newOffset = blockOffset;
        if (newOffset > bytesPerLine) {
            newOffset = newOffset % bytesPerLine;
        }
        this.offset = newOffset;
//		panel.setOffset(newOffset);
        tool.setConfigChanged(true);
    }

    ByteBlockInfo getCursorLocation() {
        throw new UnsupportedOperationException("Not supported yet.");
//		return panel.getCursorLocation();
    }

    ByteBlockSelection getBlockSelection() {
        throw new UnsupportedOperationException("Not supported yet.");
//		return panel.getViewerSelection();
    }

    void setBlockSelection(ByteBlockSelection selection) {
//		panel.setViewerSelection(selection);
    }

    ByteBlockSet getByteBlockSet() {
        return blockSet;
    }

    /**
     * Get the number of bytes displayed in a line.
     *
     * @return the number of bytes displayed in a line
     */
    int getBytesPerLine() {
        return bytesPerLine;
    }

    /**
     * Get the offset that should be applied to each byte block.
     *
     * @return the offset that should be applied to each byte block
     */
    int getOffset() {
        return offset;
    }

    Color getCursorColor() {
        return CURSOR_NON_ACTIVE_COLOR;
    }

    int getGroupSize() {
        return hexGroupSize;
    }

    void setGroupSize(int groupSize) {
        if (groupSize == hexGroupSize) {
            return;
        }
        hexGroupSize = groupSize;
        BinedFieldPanel component = viewMap.get(HexFormatModel.NAME);
        if (component != null) {
//			component.setGroupSize(groupSize);
//			component.invalidate();
            panel.getComponent().repaint();
        }
        tool.setConfigChanged(true);
    }

    void setBytesPerLine(int bytesPerLine) {
        if (this.bytesPerLine != bytesPerLine) {
            this.bytesPerLine = bytesPerLine;
//			panel.setBytesPerLine(bytesPerLine);
            tool.setConfigChanged(true);
        }
    }

    protected void writeConfigState(SaveState saveState) {
//		DataModelInfo info = panel.getDataModelInfo();
//		saveState.putStrings(VIEW_NAMES, info.getNames());
//		saveState.putInt(HEX_VIEW_GROUPSIZE, hexGroupSize);
//		saveState.putInt(BYTES_PER_LINE_NAME, bytesPerLine);
//		saveState.putInt(OFFSET_NAME, offset);
    }

    protected void readConfigState(SaveState saveState) {
        String[] names = saveState.getStrings(VIEW_NAMES, new String[0]);
        hexGroupSize = saveState.getInt(HEX_VIEW_GROUPSIZE, 1);
        restoreViews(names, false);
        bytesPerLine = saveState.getInt(BYTES_PER_LINE_NAME, DEFAULT_BYTES_PER_LINE);
        offset = saveState.getInt(OFFSET_NAME, 0);
    }

    /**
     * Restore the views.
     */
    private void restoreViews(String[] viewNames, boolean updateViewPosition) {
        // clear existing views
        for (String viewName : viewMap.keySet()) {
            removeView(viewName, false);
        }
        for (String viewName : viewNames) {
            DataFormatModel dataFormatModel = getDataFormatModel(viewName);
            if (dataFormatModel != null) {
                addView(dataFormatModel, false, updateViewPosition);
            }
        }
        if (viewMap.isEmpty()) {
            addView(DEFAULT_VIEW);
        }
    }

    void addView(String modelName) {
        DataFormatModel dataFormatModel = getDataFormatModel(modelName);
        if (dataFormatModel != null) {
            addView(dataFormatModel, false, true);
        }
    }

    private BinedFieldPanel addView(DataFormatModel model, boolean configChanged,
            boolean updateViewPosition) {

        if (model.getName().equals(HexFormatModel.NAME)) {
            model.setGroupSize(hexGroupSize);
        }

        String viewName = model.getName();

        BinedFieldPanel fieldPanel = new BinedFieldPanel(panel, new ByteViewerLayoutModel(), model, bytesPerLine);

//			panel.addView(viewName, model, editModeAction.isSelected(), updateViewPosition);
        viewMap.put(viewName, fieldPanel);
        if (configChanged) {
            tool.setConfigChanged(true);
        }

        return fieldPanel;
    }

    void removeView(String viewName, boolean configChanged) {
        BinedFieldPanel fieldPanel = viewMap.remove(viewName);
        if (fieldPanel == null) {
            return;
        }

        if (configChanged) {
            tool.setConfigChanged(true);
        }

    }

    protected abstract void updateLocation(ByteBlock block, BigInteger blockOffset, int column,
            boolean export);

    protected abstract void updateSelection(ByteBlockSelection selection);

    void dispose() {
        updateManager.dispose();
        updateManager = null;

        if (blockSet != null) {
            blockSet.dispose();
        }

        blockSet = null;
    }

    public Set<String> getCurrentViews() {
//		DataModelInfo info = panel.getDataModelInfo();
        HashSet<String> currentViewNames = new HashSet<>(); // Arrays.asList(info.getNames()));
        return currentViewNames;
    }

    private void refreshView() {
        if (tool == null) {
            return;
        }

        if (tool.isVisible(this)) {
//			panel.refreshView();
        }

    }

    /**
     * Set the status info on the tool.
     *
     * @param message non-html text to display
     */
    void setStatusMessage(String message) {
        plugin.setStatusMessage(message);
    }

    void setEditMode(boolean isEditable) {
//		panel.setEditMode(isEditable);
    }

    protected Set<DataFormatModel> getDataFormatModels() {
        Set<DataFormatModel> set = new HashSet<>();
        set.addAll(ClassSearcher.getInstances(UniversalDataFormatModel.class));
        return set;
    }

    public List<String> getDataFormatNames() {
        ArrayList<String> names = new ArrayList<>(dataFormatModelClassMap.keySet());
        // we should probably have this in a better order, but at least this is consistent for now
        Collections.sort(names);
        return names;
    }

    public DataFormatModel getDataFormatModel(String formatName) {
        Class<? extends DataFormatModel> classy = dataFormatModelClassMap.get(formatName);
        if (classy == null) {
            return null;
        }
        try {
            return classy.getConstructor().newInstance();
        } catch (Exception e) {
            // cannot happen, since we only get the value from valid class that we put into the map
            Msg.error(this, "Unexpected error loading ByteViewer model formats", e);
        }
        return null;
    }

    public MarkerService getMarkerService() {
        return tool.getService(MarkerService.class);
    }

    /**
     * Add the {@link AddressSetDisplayListener} to the byte viewer panel
     *
     * @param listener the listener to add
     */
    public void addDisplayListener(AddressSetDisplayListener listener) {
//		panel.addDisplayListener(listener);
    }

    /**
     * Remove the {@link AddressSetDisplayListener} from the byte viewer panel
     *
     * @param listener the listener to remove
     */
    public void removeDisplayListener(AddressSetDisplayListener listener) {
//		panel.removeDisplayListener(listener);
    }
}
