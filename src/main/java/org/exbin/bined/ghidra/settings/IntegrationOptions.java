/*
 * Copyright (C) ExBin Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.exbin.bined.ghidra.settings;

import org.jspecify.annotations.NullMarked;
import org.exbin.jaguif.options.api.OptionsStorage;
import org.exbin.jaguif.options.settings.api.SettingsOptions;

/**
 * Integration options.
 */
@NullMarked
public class IntegrationOptions implements SettingsOptions {

    public static final String PREFERENCES_REGISTER_FILE_MENU_OPEN_AS_BINARY = "registerFileMenuOpenAsBinary";
    public static final String PREFERENCES_REGISTER_OPEN_FILE_AS_BINARY_VIA_TOOLBAR = "registerOpenFileAsBinaryViaToolbar";
    public static final String PREFERENCES_REGISTER_CONTEXT_OPEN_AS_BINARY = "registerContextOpenAsBinary";
    public static final String PREFERENCES_REGISTER_CONTEXT_TOOLS_OPEN_AS_BINARY = "registerContextToolsBinaryEditor";
    public static final String PREFERENCES_REGISTER_BINARY_MULTIVIEW = "registerBinaryMultiview";
    public static final String PREFERENCES_REGISTER_DEBUG_VIEW_AS_BINARY = "registerDebugVariablesAsBinary";
    public static final String PREFERENCES_REGISTER_BYTE_TO_BYTE_DIFF_TOOL = "registerByteToByteDiffTool";

    public static final String PREFERENCES_REGISTER_EDIT_AS_BINARY_FOR_DB_COLUMN = "registerEditAsBinaryForDbColumn";

    private final OptionsStorage storage;

    public IntegrationOptions(OptionsStorage storage) {
        this.storage = storage;
    }

    public boolean isRegisterFileMenuOpenAsBinary() {
        return storage.getBoolean(PREFERENCES_REGISTER_FILE_MENU_OPEN_AS_BINARY, true);
    }

    public void setRegisterFileMenuOpenAsBinary(boolean registerFileMenuOpenAsBinary) {
        storage.putBoolean(PREFERENCES_REGISTER_FILE_MENU_OPEN_AS_BINARY, registerFileMenuOpenAsBinary);
    }

    public boolean isRegisterOpenFileAsBinaryViaToolbar() {
        return storage.getBoolean(PREFERENCES_REGISTER_OPEN_FILE_AS_BINARY_VIA_TOOLBAR, false);
    }

    public void setRegisterOpenFileAsBinaryViaToolbar(boolean registerOpenFileAsBinaryViaToolbar) {
        storage.putBoolean(PREFERENCES_REGISTER_OPEN_FILE_AS_BINARY_VIA_TOOLBAR, registerOpenFileAsBinaryViaToolbar);
    }

    public boolean isRegisterContextOpenAsBinary() {
        return storage.getBoolean(PREFERENCES_REGISTER_CONTEXT_OPEN_AS_BINARY, false);
    }

    public void setRegisterContextOpenAsBinary(boolean registerContextOpenAsBinary) {
        storage.putBoolean(PREFERENCES_REGISTER_CONTEXT_OPEN_AS_BINARY, registerContextOpenAsBinary);
    }

    public boolean isRegisterContextToolsOpenAsBinary() {
        return storage.getBoolean(PREFERENCES_REGISTER_CONTEXT_TOOLS_OPEN_AS_BINARY, true);
    }

    public void setRegisterContextToolsOpenAsBinary(boolean registerContextToolsOpenAsBinary) {
        storage.putBoolean(PREFERENCES_REGISTER_CONTEXT_TOOLS_OPEN_AS_BINARY, registerContextToolsOpenAsBinary);
    }

    public boolean isRegisterBinaryMultiview() {
        return storage.getBoolean(PREFERENCES_REGISTER_BINARY_MULTIVIEW, true);
    }

    public void setRegisterBinaryMultiview(boolean registerBinaryMultiview) {
        storage.putBoolean(PREFERENCES_REGISTER_BINARY_MULTIVIEW, registerBinaryMultiview);
    }

    public boolean isRegisterDebugViewAsBinary() {
        return storage.getBoolean(PREFERENCES_REGISTER_DEBUG_VIEW_AS_BINARY, true);
    }

    public void setRegisterDebugViewAsBinary(boolean registerDebugViewAsBinary) {
        storage.putBoolean(PREFERENCES_REGISTER_DEBUG_VIEW_AS_BINARY, registerDebugViewAsBinary);
    }

    public boolean isRegisterByteToByteDiffTool() {
        return storage.getBoolean(PREFERENCES_REGISTER_BYTE_TO_BYTE_DIFF_TOOL, true);
    }

    public void setRegisterByteToByteDiffTool(boolean registerByteToByteDiffTool) {
        storage.putBoolean(PREFERENCES_REGISTER_BYTE_TO_BYTE_DIFF_TOOL, registerByteToByteDiffTool);
    }

    public boolean isRegisterEditAsBinaryForDbColumn() {
        return storage.getBoolean(PREFERENCES_REGISTER_EDIT_AS_BINARY_FOR_DB_COLUMN, true);
    }

    public void setRegisterEditAsBinaryForDbColumn(boolean registerEditAsBinaryForDbColumn) {
        storage.putBoolean(PREFERENCES_REGISTER_EDIT_AS_BINARY_FOR_DB_COLUMN, registerEditAsBinaryForDbColumn);
    }

    @Override
    public void copyTo(SettingsOptions options) {
        IntegrationOptions with = (IntegrationOptions) options;
        with.setRegisterFileMenuOpenAsBinary(isRegisterFileMenuOpenAsBinary());
        with.setRegisterOpenFileAsBinaryViaToolbar(isRegisterOpenFileAsBinaryViaToolbar());
        with.setRegisterContextOpenAsBinary(isRegisterContextOpenAsBinary());
        with.setRegisterContextToolsOpenAsBinary(isRegisterContextToolsOpenAsBinary());
        with.setRegisterBinaryMultiview(isRegisterBinaryMultiview());
        with.setRegisterDebugViewAsBinary(isRegisterDebugViewAsBinary());
        with.setRegisterByteToByteDiffTool(isRegisterByteToByteDiffTool());
        with.setRegisterEditAsBinaryForDbColumn(isRegisterEditAsBinaryForDbColumn());
    }
}
