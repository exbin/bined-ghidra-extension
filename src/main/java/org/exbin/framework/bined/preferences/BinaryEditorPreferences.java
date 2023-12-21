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
package org.exbin.framework.bined.preferences;

import org.exbin.framework.api.Preferences;
import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import org.exbin.framework.bined.inspector.preferences.DataInspectorPreferences;
import org.exbin.framework.editor.text.preferences.TextEncodingPreferences;
import org.exbin.framework.editor.text.preferences.TextFontPreferences;

/**
 * Binary editor preferences.
 *
 * @author ExBin Project (https://exbin.org)
 */
@ParametersAreNonnullByDefault
public class BinaryEditorPreferences {

    private final static String PREFERENCES_VERSION = "version";
    private final static String PREFERENCES_VERSION_VALUE = "0.2.0";

    private final Preferences preferences;

//    private final IntegrationPreferences integrationPreferences;
    private final EditorPreferences editorPreferences;
    private final StatusPreferences statusPreferences;
    private final CodeAreaPreferences codeAreaPreferences;
    private final TextEncodingPreferences encodingPreferences;
    private final TextFontPreferences fontPreferences;
    private final DataInspectorPreferences dataInspectorPreferences;
    private final CodeAreaLayoutPreferences layoutPreferences;
    private final CodeAreaThemePreferences themePreferences;
    private final CodeAreaColorPreferences colorPreferences;

    public BinaryEditorPreferences(Preferences preferences) {
        this.preferences = preferences;

//        integrationPreferences = new IntegrationPreferences(preferences);
        editorPreferences = new EditorPreferences(preferences);
        statusPreferences = new StatusPreferences(preferences);
        codeAreaPreferences = new CodeAreaPreferences(preferences);
        encodingPreferences = new TextEncodingPreferences(preferences);
        fontPreferences = new TextFontPreferences(preferences);
        dataInspectorPreferences = new DataInspectorPreferences(preferences);
        layoutPreferences = new CodeAreaLayoutPreferences(preferences);
        themePreferences = new CodeAreaThemePreferences(preferences);
        colorPreferences = new CodeAreaColorPreferences(preferences);
    }

    @Nonnull
    public Preferences getPreferences() {
        return preferences;
    }

//    @Nonnull
//    public IntegrationPreferences getIntegrationPreferences() {
//        return integrationPreferences;
//    }
    @Nonnull
    public EditorPreferences getEditorPreferences() {
        return editorPreferences;
    }

    @Nonnull
    public StatusPreferences getStatusPreferences() {
        return statusPreferences;
    }

    @Nonnull
    public CodeAreaPreferences getCodeAreaPreferences() {
        return codeAreaPreferences;
    }

    @Nonnull
    public TextEncodingPreferences getEncodingPreferences() {
        return encodingPreferences;
    }

    @Nonnull
    public TextFontPreferences getFontPreferences() {
        return fontPreferences;
    }

    @Nonnull
    public DataInspectorPreferences getDataInspectorPreferences() {
        return dataInspectorPreferences;
    }

    @Nonnull
    public CodeAreaLayoutPreferences getLayoutPreferences() {
        return layoutPreferences;
    }

    @Nonnull
    public CodeAreaThemePreferences getThemePreferences() {
        return themePreferences;
    }

    @Nonnull
    public CodeAreaColorPreferences getColorPreferences() {
        return colorPreferences;
    }
}
