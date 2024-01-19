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
package org.exbin.bined.ghidra.main;

import java.awt.Font;
import java.net.URI;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.swing.JComponent;
import org.exbin.auxiliary.binary_data.BinaryData;
import org.exbin.auxiliary.binary_data.EmptyBinaryData;
import org.exbin.bined.EditMode;
import org.exbin.bined.ghidra.ByteBlocksBinaryData;
import org.exbin.bined.ghidra.ProgramByteBlockSet;
import org.exbin.bined.operation.swing.CodeAreaUndoHandler;
import org.exbin.bined.swing.extended.ExtCodeArea;
import org.exbin.framework.bined.BinEdEditorComponent;
import org.exbin.framework.bined.FileHandlingMode;
import org.exbin.framework.bined.gui.BinEdComponentFileApi;
import org.exbin.framework.editor.text.TextFontApi;
import org.exbin.framework.file.api.FileHandler;
import org.exbin.framework.file.api.FileType;

/**
 * Wrapper for Ghidra file.
 *
 * @author ExBin Project (https://exbin.org)
 */
@ParametersAreNonnullByDefault
public class BinEdWrapperFile implements FileHandler, BinEdComponentFileApi, TextFontApi {
    
    @Nonnull
    private final BinEdEditorComponent editorComponent;
    private Font defaultFont;
    private long documentOriginalSize;
    private String title = "";
    
    public BinEdWrapperFile() {
        BinEdManager binEdManager = BinEdManager.getInstance();
        editorComponent = new BinEdEditorComponent();
        binEdManager.getFileManager().initComponentPanel(editorComponent.getComponentPanel());
        binEdManager.initFileHandler(this);

        ExtCodeArea codeArea = editorComponent.getCodeArea();
        CodeAreaUndoHandler undoHandler = new CodeAreaUndoHandler(codeArea);
        editorComponent.setUndoHandler(undoHandler);

        // TODO undoHandler = new UndoHandlerWrapper(codeArea, project, this);

//        componentPanel.setModifiedChangeListener(() -> {
//            updateModified();
//        });
        defaultFont = codeArea.getCodeFont();
    }

    @Override
    public boolean isModified() {
        return editorComponent.isModified();
    }

    @Nonnull
    @Override
    public JComponent getComponent() {
        return editorComponent.getComponent();
    }

    @Nonnull
    @Override
    public BinEdEditorComponent getEditorComponent() {
        return editorComponent;
    }

    @Nonnull
    public ExtCodeArea getCodeArea() {
        return editorComponent.getCodeArea();
    }

    @Override
    public long getDocumentOriginalSize() {
        return documentOriginalSize;
    }

    @Override
    public int getId() {
        return -1;
    }

    @Nonnull
    @Override
    public Optional<URI> getFileUri() {
        return Optional.empty();
    }

    @Nonnull
    @Override
    public String getTitle() {
        return title;
    }

    @Nonnull
    @Override
    public Optional<FileType> getFileType() {
        return Optional.empty();
    }

    @Override
    public void setFileType(@Nullable FileType fileType) {
    }

    @Override
    public void clearFile() {

    }

    public void openFile(ProgramByteBlockSet blockSet) {
        ExtCodeArea codeArea = getCodeArea();
        BinaryData binaryData;
        if (blockSet == null) {
            binaryData = EmptyBinaryData.INSTANCE;
            codeArea.setEditMode(EditMode.READ_ONLY);
        } else {
            binaryData = new ByteBlocksBinaryData(blockSet);
            codeArea.setEditMode(EditMode.INPLACE);
        }
        documentOriginalSize = binaryData.getDataSize();
//        title = blockSet.
                
        codeArea.setContentData(binaryData);
    }

    @Override
    public boolean isSaveSupported() {
        return true;
    }

    @Override
    public void loadFromFile(URI fileUri, FileType fileType) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void saveFile() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void saveToFile(URI fileUri, FileType fileType) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void saveDocument() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void switchFileHandlingMode(FileHandlingMode fileHandlingMode) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void closeData() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Font getCurrentFont() {
        return getCodeArea().getCodeFont();
    }

    @Override
    public Font getDefaultFont() {
        return defaultFont;
    }

    @Override
    public void setCurrentFont(Font font) {
        getCodeArea().setCodeFont(font);
    }
}
