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

import org.exbin.bined.swing.CodeAreaCore;
import org.exbin.bined.swing.section.SectCodeArea;
import org.exbin.framework.App;
import org.exbin.framework.action.api.ComponentActivationListener;
import org.exbin.framework.bined.BinEdFileHandler;
import org.exbin.framework.bined.BinaryMultiEditorProvider;
import org.exbin.framework.file.api.FileHandler;
import org.exbin.framework.file.api.FileType;
import org.exbin.framework.frame.api.FrameModuleApi;
import org.exbin.framework.operation.undo.api.UndoRedoControl;
import org.exbin.framework.operation.undo.api.UndoRedoState;
import org.exbin.framework.utils.ClipboardActionsHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.swing.JComponent;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

/**
 * File provider for file.
 *
 * @author ExBin Project (https://exbin.org)
 */
@ParametersAreNonnullByDefault
public class BinEdGhidraEditorProvider extends BinaryMultiEditorProvider {

    public BinEdGhidraEditorProvider() {
    }

    @Nonnull
    @Override
    public List<FileHandler> getFileHandlers() {
        return List.of(activeFile);
    }

    @Nonnull
    @Override
    public String getName(FileHandler fileHandler) {
        return "";
    }

    @Override
    public void saveFile(FileHandler fileHandler) {
        throw new IllegalStateException();
    }

    @Override
    public void saveAsFile(FileHandler fileHandler) {
        throw new IllegalStateException();
    }

    @Override
    public void closeFile() {
        throw new IllegalStateException();
    }

    @Override
    public void closeFile(FileHandler fileHandler) {
        throw new IllegalStateException();
    }

    @Override
    public void closeOtherFiles(FileHandler fileHandler) {
        throw new IllegalStateException();
    }

    @Override
    public void closeAllFiles() {
        throw new IllegalStateException();
    }

    @Override
    public void saveAllFiles() {
        throw new IllegalStateException();
    }

    @Nonnull
    @Override
    public JComponent getEditorComponent() {
        if (activeFile == null) {
            return null;
        }
        return activeFile.getComponent();
    }

    @Nonnull
    @Override
    public Optional<FileHandler> getActiveFile() {
        return Optional.ofNullable(activeFile);
    }

    public void setActiveFile(@Nullable FileHandler fileHandler) {
        activeFile = fileHandler;
        activeFileChanged();
    }

    public void activeFileChanged() {
        FrameModuleApi frameModule = App.getModule(FrameModuleApi.class);
        ComponentActivationListener componentActivationListener =
                frameModule.getFrameHandler().getComponentActivationListener();

        SectCodeArea extCodeArea = null;
        ClipboardActionsHandler clipboardActionsHandler = null;
        UndoRedoControl undoHandler = null;
        if (activeFile instanceof BinEdFileHandler) {
            BinEdFileHandler binEdFileHandler = (BinEdFileHandler) activeFile;
            extCodeArea = binEdFileHandler.getCodeArea();
            undoHandler = binEdFileHandler.getUndoRedo();
            clipboardActionsHandler = binEdFileHandler;
        }

        componentActivationListener.updated(FileHandler.class, activeFile);
        componentActivationListener.updated(CodeAreaCore.class, extCodeArea);
        componentActivationListener.updated(UndoRedoState.class, undoHandler);
        componentActivationListener.updated(ClipboardActionsHandler.class, clipboardActionsHandler);

        //        if (this.undoHandler != null) {
        //            this.undoHandler.setActiveFile(this.activeFile);
        //        }
    }

    @Nonnull
    @Override
    public String getWindowTitle(String s) {
        return "";
    }

    @Override
    public void openFile(URI fileUri, FileType fileType) {
        getActiveFile().get().loadFromFile(fileUri, fileType);

    }

    @Override
    public void setModificationListener(EditorModificationListener editorModificationListener) {
        throw new IllegalStateException();
    }

    @Override
    public void newFile() {
        throw new IllegalStateException();
    }

    @Override
    public void openFile() {
        throw new IllegalStateException();
    }

    @Override
    public void saveFile() {
        throw new IllegalStateException();
    }

    @Override
    public void saveAsFile() {
        throw new IllegalStateException();
    }

    @Override
    public boolean canSave() {
        return false;
    }

    @Override
    public void loadFromFile(String s) throws URISyntaxException {
        throw new IllegalStateException();
    }

    @Override
    public void loadFromFile(URI uri, @Nullable FileType fileType) {
        throw new IllegalStateException();
    }
}
