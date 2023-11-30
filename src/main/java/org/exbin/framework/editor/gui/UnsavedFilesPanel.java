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
package org.exbin.framework.editor.gui;

import java.util.List;
import java.util.ResourceBundle;
import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.swing.DefaultListModel;
import javax.swing.event.ListSelectionEvent;
import org.exbin.framework.file.api.FileHandler;
import org.exbin.framework.utils.LanguageUtils;
import org.exbin.framework.utils.WindowUtils;

/**
 * Unsaved files panel.
 *
 * @author ExBin Project (https://exbin.org)
 */
@ParametersAreNonnullByDefault
public class UnsavedFilesPanel extends javax.swing.JPanel {

    private final ResourceBundle resourceBundle = LanguageUtils.getResourceBundleByClass(UnsavedFilesPanel.class);
    private List<FileHandler> fileHandlers;
    private Controller controller;

    public UnsavedFilesPanel() {
        initComponents();
        init();
    }

    private void init() {
        filesList.addListSelectionListener((ListSelectionEvent e) -> {
            saveButton.setEnabled(filesList.getSelectedIndex() != -1);
        });
    }

    public void assignGlobalKeys() {
        WindowUtils.assignGlobalKeyListener(this, cancelButton);
    }

    @Nonnull
    public ResourceBundle getResourceBundle() {
        return resourceBundle;
    }

    public void setController(Controller controller) {
        this.controller = controller;
    }

    public void setUnsavedFiles(List<FileHandler> fileHandlers) {
        this.fileHandlers = fileHandlers;
        DefaultListModel<String> listModel = new DefaultListModel<>();
        for (FileHandler fileHandler : fileHandlers) {
            listModel.addElement(fileHandler.getFileName());
        }
        filesList.setModel(listModel);
        filesList.invalidate();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        filesListLabel = new javax.swing.JLabel();
        filesListScrollPane = new javax.swing.JScrollPane();
        filesList = new javax.swing.JList<>();
        saveButton = new javax.swing.JButton();
        saveAllButton = new javax.swing.JButton();
        discardAllButton = new javax.swing.JButton();
        cancelButton = new javax.swing.JButton();

        setPreferredSize(new java.awt.Dimension(400, 300));

        filesListLabel.setText(resourceBundle.getString("filesListLabel.text")); // NOI18N

        filesListScrollPane.setViewportView(filesList);

        saveButton.setText(resourceBundle.getString("saveButton.text")); // NOI18N
        saveButton.setEnabled(false);
        saveButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveButtonActionPerformed(evt);
            }
        });

        saveAllButton.setText(resourceBundle.getString("saveAllButton.text")); // NOI18N
        saveAllButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveAllButtonActionPerformed(evt);
            }
        });

        discardAllButton.setText(resourceBundle.getString("discardAllButton.text")); // NOI18N
        discardAllButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                discardAllButtonActionPerformed(evt);
            }
        });

        cancelButton.setText(resourceBundle.getString("cancelButton.text")); // NOI18N
        cancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(filesListScrollPane)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(discardAllButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(saveButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(saveAllButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(cancelButton, javax.swing.GroupLayout.PREFERRED_SIZE, 104, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(filesListLabel)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(filesListLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(filesListScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 269, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(saveButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(saveAllButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(discardAllButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(cancelButton)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    private void saveButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveButtonActionPerformed
        if (controller != null) {
            int[] selectedIndices = filesList.getSelectedIndices();
            int shift = 0;
            for (int i = 0; i < selectedIndices.length; i++) {
                int selectedIndex = selectedIndices[i];
                FileHandler fileHandler = fileHandlers.get(selectedIndex - shift);
                if (controller.saveFile(fileHandler)) {
                    DefaultListModel<String> listModel = (DefaultListModel<String>) filesList.getModel();
                    listModel.remove(selectedIndex - shift);
                    fileHandlers.remove(selectedIndex - shift);
                    shift++;
                } else {
                    break;
                }
            }

            if (fileHandlers.isEmpty()) {
                controller.discardAll(fileHandlers);
            }
        }
    }//GEN-LAST:event_saveButtonActionPerformed

    private void saveAllButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveAllButtonActionPerformed
        if (controller != null) {
            int shift = 0;
            int size = fileHandlers.size();
            for (int index = 0; index < size; index++) {
                FileHandler fileHandler = fileHandlers.get(index - shift);
                if (controller.saveFile(fileHandler)) {
                    DefaultListModel<String> listModel = (DefaultListModel<String>) filesList.getModel();
                    listModel.remove(index - shift);
                    fileHandlers.remove(index - shift);
                    shift++;
                } else {
                    break;
                }
            }

            if (fileHandlers.isEmpty()) {
                controller.discardAll(fileHandlers);
            }
        }
    }//GEN-LAST:event_saveAllButtonActionPerformed

    private void discardAllButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_discardAllButtonActionPerformed
        if (controller != null) {
            controller.discardAll(fileHandlers);
        }
    }//GEN-LAST:event_discardAllButtonActionPerformed

    private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelButtonActionPerformed
        if (controller != null) {
            controller.cancel();
        }
    }//GEN-LAST:event_cancelButtonActionPerformed

    /**
     * Test method for this panel.
     *
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        WindowUtils.invokeDialog(new UnsavedFilesPanel());
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton cancelButton;
    private javax.swing.JButton discardAllButton;
    private javax.swing.JList<String> filesList;
    private javax.swing.JLabel filesListLabel;
    private javax.swing.JScrollPane filesListScrollPane;
    private javax.swing.JButton saveAllButton;
    private javax.swing.JButton saveButton;
    // End of variables declaration//GEN-END:variables

    @ParametersAreNonnullByDefault
    public interface Controller {

        boolean saveFile(FileHandler fileHandler);

        void discardAll(List<FileHandler> fileHandlers);

        void cancel();
    }
}
