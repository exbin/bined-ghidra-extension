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
package org.exbin.bined.ghidra.gui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.ButtonGroup;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.JToolBar;
import javax.swing.JToolBar.Separator;
import org.exbin.auxiliary.dropdownbutton.DropDownButton;
import org.exbin.bined.CodeType;
import org.exbin.jaguif.App;
import org.exbin.bined.jaguif.viewer.settings.CodeAreaOptions;
import org.exbin.bined.operation.command.BinaryDataUndoRedo;
import org.exbin.jaguif.language.api.LanguageModuleApi;
import org.exbin.jaguif.options.api.OptionsStorage;
import org.jspecify.annotations.NullMarked;

/**
 * Binary editor toolbar panel.
 */
@NullMarked
public class BinEdToolbarPanel extends javax.swing.JPanel {

    private final java.util.ResourceBundle componentResourceBundle;
    private final java.util.ResourceBundle viewerResourceBundle;
    private final java.util.ResourceBundle dockingResourceBundle;
    private final java.util.ResourceBundle optionsSettingsResourceBundle;
    private final java.util.ResourceBundle onlineHelpResourceBundle;
    private final java.util.ResourceBundle operationUndoResourceBundle;

    private Control codeAreaControl;
    private ActionListener optionsAction;
    private ActionListener onlineHelpAction;
    private ActionListener saveAction = null;

    private BinaryDataUndoRedo undoRedo;

    private final AbstractAction cycleCodeTypesAction;
    private final JRadioButtonMenuItem binaryCodeTypeMenuItem;
    private final JRadioButtonMenuItem octalCodeTypeMenuItem;
    private final JRadioButtonMenuItem decimalCodeTypeMenuItem;
    private final JRadioButtonMenuItem hexadecimalCodeTypeMenuItem;
    private final ButtonGroup codeTypeButtonGroup;
    private DropDownButton codeTypeDropDown;

    public BinEdToolbarPanel() {
        LanguageModuleApi languageModule = App.getModule(LanguageModuleApi.class);
        componentResourceBundle = languageModule.getBundle(org.exbin.bined.jaguif.component.BinedComponentModule.class);
        viewerResourceBundle = languageModule.getBundle(org.exbin.bined.jaguif.viewer.BinedViewerModule.class);
        dockingResourceBundle = languageModule.getBundle(org.exbin.jaguif.docking.DockingModule.class);
        optionsSettingsResourceBundle = languageModule.getBundle(org.exbin.jaguif.options.settings.OptionsSettingsModule.class);
        onlineHelpResourceBundle = languageModule.getBundle(org.exbin.jaguif.help.online.action.OnlineHelpAction.class);
        operationUndoResourceBundle = languageModule.getBundle(org.exbin.jaguif.operation.undo.OperationUndoModule.class);

        codeTypeButtonGroup = new ButtonGroup();
        Action binaryCodeTypeAction = new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                codeAreaControl.setCodeType(CodeType.BINARY);
                updateCycleButtonState();
            }
        };
        binaryCodeTypeAction.putValue(Action.NAME, viewerResourceBundle.getString("binaryCodeTypeAction.text"));
        binaryCodeTypeAction.putValue(Action.SHORT_DESCRIPTION, viewerResourceBundle.getString("binaryCodeTypeAction.shortDescription"));
        binaryCodeTypeMenuItem = new JRadioButtonMenuItem(binaryCodeTypeAction);
        codeTypeButtonGroup.add(binaryCodeTypeMenuItem);
        Action octalCodeTypeAction = new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                codeAreaControl.setCodeType(CodeType.OCTAL);
                updateCycleButtonState();
            }
        };
        octalCodeTypeAction.putValue(Action.NAME, viewerResourceBundle.getString("octalCodeTypeAction.text"));
        octalCodeTypeAction.putValue(Action.SHORT_DESCRIPTION, viewerResourceBundle.getString("octalCodeTypeAction.shortDescription"));
        octalCodeTypeMenuItem = new JRadioButtonMenuItem(octalCodeTypeAction);
        codeTypeButtonGroup.add(octalCodeTypeMenuItem);
        Action decimalCodeTypeAction = new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                codeAreaControl.setCodeType(CodeType.DECIMAL);
                updateCycleButtonState();
            }
        };
        decimalCodeTypeAction.putValue(Action.NAME, viewerResourceBundle.getString("decimalCodeTypeAction.text"));
        decimalCodeTypeAction.putValue(Action.SHORT_DESCRIPTION, viewerResourceBundle.getString("decimalCodeTypeAction.shortDescription"));
        decimalCodeTypeMenuItem = new JRadioButtonMenuItem(decimalCodeTypeAction);
        codeTypeButtonGroup.add(decimalCodeTypeMenuItem);
        Action hexadecimalCodeTypeAction = new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                codeAreaControl.setCodeType(CodeType.HEXADECIMAL);
                updateCycleButtonState();
            }
        };
        hexadecimalCodeTypeAction.putValue(Action.NAME, viewerResourceBundle.getString("hexadecimalCodeTypeAction.text"));
        hexadecimalCodeTypeAction.putValue(Action.SHORT_DESCRIPTION, viewerResourceBundle.getString("hexadecimalCodeTypeAction.shortDescription"));
        hexadecimalCodeTypeMenuItem = new JRadioButtonMenuItem(hexadecimalCodeTypeAction);
        codeTypeButtonGroup.add(hexadecimalCodeTypeMenuItem);
        cycleCodeTypesAction = new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int codeTypePos = codeAreaControl.getCodeType().ordinal();
                CodeType[] values = CodeType.values();
                CodeType next = codeTypePos + 1 >= values.length ? values[0] : values[codeTypePos + 1];
                codeAreaControl.setCodeType(next);
                updateCycleButtonState();
            }
        };

        initComponents();
        init();
    }

    private void init() {
        cycleCodeTypesAction.putValue(Action.SHORT_DESCRIPTION, viewerResourceBundle.getString("cycleCodeTypesAction.shortDescription"));
        JPopupMenu cycleCodeTypesPopupMenu = new JPopupMenu();
        cycleCodeTypesPopupMenu.add(binaryCodeTypeMenuItem);
        cycleCodeTypesPopupMenu.add(octalCodeTypeMenuItem);
        cycleCodeTypesPopupMenu.add(decimalCodeTypeMenuItem);
        cycleCodeTypesPopupMenu.add(hexadecimalCodeTypeMenuItem);
        codeTypeDropDown = new DropDownButton(cycleCodeTypesAction, cycleCodeTypesPopupMenu);
        toolBar.add(codeTypeDropDown);

        toolBar.addSeparator();
        JButton settingsAction = new JButton();
        settingsAction.setAction(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (optionsAction != null) {
                    optionsAction.actionPerformed(e);
                }
            }
        });
        settingsAction.setToolTipText(optionsSettingsResourceBundle.getString("settingsAction.text"));
        settingsAction.setIcon(new ImageIcon(getClass().getResource(optionsSettingsResourceBundle.getString("settingsAction.smallIcon"))));
        toolBar.add(settingsAction);

        JButton onlineHelpButton = new JButton();
        onlineHelpButton.setAction(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (onlineHelpAction != null) {
                    onlineHelpAction.actionPerformed(e);
                }
            }
        });
        onlineHelpButton.setToolTipText(onlineHelpResourceBundle.getString("onlineHelpAction.text"));
        onlineHelpButton.setIcon(new ImageIcon(getClass().getResource("/org/exbin/bined/ghidra/resources/icons/help.png")));
        toolBar.add(onlineHelpButton);
    }

    public void setTargetComponent(JComponent targetComponent) {
        // controlToolBar.setTargetComponent(targetComponent);
    }

    public void setCodeAreaControl(Control codeAreaControl) {
        this.codeAreaControl = codeAreaControl;
        updateCycleButtonState();
    }

    public void setOptionsAction(ActionListener optionsAction) {
        this.optionsAction = optionsAction;
    }

    public void setOnlineHelpAction(ActionListener onlineHelpAction) {
        this.onlineHelpAction = onlineHelpAction;
    }

    private void updateCycleButtonState() {
        CodeType codeType = codeAreaControl.getCodeType();
        codeTypeDropDown.setActionText(codeType.name().substring(0, 3));
        switch (codeType) {
            case BINARY: {
                if (!binaryCodeTypeMenuItem.isSelected()) {
                    binaryCodeTypeMenuItem.setSelected(true);
                }
                break;
            }
            case OCTAL: {
                if (!octalCodeTypeMenuItem.isSelected()) {
                    octalCodeTypeMenuItem.setSelected(true);
                }
                break;
            }
            case DECIMAL: {
                if (!decimalCodeTypeMenuItem.isSelected()) {
                    decimalCodeTypeMenuItem.setSelected(true);
                }
                break;
            }
            case HEXADECIMAL: {
                if (!hexadecimalCodeTypeMenuItem.isSelected()) {
                    hexadecimalCodeTypeMenuItem.setSelected(true);
                }
                break;
            }
        }
    }

    public void applyFromCodeArea() {
        updateCycleButtonState();
        updateNonprintables();
    }

    public void loadFromOptions(OptionsStorage options) {
        codeAreaControl.setCodeType(new CodeAreaOptions(options).getCodeType());
        updateCycleButtonState();
        updateNonprintables();
    }

    public void updateNonprintables() {
        showNonprintablesToggleButton.setSelected(codeAreaControl.isShowNonprintables());
    }

    public void updateUndoState() {
        undoEditButton.setEnabled(undoRedo.canUndo());
        redoEditButton.setEnabled(undoRedo.canRedo());
        saveFileButton.setEnabled(undoRedo.getCommandPosition() != undoRedo.getSyncPosition());
    }

    public void setUndoHandler(BinaryDataUndoRedo undoRedo, ActionListener saveAction) {
        this.undoRedo = undoRedo;
        saveFileButton.addActionListener((event) -> saveAction.actionPerformed(event));

        toolBar.add(saveFileButton, 0);
        toolBar.add(new Separator(), 1);
        toolBar.add(undoEditButton, 2);
        toolBar.add(redoEditButton, 3);
        toolBar.add(new Separator(), 4);
        updateUndoState();
    }

    @Override
    public void updateUI() {
        super.updateUI();
        if (codeTypeDropDown != null) {
            codeTypeDropDown.updateUI();
        }
    }

    public JToolBar getToolBar() {
        return toolBar;
    }

    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        saveFileButton = new javax.swing.JButton();
        undoEditButton = new javax.swing.JButton();
        redoEditButton = new javax.swing.JButton();
        toolBar = new javax.swing.JToolBar();
        showNonprintablesToggleButton = new javax.swing.JToggleButton();
        separator1 = new javax.swing.JToolBar.Separator();

        saveFileButton.setIcon(new javax.swing.ImageIcon(getClass().getResource(dockingResourceBundle.getString("saveFileAction.smallIcon"))));
        saveFileButton.setToolTipText(dockingResourceBundle.getString("saveFileAction.shortDescription"));
        saveFileButton.setEnabled(false);
        saveFileButton.setFocusable(false);
        saveFileButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        saveFileButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        saveFileButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveFileButtonActionPerformed(evt);
            }
        });

        undoEditButton.setIcon(new javax.swing.ImageIcon(getClass().getResource(operationUndoResourceBundle.getString("editUndoAction.smallIcon"))));
        undoEditButton.setToolTipText(operationUndoResourceBundle.getString("editUndoAction.shortDescription"));
        undoEditButton.setFocusable(false);
        undoEditButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        undoEditButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        undoEditButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                undoEditButtonActionPerformed(evt);
            }
        });

        redoEditButton.setIcon(new javax.swing.ImageIcon(getClass().getResource(operationUndoResourceBundle.getString("editRedoAction.smallIcon"))));
        redoEditButton.setToolTipText(operationUndoResourceBundle.getString("editRedoAction.shortDescription"));
        redoEditButton.setFocusable(false);
        redoEditButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        redoEditButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        redoEditButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                redoEditButtonActionPerformed(evt);
            }
        });

        toolBar.setBorder(null);
        toolBar.setRollover(true);

        showNonprintablesToggleButton.setIcon(new javax.swing.ImageIcon(getClass().getResource(componentResourceBundle.getString("toggleNonprintablesAction.smallIcon"))));
        showNonprintablesToggleButton.setToolTipText(componentResourceBundle.getString("viewNonprintablesAction.shortDescription"));
        showNonprintablesToggleButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                showNonprintablesToggleButtonActionPerformed(evt);
            }
        });
        toolBar.add(showNonprintablesToggleButton);
        toolBar.add(separator1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(toolBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 354, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(toolBar, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, 0))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void showNonprintablesToggleButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_showNonprintablesToggleButtonActionPerformed
        codeAreaControl.setShowNonprintables(showNonprintablesToggleButton.isSelected());
    }//GEN-LAST:event_showNonprintablesToggleButtonActionPerformed

    private void redoEditButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_redoEditButtonActionPerformed
        try {
            undoRedo.performRedo();
            codeAreaControl.repaint();
            updateUndoState();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }//GEN-LAST:event_redoEditButtonActionPerformed

    private void undoEditButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_undoEditButtonActionPerformed
        try {
            undoRedo.performUndo();
            codeAreaControl.repaint();
            updateUndoState();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }//GEN-LAST:event_undoEditButtonActionPerformed

    private void saveFileButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveFileButtonActionPerformed
        if (saveAction != null) saveAction.actionPerformed(evt);
    }//GEN-LAST:event_saveFileButtonActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton redoEditButton;
    private javax.swing.JButton saveFileButton;
    private javax.swing.JToolBar.Separator separator1;
    private javax.swing.JToggleButton showNonprintablesToggleButton;
    private javax.swing.JToolBar toolBar;
    private javax.swing.JButton undoEditButton;
    // End of variables declaration//GEN-END:variables

    @NullMarked
    public interface Control {

        CodeType getCodeType();

        void setCodeType(CodeType codeType);

        boolean isShowNonprintables();

        void setShowNonprintables(boolean showNonprintables);

        void repaint();
    }
}
