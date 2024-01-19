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
import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
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
import org.exbin.bined.CodeType;
import org.exbin.bined.operation.BinaryDataCommand;
import org.exbin.bined.operation.undo.BinaryDataUndoHandler;
import org.exbin.bined.operation.undo.BinaryDataUndoUpdateListener;
import org.exbin.framework.bined.preferences.BinaryEditorPreferences;
import org.exbin.framework.action.gui.DropDownButton;
import org.exbin.framework.utils.LanguageUtils;

/**
 * Binary editor toolbar panel.
 *
 * @author ExBin Project (https://exbin.org)
 */
@ParametersAreNonnullByDefault
public class BinEdToolbarPanel extends javax.swing.JPanel {

    private final java.util.ResourceBundle resourceBundle = LanguageUtils.getResourceBundleByClass(BinEdToolbarPanel.class);

    private final Control codeAreaControl;
    private AbstractAction optionsAction;
    private AbstractAction onlineHelpAction;
    private BinaryDataUndoHandler undoHandler;

    private ActionListener saveAction = null;
    private final AbstractAction cycleCodeTypesAction;
    private final JRadioButtonMenuItem binaryCodeTypeAction;
    private final JRadioButtonMenuItem octalCodeTypeAction;
    private final JRadioButtonMenuItem decimalCodeTypeAction;
    private final JRadioButtonMenuItem hexadecimalCodeTypeAction;
    private final ButtonGroup codeTypeButtonGroup;
    private DropDownButton codeTypeDropDown;

    public BinEdToolbarPanel(JComponent targetComponent, Control codeAreaControl) {
        // BinaryEditorPreferences preferences, ExtCodeArea codeArea, AbstractAction optionsAction, AbstractAction onlineHelpAction
        this.codeAreaControl = codeAreaControl;

        codeTypeButtonGroup = new ButtonGroup();
        binaryCodeTypeAction = new JRadioButtonMenuItem(new AbstractAction("Binary") {
            @Override
            public void actionPerformed(ActionEvent e) {
                codeAreaControl.setCodeType(CodeType.BINARY);
                updateCycleButtonState();
            }
        });
        codeTypeButtonGroup.add(binaryCodeTypeAction);
        octalCodeTypeAction = new JRadioButtonMenuItem(new AbstractAction("Octal") {
            @Override
            public void actionPerformed(ActionEvent e) {
                codeAreaControl.setCodeType(CodeType.OCTAL);
                updateCycleButtonState();
            }
        });
        codeTypeButtonGroup.add(octalCodeTypeAction);
        decimalCodeTypeAction = new JRadioButtonMenuItem(new AbstractAction("Decimal") {
            @Override
            public void actionPerformed(ActionEvent e) {
                codeAreaControl.setCodeType(CodeType.DECIMAL);
                updateCycleButtonState();
            }
        });
        codeTypeButtonGroup.add(decimalCodeTypeAction);
        hexadecimalCodeTypeAction = new JRadioButtonMenuItem(new AbstractAction("Hexadecimal") {
            @Override
            public void actionPerformed(ActionEvent e) {
                codeAreaControl.setCodeType(CodeType.HEXADECIMAL);
                updateCycleButtonState();
            }
        });
        codeTypeButtonGroup.add(hexadecimalCodeTypeAction);
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
        cycleCodeTypesAction.putValue(Action.SHORT_DESCRIPTION, "Cycle thru code types");
        JPopupMenu cycleCodeTypesPopupMenu = new JPopupMenu();
        cycleCodeTypesPopupMenu.add(binaryCodeTypeAction);
        cycleCodeTypesPopupMenu.add(octalCodeTypeAction);
        cycleCodeTypesPopupMenu.add(decimalCodeTypeAction);
        cycleCodeTypesPopupMenu.add(hexadecimalCodeTypeAction);
        codeTypeDropDown = new DropDownButton(cycleCodeTypesAction, cycleCodeTypesPopupMenu);
        updateCycleButtonState();
        controlToolBar.add(codeTypeDropDown);

        controlToolBar.addSeparator();
        JButton optionsButton = new JButton();
        optionsButton.setAction(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (optionsAction != null) {
                    optionsAction.actionPerformed(e);
                }
            }
        });
        optionsButton.setToolTipText("Options");
        optionsButton.setIcon(new ImageIcon(getClass().getResource("/org/exbin/framework/options/gui/resources/icons/Preferences16.gif")));
        controlToolBar.add(optionsButton);

        JButton onlineHelpButton = new JButton();
        onlineHelpButton.setAction(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (onlineHelpAction != null) {
                    onlineHelpAction.actionPerformed(e);
                }
            }
        });
        onlineHelpButton.setToolTipText("Online Help");
        onlineHelpButton.setIcon(new ImageIcon(getClass().getResource("/org/exbin/framework/bined/resources/icons/open_icon_library/icons/png/16x16/actions/help.png")));
        controlToolBar.add(onlineHelpButton);
    }

    public void setOptionsAction(AbstractAction optionsAction) {
        this.optionsAction = optionsAction;
    }

    public void setOnlineHelpAction(AbstractAction onlineHelpAction) {
        this.onlineHelpAction = onlineHelpAction;
    }

    private void updateCycleButtonState() {
        CodeType codeType = codeAreaControl.getCodeType();
        codeTypeDropDown.setActionText(codeType.name().substring(0, 3));
        switch (codeType) {
            case BINARY: {
                if (!binaryCodeTypeAction.isSelected()) {
                    binaryCodeTypeAction.setSelected(true);
                }
                break;
            }
            case OCTAL: {
                if (!octalCodeTypeAction.isSelected()) {
                    octalCodeTypeAction.setSelected(true);
                }
                break;
            }
            case DECIMAL: {
                if (!decimalCodeTypeAction.isSelected()) {
                    decimalCodeTypeAction.setSelected(true);
                }
                break;
            }
            case HEXADECIMAL: {
                if (!hexadecimalCodeTypeAction.isSelected()) {
                    hexadecimalCodeTypeAction.setSelected(true);
                }
                break;
            }
        }
    }

    public void applyFromCodeArea() {
        updateCycleButtonState();
        updateUnprintables();
    }

    public void loadFromPreferences(BinaryEditorPreferences preferences) {
        codeAreaControl.setCodeType(preferences.getCodeAreaPreferences().getCodeType());
        updateCycleButtonState();
        updateUnprintables();
    }

    public void updateUnprintables() {
        showUnprintablesToggleButton.setSelected(codeAreaControl.isShowUnprintables());
    }

    public void updateUndoState() {
        undoEditButton.setEnabled(undoHandler.canUndo());
        redoEditButton.setEnabled(undoHandler.canRedo());
        saveFileButton.setEnabled(undoHandler.getCommandPosition() != undoHandler.getSyncPoint());
    }

    public void setUndoHandler(BinaryDataUndoHandler undoHandler, ActionListener saveAction) {
        this.undoHandler = undoHandler;
        saveFileButton.addActionListener((event) -> saveAction.actionPerformed(event));

        controlToolBar.add(saveFileButton, 0);
        controlToolBar.add(new Separator(), 1);
        controlToolBar.add(undoEditButton, 2);
        controlToolBar.add(redoEditButton, 3);
        controlToolBar.add(new Separator(), 4);
        undoHandler.addUndoUpdateListener(new BinaryDataUndoUpdateListener() {
            @Override
            public void undoCommandPositionChanged() {
                updateCycleButtonState();
            }

            @Override
            public void undoCommandAdded(BinaryDataCommand command) {
            }
        });
        updateUndoState();
    }

    @Override
    public void updateUI() {
        super.updateUI();
        if (codeTypeDropDown != null) {
            codeTypeDropDown.updateUI();
        }
    }

    @Nonnull
    public JToolBar getToolBar() {
        return controlToolBar;
    }

    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        saveFileButton = new javax.swing.JButton();
        undoEditButton = new javax.swing.JButton();
        redoEditButton = new javax.swing.JButton();
        controlToolBar = new javax.swing.JToolBar();
        showUnprintablesToggleButton = new javax.swing.JToggleButton();
        separator1 = new javax.swing.JToolBar.Separator();

        saveFileButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/org/exbin/bined/ghidra/resources/icons/document-save.png"))); // NOI18N
        saveFileButton.setToolTipText(resourceBundle.getString("BinEdToolbarPanel.saveFileButton.toolTipText")); // NOI18N
        saveFileButton.setEnabled(false);
        saveFileButton.setFocusable(false);
        saveFileButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        saveFileButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        saveFileButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveFileButtonActionPerformed(evt);
            }
        });

        undoEditButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/org/exbin/bined/ghidra/resources/icons/edit-undo.png"))); // NOI18N
        undoEditButton.setToolTipText(resourceBundle.getString("BinEdToolbarPanel.undoEditButton.toolTipText")); // NOI18N
        undoEditButton.setFocusable(false);
        undoEditButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        undoEditButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        undoEditButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                undoEditButtonActionPerformed(evt);
            }
        });

        redoEditButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/org/exbin/bined/ghidra/resources/icons/edit-redo.png"))); // NOI18N
        redoEditButton.setToolTipText(resourceBundle.getString("BinEdToolbarPanel.redoEditButton.toolTipText")); // NOI18N
        redoEditButton.setFocusable(false);
        redoEditButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        redoEditButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        redoEditButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                redoEditButtonActionPerformed(evt);
            }
        });

        controlToolBar.setBorder(null);
        controlToolBar.setRollover(true);

        showUnprintablesToggleButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/org/exbin/bined/ghidra/resources/icons/insert-pilcrow.png"))); // NOI18N
        showUnprintablesToggleButton.setToolTipText(resourceBundle.getString("showUnprintablesToggleButton.toolTipText")); // NOI18N
        showUnprintablesToggleButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                showUnprintablesToggleButtonActionPerformed(evt);
            }
        });
        controlToolBar.add(showUnprintablesToggleButton);
        controlToolBar.add(separator1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(controlToolBar, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 338, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(controlToolBar, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, 0))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void showUnprintablesToggleButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_showUnprintablesToggleButtonActionPerformed
        codeAreaControl.setShowUnprintables(showUnprintablesToggleButton.isSelected());
    }//GEN-LAST:event_showUnprintablesToggleButtonActionPerformed

    private void redoEditButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_redoEditButtonActionPerformed
        try {
            undoHandler.performRedo();
            codeAreaControl.repaint();
            updateUndoState();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }//GEN-LAST:event_redoEditButtonActionPerformed

    private void undoEditButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_undoEditButtonActionPerformed
        try {
            undoHandler.performUndo();
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
    private javax.swing.JToolBar controlToolBar;
    private javax.swing.JButton redoEditButton;
    private javax.swing.JButton saveFileButton;
    private javax.swing.JToolBar.Separator separator1;
    private javax.swing.JToggleButton showUnprintablesToggleButton;
    private javax.swing.JButton undoEditButton;
    // End of variables declaration//GEN-END:variables

    @ParametersAreNonnullByDefault
    public interface Control {

        @Nonnull
        CodeType getCodeType();

        void setCodeType(CodeType codeType);

        boolean isShowUnprintables();

        void setShowUnprintables(boolean showUnprintables);

        void repaint();
    }
}
