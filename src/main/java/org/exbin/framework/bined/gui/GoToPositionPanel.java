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
package org.exbin.framework.bined.gui;

import java.util.ResourceBundle;
import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import org.exbin.bined.CodeAreaUtils;
import org.exbin.framework.utils.LanguageUtils;
import org.exbin.framework.utils.WindowUtils;

/**
 * Go-to position panel for binary editor.
 *
 * @author ExBin Project (https://exbin.org)
 */
@ParametersAreNonnullByDefault
public class GoToPositionPanel extends javax.swing.JPanel {

    private final java.util.ResourceBundle resourceBundle = LanguageUtils.getResourceBundleByClass(GoToPositionPanel.class);

    private long cursorPosition;
    private long maxPosition;
    private RelativePositionMode goToMode = RelativePositionMode.FROM_START;

    public GoToPositionPanel() {
        initComponents();

        positionBaseSwitchableSpinnerPanel.setMinimum(0L);
        positionBaseSwitchableSpinnerPanel.addChangeListener((javax.swing.event.ChangeEvent evt) -> {
            updateTargetPosition();
        });
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        positionTypeButtonGroup = new javax.swing.ButtonGroup();
        currentPositionLabel = new javax.swing.JLabel();
        currentPositionTextField = new javax.swing.JTextField();
        goToPanel = new javax.swing.JPanel();
        fromStartRadioButton = new javax.swing.JRadioButton();
        fromEndRadioButton = new javax.swing.JRadioButton();
        fromCursorRadioButton = new javax.swing.JRadioButton();
        positionLabel = new javax.swing.JLabel();
        positionBaseSwitchableSpinnerPanel = new org.exbin.framework.bined.gui.BaseSwitchableSpinnerPanel();
        targetPositionLabel = new javax.swing.JLabel();
        targetPositionTextField = new javax.swing.JTextField();

        currentPositionLabel.setText(resourceBundle.getString("currentPositionLabel.text")); // NOI18N

        currentPositionTextField.setEditable(false);
        currentPositionTextField.setText("0"); // NOI18N

        goToPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(resourceBundle.getString("goToPanel.border.title"))); // NOI18N

        positionTypeButtonGroup.add(fromStartRadioButton);
        fromStartRadioButton.setSelected(true);
        fromStartRadioButton.setText(resourceBundle.getString("fromStartRadioButton.text")); // NOI18N
        fromStartRadioButton.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                fromStartRadioButtonItemStateChanged(evt);
            }
        });

        positionTypeButtonGroup.add(fromEndRadioButton);
        fromEndRadioButton.setText(resourceBundle.getString("fromEndRadioButton.text")); // NOI18N
        fromEndRadioButton.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                fromEndRadioButtonItemStateChanged(evt);
            }
        });

        positionTypeButtonGroup.add(fromCursorRadioButton);
        fromCursorRadioButton.setText(resourceBundle.getString("fromCursorRadioButton.text")); // NOI18N
        fromCursorRadioButton.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                fromCursorRadioButtonItemStateChanged(evt);
            }
        });

        positionLabel.setText(resourceBundle.getString("positionLabel.text")); // NOI18N

        javax.swing.GroupLayout goToPanelLayout = new javax.swing.GroupLayout(goToPanel);
        goToPanel.setLayout(goToPanelLayout);
        goToPanelLayout.setHorizontalGroup(
            goToPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, goToPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(goToPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(fromCursorRadioButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(fromEndRadioButton, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(fromStartRadioButton, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(positionBaseSwitchableSpinnerPanel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 400, Short.MAX_VALUE)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, goToPanelLayout.createSequentialGroup()
                        .addComponent(positionLabel)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        goToPanelLayout.setVerticalGroup(
            goToPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(goToPanelLayout.createSequentialGroup()
                .addComponent(fromStartRadioButton, javax.swing.GroupLayout.PREFERRED_SIZE, 22, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(fromEndRadioButton, javax.swing.GroupLayout.PREFERRED_SIZE, 22, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(fromCursorRadioButton, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(positionLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(positionBaseSwitchableSpinnerPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        targetPositionLabel.setText(resourceBundle.getString("targetPositionLabel.text")); // NOI18N

        targetPositionTextField.setEditable(false);
        targetPositionTextField.setText("0"); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(currentPositionTextField)
                    .addComponent(goToPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(targetPositionTextField)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(currentPositionLabel)
                            .addComponent(targetPositionLabel))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(currentPositionLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(currentPositionTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(goToPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(targetPositionLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(targetPositionTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void fromStartRadioButtonItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_fromStartRadioButtonItemStateChanged
        if (fromStartRadioButton.isSelected()) {
            switchGoToMode(RelativePositionMode.FROM_START);
        }
    }//GEN-LAST:event_fromStartRadioButtonItemStateChanged

    private void fromEndRadioButtonItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_fromEndRadioButtonItemStateChanged
        if (fromEndRadioButton.isSelected()) {
            switchGoToMode(RelativePositionMode.FROM_END);
        }
    }//GEN-LAST:event_fromEndRadioButtonItemStateChanged

    private void fromCursorRadioButtonItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_fromCursorRadioButtonItemStateChanged
        if (fromCursorRadioButton.isSelected()) {
            switchGoToMode(RelativePositionMode.FROM_CURSOR);
        }
    }//GEN-LAST:event_fromCursorRadioButtonItemStateChanged

    private void updateTargetPosition() {
        targetPositionTextField.setText(String.valueOf(getTargetPosition()));
    }

    public void initFocus() {
        positionBaseSwitchableSpinnerPanel.initFocus();
    }

    public long getTargetPosition() {
        long absolutePosition;
        long position = getPositionValue();
        switch (goToMode) {
            case FROM_START:
                absolutePosition = position;
                break;
            case FROM_END:
                absolutePosition = maxPosition - position;
                break;
            case FROM_CURSOR:
                absolutePosition = cursorPosition + position;
                break;
            default:
                throw CodeAreaUtils.getInvalidTypeException(goToMode);
        }

        if (absolutePosition < 0) {
            absolutePosition = 0;
        } else if (absolutePosition > maxPosition) {
            absolutePosition = maxPosition;
        }
        return absolutePosition;
    }

    public void setTargetPosition(long absolutePosition) {
        if (absolutePosition < 0) {
            absolutePosition = 0;
        } else if (absolutePosition > maxPosition) {
            absolutePosition = maxPosition;
        }
        switch (goToMode) {
            case FROM_START:
                setPositionValue(absolutePosition);
                break;
            case FROM_END:
                setPositionValue(maxPosition - absolutePosition);
                break;
            case FROM_CURSOR:
                setPositionValue(absolutePosition - cursorPosition);
                break;
            default:
                throw CodeAreaUtils.getInvalidTypeException(goToMode);
        }
        updateTargetPosition();
    }

    public long getCursorPosition() {
        return cursorPosition;
    }

    public void setCursorPosition(long cursorPosition) {
        this.cursorPosition = cursorPosition;
        setPositionValue(cursorPosition);
        currentPositionTextField.setText(String.valueOf(cursorPosition));
    }

    public void setMaxPosition(long maxPosition) {
        this.maxPosition = maxPosition;
        positionBaseSwitchableSpinnerPanel.setMaximum(maxPosition);
        updateTargetPosition();
    }

    public void setSelected() {
        positionBaseSwitchableSpinnerPanel.requestFocusInWindow();
    }

    @Nonnull
    public ResourceBundle getResourceBundle() {
        return resourceBundle;
    }

    private void switchGoToMode(RelativePositionMode goToMode) {
        if (this.goToMode == goToMode) {
            return;
        }

        long absolutePosition = getTargetPosition();
        this.goToMode = goToMode;
        switch (goToMode) {
            case FROM_START:
            case FROM_END: {
                setPositionValue(0L);
                positionBaseSwitchableSpinnerPanel.setMinimum(0L);
                positionBaseSwitchableSpinnerPanel.setMaximum(maxPosition);
                positionBaseSwitchableSpinnerPanel.revalidateSpinner();
                break;
            }
            case FROM_CURSOR: {
                setPositionValue(0L);
                positionBaseSwitchableSpinnerPanel.setMinimum(-cursorPosition);
                positionBaseSwitchableSpinnerPanel.setMaximum(maxPosition - cursorPosition);
                positionBaseSwitchableSpinnerPanel.revalidateSpinner();
                break;
            }
            default:
                throw CodeAreaUtils.getInvalidTypeException(goToMode);
        }
        setTargetPosition(absolutePosition);
    }

    private long getPositionValue() {
        return positionBaseSwitchableSpinnerPanel.getValue();
    }

    private void setPositionValue(long value) {
        positionBaseSwitchableSpinnerPanel.setValue(value);
        updateTargetPosition();
    }

    /**
     * Test method for this panel.
     *
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        WindowUtils.invokeDialog(new GoToPositionPanel());
    }

    public void acceptInput() {
        positionBaseSwitchableSpinnerPanel.acceptInput();
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel currentPositionLabel;
    private javax.swing.JTextField currentPositionTextField;
    private javax.swing.JRadioButton fromCursorRadioButton;
    private javax.swing.JRadioButton fromEndRadioButton;
    private javax.swing.JRadioButton fromStartRadioButton;
    private javax.swing.JPanel goToPanel;
    private org.exbin.framework.bined.gui.BaseSwitchableSpinnerPanel positionBaseSwitchableSpinnerPanel;
    private javax.swing.JLabel positionLabel;
    private javax.swing.ButtonGroup positionTypeButtonGroup;
    private javax.swing.JLabel targetPositionLabel;
    private javax.swing.JTextField targetPositionTextField;
    // End of variables declaration//GEN-END:variables

}
