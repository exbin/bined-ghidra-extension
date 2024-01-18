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
package org.exbin.framework.bined.macro.operation;

import java.awt.event.KeyEvent;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import org.exbin.bined.CodeAreaCaretPosition;
import org.exbin.bined.CodeAreaSection;
import org.exbin.bined.CodeAreaUtils;
import org.exbin.bined.CodeType;
import org.exbin.bined.EditMode;
import org.exbin.bined.EditOperation;
import org.exbin.bined.SelectionRange;
import org.exbin.bined.basic.BasicCodeAreaSection;
import org.exbin.bined.basic.MovementDirection;
import org.exbin.bined.capability.CaretCapable;
import org.exbin.bined.capability.CodeTypeCapable;
import org.exbin.bined.capability.EditModeCapable;
import org.exbin.bined.capability.ScrollingCapable;
import org.exbin.bined.capability.SelectionCapable;
import org.exbin.bined.operation.BinaryDataOperationException;
import org.exbin.bined.operation.undo.BinaryDataUndoHandler;
import org.exbin.bined.swing.CodeAreaCommandHandler;
import org.exbin.bined.swing.CodeAreaCore;
import org.exbin.bined.operation.swing.CodeAreaOperationCommandHandler;
import org.exbin.bined.operation.swing.CodeAreaUndoHandler;
import org.exbin.bined.operation.swing.command.BinaryCompoundCommand;
import org.exbin.bined.operation.swing.command.CodeAreaCommand;
import org.exbin.bined.operation.swing.command.CodeAreaCommandType;
import org.exbin.bined.operation.swing.command.EditCharDataCommand;
import org.exbin.bined.operation.swing.command.EditCodeDataCommand;
import org.exbin.bined.operation.swing.command.EditDataCommand;
import org.exbin.bined.operation.swing.command.RemoveDataCommand;
import org.exbin.bined.swing.CodeAreaSwingUtils;
import org.exbin.bined.swing.basic.DefaultCodeAreaCommandHandler;
import org.exbin.framework.bined.macro.model.MacroRecord;
import static org.exbin.framework.bined.macro.operation.MacroStep.CARET_MOVE;

/**
 * Command handler with support for macro recording.
 *
 * @author ExBin Project (https://exbin.org)
 */
@ParametersAreNonnullByDefault
public class CodeAreaMacroCommandHandler extends CodeAreaOperationCommandHandler {

    private final int metaMask = CodeAreaSwingUtils.getMetaMaskDown();
    private MacroRecord recordingMacro = null;
    private MacroStep lastMacroStep = null;

    public CodeAreaMacroCommandHandler(CodeAreaCore codeArea, BinaryDataUndoHandler undoHandler) {
        super(codeArea, undoHandler);
    }

    @Nonnull
    public static CodeAreaCommandHandler.CodeAreaCommandHandlerFactory createDefaultCodeAreaCommandHandlerFactory() {
        return (CodeAreaCore codeAreaCore) -> new CodeAreaMacroCommandHandler(codeAreaCore, new CodeAreaUndoHandler(codeAreaCore));
    }

    @Nonnull
    public Optional<MacroRecord> getRecordingMacro() {
        return Optional.ofNullable(recordingMacro);
    }

    public void setRecordingMacro(MacroRecord recordingMacro) {
        this.recordingMacro = recordingMacro;
        lastMacroStep = null;
    }

    @Override
    public void keyPressed(KeyEvent keyEvent) {
        if (isMacroRecording()) {
            switch (keyEvent.getKeyCode()) {
                case KeyEvent.VK_LEFT: {
                    CodeAreaMacroCommandHandler.this.appendMacroOperationStep(isSelecting(keyEvent) ? MacroStep.SELECTION_UPDATE : MacroStep.CARET_MOVE, Arrays.asList(MovementDirection.LEFT));
                    break;
                }
                case KeyEvent.VK_RIGHT: {
                    CodeAreaMacroCommandHandler.this.appendMacroOperationStep(isSelecting(keyEvent) ? MacroStep.SELECTION_UPDATE : MacroStep.CARET_MOVE, Arrays.asList(MovementDirection.RIGHT));
                    break;
                }
                case KeyEvent.VK_UP: {
                    CodeAreaMacroCommandHandler.this.appendMacroOperationStep(isSelecting(keyEvent) ? MacroStep.SELECTION_UPDATE : MacroStep.CARET_MOVE, Arrays.asList(MovementDirection.UP));
                    break;
                }
                case KeyEvent.VK_DOWN: {
                    CodeAreaMacroCommandHandler.this.appendMacroOperationStep(isSelecting(keyEvent) ? MacroStep.SELECTION_UPDATE : MacroStep.CARET_MOVE, Arrays.asList(MovementDirection.DOWN));
                    break;
                }
                case KeyEvent.VK_HOME: {
                    CodeAreaMacroCommandHandler.this.appendMacroOperationStep(isSelecting(keyEvent) ? MacroStep.SELECTION_UPDATE : MacroStep.CARET_MOVE, Arrays.asList((keyEvent.getModifiersEx() & metaMask) > 0 ? MovementDirection.DOC_START : MovementDirection.ROW_START));
                    break;
                }
                case KeyEvent.VK_END: {
                    CodeAreaMacroCommandHandler.this.appendMacroOperationStep(isSelecting(keyEvent) ? MacroStep.SELECTION_UPDATE : MacroStep.CARET_MOVE, Arrays.asList((keyEvent.getModifiersEx() & metaMask) > 0 ? MovementDirection.DOC_END : MovementDirection.ROW_END));
                    break;
                }
                case KeyEvent.VK_PAGE_UP: {
                    CodeAreaMacroCommandHandler.this.appendMacroOperationStep(isSelecting(keyEvent) ? MacroStep.SELECTION_UPDATE : MacroStep.CARET_MOVE, Arrays.asList(MovementDirection.PAGE_UP));
                    break;
                }
                case KeyEvent.VK_PAGE_DOWN: {
                    CodeAreaMacroCommandHandler.this.appendMacroOperationStep(isSelecting(keyEvent) ? MacroStep.SELECTION_UPDATE : MacroStep.CARET_MOVE, Arrays.asList(MovementDirection.PAGE_DOWN));
                    break;
                }
                case KeyEvent.VK_INSERT: {
                    appendMacroOperationStep(MacroStep.EDIT_OPERATION_CHANGE);
                    break;
                }
            }
        }

        super.keyPressed(keyEvent);
    }

    @Override
    public void keyTyped(KeyEvent keyEvent) {
        char keyValue = keyEvent.getKeyChar();
        if (recordingMacro != null && keyValue != KeyEvent.CHAR_UNDEFINED) {
            CodeAreaSection section = ((CaretCapable) codeArea).getActiveSection();
            if (section != BasicCodeAreaSection.TEXT_PREVIEW) {
                CodeAreaMacroCommandHandler.this.appendMacroOperationStep(MacroStep.KEY_PRESSED, Arrays.asList(String.valueOf(keyValue)));
            } else {
                if (keyValue > DefaultCodeAreaCommandHandler.LAST_CONTROL_CODE && keyValue != DELETE_CHAR) {
                    CodeAreaMacroCommandHandler.this.appendMacroOperationStep(MacroStep.KEY_PRESSED, Arrays.asList(String.valueOf(keyValue)));
                }
            }
        }

        altKeyTyped(keyEvent);
    }

    /** Replacement due to issue with INPLACE mode */
    public void altKeyTyped(KeyEvent keyEvent) {
        char keyValue = keyEvent.getKeyChar();
        if (keyValue == KeyEvent.CHAR_UNDEFINED) {
            return;
        }
        if (!checkEditAllowed()) {
            return;
        }

        CodeAreaSection section = ((CaretCapable) codeArea).getActiveSection();
        if (section != BasicCodeAreaSection.TEXT_PREVIEW) {
            int modifiersEx = keyEvent.getModifiersEx();
            if (modifiersEx == 0 || modifiersEx == KeyEvent.SHIFT_DOWN_MASK) {
                pressedCharAsCode(keyValue);
            }
        } else {
            if (keyValue > DefaultCodeAreaCommandHandler.LAST_CONTROL_CODE && keyValue != DELETE_CHAR) {
                pressedCharInPreview(keyValue);
            }
        }
    }

    private void pressedCharAsCode(char keyChar) {
        CodeAreaCaretPosition caretPosition = ((CaretCapable) codeArea).getCaretPosition();
        int startCodeOffset = caretPosition.getCodeOffset();
        CodeType codeType = getCodeType();
        boolean validKey = CodeAreaUtils.isValidCodeKeyValue(keyChar, startCodeOffset, codeType);
        if (validKey) {
            EditMode editMode = ((EditModeCapable) codeArea).getEditMode();
            EditOperation editOperation = ((EditModeCapable) codeArea).getActiveOperation();
            DeleteSelectionCommand deleteSelectionCommand = null;
            if (codeArea.hasSelection()) {
                long selectionStart = ((SelectionCapable) codeArea).getSelection().getFirst();
                deleteSelectionCommand = new DeleteSelectionCommand(codeArea);
                ((CaretCapable) codeArea).setCaretPosition(selectionStart);
                undoSequenceBreak();
            }

            int value;
            if (keyChar >= '0' && keyChar <= '9') {
                value = keyChar - '0';
            } else {
                value = Character.toLowerCase(keyChar) - 'a' + 10;
            }

//                if (codeArea.getEditAllowed() == EditAllowed.OVERWRITE_ONLY && codeArea.getEditMode() == EditMode.OVERWRITE && dataPosition == dataSize) {
//                    return;
//                }
            if (editCommand != null && editCommand.wasReverted()) {
                editCommand = null;
            }

            if ((editMode == EditMode.EXPANDING && editOperation == EditOperation.OVERWRITE) || editMode == EditMode.INPLACE) {
                if (editCommand == null
                        || !(editCommand instanceof EditCodeDataCommand)
                        || editCommand.getCommandType() != EditDataCommand.EditCommandType.OVERWRITE
                        || !isAppendAllowed()) {
                    if (deleteSelectionCommand != null) {
                        BinaryCompoundCommand compoundCommand = new BinaryCompoundCommand(codeArea);
                        compoundCommand.appendCommand(deleteSelectionCommand);
                        try {
                            undoHandler.execute(compoundCommand);
                        } catch (BinaryDataOperationException ex) {
                            Logger.getLogger(CodeAreaOperationCommandHandler.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        long dataPosition = ((CaretCapable) codeArea).getDataPosition();
                        int codeOffset = ((CaretCapable) codeArea).getCaretPosition().getCodeOffset();
                        editCommand = new EditCodeDataCommand(codeArea, EditCodeDataCommand.EditCommandType.OVERWRITE, dataPosition, codeOffset);
                        compoundCommand.appendCommand(editCommand);
                    } else {
                        long dataPosition = ((CaretCapable) codeArea).getDataPosition();
                        int codeOffset = ((CaretCapable) codeArea).getCaretPosition().getCodeOffset();
                        editCommand = new EditCodeDataCommand(codeArea, EditCodeDataCommand.EditCommandType.OVERWRITE, dataPosition, codeOffset);
                        undoHandler.addCommand(editCommand);
                    }
                }

                ((EditCodeDataCommand) editCommand).appendEdit((byte) value);
            } else {
                if (editCommand == null
                        || !(editCommand instanceof EditCodeDataCommand)
                        || editCommand.getCommandType() != EditCodeDataCommand.EditCommandType.INSERT
                        || !isAppendAllowed()) {
                    if (deleteSelectionCommand != null) {
                        BinaryCompoundCommand compoundCommand = new BinaryCompoundCommand(codeArea);
                        compoundCommand.appendCommand(deleteSelectionCommand);
                        try {
                            undoHandler.execute(compoundCommand);
                        } catch (BinaryDataOperationException ex) {
                            Logger.getLogger(CodeAreaOperationCommandHandler.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        long dataPosition = ((CaretCapable) codeArea).getDataPosition();
                        int codeOffset = ((CaretCapable) codeArea).getCaretPosition().getCodeOffset();
                        editCommand = new EditCodeDataCommand(codeArea, EditCharDataCommand.EditCommandType.INSERT, dataPosition, codeOffset);
                        compoundCommand.appendCommand(editCommand);
                    } else {
                        long dataPosition = ((CaretCapable) codeArea).getDataPosition();
                        int codeOffset = ((CaretCapable) codeArea).getCaretPosition().getCodeOffset();
                        editCommand = new EditCodeDataCommand(codeArea, EditCharDataCommand.EditCommandType.INSERT, dataPosition, codeOffset);
                        undoHandler.addCommand(editCommand);
                    }
                }

                ((EditCodeDataCommand) editCommand).appendEdit((byte) value);
            }
            codeArea.notifyDataChanged();
            move(SelectingMode.NONE, MovementDirection.RIGHT);
            revealCursor();
        }
    }

    /** Replacement due to issue with INPLACE mode */
    private void pressedCharInPreview(char keyChar) {
        boolean validKey = isValidChar(keyChar);
        if (validKey) {
            EditMode editMode = ((EditModeCapable) codeArea).getEditMode();
            EditOperation editOperation = ((EditModeCapable) codeArea).getActiveOperation();
            if (editCommand != null && editCommand.wasReverted()) {
                editCommand = null;
            }
            DeleteSelectionCommand deleteCommand = null;
            if (codeArea.hasSelection()) {
                undoSequenceBreak();
                deleteCommand = new DeleteSelectionCommand(codeArea);
            }

            if ((editMode == EditMode.EXPANDING && editOperation == EditOperation.OVERWRITE) || editMode == EditMode.INPLACE) {
                if (editCommand == null
                        || !(editCommand instanceof EditCharDataCommand)
                        || editCommand.getCommandType() != EditCodeDataCommand.EditCommandType.OVERWRITE
                        || !isAppendAllowed()) {
                    if (deleteCommand != null) {
                        BinaryCompoundCommand compoundCommand = new BinaryCompoundCommand(codeArea);
                        compoundCommand.appendCommand(deleteCommand);
                        try {
                            undoHandler.execute(compoundCommand);
                        } catch (BinaryDataOperationException ex) {
                            Logger.getLogger(CodeAreaOperationCommandHandler.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        long dataPosition = ((CaretCapable) codeArea).getDataPosition();
                        editCommand = new EditCharDataCommand(codeArea, EditCodeDataCommand.EditCommandType.OVERWRITE, dataPosition);
                        compoundCommand.appendCommand(editCommand);
                    } else {
                        long dataPosition = ((CaretCapable) codeArea).getDataPosition();
                        editCommand = new EditCharDataCommand(codeArea, EditCodeDataCommand.EditCommandType.OVERWRITE, dataPosition);
                        undoHandler.addCommand(editCommand);
                    }
                }

                ((EditCharDataCommand) editCommand).appendEdit(keyChar);
            } else {
                if (editCommand == null
                        || !(editCommand instanceof EditCharDataCommand)
                        || editCommand.getCommandType() != EditCodeDataCommand.EditCommandType.INSERT
                        || !isAppendAllowed()) {
                    if (deleteCommand != null) {
                        BinaryCompoundCommand compoundCommand = new BinaryCompoundCommand(codeArea);
                        compoundCommand.appendCommand(deleteCommand);
                        try {
                            undoHandler.execute(compoundCommand);
                        } catch (BinaryDataOperationException ex) {
                            Logger.getLogger(CodeAreaOperationCommandHandler.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        long dataPosition = ((CaretCapable) codeArea).getDataPosition();
                        editCommand = new EditCharDataCommand(codeArea, EditCodeDataCommand.EditCommandType.INSERT, dataPosition);
                        compoundCommand.appendCommand(editCommand);
                    } else {
                        long dataPosition = ((CaretCapable) codeArea).getDataPosition();
                        editCommand = new EditCharDataCommand(codeArea, EditCodeDataCommand.EditCommandType.INSERT, dataPosition);
                        undoHandler.addCommand(editCommand);
                    }
                }

                ((EditCharDataCommand) editCommand).appendEdit(keyChar);
            }

            codeArea.notifyDataChanged();
            revealCursor();
        }
    }

    private boolean isAppendAllowed() {
        return undoHandler.getCommandPosition() != undoHandler.getSyncPoint();
    }

    @Nonnull
    private CodeType getCodeType() {
        if (codeArea instanceof CodeTypeCapable) {
            return ((CodeTypeCapable) codeArea).getCodeType();
        }

        return CodeType.HEXADECIMAL;
    }

    private void revealCursor() {
        ((ScrollingCapable) codeArea).revealCursor();
        codeArea.repaint();
    }

    @Override
    public void enterPressed() {
        if (isMacroRecording()) {
            CodeAreaSection section = ((CaretCapable) codeArea).getActiveSection();
            if (section == BasicCodeAreaSection.TEXT_PREVIEW) {
                CodeAreaMacroCommandHandler.this.appendMacroOperationStep(MacroStep.ENTER_KEY);
            }
        }

        super.enterPressed();
    }

    @Override
    public void tabPressed() {
        tabPressed(SelectingMode.NONE);
    }

    @Override
    public void tabPressed(SelectingMode selectingMode) {
        super.tabPressed(selectingMode);
    }

    @Override
    public void backSpacePressed() {
        if (isMacroRecording()) {
            CodeAreaMacroCommandHandler.this.appendMacroOperationStep(MacroStep.BACKSPACE_KEY);
        }

        super.backSpacePressed();
    }

    @Override
    public void deletePressed() {
        if (isMacroRecording()) {
            CodeAreaMacroCommandHandler.this.appendMacroOperationStep(MacroStep.DELETE_KEY);
        }

        super.deletePressed();
    }

    @Override
    public void delete() {
        if (isMacroRecording()) {
            appendMacroOperationStep(MacroStep.CLIPBOARD_DELETE);
        }

        super.delete();
    }

    @Override
    public void copy() {
        if (isMacroRecording()) {
            appendMacroOperationStep(MacroStep.CLIPBOARD_COPY);
        }

        super.copy();
    }

    @Override
    public void copyAsCode() {
        if (isMacroRecording()) {
            appendMacroOperationStep(MacroStep.CLIPBOARD_COPY_AS_CODE);
        }

        super.copyAsCode();
    }

    @Override
    public void cut() {
        if (isMacroRecording()) {
            appendMacroOperationStep(MacroStep.CLIPBOARD_CUT);
        }

        super.cut();
    }

    @Override
    public void paste() {
        if (isMacroRecording()) {
            appendMacroOperationStep(MacroStep.CLIPBOARD_PASTE);
        }

        super.paste();
    }

    @Override
    public void pasteFromCode() {
        if (isMacroRecording()) {
            appendMacroOperationStep(MacroStep.CLIPBOARD_PASTE_FROM_CODE);
        }

        super.pasteFromCode();
    }

    @Override
    public void selectAll() {
        if (isMacroRecording()) {
            appendMacroOperationStep(MacroStep.SELECTION_SELECT_ALL);
        }

        super.selectAll();
    }

    @Override
    public void clearSelection() {
        if (isMacroRecording()) {
            appendMacroOperationStep(MacroStep.SELECTION_CLEAR);
        }

        super.clearSelection();
    }

    @Nonnull
    private static boolean isSelecting(KeyEvent keyEvent) {
        return (keyEvent.getModifiersEx() & KeyEvent.SHIFT_DOWN_MASK) > 0;
    }

    public boolean isMacroRecording() {
        return recordingMacro != null;
    }

    public void executeMacroStep(MacroStep macroStep, List<Object> parameters) {
        switch (macroStep) {
            case KEY_PRESSED: {
                Object param = parameters.get(0);
                if (param instanceof Character) {
                    keyTyped(new KeyEvent(codeArea, -1, -1, 0, 0, (char) param));
                }
                break;
            }
            case BACKSPACE_KEY: {
                backSpacePressed();
                break;
            }
            case DELETE_KEY: {
                deletePressed();
                break;
            }
            case ENTER_KEY: {
                enterPressed();
                break;
            }
            case EDIT_OPERATION_CHANGE: {
                changeEditOperation();
                break;
            }
            case CLIPBOARD_CUT: {
                cut();
                break;
            }
            case CLIPBOARD_COPY: {
                copy();
                break;
            }
            case CLIPBOARD_COPY_AS_CODE: {
                copyAsCode();
                break;
            }
            case CLIPBOARD_PASTE: {
                paste();
                break;
            }
            case CLIPBOARD_PASTE_FROM_CODE: {
                pasteFromCode();
                break;
            }
            case CLIPBOARD_DELETE: {
                delete();
                break;
            }
            case SELECTION_SELECT_ALL: {
                selectAll();
                break;
            }
            case SELECTION_CLEAR: {
                clearSelection();
                break;
            }
            case CARET_MOVE: {
                MovementDirection movementDirection = (MovementDirection) parameters.get(0);
                move(SelectingMode.NONE, movementDirection);
                break;
            }
            case SELECTION_SET: {
                updateSelection(SelectingMode.SELECTING, ((CaretCapable) codeArea).getCaretPosition());
                break;
            }
            case SELECTION_UPDATE: {
                MovementDirection movementDirection = (MovementDirection) parameters.get(0);
                move(SelectingMode.SELECTING, movementDirection);
                break;
            }
            default:
                throw new AssertionError();
        }
    }

    public void appendMacroOperationStep(MacroStep macroStep) {
        CodeAreaMacroCommandHandler.this.appendMacroOperationStep(macroStep, Arrays.asList());
    }

    public void appendMacroOperationStep(MacroStep macroStep, List<Object> parameters) {
        if (lastMacroStep == macroStep) {
            List<String> steps = recordingMacro.getSteps();
            try {
                int stepIndex = steps.size() - 1;
                MacroOperation macroOperation = parseStep(steps.get(stepIndex));
                List<Object> stepParameters = macroOperation.getParameters();
                switch (macroStep) {
                    case CARET_MOVE: {
                        if (stepParameters.get(0) == parameters.get(0)) {
                            if (stepParameters.size() > 1) {
                                stepParameters.set(1, (Integer) stepParameters.get(1) + 1);
                            } else {
                                stepParameters.add(2);
                            }

                            recordingMacro.setStep(stepIndex, stepAsString(macroOperation.getMacroStep(), stepParameters));
                            return;
                        }
                        break;
                    }
                    case KEY_PRESSED: {
                        stepParameters.set(0, (String) stepParameters.get(0) + parameters.get(0));
                        recordingMacro.setStep(stepIndex, stepAsString(macroOperation.getMacroStep(), stepParameters));
                        return;
                    }
                    case CLIPBOARD_COPY:
                    case CLIPBOARD_COPY_AS_CODE:
                    case SELECTION_SELECT_ALL:
                    case SELECTION_CLEAR: {
                        // Don't repeat this steps
                        return;
                    }
                }
            } catch (ParseException | NumberFormatException ex) {
                Logger.getLogger(CodeAreaMacroCommandHandler.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        recordingMacro.addStep(stepAsString(macroStep, parameters));
        lastMacroStep = macroStep;
    }

    @Nonnull
    public static String stepAsString(MacroStep macroStep, List<Object> parameters) {
        if (parameters.isEmpty()) {
            return macroStep.getOperationCode();
        }
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(macroStep.getOperationCode());
        if (parameters.isEmpty()) {
            return stringBuilder.toString();
        }

        stringBuilder.append("(");
        boolean first = true;
        for (Object parameter : parameters) {
            if (!first) {
                stringBuilder.append(",");
            } else {
                first = false;
            }

            if (parameter instanceof String) {
                stringBuilder.append("\"");
                for (char c : ((String) parameter).toCharArray()) {
                    if (c >= 128) {
                        stringBuilder.append("\\u").append(String.format("%04X", (int) c));
                    } else {
                        switch (c) {
                            case 13: {
                                stringBuilder.append("\\n");
                                break;
                            }
                            case 10: {
                                stringBuilder.append("\\r");
                                break;
                            }
                            case 9: {
                                stringBuilder.append("\\t");
                                break;
                            }
                            case 34: {
                                stringBuilder.append("\\\"");
                                break;
                            }
                            case 92: {
                                stringBuilder.append("\\\\");
                                break;
                            }

                            default:
                                stringBuilder.append(c);
                        }
                    }
                }
                stringBuilder.append("\"");
            } else if (parameter instanceof Integer) {
                stringBuilder.append(Integer.toString((Integer) parameter));
            } else if (parameter instanceof MovementDirection) {
                stringBuilder.append(((MovementDirection) parameter).name());
            }
        }

        stringBuilder.append(")");
        return stringBuilder.toString();
    }

    @Nonnull
    public static MacroOperation parseStep(String stepString) throws ParseException, NumberFormatException {
        String operationCode;
        List<Object> parameters = new ArrayList<>();
        int parametersStart = stepString.indexOf("(");
        if (parametersStart >= 0) {
            operationCode = stepString.substring(0, parametersStart);

            int position = parametersStart + 1;
            while (position < stepString.length()) {
                char firstChar = stepString.charAt(position);
                if (firstChar == '\"') {
                    StringBuilder stringBuilder = new StringBuilder();
                    position++;
                    while (position < stepString.length()) {
                        char nextChar = stepString.charAt(position);
                        if (nextChar == 34) {
                            position++;
                            if (position == stepString.length()) {
                                throw new ParseException("Missing close bracket", stepString.length() - 1);
                            }
                            nextChar = stepString.charAt(position);
                            if (nextChar == ',' || nextChar == ')') {
                                position++;
                            } else {
                                throw new ParseException("Unexpected character", position);
                            }
                            break;
                        } else if (nextChar == 92) {
                            position++;
                            if (position == stepString.length()) {
                                throw new ParseException("Missing escaped character", stepString.length() - 1);
                            }
                            nextChar = stepString.charAt(position);
                            switch (nextChar) {
                                case 'n': {
                                    stringBuilder.append("\n");
                                    break;
                                }
                                case 'r': {
                                    stringBuilder.append("\r");
                                    break;
                                }
                                case 't': {
                                    stringBuilder.append("\t");
                                    break;
                                }
                                case '\"': {
                                    stringBuilder.append("\"");
                                    break;
                                }
                                case '\\': {
                                    stringBuilder.append("\\");
                                    break;
                                }
                                case 'u': {
                                    if (position <= stepString.length() - 5) {
                                        throw new ParseException("Incomplete unicode escape sequence", position);
                                    }
                                    int code = Integer.parseInt(
                                            String.valueOf(stepString.charAt(position + 1))
                                            + stepString.charAt(position + 2)
                                            + stepString.charAt(position + 3)
                                            + stepString.charAt(position + 4), 16);
                                    stringBuilder.append(Character.toChars(code));
                                    position += 4;
                                    break;
                                }
                                default:
                                    throw new ParseException("Unsupported escaped character", position);
                            }
                            position++;
                        } else {
                            stringBuilder.append(nextChar);
                            position++;
                        }
                    }
                    parameters.add(stringBuilder.toString());
                } else {
                    int paramEnd = stepString.indexOf(",", position);
                    if (paramEnd == -1) {
                        paramEnd = stepString.indexOf(")", position);
                        if (paramEnd == -1) {
                            throw new ParseException("Missing close bracket", stepString.length() - 1);
                        }
                    }
                    if (firstChar >= '0' && firstChar <= '9') {
                        Integer parameter = Integer.valueOf(stepString.substring(position, paramEnd));
                        parameters.add(parameter);
                    } else {
                        // Currently only direction enum is supported
                        String value = stepString.substring(position, paramEnd);
                        MovementDirection parameter = movementDirectionFromCode(value);
                        if (parameter != null) {
                            parameters.add(parameter);
                        } else {
                            throw new ParseException("Unknown value", position);
                        }
                    }
                    position = paramEnd + 1;
                }
            }
        } else {
            operationCode = stepString;
        }

        Optional<MacroStep> macroStep = MacroStep.findByCode(operationCode);
        if (!macroStep.isPresent()) {
            throw new ParseException("Unknown operation: " + operationCode, 0);
        }

        return new MacroOperation(macroStep.get(), parameters);
    }

    @Nullable
    private static MovementDirection movementDirectionFromCode(String code) {
        MovementDirection parameter = null;
        for (MovementDirection movementDirection : MovementDirection.values()) {
            if (code.equals(movementDirection.name())) {
                parameter = movementDirection;
                break;
            }
        }
        return parameter;
    }

    @ParametersAreNonnullByDefault
    private static class DeleteSelectionCommand extends CodeAreaCommand {

        private final RemoveDataCommand removeCommand;
        private final long position;
        private final long size;

        public DeleteSelectionCommand(CodeAreaCore coreArea) {
            super(coreArea);
            SelectionRange selection = ((SelectionCapable) coreArea).getSelection();
            position = selection.getFirst();
            size = selection.getLast() - position + 1;
            removeCommand = new RemoveDataCommand(coreArea, position, 0, size);
        }

        @Override
        public void execute() throws BinaryDataOperationException {
            super.execute();
        }

        @Override
        public void redo() throws BinaryDataOperationException {
            removeCommand.redo();
            ((CaretCapable) codeArea).setCaretPosition(position);
            clearSelection();
            ((ScrollingCapable) codeArea).revealCursor();
            codeArea.notifyDataChanged();
        }

        @Override
        public void undo() throws BinaryDataOperationException {
            removeCommand.undo();
            clearSelection();
            ((CaretCapable) codeArea).setCaretPosition(position + size);
            ((ScrollingCapable) codeArea).revealCursor();
            codeArea.notifyDataChanged();
        }

        @Nonnull
        @Override
        public CodeAreaCommandType getType() {
            return CodeAreaCommandType.DATA_REMOVED;
        }

        @Override
        public boolean canUndo() {
            return true;
        }

        private void clearSelection() {
            long dataPosition = ((CaretCapable) codeArea).getDataPosition();
            ((SelectionCapable) codeArea).setSelection(dataPosition, dataPosition);
        }
    }
}
