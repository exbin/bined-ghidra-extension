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
package org.exbin.bined.ghidra;

import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramHighlightPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.byteviewer.ByteBlockChangePluginEvent;
import ghidra.app.services.ClipboardService;
import ghidra.app.services.GoToService;
import ghidra.app.services.NavigationHistoryService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.SystemUtilities;
import java.util.Iterator;
import javax.annotation.ParametersAreNonnullByDefault;

/**
 * BinEd plugin for Ghidra SRE.
 *
 * @author ExBin Project (https://exbin.org)
 */
@PluginInfo(status = PluginStatus.UNSTABLE, packageName = CorePluginPackage.NAME, category = PluginCategoryNames.BYTE_VIEWER, shortDescription = "Viewer / editor for binary data", description = "Viewer / editor for binary data using BinEd library",
        servicesRequired = {
            ProgramManager.class, GoToService.class, NavigationHistoryService.class,
            ClipboardService.class},
        eventsConsumed = {
            ProgramLocationPluginEvent.class,
            ProgramActivatedPluginEvent.class, ProgramSelectionPluginEvent.class,
            ProgramHighlightPluginEvent.class, ProgramClosedPluginEvent.class,
            ByteBlockChangePluginEvent.class},
        eventsProduced = {
            ProgramLocationPluginEvent.class, ProgramSelectionPluginEvent.class,
            ByteBlockChangePluginEvent.class})
@ParametersAreNonnullByDefault
public class BinedExtensionPlugin extends AbstractByteViewerPlugin<ProgramByteViewerComponentProvider> {

    public BinedExtensionPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected ProgramByteViewerComponentProvider createProvider(boolean isConnected) {
        return new ProgramByteViewerComponentProvider(tool, this, isConnected);
    }

    @Override
    public void processEvent(PluginEvent event) {
        if (event instanceof ProgramClosedPluginEvent) {
            Program program = ((ProgramClosedPluginEvent) event).getProgram();
            programClosed(program);
            return;
        }

        if (event instanceof ProgramActivatedPluginEvent) {
            currentProgram = ((ProgramActivatedPluginEvent) event).getActiveProgram();
            currentLocation = null;
        } else if (event instanceof ProgramLocationPluginEvent) {
            currentLocation = ((ProgramLocationPluginEvent) event).getLocation();
        }

        connectedProvider.doHandleEvent(event);
    }

    void programClosed(Program closedProgram) {
        Iterator<ProgramByteViewerComponentProvider> iterator = disconnectedProviders.iterator();
        while (iterator.hasNext()) {
            ProgramByteViewerComponentProvider provider = iterator.next();
            if (provider.getProgram() == closedProgram) {
                iterator.remove();
                removeProvider(provider);
            }
        }
    }

    @Override
    public void updateLocation(ProgramByteViewerComponentProvider provider,
            ProgramLocationPluginEvent event, boolean export) {

        if (eventsDisabled()) {
            return;
        }

        if (provider == connectedProvider) {
            fireProgramLocationPluginEvent(provider, event);
        } else if (export) {
            exportLocation(provider.getProgram(), event.getLocation());
        }
    }

    @Override
    public void fireProgramLocationPluginEvent(ProgramByteViewerComponentProvider provider,
            ProgramLocationPluginEvent event) {

        if (SystemUtilities.isEqual(event.getLocation(), currentLocation)) {
            return;
        }

        currentLocation = event.getLocation();
        if (provider == connectedProvider) {
            firePluginEvent(event);
        }
    }

    @Override
    public void updateSelection(BinEdComponentProvider provider,
            ProgramSelectionPluginEvent event, Program program) {
        if (provider == connectedProvider) {
            firePluginEvent(event);
        }
    }

    @Override
    public void highlightChanged(BinEdComponentProvider provider, ProgramSelection highlight) {
        if (provider == connectedProvider) {
            tool.firePluginEvent(new ProgramHighlightPluginEvent(getName(), highlight,
                    connectedProvider.getProgram()));
        }
    }
}
