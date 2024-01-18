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
package org.exbin.framework.api;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * XBUP framework modules repository interface.
 *
 * @author ExBin Project (https://exbin.org)
 */
public interface XBApplicationModuleRepository {

    /**
     * Gets info about module.
     *
     * @param moduleId module identifier
     * @return application module record
     */
    @Nullable
    Object getModuleRecordById(String moduleId);

    /**
     * Gets module for specified identified.
     *
     * @param moduleId module identifier
     * @return application module
     * @throws IllegalArgumentException when module not found
     */
    @Nonnull
    Object getModuleById(String moduleId);

    /**
     * Gets module instance by module interface.
     *
     * @param <T> interface class
     * @param interfaceClass interface class
     * @return application module record
     * @throws IllegalArgumentException when module not found
     */
    @Nonnull
    <T> T getModuleByInterface(Class<T> interfaceClass);
}
