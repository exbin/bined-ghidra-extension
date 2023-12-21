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

import ghidra.framework.options.SaveState;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import org.exbin.framework.api.Preferences;

/**
 * Wrapper for preferences.
 *
 * @author ExBin Project (https://exbin.org)
 */
@ParametersAreNonnullByDefault
public class BinEdPreferencesWrapper implements Preferences {

    private SaveState saveState;

    public BinEdPreferencesWrapper(SaveState saveState) {
        this.saveState = saveState;
    }

    @Override
    public boolean exists(String key) {
        return saveState.hasValue(key);
    }

    @Nonnull
    @Override
    public Optional<String> get(String key) {
        return exists(key) ? Optional.ofNullable(saveState.getString(key, null)) : Optional.empty();
    }

    @Nonnull
    @Override
    public String get(String key, String def) {
        return saveState.getString(key, Objects.requireNonNull(def));
    }

    @Override
    public void put(String key, @Nullable String value) {
        if (value == null) {
            saveState.remove(key);
        } else {
            saveState.putString(key, value);
        }
    }

    @Override
    public void remove(String key) {
        saveState.remove(key);
    }

    @Override
    public void putInt(String key, int value) {
        saveState.putInt(key, value);
    }

    @Override
    public int getInt(String key, int defaultValue) {
        return saveState.getInt(key, defaultValue);
    }

    @Override
    public void putLong(String key, long value) {
        saveState.putLong(key, value);
    }

    @Override
    public long getLong(String key, long defaultValue) {
        return saveState.getLong(key, defaultValue);
    }

    @Override
    public void putBoolean(String key, boolean value) {
        saveState.putBoolean(key, value);
    }

    @Override
    public boolean getBoolean(String key, boolean defaultValue) {
        return saveState.getBoolean(key, defaultValue);
    }

    @Override
    public void putFloat(String key, float value) {
        saveState.putFloat(key, value);
    }

    @Override
    public float getFloat(String key, float defaultValue) {
        return saveState.getFloat(key, defaultValue);
    }

    @Override
    public void putDouble(String key, double value) {
        saveState.putDouble(key, value);
    }

    @Override
    public double getDouble(String key, double defaultValue) {
        return saveState.getDouble(key, defaultValue);
    }

    @Override
    public void putByteArray(String key, byte[] value) {
        saveState.putBytes(key, value);
    }

    @Override
    public byte[] getByteArray(String key, byte[] defaultValue) {
        return saveState.getBytes(key, defaultValue);
    }

    @Override
    public void flush() {
    }

    @Override
    public void sync() {
    }
}
