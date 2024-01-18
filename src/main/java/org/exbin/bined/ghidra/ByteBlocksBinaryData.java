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

import ghidra.app.plugin.core.format.ByteBlock;
import ghidra.app.plugin.core.format.ByteBlockAccessException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import org.exbin.auxiliary.binary_data.BinaryData;
import org.exbin.auxiliary.binary_data.ByteArrayEditableData;

/**
 * Binary data convertor for block set.
 *
 * @author ExBin Project (https://exbin.org)
 */
@ParametersAreNonnullByDefault
public class ByteBlocksBinaryData implements BinaryData {

    private final ProgramByteBlockSet blockSet;

    public ByteBlocksBinaryData(ProgramByteBlockSet blockSet) {
        this.blockSet = blockSet;
    }

    @Override
    public boolean isEmpty() {
        return blockSet.getBlocks().length == 0;
    }

    @Override
    public long getDataSize() {
        long length = 0;
        for (ByteBlock block : blockSet.getBlocks()) {
            length += block.getLength().longValue();
        }

        return length;
    }

    @Override
    public byte getByte(long position) {
        long blockPosition = position;
        for (ByteBlock block : blockSet.getBlocks()) {
            long blockLength = block.getLength().longValue();
            if (blockPosition < blockLength) {
                try {
                    return block.getByte(BigInteger.valueOf(blockPosition));
                } catch (ByteBlockAccessException ex) {
                    Logger.getLogger(ByteBlocksBinaryData.class.getName()).log(Level.SEVERE, null, ex);
                    // TODO
                    return 0;
                }
            }

            blockPosition -= blockLength;
        }

        throw new IllegalStateException();
    }

    @Nonnull
    @Override
    public BinaryData copy() {
        return new ByteBlocksBinaryData(blockSet);
    }

    @Nonnull
    @Override
    public BinaryData copy(long startFrom, long length) {
        ByteArrayEditableData result = new ByteArrayEditableData();
        result.insertUninitialized(0, length);
        for (int i = 0; i < length; i++) {
            result.setByte(i, getByte(startFrom + i));
        }
        return result;
    }

    @Override
    public void copyToArray(long startFrom, byte[] target, int offset, int length) {
        for (int i = 0; i < length; i++) {
            target[offset + i] = getByte(startFrom + i);
        }
    }

    @Override
    public void saveToStream(OutputStream outputStream) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public InputStream getDataInputStream() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void dispose() {
    }
}
