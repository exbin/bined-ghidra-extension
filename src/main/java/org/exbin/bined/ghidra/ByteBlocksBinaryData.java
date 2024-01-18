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
import org.exbin.auxiliary.binary_data.EditableBinaryData;
import org.exbin.auxiliary.binary_data.OutOfBoundsException;

/**
 * Binary data convertor for block set.
 *
 * @author ExBin Project (https://exbin.org)
 */
@ParametersAreNonnullByDefault
public class ByteBlocksBinaryData implements EditableBinaryData {

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
        throw new UnsupportedOperationException();
    }

    @Override
    public InputStream getDataInputStream() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void dispose() {
    }

    @Override
    public void setDataSize(long size) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setByte(long position, byte value) {
        int transaction = blockSet.startTransaction();
        setByteInt(position, value);
        blockSet.endTransaction(transaction, true);
    }

    @Override
    public void insertUninitialized(long startFrom, long length) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void insert(long startFrom, long length) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void insert(long startFrom, byte[] insertedData) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void insert(long startFrom, byte[] insertedData, int insertedDataOffset, int insertedDataLength) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void insert(long startFrom, BinaryData insertedData) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void insert(long startFrom, BinaryData insertedData, long insertedDataOffset, long insertedDataLength) {
        throw new UnsupportedOperationException();
    }

    @Override
    public long insert(long startFrom, InputStream inputStream, long maximumDataSize) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void replace(long targetPosition, BinaryData replacingData) {
        replace(targetPosition, replacingData, 0, replacingData.getDataSize());
    }

    @Override
    public void replace(long targetPosition, BinaryData replacingData, long startFrom, long length) {
        if (targetPosition + length > getDataSize()) {
            throw new OutOfBoundsException("Data can be replaced only inside or at the end");
        }

        int transaction = blockSet.startTransaction();
        while (length > 0) {
            setByte(targetPosition, replacingData.getByte(startFrom));

            length--;
            targetPosition++;
            startFrom++;
        }
        blockSet.endTransaction(transaction, true);
    }

    @Override
    public void replace(long targetPosition, byte[] replacingData) {
        replace(targetPosition, replacingData, 0, replacingData.length);
    }

    @Override
    public void replace(long targetPosition, byte[] replacingData, int replacingDataOffset, int length) {
        if (targetPosition + length > getDataSize()) {
            throw new OutOfBoundsException("Data can be replaced only inside or at the end");
        }

        int transaction = blockSet.startTransaction();
        while (length > 0) {
            setByte(targetPosition, replacingData[replacingDataOffset]);

            length--;
            targetPosition++;
            replacingDataOffset++;
        }
        blockSet.endTransaction(transaction, true);
    }

    @Override
    public void fillData(long startFrom, long length) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void fillData(long startFrom, long length, byte fill) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void remove(long startFrom, long length) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void clear() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void loadFromStream(InputStream inputStream) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public OutputStream getDataOutputStream() {
        throw new UnsupportedOperationException();
    }
    
    private void setByteInt(long position, byte value) {
        long blockPosition = position;
        for (ByteBlock block : blockSet.getBlocks()) {
            long blockLength = block.getLength().longValue();
            if (blockPosition < blockLength) {
                try {
                    block.setByte(BigInteger.valueOf(blockPosition), value);
                    return;
                } catch (ByteBlockAccessException ex) {
                    throw new IllegalStateException(ex);
                }
            }

            blockPosition -= blockLength;
        }

        throw new IllegalStateException();
    }
}
