/*
 *  BIP32 library, a Java implementation of BIP32
 *  Copyright (C) 2017 Alan Evans, NovaCrypto
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *  Original source: https://github.com/NovaCrypto/BIP32
 *  You can contact the authors via github issues.
 */

package io.github.novacrypto.bip32;

public final class ByteArrayWriter {

    private final byte[] bytes;
    private int idx = 0;

    public ByteArrayWriter(final byte[] target) {
        this.bytes = target;
    }

    public void writeBytes(byte[] bytesSource, int length) {
        System.arraycopy(bytesSource, 0, bytes, idx, length);
        idx += length;
    }

    public void writeBytes(byte[] bytesSource) {
        writeBytes(bytesSource, bytesSource.length);
    }

    public void writeIntBigEndian(int value) {
        writeByte((byte) (value >> 24));
        writeByte((byte) (value >> 16));
        writeByte((byte) (value >> 8));
        writeByte((byte) (value));
    }

    public void writeByte(byte b) {
        bytes[idx++] = b;
    }
}