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

package io.github.novacrypto.hash;

import io.github.novacrypto.toruntime.CheckedExceptionToRuntime;

import java.security.MessageDigest;

import static io.github.novacrypto.toruntime.CheckedExceptionToRuntime.toRuntime;

public final class Sha256 {

    public static byte[] sha256(byte[] bytes) {
        return sha256(bytes, 0, bytes.length);
    }

    public static byte[] sha256(byte[] bytes, int offset, int length) {
        try {
            MessageDigest digest = sha256();
            digest.update(bytes, offset, length);
            return digest.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static MessageDigest sha256() {
        return toRuntime(new CheckedExceptionToRuntime.Func<MessageDigest>() {
            @Override
            public MessageDigest run() throws Exception {
                return MessageDigest.getInstance("SHA-256");
            }
        });
    }
}