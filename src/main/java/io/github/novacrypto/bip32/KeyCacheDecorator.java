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

import io.github.novacrypto.bip32.derivation.Derivation;

import java.util.HashMap;
import java.util.Map;

final class KeyCacheDecorator<Node> implements Derivation.Visitor<Node> {

    static <Node> Derivation.Visitor<Node> newCacheOf(final Derivation.Visitor<Node> decorated) {
        return new KeyCacheDecorator<>(decorated);
    }

    private final Derivation.Visitor<Node> derivationVisitor;

    private final Map<NodeKey, Node> cache = new HashMap<>();

    private KeyCacheDecorator(final Derivation.Visitor<Node> derivationVisitor) {
        this.derivationVisitor = derivationVisitor;
    }

    @Override
    public Node visit(final Node parent, final int childIndex) {
        final NodeKey key = new NodeKey(parent, childIndex);
        final Node value = cache.get(key);
        if (value != null) {
            return value;
        }
        final Node newValue = derivationVisitor.visit(parent, childIndex);
        cache.put(key, newValue);
        return newValue;
    }

    private static class NodeKey {
        private final Object parent;
        private final int childIndex;
        private final int hashcode;

        NodeKey(final Object parent, final int childIndex) {
            this.parent = parent;
            this.childIndex = childIndex;
            hashcode = parent.hashCode() * 31 + childIndex;
        }

        @Override
        public boolean equals(final Object obj) {
            if (!(obj instanceof NodeKey)) return false;
            final NodeKey other = (NodeKey) obj;
            return other.parent == parent && other.childIndex == childIndex;
        }

        @Override
        public int hashCode() {
            return hashcode;
        }
    }
}