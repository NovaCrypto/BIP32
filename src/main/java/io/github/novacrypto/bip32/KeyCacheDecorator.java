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

    private final Map<Node, HashMap<Integer, Node>> cache = new HashMap<>();

    private KeyCacheDecorator(final Derivation.Visitor<Node> derivationVisitor) {
        this.derivationVisitor = derivationVisitor;
    }

    @Override
    public Node visit(final Node parent, final int childIndex) {
        final Map<Integer, Node> mapForParent = getMapOf(parent);
        //noinspection SynchronizationOnLocalVariableOrMethodParameter
        synchronized (mapForParent) {
            Node child = mapForParent.get(childIndex);
            if (child == null) {
                child = derivationVisitor.visit(parent, childIndex);
                mapForParent.put(childIndex, child);
            }
            return child;
        }
    }

    private Map<Integer, Node> getMapOf(final Node parentNode) {
        synchronized (cache) {
            HashMap<Integer, Node> mapForParent = cache.get(parentNode);
            if (mapForParent == null) {
                mapForParent = new HashMap<>();
                cache.put(parentNode, mapForParent);
            }
            return mapForParent;
        }
    }
}