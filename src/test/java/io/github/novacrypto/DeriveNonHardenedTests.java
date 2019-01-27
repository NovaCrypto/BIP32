/*
 *  BIP32 library, a Java implementation of BIP32
 *  Copyright (C) 2017-2019 Alan Evans, NovaCrypto
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

package io.github.novacrypto;

import io.github.novacrypto.bip32.Network;
import io.github.novacrypto.bip32.ExtendedPrivateKey;
import io.github.novacrypto.bip32.ExtendedPublicKey;
import io.github.novacrypto.bip32.networks.Bitcoin;
import io.github.novacrypto.bip39.SeedCalculator;
import org.junit.Test;

import static io.github.novacrypto.Asserts.assertBase58KeysEqual;

public final class DeriveNonHardenedTests {

    @Test
    public void deriveFirstIndexNonHardened() {
        assertPrivateKey("xprv9vUtFfdFpb4T59CoQMSLmbpVg1dVZcWXsznR8BVeV4gn7pN1dZa7Kq1VR7fovgbbodEziyyk1i9wrb8wmfwr69DsGsdgV24EtDh5XgzqjHD",
                "edge talent poet tortoise trumpet dose", "m/0", Bitcoin.MAIN_NET);
    }

    @Test
    public void deriveFirstIndexNonHardenedPublic() {
        assertPublicKey("xpub69UEfBA9exckHdHGWNyM8jmEE3Tyy5EPFDi1vZuG3QDkzchAB6tMsdKyGQUqT81RAauDSrmC4C69APBpt93RT7n3owDDB7LgBsdqHqcSoi7",
                "edge talent poet tortoise trumpet dose", "m/0", Bitcoin.MAIN_NET);
    }

    @Test
    public void deriveSecondIndexNonHardened() {
        assertPrivateKey("xprv9vUtFfdFpb4T9JCuTLJG1ZBQtno7iBXnH82WzuX9qaAptWEEUDApggPW6A1SSyiunpBjsrLimC1GyV7CPYaG5erJNHTkHBj9QwN9LXw6GTV",
                "edge talent poet tortoise trumpet dose", "m/1", Bitcoin.MAIN_NET);
    }

    @Test
    public void deriveThirdIndexNonHardened() {
        assertPrivateKey("xprv9vUtFfdFpb4TBot36QNbPt35wgshz2HfeSrw2Er3Znf7AhD9qUKEafG1DQUdqeHWPs19YWumnggvTXQT8xosK92ZqTjacFbWQpL9p5wdabj",
                "edge talent poet tortoise trumpet dose", "m/2", Bitcoin.MAIN_NET);
    }

    @Test
    public void deriveFirstFirstIndexNonHardened() {
        assertPrivateKey("xprv9xTw8QJDWHrmnWvgkrX1brkMQJzCvVrsv27MDa2MGUpgsExLpYVGP66edfZbqrWuQkDs4eZhbRQm2NjYCR6shAjzsoK78GhsJtzARSeDmqv",
                "edge talent poet tortoise trumpet dose", "m/0/0", Bitcoin.MAIN_NET);
    }

    @Test
    public void deriveFirstSecondIndexNonHardened() {
        assertPrivateKey("xprv9xTw8QJDWHrmrYVKZx7kTHy8SpaWJLrpa5nrhjNm7gAQdRDG2DTCwtctW6Pecuosk9EV7xS2zEthZ6ic8A4vUVKZGA5qZ367E7faqK9x2HE",
                "edge talent poet tortoise trumpet dose", "m/0/1", Bitcoin.MAIN_NET);
    }

    private void assertPublicKey(String expectedBase58Key, String mnemonic, String derivationPath, Bitcoin network) {
        final byte[] seed = new SeedCalculator().calculateSeed(mnemonic, "");

        final String actualBip32RootFromPrv = findPublicExtendedKeyByPrivate(seed, network, derivationPath);
        final String actualBip32RootFromPub = findPublicExtendedKeyByPublic(seed, network, derivationPath);
        assertBase58KeysEqual(actualBip32RootFromPrv, actualBip32RootFromPub);
        assertBase58KeysEqual(expectedBase58Key, actualBip32RootFromPub);
    }

    private void assertPrivateKey(String expectedBase58Key, String mnemonic, String derivationPath, Network network) {
        final byte[] seed = new SeedCalculator().calculateSeed(mnemonic, "");

        final String actualBip32Root = findPrivateExtendedKey(seed, network, derivationPath);
        assertBase58KeysEqual(expectedBase58Key, actualBip32Root);
    }

    private String findPrivateExtendedKey(byte[] seed, Network network, String derivationPath) {
        return derivePrivate(seed, network, derivationPath).extendedBase58();
    }

    private String findPublicExtendedKeyByPrivate(byte[] seed, Bitcoin network, String derivationPath) {
        return derivePrivate(seed, network, derivationPath)
                .neuter()
                .extendedBase58();
    }

    private String findPublicExtendedKeyByPublic(byte[] seed, Bitcoin network, String derivationPath) {
        return derivePublic(seed, network, derivationPath)
                .extendedBase58();
    }

    private ExtendedPrivateKey derivePrivate(byte[] seed, Network network, String derivationPath) {
        return ExtendedPrivateKey.fromSeed(seed, network).derive(derivationPath);
    }

    private ExtendedPublicKey derivePublic(byte[] seed, Network network, String derivationPath) {
        return derivePrivate(seed, network, "m").neuter().derive(derivationPath);
    }
}