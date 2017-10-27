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

package io.github.novacrypto.Bip0032WikiTestVectors;

import io.github.novacrypto.bip32.PrivateKey;
import org.junit.Test;

import static io.github.novacrypto.Bip0032WikiTestVectors.TestVectorHelpers.*;

public final class TestVector2 {

    private final PrivateKey root = createMainNetRootFromSeed(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
    );

    @Test
    public void m_public() {
        assertBase58("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
                root.neuter());
    }

    @Test
    public void m_private() {
        assertBase58("xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                root);
    }

    @Test
    public void chain_m_0_public() {
        assertBase58("xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
                root
                        .cKDpriv(0)
                        .neuter());
    }

    @Test
    public void chain_m_0_public_CKDpub_last() {
        assertBase58("xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
                root
                        .cKDpub(0));
    }

    @Test
    public void chain_m_0_private() {
        assertBase58("xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                root
                        .cKDpriv(0));
    }

    @Test
    public void chain_m_0_2147483647h_public() {
        assertBase58("xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
                root
                        .cKDpriv(0)
                        .cKDpriv(hard(2147483647))
                        .neuter());
    }

    @Test
    public void chain_m_0_2147483647h_CKDpub_last() {
        assertBase58("xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
                root
                        .cKDpriv(0)
                        .cKDpub(hard(2147483647))
        );
    }

    @Test
    public void chain_m_0_2147483647h_private() {
        assertBase58("xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                root
                        .cKDpriv(0)
                        .cKDpriv(hard(2147483647)));
    }

    @Test
    public void chain_m_0_2147483647h_1_public() {
        assertBase58("xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
                root
                        .cKDpriv(0)
                        .cKDpriv(hard(2147483647))
                        .cKDpriv(1)
                        .neuter());
    }

    @Test
    public void chain_m_0_2147483647h_1_public_CKDpub_last() {
        assertBase58("xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
                root
                        .cKDpriv(0)
                        .cKDpriv(hard(2147483647))
                        .cKDpub(1));
    }

    @Test
    public void chain_m_0_2147483647h_1_private() {
        assertBase58("xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                root
                        .cKDpriv(0)
                        .cKDpriv(hard(2147483647))
                        .cKDpriv(1));
    }

    @Test
    public void chain_m_0_2147483647h_1_2147483646h_public() {
        assertBase58("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
                root
                        .cKDpriv(0)
                        .cKDpriv(hard(2147483647))
                        .cKDpriv(1)
                        .cKDpriv(hard(2147483646))
                        .neuter());
    }

    @Test
    public void chain_m_0_2147483647h_1_2147483646h_public_CKDpub_last() {
        assertBase58("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
                root
                        .cKDpriv(0)
                        .cKDpriv(hard(2147483647))
                        .cKDpriv(1)
                        .cKDpub(hard(2147483646)));
    }

    @Test
    public void chain_m_0_2147483647h_1_2147483646h_private() {
        assertBase58("xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                root
                        .cKDpriv(0)
                        .cKDpriv(hard(2147483647))
                        .cKDpriv(1)
                        .cKDpriv(hard(2147483646)));
    }

    @Test
    public void chain_m_0_2147483647h_1_2147483646h_2_public() {
        assertBase58("xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
                root
                        .cKDpriv(0)
                        .cKDpriv(hard(2147483647))
                        .cKDpriv(1)
                        .cKDpriv(hard(2147483646))
                        .cKDpriv(2)
                        .neuter());
    }

    @Test
    public void chain_m_0_2147483647h_1_2147483646h_2_private() {
        assertBase58("xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                root
                        .cKDpriv(0)
                        .cKDpriv(hard(2147483647))
                        .cKDpriv(1)
                        .cKDpriv(hard(2147483646))
                        .cKDpriv(2));
    }

    @Test
    public void chain_m_0_2147483647h_1_2147483646h_2_public_CKDpub_last() {
        assertBase58("xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
                root
                        .cKDpriv(0)
                        .cKDpriv(hard(2147483647))
                        .cKDpriv(1)
                        .cKDpriv(hard(2147483646))
                        .cKDpub(2));
    }
}