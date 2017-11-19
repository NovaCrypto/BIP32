[![Download](https://api.bintray.com/packages/novacrypto/BIP/BIP32/images/download.svg)](https://bintray.com/novacrypto/BIP/BIP32/_latestVersion) [![Build Status](https://travis-ci.org/NovaCrypto/BIP32.svg?branch=master)](https://travis-ci.org/NovaCrypto/BIP32) [![codecov](https://codecov.io/gh/NovaCrypto/BIP32/branch/master/graph/badge.svg)](https://codecov.io/gh/NovaCrypto/BIP32)

# WIP

!!! This is a work in progress and you shouldn't use this just yet for any main net transactions. !!!

# Install

Repository:

```
repositories {
    maven {
        url 'https://dl.bintray.com/novacrypto/BIP/'
    }
}
```

Add dependency:

```
dependencies {
    compile 'io.github.novacrypto:BIP32:0.0.5'
}

```

# Usage

```
PrivateKey key = PrivateKey.fromSeed(seed, Bitcoin.MAIN_NET);
PrivateKey child = key.derive("m/0'/0);
PublicKey childPub = child.neuter();
```

Need a seed from mnemonic/passphrase? check out [NovaCrypto/Bip39](https://github.com/NovaCrypto/Bip39).

# Serialize

```
String extendedKey = key.extendedBase58();
```

Or manually using [NovaCrypto/Base58](https://github.com/NovaCrypto/Base58):

```
String extendedKey = base58Encode(key.extendedKeyByteArray());
```

# Serialize address

## Pay to Public Key Hash

```
String p2pkh = public.p2pkhAddress();
```

## Pay to Script Hash

```
String p2sh = public.p2shAddress();
```
