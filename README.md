typepki-oiddb: Object Identifier (OID) database and utilities for TypePKI Library
=================================================================================

[TOP](https://kjur.github.io/typepki-oiddb/) | [github](https://github.com/kjur/typepki-oiddb) | [npm](https://www.npmjs.com/package/typepki-oiddb) | [TypePKI](https://kjur.github.io/typepki/) 

The 'TypePKI' library is an opensource free TypeScript PKI library which is the successor of the long lived [jsrsasign](https://kjur.github.io/jsrsasign) library.

The 'typepki-oiddb' is a Object Identifier (OID) database and utilities for TypePKI Library.

## FEATURE
- singleton OID database
- Dual CommonJS/ES module package supporting CommonJS(CJS) and ES modules

## Usage
```ts
import { OIDDataBase, OIDSET_CRYPTO, OIDSET_X509 } from "typepki-oiddb";
const oiddb = OIDDatabase.instance; // singleton object
oiddb.regist([OIDSET_CRYPTO, OIDSET_X509]);
oiddb.oidtoname("2.5.29.15") -> "keyUsage"
```

## "typepki-oiddb" Bulitin OID registration

There are two builtin OID data set:

- OIDSET_CRYPTO - OIDs for common cryptographic algorithms and parameters
- OIDSET_X509 - common OIDs for X.509 certificates, CRLs and extensions

## OID data sets published

There is no data sets for now but they will be published near in the future.

## Custom OID registration

```ts
import { OIDDataBase, OIDDataSet, OIDSET_CRYPTO, OIDSET_X509 } from "typepki-oiddb";
const oiddb = OIDDatabase.instance; // singleton object
oiddb.regist([OIDSET_CRYPTO, OIDSET_X509]);
```

When you want to add some OID name definitions, you can do it like this:

```ts
const MYOIDSET: OIDDataSet = {
  setname: "myoid",
  nametooid: {
    "my-oid-one": "1.2.3.4.5.1",
    "my-oid-two": "1.2.3.4.5.2",
  },
};
oiddb.regist([MYOIDSET]);
oiddb.nametooid("my-oid-two") -> "1.2.3.4.5.2"
```
