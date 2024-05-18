/**
 * Singleton class for OID(object identifier) name database
 * @example
 * import { OIDDataBase, OIDSET_CRYPTO, OIDSET_X509 } from "typepki-oiddb";
 * const oiddb = OIDDatabase.instance; // singleton object
 * oiddb.regist([OIDSET_CRYPTO, OIDSET_X509]);
 * oiddb.oidtoname("2.5.29.15") -> "keyUsage"
 * oiddb.nametooid("P-521") -> "1.3.132.0.35"
 * oiddb.shorttoname("CN") -> "commonName"
 * oiddb.nametoshort("commonName") -> "CN"
 * oiddb.shorttooid("C") -> "2.5.4.6"
 * oiddb.oidtoshort("2.5.4.6") -> "C"
 * oiddb.aliasto("P-256") -> "prime256v1"
 */
export class OIDDataBase {
  // instance
  private static _instance: OIDDataBase;
  private _uuid: string = "";
  private _dbOID2NAME: Record<string, string> = {};
  private _dbNAME2OID: Record<string, string> = {};
  private _dbSHORT2NAME: Record<string, string> = {};
  private _dbNAME2SHORT: Record<string, string> = {};
  private _dbALIAS: Record<string, string> = {};
  private _setlist: string[] = [];
  
  // constructor
  private constructor() {
  }

  /**
   * get instance of OIDDataBase
   * @example
   * const oiddb = OIDDataBase.instance;
   */
  public static get instance(): OIDDataBase {
    if (!this._instance) {
      this._instance = new OIDDataBase();
      this._instance._uuid = crypto.randomUUID();
    }
    return this._instance;
  }

  /**
   * get UUID value of this object. This is debugging purpose.
   */
  public get uuid(): string {
    return this._uuid;
  }

  /**
   * convert OID value to OID name defined in internal database
   * @param oid - OID value (ex. "1.2.3.4")
   * @return OID name. (ex. "countryName"). Return undefined if not defined.
   * @example
   * oiddb.oidtoname("2.5.29.15") -> "keyUsage"
   * oiddb.oidtoname("1.2.3.4") -> undefined
   */
  oidtoname(oid: string): string {
    return this._dbOID2NAME[oid];
  }

  /**
   * convert OID name to OID value defined in internal database
   * @param name - OID name. (ex. "countryName").
   * @return OID value (ex. "1.2.3.4"). Return undefined if not defined.
   * @example
   * oiddb.nametooid("keyUsage") -> "2.5.29.15"
   * oiddb.nametooid("foo-bar-") -> undefined // not registered
   * oiddb.nametooid("P-521") -> "1.3.132.0.35"
   */
  nametooid(name: string): string {
    const name2 = (this._dbALIAS[name] !== undefined) ? this._dbALIAS[name] : name;
    return this._dbNAME2OID[name2];
  }

  /**
   * convert short attribute type name to OID value defined in internal database
   * @param short - short attribute type name for distinguished name. (ex. "CN").
   * @return OID name (ex. "commonName"). Return undefined if not defined.
   * @example
   * oiddb.shorttoname("CN") -> "commonName"
   * oiddb.shorttoname("FOO") -> undefined // not registered
   */
  shorttoname(short: string): string {
    return this._dbSHORT2NAME[short];
  }

  /**
   * convert OID name to short attribute type name defined in internal database
   * @param name - OID name (ex. "commonName").
   * @return short attribute type name for distinguished name. (ex. "CN"). Return OID name if not defined.
   * @example
   * oiddb.nametoshort("commonName") -> "CN"
   * oiddb.nametoshort("serialNumber") -> "serialNumber" // for undefined short name
   */
  nametoshort(name: string): string {
    return this._dbNAME2SHORT[name];
  }

  /**
   * convert OID value to short attribute type name defined in internal database
   * @param oid - OID value (ex. "2.5.4.6").
   * @return short attribute type name for distinguished name. (ex. "C"). Return OID name if not defined.
   * @example
   * oiddb.oidtoshort("2.5.4.6") -> "CN"
   * oiddb.oidtoshort("2.5.4.97") -> "organizationIdentifier" // OID defined but short name not defined
   * oiddb.oidtoshort("1.2.3.4") -> "1.2.3.4" // for undefined short name nor OID name
   */
  oidtoshort(oid: string): string {
    const name = this._dbOID2NAME[oid];
    if (name == undefined) return oid;
    const short = this._dbNAME2SHORT[name];
    if (short == undefined) return name;
    return short;
  }

  
  shorttooid(short: string): string {
    const name = this._dbSHORT2NAME[short];
    if (name == undefined) return name;
    return this._dbNAME2OID[name];
  }

  /**
   * convert alias name to original OID name defined in internal database
   * @param aliasfrom - alias name (ex. "P-256").
   * @return original OID name (ex. "prime256v1"). Return undefined if not defined.
   * @example
   * oiddb.aliasto("P-256") -> "prime256v1"
   * oiddb.aliasto("FOO") -> undefined // FOO is not defined in aliases
   */
  aliasto(aliasfrom: string): string {
    return this._dbALIAS[aliasfrom];
  }

  /**
   * Register OID data set to a singleton object
   * @param datasetList - array of OIDDataSet
   * @description
   * This method will add OID definitions to object internal
   * database by the list of {@link OIDDataSet}.
   * When the OIDDataSet.setname already registered, 
   * its importing will be skipped.
   * Also when the registering OID is already registered,
   * its OID registration is skipped. 
   * This means existing OID definition will not
   * be overwritten.
   * @example
   * import { OIDDataBase, OIDSET_CRYPTO, OIDSET_X509 } from "typepki-oiddb";
   * const oiddb = OIDDatabase.instance;
   * oiddb.regist([OIDSET_CRYPTO, OIDSET_X509]);
   */
  regist(datasetList: OIDDataSet[]): void {
    datasetList.forEach((value, index, array) => {
      this.registOne(value);
    });
  }

  private registOne(dataset: OIDDataSet): void {
    if (this._setlist.includes(dataset.setname)) return;
    for (let name in dataset.nametooid) {
      const oid = dataset.nametooid[name];
      if (! (name in this._dbNAME2OID)) this._dbNAME2OID[name] = oid;
      if (! (oid in this._dbOID2NAME)) this._dbOID2NAME[oid] = name;
    }
    if (dataset.shorttoname !== undefined) {
      for (let short in dataset.shorttoname) {
        const name = dataset.shorttoname[short];
        if (! (short in this._dbSHORT2NAME)) this._dbSHORT2NAME[short] = name;
        if (! (name in this._dbNAME2SHORT)) this._dbNAME2SHORT[name] = short;
      }
    }
    if (dataset.alias !== undefined) {
      for (let alias in dataset.alias) {
        const origin = dataset.alias[alias];
        if (! (alias in this._dbALIAS)) this._dbALIAS[alias] = origin;
      }
    }
  }
}

/**
 * OID data set information to register
 */
export interface OIDDataSet {
  /**
   * OIDDataSet name
   */
  setname: string;
  /**
   * key value object with OID name (ex. "keyUsage") and OID value (ex."1.2.3")
   */
  nametooid: Record<string, string>;
  /**
   * key value object for short name(ex. "C") and original name(ex. "countryName") for distinguished name
   */
  shorttoname?: Record<string, string>;
  /**
   * key value object for alias (ex. "P-256") and original name(ex. "prime256v1")
   */
  alias?: Record<string, string>;
}

// == OIDSET ================================================
/** OID definitions for cryptograhpic algorithms */
export const OIDSET_CRYPTO: OIDDataSet = {
  setname: "crypto",
  nametooid: {
    "ecPublicKey": "1.2.840.10045.2.1",
    "prime256v1": "1.2.840.10045.3.1.7",
    "ecdsaWithSHA1": "1.2.840.10045.4.1", 
    "ecdsaWithSHA224": "1.2.840.10045.4.3.1",
    "ecdsaWithSHA256": "1.2.840.10045.4.3.2",
    "ecdsaWithSHA384": "1.2.840.10045.4.3.3",
    "ecdsaWithSHA512": "1.2.840.10045.4.3.4",
    "rsaEncryption": "1.2.840.113549.1.1.1",
    "sha1WithRSAEncryption": "1.2.840.113549.1.1.5",
    "mgf1": "1.2.840.113549.1.1.8",
    "rsaPSS": "1.2.840.113549.1.1.10",
    "sha256WithRSAEncryption": "1.2.840.113549.1.1.11",
    "sha384WithRSAEncryption": "1.2.840.113549.1.1.12",
    "sha512WithRSAEncryption": "1.2.840.113549.1.1.13",
    "sha224WithRSAEncryption": "1.2.840.113549.1.1.14",
    "sha1": "1.3.14.3.2.26",
    "secp384r1": "1.3.132.0.34",
    "secp521r1": "1.3.132.0.35",
    "sha224": "2.16.840.1.101.3.4.2.4",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
    "dsa": "1.2.840.10040.4.1",
    "SHA1withDSA": "1.2.840.10040.4.3",
    "SHA224withDSA": "2.16.840.1.101.3.4.3.1",
    "SHA256withDSA": "2.16.840.1.101.3.4.3.2",
  },
  alias: {
    "P-256": "prime256v1",
    "P-384": "secp384r1",
    "P-521": "secp521r1",
    "NIST P-256": "prime256v1",
    "NIST P-384": "secp384r1",
    "NIST P-521": "secp521r1",
    "secp256r1": "prime256v1",
  },
};

/** OID definitions for basic X.509 */
/*
MUST
      * country,
      * organization,
      * organizational unit,
      * distinguished name qualifier,
      * state or province name,
      * common name (e.g., "Susan Housley"), and
      * serial number.
SHOULD
      * locality,
      * title,
      * surname,
      * given name,
      * initials,
      * pseudonym, and
      * generation qualifier (e.g., "Jr.", "3rd", or "IV").
Other COMMON
 domainComponent
 emailAddress
Other less COMMON
 postalAddress
 street

 */
export const OIDSET_X509: OIDDataSet = {
  setname: "x509",
  nametooid: {
    // DN attribute types
    "commonName": "2.5.4.3",
    "countryName": "2.5.4.6",
    "organizationName": "2.5.4.10",
    "organizationIdentifier": "2.5.4.97",
    // RFC 5280 standard extensions
    "subjectKeyIdentifier": "2.5.29.14",
    "keyUsage": "2.5.29.15", 
    "subjectAltName": "2.5.29.17",
    "basicConstraints": "2.5.29.19",
    "certificatePolicies": "2.5.29.32",
    "authorityKeyIdentifier": "2.5.29.35",
    "extKeyUsage": "2.5.29.37", 
    // NON RFC 5280 standards but quite common
    "authorityInfoAccess": "1.3.6.1.5.5.7.1.1", 
    "serverAuth": "1.3.6.1.5.5.7.3.1", 
    "clientAuth": "1.3.6.1.5.5.7.3.2", 
    "ocsp": "1.3.6.1.5.5.7.48.1", 
    "caIssuers": "1.3.6.1.5.5.7.48.2", 
    // Others
    "extendedValidationCertificates": "1.3.6.1.4.1.11129.2.4.2", 
    "cabfBrDomainValidated": "2.23.140.1.2.1", 
  },
  shorttoname: {
    "CN": "commonName",
    "OU": "organizationName",
    "C": "countryName",
  },
};

