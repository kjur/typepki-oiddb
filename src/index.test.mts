import { describe, expect, test } from "bun:test";
import { OIDDataBase, OIDSET_CRYPTO, OIDSET_X509 } from "./index.mts";

const oiddb = OIDDataBase.instance;
oiddb.regist([OIDSET_CRYPTO, OIDSET_X509]);

test("OIDDataBase", () => {
  expect(oiddb.oidtoname("2.5.29.15")).toBe("keyUsage");
  expect(oiddb.shorttoname("CN")).toBe("commonName");
  expect(oiddb.nametoshort("commonName")).toBe("CN");
  expect(oiddb.oidtoshort("2.5.4.6")).toBe("C");
  expect(oiddb.shorttooid("C")).toBe("2.5.4.6");
});

test("OIDDatabase.nametooid", () => {
  const oiddb = OIDDataBase.instance;
  expect(oiddb.nametooid("keyUsage")).toBe("2.5.29.15");
  expect(oiddb.nametooid("P-256")).toBe("1.2.840.10045.3.1.7");
  expect(oiddb.nametooid("P-521")).toBe("1.3.132.0.35");
});

test("OIDDataBase.aliasto", () => {
  const oiddb = OIDDataBase.instance;
  expect(oiddb.aliasto("P-256")).toBe("prime256v1");  
});
