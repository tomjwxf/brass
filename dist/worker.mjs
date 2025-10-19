var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require2() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// polyfills.ts
var init_polyfills = __esm({
  "polyfills.ts"() {
    globalThis.process ||= { env: {} };
    globalThis.global ||= globalThis;
  }
});

// node_modules/@cloudflare/voprf-ts/lib/cjs/src/groupTypes.js
var require_groupTypes = __commonJS({
  "node_modules/@cloudflare/voprf-ts/lib/cjs/src/groupTypes.js"(exports) {
    "use strict";
    init_polyfills();
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.GROUP = void 0;
    exports.errBadGroup = errBadGroup;
    exports.GROUP = {
      // P256_XMD:SHA-256_SSWU_RO_
      P256: "P-256",
      // P384_XMD:SHA-384_SSWU_RO_
      P384: "P-384",
      // P521_XMD:SHA-512_SSWU_RO_
      P521: "P-521",
      // ristretto255_XMD:SHA-512_R255MAP_RO_
      RISTRETTO255: "ristretto255",
      // decaf448_XOF:SHAKE256_D448MAP_RO_
      DECAF448: "decaf448"
    };
    function errBadGroup(X) {
      return new Error(`group: bad group name ${X}.`);
    }
  }
});

// node_modules/@cloudflare/voprf-ts/lib/cjs/src/util.js
var require_util = __commonJS({
  "node_modules/@cloudflare/voprf-ts/lib/cjs/src/util.js"(exports) {
    "use strict";
    init_polyfills();
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.joinAll = joinAll;
    exports.xor = xor;
    exports.ctEqual = ctEqual;
    exports.zip = zip;
    exports.to16bits = to16bits;
    exports.toU16LenPrefix = toU16LenPrefix;
    exports.toU16LenPrefixUint8Array = toU16LenPrefixUint8Array;
    exports.toU16LenPrefixClass = toU16LenPrefixClass;
    exports.fromU16LenPrefix = fromU16LenPrefix;
    exports.fromU16LenPrefixDes = fromU16LenPrefixDes;
    exports.fromU16LenPrefixUint8Array = fromU16LenPrefixUint8Array;
    exports.checkSize = checkSize;
    exports.errDeserialization = errDeserialization;
    exports.errGroup = errGroup;
    exports.compat = compat;
    function joinAll(a) {
      let size = 0;
      for (const ai of a) {
        size += ai.length;
      }
      const ret = new Uint8Array(new ArrayBuffer(size));
      let offset = 0;
      for (const ai of a) {
        ret.set(ai, offset);
        offset += ai.length;
      }
      return ret;
    }
    function xor(a, b) {
      if (a.length !== b.length || a.length === 0) {
        throw new Error("arrays of different length");
      }
      const n = a.length;
      const c = new Uint8Array(n);
      for (let i = 0; i < n; i++) {
        c[i] = a[i] ^ b[i];
      }
      return c;
    }
    function ctEqual(a, b) {
      if (a.length !== b.length || a.length === 0) {
        return false;
      }
      const n = a.length;
      let c = 0;
      for (let i = 0; i < n; i++) {
        c |= a[i] ^ b[i];
      }
      return c === 0;
    }
    function zip(x, y) {
      return x.map((xi, i) => [xi, y[i]]);
    }
    function to16bits(n) {
      if (!(n >= 0 && n < 65535)) {
        throw new Error("number bigger than 2^16");
      }
      return new Uint8Array([n >> 8 & 255, n & 255]);
    }
    function toU16LenPrefix(b) {
      return [to16bits(b.length), b];
    }
    function toU16LenPrefixUint8Array(b) {
      return [to16bits(b.length), ...b.flatMap((x) => toU16LenPrefix(x))];
    }
    function toU16LenPrefixClass(b) {
      return [to16bits(b.length), ...b.map((x) => x.serialize())];
    }
    function fromU16LenPrefix(b) {
      if (b.length < 2) {
        throw new Error(`buffer shorter than expected`);
      }
      const n = b[0] << 8 | b[1];
      if (b.length < 2 + n) {
        throw new Error(`buffer shorter than expected`);
      }
      const head = b.subarray(2, 2 + n);
      const tail = b.subarray(2 + n);
      return { head, tail };
    }
    function fromU16LenPrefixDes(c, b) {
      if (b.length < 2) {
        throw new Error(`buffer shorter than expected`);
      }
      const n = b[0] << 8 | b[1];
      const size = c.size();
      if (b.length < 2 + n * size) {
        throw new Error(`buffer shorter than expected`);
      }
      const head = [];
      for (let i = 0; i < n; i++) {
        head.push(c.deserialize(b.subarray(2 + i * size, 2 + (i + 1) * size)));
      }
      const tail = b.subarray(2 + n * size);
      return { head, tail };
    }
    function fromU16LenPrefixUint8Array(b) {
      if (b.length < 2) {
        throw new Error(`buffer shorter than expected`);
      }
      const n = b[0] << 8 | b[1];
      let run = b.subarray(2);
      const output = [];
      for (let i = 0; i < n; i++) {
        const { head, tail } = fromU16LenPrefix(run);
        output.push(head);
        run = tail;
      }
      return { head: output, tail: run };
    }
    function checkSize(x, T, u) {
      if (x.length < T.size(u)) {
        throw new Error(`error deserializing ${T.name}: buffer shorter than expected`);
      }
    }
    function errDeserialization(T) {
      return new Error(`group: deserialization of ${T.name} failed.`);
    }
    function errGroup(X, Y) {
      return new Error(`group: mismatch between groups ${X} and ${Y}.`);
    }
    function compat(x, y) {
      if (x.g.id !== y.g.id)
        throw errGroup(x.g.id, y.g.id);
    }
  }
});

// node_modules/@cloudflare/voprf-ts/lib/cjs/src/consts.js
var require_consts = __commonJS({
  "node_modules/@cloudflare/voprf-ts/lib/cjs/src/consts.js"(exports) {
    "use strict";
    init_polyfills();
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.LABELS = exports.SUITE = exports.MODE = void 0;
    exports.MODE = {
      OPRF: 0,
      VOPRF: 1,
      POPRF: 2
    };
    exports.SUITE = {
      P256_SHA256: "P256-SHA256",
      P384_SHA384: "P384-SHA384",
      P521_SHA512: "P521-SHA512",
      RISTRETTO255_SHA512: "ristretto255-SHA512",
      DECAF448_SHAKE256: "decaf448-SHAKE256"
    };
    exports.LABELS = {
      Version: "OPRFV1-",
      FinalizeDST: "Finalize",
      HashToGroupDST: "HashToGroup-",
      HashToScalarDST: "HashToScalar-",
      DeriveKeyPairDST: "DeriveKeyPair",
      InfoLabel: "Info"
    };
  }
});

// node_modules/@cloudflare/voprf-ts/lib/cjs/src/oprf.js
var require_oprf = __commonJS({
  "node_modules/@cloudflare/voprf-ts/lib/cjs/src/oprf.js"(exports) {
    "use strict";
    init_polyfills();
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.FinalizeData = exports.EvaluationRequest = exports.Evaluation = exports.Oprf = void 0;
    exports.getOprfParams = getOprfParams;
    exports.getSupportedSuites = getSupportedSuites;
    var dleq_js_1 = require_dleq();
    var groupTypes_js_1 = require_groupTypes();
    var util_js_1 = require_util();
    var consts_js_1 = require_consts();
    var cryptoImpl_js_1 = require_cryptoImpl();
    function assertNever(name, x) {
      throw new Error(`unexpected ${name} identifier: ${x}`);
    }
    function getOprfParams(id) {
      switch (id) {
        case Oprf2.Suite.P256_SHA256:
          return [Oprf2.Suite.P256_SHA256, groupTypes_js_1.GROUP.P256, "SHA-256", 32];
        case Oprf2.Suite.P384_SHA384:
          return [Oprf2.Suite.P384_SHA384, groupTypes_js_1.GROUP.P384, "SHA-384", 48];
        case Oprf2.Suite.P521_SHA512:
          return [Oprf2.Suite.P521_SHA512, groupTypes_js_1.GROUP.P521, "SHA-512", 64];
        case Oprf2.Suite.RISTRETTO255_SHA512:
          return [Oprf2.Suite.RISTRETTO255_SHA512, groupTypes_js_1.GROUP.RISTRETTO255, "SHA-512", 64];
        case Oprf2.Suite.DECAF448_SHAKE256:
          return [Oprf2.Suite.DECAF448_SHAKE256, groupTypes_js_1.GROUP.DECAF448, "SHAKE256", 64];
        default:
          assertNever("Oprf.Suite", id);
      }
    }
    function getSupportedSuites(g) {
      return Object.values(Oprf2.Suite).filter((v) => g.supportedGroups.includes(getOprfParams(v)[1]));
    }
    var Oprf2 = class _Oprf {
      static set Crypto(provider) {
        (0, cryptoImpl_js_1.setCryptoProvider)(provider);
      }
      static get Crypto() {
        return (0, cryptoImpl_js_1.getCryptoProvider)();
      }
      static validateMode(m) {
        switch (m) {
          case _Oprf.Mode.OPRF:
          case _Oprf.Mode.VOPRF:
          case _Oprf.Mode.POPRF:
            return m;
          default:
            assertNever("Oprf.Mode", m);
        }
      }
      static getGroup(suite, ...arg) {
        return (0, cryptoImpl_js_1.getSuiteGroup)(suite, arg);
      }
      static getHash(suite) {
        return getOprfParams(suite)[2];
      }
      static getOprfSize(suite) {
        return getOprfParams(suite)[3];
      }
      static getDST(mode, suite, name) {
        const m = _Oprf.validateMode(mode);
        const te = new TextEncoder();
        return (0, util_js_1.joinAll)([
          te.encode(name + _Oprf.LABELS.Version),
          Uint8Array.of(m),
          te.encode("-" + suite)
        ]);
      }
      constructor(mode, suite, ...arg) {
        const [ID, gid, hash] = getOprfParams(suite);
        this.crypto = (0, cryptoImpl_js_1.getCrypto)(arg);
        this.group = this.crypto.Group.get(gid);
        this.suite = ID;
        this.hashID = hash;
        this.mode = _Oprf.validateMode(mode);
      }
      getDLEQParams() {
        const EMPTY_DST = "";
        return { group: this.group.id, hash: this.hashID, dst: this.getDST(EMPTY_DST) };
      }
      getDST(name) {
        return _Oprf.getDST(this.mode, this.suite, name);
      }
      async coreFinalize(input, issuedElement, info) {
        let hasInfo = [];
        if (this.mode === _Oprf.Mode.POPRF) {
          hasInfo = (0, util_js_1.toU16LenPrefix)(info);
        }
        const hashInput = (0, util_js_1.joinAll)([
          ...(0, util_js_1.toU16LenPrefix)(input),
          ...hasInfo,
          ...(0, util_js_1.toU16LenPrefix)(issuedElement),
          new TextEncoder().encode(_Oprf.LABELS.FinalizeDST)
        ]);
        return await this.crypto.hash(this.hashID, hashInput);
      }
      scalarFromInfo(info) {
        if (info.length >= 1 << 16) {
          throw new Error("invalid info length");
        }
        const te = new TextEncoder();
        const framedInfo = (0, util_js_1.joinAll)([te.encode(_Oprf.LABELS.InfoLabel), ...(0, util_js_1.toU16LenPrefix)(info)]);
        return this.group.hashToScalar(framedInfo, this.getDST(_Oprf.LABELS.HashToScalarDST));
      }
    };
    exports.Oprf = Oprf2;
    Oprf2.Mode = consts_js_1.MODE;
    Oprf2.Suite = consts_js_1.SUITE;
    Oprf2.LABELS = consts_js_1.LABELS;
    var Evaluation = class _Evaluation {
      constructor(mode, evaluated, proof) {
        this.mode = mode;
        this.evaluated = evaluated;
        this.proof = proof;
      }
      serialize() {
        let proofBytes = new Uint8Array();
        if (this.proof && (this.mode == Oprf2.Mode.VOPRF || this.mode == Oprf2.Mode.POPRF)) {
          proofBytes = this.proof.serialize();
        }
        return (0, util_js_1.joinAll)([
          ...(0, util_js_1.toU16LenPrefixClass)(this.evaluated),
          Uint8Array.from([this.mode]),
          proofBytes
        ]);
      }
      isEqual(e) {
        if (this.mode !== e.mode || this.proof && !e.proof || !this.proof && e.proof) {
          return false;
        }
        let res = this.evaluated.every((x, i) => x.isEqual(e.evaluated[i]));
        if (this.proof && e.proof) {
          res && (res = this.proof.isEqual(e.proof));
        }
        return res;
      }
      static deserialize(suite, bytes, ...arg) {
        const group = (0, cryptoImpl_js_1.getSuiteGroup)(suite, arg);
        const { head: evalList, tail } = (0, util_js_1.fromU16LenPrefixDes)(group.eltDes, bytes);
        let proof;
        const proofSize = dleq_js_1.DLEQProof.size(group);
        const proofBytes = tail.subarray(1, 1 + proofSize);
        const mode = tail[0];
        switch (mode) {
          case Oprf2.Mode.OPRF:
            break;
          case Oprf2.Mode.VOPRF:
          case Oprf2.Mode.POPRF:
            proof = dleq_js_1.DLEQProof.deserialize(group.id, proofBytes, ...arg);
            break;
          default:
            assertNever("Oprf.Mode", mode);
        }
        return new _Evaluation(mode, evalList, proof);
      }
    };
    exports.Evaluation = Evaluation;
    var EvaluationRequest = class _EvaluationRequest {
      constructor(blinded) {
        this.blinded = blinded;
      }
      serialize() {
        return (0, util_js_1.joinAll)((0, util_js_1.toU16LenPrefixClass)(this.blinded));
      }
      isEqual(e) {
        return this.blinded.every((x, i) => x.isEqual(e.blinded[i]));
      }
      static deserialize(suite, bytes, ...arg) {
        const g = (0, cryptoImpl_js_1.getSuiteGroup)(suite, arg);
        const { head: blindedList } = (0, util_js_1.fromU16LenPrefixDes)(g.eltDes, bytes);
        return new _EvaluationRequest(blindedList);
      }
    };
    exports.EvaluationRequest = EvaluationRequest;
    var FinalizeData = class _FinalizeData {
      constructor(inputs, blinds, evalReq) {
        this.inputs = inputs;
        this.blinds = blinds;
        this.evalReq = evalReq;
      }
      serialize() {
        return (0, util_js_1.joinAll)([
          ...(0, util_js_1.toU16LenPrefixUint8Array)(this.inputs),
          ...(0, util_js_1.toU16LenPrefixClass)(this.blinds),
          this.evalReq.serialize()
        ]);
      }
      isEqual(f) {
        return this.inputs.every((x, i) => x.toString() === f.inputs[i].toString()) && this.blinds.every((x, i) => x.isEqual(f.blinds[i])) && this.evalReq.isEqual(f.evalReq);
      }
      static deserialize(suite, bytes, ...arg) {
        const g = (0, cryptoImpl_js_1.getSuiteGroup)(suite, arg);
        const { head: inputs, tail: t0 } = (0, util_js_1.fromU16LenPrefixUint8Array)(bytes);
        const { head: blinds, tail: t1 } = (0, util_js_1.fromU16LenPrefixDes)(g.scalarDes, t0);
        const evalReq = EvaluationRequest.deserialize(suite, t1, ...arg);
        return new _FinalizeData(inputs, blinds, evalReq);
      }
    };
    exports.FinalizeData = FinalizeData;
  }
});

// node_modules/@cloudflare/voprf-ts/lib/cjs/src/sjcl/index.js
var require_sjcl = __commonJS({
  "node_modules/@cloudflare/voprf-ts/lib/cjs/src/sjcl/index.js"(exports, module) {
    "use strict";
    init_polyfills();
    Object.defineProperty(exports, "__esModule", { value: true });
    var sjcl = {
      /**
       * Symmetric ciphers.
       * @namespace
       */
      cipher: {},
      /**
       * Hash functions.  Right now only SHA256 is implemented.
       * @namespace
       */
      hash: {},
      /**
       * Key exchange functions.  Right now only SRP is implemented.
       * @namespace
       */
      keyexchange: {},
      /**
       * Cipher modes of operation.
       * @namespace
       */
      mode: {},
      /**
       * Miscellaneous.  HMAC and PBKDF2.
       * @namespace
       */
      misc: {},
      /**
       * Bit array encoders and decoders.
       * @namespace
       *
       * @description
       * The members of this namespace are functions which translate between
       * SJCL's bitArrays and other objects (usually strings).  Because it
       * isn't always clear which direction is encoding and which is decoding,
       * the method names are "fromBits" and "toBits".
       */
      codec: {},
      /**
       * Exceptions.
       * @namespace
       */
      exception: {
        /**
         * Ciphertext is corrupt.
         * @constructor
         */
        corrupt: function(message) {
          this.toString = function() {
            return "CORRUPT: " + this.message;
          };
          this.message = message;
        },
        /**
         * Invalid parameter.
         * @constructor
         */
        invalid: function(message) {
          this.toString = function() {
            return "INVALID: " + this.message;
          };
          this.message = message;
        },
        /**
         * Bug or missing feature in SJCL.
         * @constructor
         */
        bug: function(message) {
          this.toString = function() {
            return "BUG: " + this.message;
          };
          this.message = message;
        },
        /**
         * Something isn't ready.
         * @constructor
         */
        notReady: function(message) {
          this.toString = function() {
            return "NOT READY: " + this.message;
          };
          this.message = message;
        }
      }
    };
    sjcl.cipher.aes = function(key) {
      if (!this._tables[0][0][0]) {
        this._precompute();
      }
      var i, j2, tmp, encKey, decKey, sbox = this._tables[0][4], decTable = this._tables[1], keyLen = key.length, rcon = 1;
      if (keyLen !== 4 && keyLen !== 6 && keyLen !== 8) {
        throw new sjcl.exception.invalid("invalid aes key size");
      }
      this._key = [encKey = key.slice(0), decKey = []];
      for (i = keyLen; i < 4 * keyLen + 28; i++) {
        tmp = encKey[i - 1];
        if (i % keyLen === 0 || keyLen === 8 && i % keyLen === 4) {
          tmp = sbox[tmp >>> 24] << 24 ^ sbox[tmp >> 16 & 255] << 16 ^ sbox[tmp >> 8 & 255] << 8 ^ sbox[tmp & 255];
          if (i % keyLen === 0) {
            tmp = tmp << 8 ^ tmp >>> 24 ^ rcon << 24;
            rcon = rcon << 1 ^ (rcon >> 7) * 283;
          }
        }
        encKey[i] = encKey[i - keyLen] ^ tmp;
      }
      for (j2 = 0; i; j2++, i--) {
        tmp = encKey[j2 & 3 ? i : i - 4];
        if (i <= 4 || j2 < 4) {
          decKey[j2] = tmp;
        } else {
          decKey[j2] = decTable[0][sbox[tmp >>> 24]] ^ decTable[1][sbox[tmp >> 16 & 255]] ^ decTable[2][sbox[tmp >> 8 & 255]] ^ decTable[3][sbox[tmp & 255]];
        }
      }
    };
    sjcl.cipher.aes.prototype = {
      // public
      /* Something like this might appear here eventually
      name: "AES",
      blockSize: 4,
      keySizes: [4,6,8],
      */
      /**
       * Encrypt an array of 4 big-endian words.
       * @param {Array} data The plaintext.
       * @return {Array} The ciphertext.
       */
      encrypt: function(data) {
        return this._crypt(data, 0);
      },
      /**
       * Decrypt an array of 4 big-endian words.
       * @param {Array} data The ciphertext.
       * @return {Array} The plaintext.
       */
      decrypt: function(data) {
        return this._crypt(data, 1);
      },
      /**
       * The expanded S-box and inverse S-box tables.  These will be computed
       * on the client so that we don't have to send them down the wire.
       *
       * There are two tables, _tables[0] is for encryption and
       * _tables[1] is for decryption.
       *
       * The first 4 sub-tables are the expanded S-box with MixColumns.  The
       * last (_tables[01][4]) is the S-box itself.
       *
       * @private
       */
      _tables: [[[], [], [], [], []], [[], [], [], [], []]],
      /**
       * Expand the S-box tables.
       *
       * @private
       */
      _precompute: function() {
        var encTable = this._tables[0], decTable = this._tables[1], sbox = encTable[4], sboxInv = decTable[4], i, x, xInv, d = [], th = [], x2, x4, x8, s, tEnc, tDec;
        for (i = 0; i < 256; i++) {
          th[(d[i] = i << 1 ^ (i >> 7) * 283) ^ i] = i;
        }
        for (x = xInv = 0; !sbox[x]; x ^= x2 || 1, xInv = th[xInv] || 1) {
          s = xInv ^ xInv << 1 ^ xInv << 2 ^ xInv << 3 ^ xInv << 4;
          s = s >> 8 ^ s & 255 ^ 99;
          sbox[x] = s;
          sboxInv[s] = x;
          x8 = d[x4 = d[x2 = d[x]]];
          tDec = x8 * 16843009 ^ x4 * 65537 ^ x2 * 257 ^ x * 16843008;
          tEnc = d[s] * 257 ^ s * 16843008;
          for (i = 0; i < 4; i++) {
            encTable[i][x] = tEnc = tEnc << 24 ^ tEnc >>> 8;
            decTable[i][s] = tDec = tDec << 24 ^ tDec >>> 8;
          }
        }
        for (i = 0; i < 5; i++) {
          encTable[i] = encTable[i].slice(0);
          decTable[i] = decTable[i].slice(0);
        }
      },
      /**
       * Encryption and decryption core.
       * @param {Array} input Four words to be encrypted or decrypted.
       * @param dir The direction, 0 for encrypt and 1 for decrypt.
       * @return {Array} The four encrypted or decrypted words.
       * @private
       */
      _crypt: function(input, dir) {
        if (input.length !== 4) {
          throw new sjcl.exception.invalid("invalid aes block size");
        }
        var key = this._key[dir], a = input[0] ^ key[0], b = input[dir ? 3 : 1] ^ key[1], c = input[2] ^ key[2], d = input[dir ? 1 : 3] ^ key[3], a2, b2, c2, nInnerRounds = key.length / 4 - 2, i, kIndex = 4, out = [0, 0, 0, 0], table = this._tables[dir], t0 = table[0], t1 = table[1], t2 = table[2], t3 = table[3], sbox = table[4];
        for (i = 0; i < nInnerRounds; i++) {
          a2 = t0[a >>> 24] ^ t1[b >> 16 & 255] ^ t2[c >> 8 & 255] ^ t3[d & 255] ^ key[kIndex];
          b2 = t0[b >>> 24] ^ t1[c >> 16 & 255] ^ t2[d >> 8 & 255] ^ t3[a & 255] ^ key[kIndex + 1];
          c2 = t0[c >>> 24] ^ t1[d >> 16 & 255] ^ t2[a >> 8 & 255] ^ t3[b & 255] ^ key[kIndex + 2];
          d = t0[d >>> 24] ^ t1[a >> 16 & 255] ^ t2[b >> 8 & 255] ^ t3[c & 255] ^ key[kIndex + 3];
          kIndex += 4;
          a = a2;
          b = b2;
          c = c2;
        }
        for (i = 0; i < 4; i++) {
          out[dir ? 3 & -i : i] = sbox[a >>> 24] << 24 ^ sbox[b >> 16 & 255] << 16 ^ sbox[c >> 8 & 255] << 8 ^ sbox[d & 255] ^ key[kIndex++];
          a2 = a;
          a = b;
          b = c;
          c = d;
          d = a2;
        }
        return out;
      }
    };
    sjcl.bitArray = {
      /**
       * Array slices in units of bits.
       * @param {bitArray} a The array to slice.
       * @param {Number} bstart The offset to the start of the slice, in bits.
       * @param {Number} bend The offset to the end of the slice, in bits.  If this is undefined,
       * slice until the end of the array.
       * @return {bitArray} The requested slice.
       */
      bitSlice: function(a, bstart, bend) {
        a = sjcl.bitArray._shiftRight(a.slice(bstart / 32), 32 - (bstart & 31)).slice(1);
        return bend === void 0 ? a : sjcl.bitArray.clamp(a, bend - bstart);
      },
      /**
       * Extract a number packed into a bit array.
       * @param {bitArray} a The array to slice.
       * @param {Number} bstart The offset to the start of the slice, in bits.
       * @param {Number} blength The length of the number to extract.
       * @return {Number} The requested slice.
       */
      extract: function(a, bstart, blength) {
        var x, sh = Math.floor(-bstart - blength & 31);
        if ((bstart + blength - 1 ^ bstart) & -32) {
          x = a[bstart / 32 | 0] << 32 - sh ^ a[bstart / 32 + 1 | 0] >>> sh;
        } else {
          x = a[bstart / 32 | 0] >>> sh;
        }
        return x & (1 << blength) - 1;
      },
      /**
       * Concatenate two bit arrays.
       * @param {bitArray} a1 The first array.
       * @param {bitArray} a2 The second array.
       * @return {bitArray} The concatenation of a1 and a2.
       */
      concat: function(a1, a2) {
        if (a1.length === 0 || a2.length === 0) {
          return a1.concat(a2);
        }
        var last = a1[a1.length - 1], shift = sjcl.bitArray.getPartial(last);
        if (shift === 32) {
          return a1.concat(a2);
        } else {
          return sjcl.bitArray._shiftRight(a2, shift, last | 0, a1.slice(0, a1.length - 1));
        }
      },
      /**
       * Find the length of an array of bits.
       * @param {bitArray} a The array.
       * @return {Number} The length of a, in bits.
       */
      bitLength: function(a) {
        var l = a.length, x;
        if (l === 0) {
          return 0;
        }
        x = a[l - 1];
        return (l - 1) * 32 + sjcl.bitArray.getPartial(x);
      },
      /**
       * Truncate an array.
       * @param {bitArray} a The array.
       * @param {Number} len The length to truncate to, in bits.
       * @return {bitArray} A new array, truncated to len bits.
       */
      clamp: function(a, len) {
        if (a.length * 32 < len) {
          return a;
        }
        a = a.slice(0, Math.ceil(len / 32));
        var l = a.length;
        len = len & 31;
        if (l > 0 && len) {
          a[l - 1] = sjcl.bitArray.partial(len, a[l - 1] & 2147483648 >> len - 1, 1);
        }
        return a;
      },
      /**
       * Make a partial word for a bit array.
       * @param {Number} len The number of bits in the word.
       * @param {Number} x The bits.
       * @param {Number} [_end=0] Pass 1 if x has already been shifted to the high side.
       * @return {Number} The partial word.
       */
      partial: function(len, x, _end) {
        if (len === 32) {
          return x;
        }
        return (_end ? x | 0 : x << 32 - len) + len * 1099511627776;
      },
      /**
       * Get the number of bits used by a partial word.
       * @param {Number} x The partial word.
       * @return {Number} The number of bits used by the partial word.
       */
      getPartial: function(x) {
        return Math.round(x / 1099511627776) || 32;
      },
      /**
       * Compare two arrays for equality in a predictable amount of time.
       * @param {bitArray} a The first array.
       * @param {bitArray} b The second array.
       * @return {boolean} true if a == b; false otherwise.
       */
      equal: function(a, b) {
        if (sjcl.bitArray.bitLength(a) !== sjcl.bitArray.bitLength(b)) {
          return false;
        }
        var x = 0, i;
        for (i = 0; i < a.length; i++) {
          x |= a[i] ^ b[i];
        }
        return x === 0;
      },
      /** Shift an array right.
       * @param {bitArray} a The array to shift.
       * @param {Number} shift The number of bits to shift.
       * @param {Number} [carry=0] A byte to carry in
       * @param {bitArray} [out=[]] An array to prepend to the output.
       * @private
       */
      _shiftRight: function(a, shift, carry, out) {
        var i, last2 = 0, shift2;
        if (out === void 0) {
          out = [];
        }
        for (; shift >= 32; shift -= 32) {
          out.push(carry);
          carry = 0;
        }
        if (shift === 0) {
          return out.concat(a);
        }
        for (i = 0; i < a.length; i++) {
          out.push(carry | a[i] >>> shift);
          carry = a[i] << 32 - shift;
        }
        last2 = a.length ? a[a.length - 1] : 0;
        shift2 = sjcl.bitArray.getPartial(last2);
        out.push(sjcl.bitArray.partial(shift + shift2 & 31, shift + shift2 > 32 ? carry : out.pop(), 1));
        return out;
      },
      /** xor a block of 4 words together.
       * @private
       */
      _xor4: function(x, y) {
        return [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]];
      },
      /** byteswap a word array inplace.
       * (does not handle partial words)
       * @param {sjcl.bitArray} a word array
       * @return {sjcl.bitArray} byteswapped array
       */
      byteswapM: function(a) {
        var i, v, m = 65280;
        for (i = 0; i < a.length; ++i) {
          v = a[i];
          a[i] = v >>> 24 | v >>> 8 & m | (v & m) << 8 | v << 24;
        }
        return a;
      }
    };
    sjcl.codec.utf8String = {
      /** Convert from a bitArray to a UTF-8 string. */
      fromBits: function(arr) {
        var out = "", bl = sjcl.bitArray.bitLength(arr), i, tmp;
        for (i = 0; i < bl / 8; i++) {
          if ((i & 3) === 0) {
            tmp = arr[i / 4];
          }
          out += String.fromCharCode(tmp >>> 8 >>> 8 >>> 8);
          tmp <<= 8;
        }
        return decodeURIComponent(escape(out));
      },
      /** Convert from a UTF-8 string to a bitArray. */
      toBits: function(str) {
        str = unescape(encodeURIComponent(str));
        var out = [], i, tmp = 0;
        for (i = 0; i < str.length; i++) {
          tmp = tmp << 8 | str.charCodeAt(i);
          if ((i & 3) === 3) {
            out.push(tmp);
            tmp = 0;
          }
        }
        if (i & 3) {
          out.push(sjcl.bitArray.partial(8 * (i & 3), tmp));
        }
        return out;
      }
    };
    sjcl.codec.hex = {
      /** Convert from a bitArray to a hex string. */
      fromBits: function(arr) {
        var out = "", i;
        for (i = 0; i < arr.length; i++) {
          out += ((arr[i] | 0) + 263882790666240).toString(16).substr(4);
        }
        return out.substr(0, sjcl.bitArray.bitLength(arr) / 4);
      },
      /** Convert from a hex string to a bitArray. */
      toBits: function(str) {
        var i, out = [], len;
        str = str.replace(/\s|0x/g, "");
        len = str.length;
        str = str + "00000000";
        for (i = 0; i < str.length; i += 8) {
          out.push(parseInt(str.substr(i, 8), 16) ^ 0);
        }
        return sjcl.bitArray.clamp(out, len * 4);
      }
    };
    sjcl.codec.base64 = {
      /** The base64 alphabet.
       * @private
       */
      _chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
      /** Convert from a bitArray to a base64 string. */
      fromBits: function(arr, _noEquals, _url) {
        var out = "", i, bits = 0, c = sjcl.codec.base64._chars, ta = 0, bl = sjcl.bitArray.bitLength(arr);
        if (_url) {
          c = c.substr(0, 62) + "-_";
        }
        for (i = 0; out.length * 6 < bl; ) {
          out += c.charAt((ta ^ arr[i] >>> bits) >>> 26);
          if (bits < 6) {
            ta = arr[i] << 6 - bits;
            bits += 26;
            i++;
          } else {
            ta <<= 6;
            bits -= 6;
          }
        }
        while (out.length & 3 && !_noEquals) {
          out += "=";
        }
        return out;
      },
      /** Convert from a base64 string to a bitArray */
      toBits: function(str, _url) {
        str = str.replace(/\s|=/g, "");
        var out = [], i, bits = 0, c = sjcl.codec.base64._chars, ta = 0, x;
        if (_url) {
          c = c.substr(0, 62) + "-_";
        }
        for (i = 0; i < str.length; i++) {
          x = c.indexOf(str.charAt(i));
          if (x < 0) {
            throw new sjcl.exception.invalid("this isn't base64!");
          }
          if (bits > 26) {
            bits -= 26;
            out.push(ta ^ x >>> bits);
            ta = x << 32 - bits;
          } else {
            bits += 6;
            ta ^= x << 32 - bits;
          }
        }
        if (bits & 56) {
          out.push(sjcl.bitArray.partial(bits & 56, ta, 1));
        }
        return out;
      }
    };
    sjcl.codec.base64url = {
      fromBits: function(arr) {
        return sjcl.codec.base64.fromBits(arr, 1, 1);
      },
      toBits: function(str) {
        return sjcl.codec.base64.toBits(str, 1);
      }
    };
    sjcl.codec.bytes = {
      /** Convert from a bitArray to an array of bytes. */
      fromBits: function(arr) {
        var out = [], bl = sjcl.bitArray.bitLength(arr), i, tmp;
        for (i = 0; i < bl / 8; i++) {
          if ((i & 3) === 0) {
            tmp = arr[i / 4];
          }
          out.push(tmp >>> 24);
          tmp <<= 8;
        }
        return out;
      },
      /** Convert from an array of bytes to a bitArray. */
      toBits: function(bytes) {
        var out = [], i, tmp = 0;
        for (i = 0; i < bytes.length; i++) {
          tmp = tmp << 8 | bytes[i];
          if ((i & 3) === 3) {
            out.push(tmp);
            tmp = 0;
          }
        }
        if (i & 3) {
          out.push(sjcl.bitArray.partial(8 * (i & 3), tmp));
        }
        return out;
      }
    };
    sjcl.hash.sha256 = function(hash) {
      if (!this._key[0]) {
        this._precompute();
      }
      if (hash) {
        this._h = hash._h.slice(0);
        this._buffer = hash._buffer.slice(0);
        this._length = hash._length;
      } else {
        this.reset();
      }
    };
    sjcl.hash.sha256.hash = function(data) {
      return new sjcl.hash.sha256().update(data).finalize();
    };
    sjcl.hash.sha256.prototype = {
      /**
       * The hash's block size, in bits.
       * @constant
       */
      blockSize: 512,
      /**
       * Reset the hash state.
       * @return this
       */
      reset: function() {
        this._h = this._init.slice(0);
        this._buffer = [];
        this._length = 0;
        return this;
      },
      /**
       * Input several words to the hash.
       * @param {bitArray|String} data the data to hash.
       * @return this
       */
      update: function(data) {
        if (typeof data === "string") {
          data = sjcl.codec.utf8String.toBits(data);
        }
        var i, b = this._buffer = sjcl.bitArray.concat(this._buffer, data), ol = this._length, nl = this._length = ol + sjcl.bitArray.bitLength(data);
        if (nl > 9007199254740991) {
          throw new sjcl.exception.invalid("Cannot hash more than 2^53 - 1 bits");
        }
        if (typeof Uint32Array !== "undefined") {
          var c = new Uint32Array(b);
          var j2 = 0;
          for (i = 512 + ol - (512 + ol & 511); i <= nl; i += 512) {
            this._block(c.subarray(16 * j2, 16 * (j2 + 1)));
            j2 += 1;
          }
          b.splice(0, 16 * j2);
        } else {
          for (i = 512 + ol - (512 + ol & 511); i <= nl; i += 512) {
            this._block(b.splice(0, 16));
          }
        }
        return this;
      },
      /**
       * Complete hashing and output the hash value.
       * @return {bitArray} The hash value, an array of 8 big-endian words.
       */
      finalize: function() {
        var i, b = this._buffer, h = this._h;
        b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1, 1)]);
        for (i = b.length + 2; i & 15; i++) {
          b.push(0);
        }
        b.push(Math.floor(this._length / 4294967296));
        b.push(this._length | 0);
        while (b.length) {
          this._block(b.splice(0, 16));
        }
        this.reset();
        return h;
      },
      /**
       * The SHA-256 initialization vector, to be precomputed.
       * @private
       */
      _init: [],
      /*
      _init:[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
      */
      /**
       * The SHA-256 hash key, to be precomputed.
       * @private
       */
      _key: [],
      /*
      _key:
        [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],
      */
      /**
       * Function to precompute _init and _key.
       * @private
       */
      _precompute: function() {
        var i = 0, prime = 2, factor, isPrime;
        function frac(x) {
          return (x - Math.floor(x)) * 4294967296 | 0;
        }
        for (; i < 64; prime++) {
          isPrime = true;
          for (factor = 2; factor * factor <= prime; factor++) {
            if (prime % factor === 0) {
              isPrime = false;
              break;
            }
          }
          if (isPrime) {
            if (i < 8) {
              this._init[i] = frac(Math.pow(prime, 1 / 2));
            }
            this._key[i] = frac(Math.pow(prime, 1 / 3));
            i++;
          }
        }
      },
      /**
       * Perform one cycle of SHA-256.
       * @param {Uint32Array|bitArray} w one block of words.
       * @private
       */
      _block: function(w) {
        var i, tmp, a, b, h = this._h, k = this._key, h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4], h5 = h[5], h6 = h[6], h7 = h[7];
        for (i = 0; i < 64; i++) {
          if (i < 16) {
            tmp = w[i];
          } else {
            a = w[i + 1 & 15];
            b = w[i + 14 & 15];
            tmp = w[i & 15] = (a >>> 7 ^ a >>> 18 ^ a >>> 3 ^ a << 25 ^ a << 14) + (b >>> 17 ^ b >>> 19 ^ b >>> 10 ^ b << 15 ^ b << 13) + w[i & 15] + w[i + 9 & 15] | 0;
          }
          tmp = tmp + h7 + (h4 >>> 6 ^ h4 >>> 11 ^ h4 >>> 25 ^ h4 << 26 ^ h4 << 21 ^ h4 << 7) + (h6 ^ h4 & (h5 ^ h6)) + k[i];
          h7 = h6;
          h6 = h5;
          h5 = h4;
          h4 = h3 + tmp | 0;
          h3 = h2;
          h2 = h1;
          h1 = h0;
          h0 = tmp + (h1 & h2 ^ h3 & (h1 ^ h2)) + (h1 >>> 2 ^ h1 >>> 13 ^ h1 >>> 22 ^ h1 << 30 ^ h1 << 19 ^ h1 << 10) | 0;
        }
        h[0] = h[0] + h0 | 0;
        h[1] = h[1] + h1 | 0;
        h[2] = h[2] + h2 | 0;
        h[3] = h[3] + h3 | 0;
        h[4] = h[4] + h4 | 0;
        h[5] = h[5] + h5 | 0;
        h[6] = h[6] + h6 | 0;
        h[7] = h[7] + h7 | 0;
      }
    };
    sjcl.mode.ccm = {
      /** The name of the mode.
       * @constant
       */
      name: "ccm",
      _progressListeners: [],
      listenProgress: function(cb) {
        sjcl.mode.ccm._progressListeners.push(cb);
      },
      unListenProgress: function(cb) {
        var index = sjcl.mode.ccm._progressListeners.indexOf(cb);
        if (index > -1) {
          sjcl.mode.ccm._progressListeners.splice(index, 1);
        }
      },
      _callProgressListener: function(val) {
        var p = sjcl.mode.ccm._progressListeners.slice(), i;
        for (i = 0; i < p.length; i += 1) {
          p[i](val);
        }
      },
      /** Encrypt in CCM mode.
       * @static
       * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
       * @param {bitArray} plaintext The plaintext data.
       * @param {bitArray} iv The initialization value.
       * @param {bitArray} [adata=[]] The authenticated data.
       * @param {Number} [tlen=64] the desired tag length, in bits.
       * @return {bitArray} The encrypted data, an array of bytes.
       */
      encrypt: function(prf, plaintext, iv, adata, tlen) {
        var L, out = plaintext.slice(0), tag, w = sjcl.bitArray, ivl = w.bitLength(iv) / 8, ol = w.bitLength(out) / 8;
        tlen = tlen || 64;
        adata = adata || [];
        if (ivl < 7) {
          throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");
        }
        for (L = 2; L < 4 && ol >>> 8 * L; L++) {
        }
        if (L < 15 - ivl) {
          L = 15 - ivl;
        }
        iv = w.clamp(iv, 8 * (15 - L));
        tag = sjcl.mode.ccm._computeTag(prf, plaintext, iv, adata, tlen, L);
        out = sjcl.mode.ccm._ctrMode(prf, out, iv, tag, tlen, L);
        return w.concat(out.data, out.tag);
      },
      /** Decrypt in CCM mode.
       * @static
       * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
       * @param {bitArray} ciphertext The ciphertext data.
       * @param {bitArray} iv The initialization value.
       * @param {bitArray} [adata=[]] adata The authenticated data.
       * @param {Number} [tlen=64] tlen the desired tag length, in bits.
       * @return {bitArray} The decrypted data.
       */
      decrypt: function(prf, ciphertext, iv, adata, tlen) {
        tlen = tlen || 64;
        adata = adata || [];
        var L, w = sjcl.bitArray, ivl = w.bitLength(iv) / 8, ol = w.bitLength(ciphertext), out = w.clamp(ciphertext, ol - tlen), tag = w.bitSlice(ciphertext, ol - tlen), tag2;
        ol = (ol - tlen) / 8;
        if (ivl < 7) {
          throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");
        }
        for (L = 2; L < 4 && ol >>> 8 * L; L++) {
        }
        if (L < 15 - ivl) {
          L = 15 - ivl;
        }
        iv = w.clamp(iv, 8 * (15 - L));
        out = sjcl.mode.ccm._ctrMode(prf, out, iv, tag, tlen, L);
        tag2 = sjcl.mode.ccm._computeTag(prf, out.data, iv, adata, tlen, L);
        if (!w.equal(out.tag, tag2)) {
          throw new sjcl.exception.corrupt("ccm: tag doesn't match");
        }
        return out.data;
      },
      _macAdditionalData: function(prf, adata, iv, tlen, ol, L) {
        var mac, tmp, i, macData = [], w = sjcl.bitArray, xor = w._xor4;
        mac = [w.partial(8, (adata.length ? 1 << 6 : 0) | tlen - 2 << 2 | L - 1)];
        mac = w.concat(mac, iv);
        mac[3] |= ol;
        mac = prf.encrypt(mac);
        if (adata.length) {
          tmp = w.bitLength(adata) / 8;
          if (tmp <= 65279) {
            macData = [w.partial(16, tmp)];
          } else if (tmp <= 4294967295) {
            macData = w.concat([w.partial(16, 65534)], [tmp]);
          }
          macData = w.concat(macData, adata);
          for (i = 0; i < macData.length; i += 4) {
            mac = prf.encrypt(xor(mac, macData.slice(i, i + 4).concat([0, 0, 0])));
          }
        }
        return mac;
      },
      /* Compute the (unencrypted) authentication tag, according to the CCM specification
       * @param {Object} prf The pseudorandom function.
       * @param {bitArray} plaintext The plaintext data.
       * @param {bitArray} iv The initialization value.
       * @param {bitArray} adata The authenticated data.
       * @param {Number} tlen the desired tag length, in bits.
       * @return {bitArray} The tag, but not yet encrypted.
       * @private
       */
      _computeTag: function(prf, plaintext, iv, adata, tlen, L) {
        var mac, i, w = sjcl.bitArray, xor = w._xor4;
        tlen /= 8;
        if (tlen % 2 || tlen < 4 || tlen > 16) {
          throw new sjcl.exception.invalid("ccm: invalid tag length");
        }
        if (adata.length > 4294967295 || plaintext.length > 4294967295) {
          throw new sjcl.exception.bug("ccm: can't deal with 4GiB or more data");
        }
        mac = sjcl.mode.ccm._macAdditionalData(prf, adata, iv, tlen, w.bitLength(plaintext) / 8, L);
        for (i = 0; i < plaintext.length; i += 4) {
          mac = prf.encrypt(xor(mac, plaintext.slice(i, i + 4).concat([0, 0, 0])));
        }
        return w.clamp(mac, tlen * 8);
      },
      /** CCM CTR mode.
       * Encrypt or decrypt data and tag with the prf in CCM-style CTR mode.
       * May mutate its arguments.
       * @param {Object} prf The PRF.
       * @param {bitArray} data The data to be encrypted or decrypted.
       * @param {bitArray} iv The initialization vector.
       * @param {bitArray} tag The authentication tag.
       * @param {Number} tlen The length of th etag, in bits.
       * @param {Number} L The CCM L value.
       * @return {Object} An object with data and tag, the en/decryption of data and tag values.
       * @private
       */
      _ctrMode: function(prf, data, iv, tag, tlen, L) {
        var enc, i, w = sjcl.bitArray, xor = w._xor4, ctr, l = data.length, bl = w.bitLength(data), n = l / 50, p = n;
        ctr = w.concat([w.partial(8, L - 1)], iv).concat([0, 0, 0]).slice(0, 4);
        tag = w.bitSlice(xor(tag, prf.encrypt(ctr)), 0, tlen);
        if (!l) {
          return { tag, data: [] };
        }
        for (i = 0; i < l; i += 4) {
          if (i > n) {
            sjcl.mode.ccm._callProgressListener(i / l);
            n += p;
          }
          ctr[3]++;
          enc = prf.encrypt(ctr);
          data[i] ^= enc[0];
          data[i + 1] ^= enc[1];
          data[i + 2] ^= enc[2];
          data[i + 3] ^= enc[3];
        }
        return { tag, data: w.clamp(data, bl) };
      }
    };
    sjcl.misc.hmac = function(key, Hash) {
      this._hash = Hash = Hash || sjcl.hash.sha256;
      var exKey = [[], []], i, bs = Hash.prototype.blockSize / 32;
      this._baseHash = [new Hash(), new Hash()];
      if (key.length > bs) {
        key = Hash.hash(key);
      }
      for (i = 0; i < bs; i++) {
        exKey[0][i] = key[i] ^ 909522486;
        exKey[1][i] = key[i] ^ 1549556828;
      }
      this._baseHash[0].update(exKey[0]);
      this._baseHash[1].update(exKey[1]);
      this._resultHash = new Hash(this._baseHash[0]);
    };
    sjcl.misc.hmac.prototype.encrypt = sjcl.misc.hmac.prototype.mac = function(data) {
      if (!this._updated) {
        this.update(data);
        return this.digest(data);
      } else {
        throw new sjcl.exception.invalid("encrypt on already updated hmac called!");
      }
    };
    sjcl.misc.hmac.prototype.reset = function() {
      this._resultHash = new this._hash(this._baseHash[0]);
      this._updated = false;
    };
    sjcl.misc.hmac.prototype.update = function(data) {
      this._updated = true;
      this._resultHash.update(data);
    };
    sjcl.misc.hmac.prototype.digest = function() {
      var w = this._resultHash.finalize(), result = new this._hash(this._baseHash[1]).update(w).finalize();
      this.reset();
      return result;
    };
    sjcl.misc.pbkdf2 = function(password, salt, count, length, Prff) {
      count = count || 1e4;
      if (length < 0 || count < 0) {
        throw new sjcl.exception.invalid("invalid params to pbkdf2");
      }
      if (typeof password === "string") {
        password = sjcl.codec.utf8String.toBits(password);
      }
      if (typeof salt === "string") {
        salt = sjcl.codec.utf8String.toBits(salt);
      }
      Prff = Prff || sjcl.misc.hmac;
      var prf = new Prff(password), u, ui, i, j2, k, out = [], b = sjcl.bitArray;
      for (k = 1; 32 * out.length < (length || 1); k++) {
        u = ui = prf.encrypt(b.concat(salt, [k]));
        for (i = 1; i < count; i++) {
          ui = prf.encrypt(ui);
          for (j2 = 0; j2 < ui.length; j2++) {
            u[j2] ^= ui[j2];
          }
        }
        out = out.concat(u);
      }
      if (length) {
        out = b.clamp(out, length);
      }
      return out;
    };
    sjcl.prng = function(defaultParanoia) {
      this._pools = [new sjcl.hash.sha256()];
      this._poolEntropy = [0];
      this._reseedCount = 0;
      this._robins = {};
      this._eventId = 0;
      this._collectorIds = {};
      this._collectorIdNext = 0;
      this._strength = 0;
      this._poolStrength = 0;
      this._nextReseed = 0;
      this._key = [0, 0, 0, 0, 0, 0, 0, 0];
      this._counter = [0, 0, 0, 0];
      this._cipher = void 0;
      this._defaultParanoia = defaultParanoia;
      this._collectorsStarted = false;
      this._callbacks = { progress: {}, seeded: {} };
      this._callbackI = 0;
      this._NOT_READY = 0;
      this._READY = 1;
      this._REQUIRES_RESEED = 2;
      this._MAX_WORDS_PER_BURST = 65536;
      this._PARANOIA_LEVELS = [0, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024];
      this._MILLISECONDS_PER_RESEED = 3e4;
      this._BITS_PER_RESEED = 80;
    };
    sjcl.prng.prototype = {
      /** Generate several random words, and return them in an array.
       * A word consists of 32 bits (4 bytes)
       * @param {Number} nwords The number of words to generate.
       */
      randomWords: function(nwords, paranoia) {
        var out = [], i, readiness = this.isReady(paranoia), g;
        if (readiness === this._NOT_READY) {
          throw new sjcl.exception.notReady("generator isn't seeded");
        } else if (readiness & this._REQUIRES_RESEED) {
          this._reseedFromPools(!(readiness & this._READY));
        }
        for (i = 0; i < nwords; i += 4) {
          if ((i + 1) % this._MAX_WORDS_PER_BURST === 0) {
            this._gate();
          }
          g = this._gen4words();
          out.push(g[0], g[1], g[2], g[3]);
        }
        this._gate();
        return out.slice(0, nwords);
      },
      setDefaultParanoia: function(paranoia, allowZeroParanoia) {
        if (paranoia === 0 && allowZeroParanoia !== "Setting paranoia=0 will ruin your security; use it only for testing") {
          throw new sjcl.exception.invalid("Setting paranoia=0 will ruin your security; use it only for testing");
        }
        this._defaultParanoia = paranoia;
      },
      /**
       * Add entropy to the pools.
       * @param data The entropic value.  Should be a 32-bit integer, array of 32-bit integers, or string
       * @param {Number} estimatedEntropy The estimated entropy of data, in bits
       * @param {String} source The source of the entropy, eg "mouse"
       */
      addEntropy: function(data, estimatedEntropy, source) {
        source = source || "user";
        var id, i, tmp, t = (/* @__PURE__ */ new Date()).valueOf(), robin = this._robins[source], oldReady = this.isReady(), err = 0, objName;
        id = this._collectorIds[source];
        if (id === void 0) {
          id = this._collectorIds[source] = this._collectorIdNext++;
        }
        if (robin === void 0) {
          robin = this._robins[source] = 0;
        }
        this._robins[source] = (this._robins[source] + 1) % this._pools.length;
        switch (typeof data) {
          case "number":
            if (estimatedEntropy === void 0) {
              estimatedEntropy = 1;
            }
            this._pools[robin].update([id, this._eventId++, 1, estimatedEntropy, t, 1, data | 0]);
            break;
          case "object":
            objName = Object.prototype.toString.call(data);
            if (objName === "[object Uint32Array]") {
              tmp = [];
              for (i = 0; i < data.length; i++) {
                tmp.push(data[i]);
              }
              data = tmp;
            } else {
              if (objName !== "[object Array]") {
                err = 1;
              }
              for (i = 0; i < data.length && !err; i++) {
                if (typeof data[i] !== "number") {
                  err = 1;
                }
              }
            }
            if (!err) {
              if (estimatedEntropy === void 0) {
                estimatedEntropy = 0;
                for (i = 0; i < data.length; i++) {
                  tmp = data[i];
                  while (tmp > 0) {
                    estimatedEntropy++;
                    tmp = tmp >>> 1;
                  }
                }
              }
              this._pools[robin].update([id, this._eventId++, 2, estimatedEntropy, t, data.length].concat(data));
            }
            break;
          case "string":
            if (estimatedEntropy === void 0) {
              estimatedEntropy = data.length;
            }
            this._pools[robin].update([id, this._eventId++, 3, estimatedEntropy, t, data.length]);
            this._pools[robin].update(data);
            break;
          default:
            err = 1;
        }
        if (err) {
          throw new sjcl.exception.bug("random: addEntropy only supports number, array of numbers or string");
        }
        this._poolEntropy[robin] += estimatedEntropy;
        this._poolStrength += estimatedEntropy;
        if (oldReady === this._NOT_READY) {
          if (this.isReady() !== this._NOT_READY) {
            this._fireEvent("seeded", Math.max(this._strength, this._poolStrength));
          }
          this._fireEvent("progress", this.getProgress());
        }
      },
      /** Is the generator ready? */
      isReady: function(paranoia) {
        var entropyRequired = this._PARANOIA_LEVELS[paranoia !== void 0 ? paranoia : this._defaultParanoia];
        if (this._strength && this._strength >= entropyRequired) {
          return this._poolEntropy[0] > this._BITS_PER_RESEED && (/* @__PURE__ */ new Date()).valueOf() > this._nextReseed ? this._REQUIRES_RESEED | this._READY : this._READY;
        } else {
          return this._poolStrength >= entropyRequired ? this._REQUIRES_RESEED | this._NOT_READY : this._NOT_READY;
        }
      },
      /** Get the generator's progress toward readiness, as a fraction */
      getProgress: function(paranoia) {
        var entropyRequired = this._PARANOIA_LEVELS[paranoia ? paranoia : this._defaultParanoia];
        if (this._strength >= entropyRequired) {
          return 1;
        } else {
          return this._poolStrength > entropyRequired ? 1 : this._poolStrength / entropyRequired;
        }
      },
      /** start the built-in entropy collectors */
      startCollectors: function() {
        if (this._collectorsStarted) {
          return;
        }
        this._eventListener = {
          loadTimeCollector: this._bind(this._loadTimeCollector),
          mouseCollector: this._bind(this._mouseCollector),
          keyboardCollector: this._bind(this._keyboardCollector),
          accelerometerCollector: this._bind(this._accelerometerCollector),
          touchCollector: this._bind(this._touchCollector)
        };
        if (window.addEventListener) {
          window.addEventListener("load", this._eventListener.loadTimeCollector, false);
          window.addEventListener("mousemove", this._eventListener.mouseCollector, false);
          window.addEventListener("keypress", this._eventListener.keyboardCollector, false);
          window.addEventListener("devicemotion", this._eventListener.accelerometerCollector, false);
          window.addEventListener("touchmove", this._eventListener.touchCollector, false);
        } else if (document.attachEvent) {
          document.attachEvent("onload", this._eventListener.loadTimeCollector);
          document.attachEvent("onmousemove", this._eventListener.mouseCollector);
          document.attachEvent("keypress", this._eventListener.keyboardCollector);
        } else {
          throw new sjcl.exception.bug("can't attach event");
        }
        this._collectorsStarted = true;
      },
      /** stop the built-in entropy collectors */
      stopCollectors: function() {
        if (!this._collectorsStarted) {
          return;
        }
        if (window.removeEventListener) {
          window.removeEventListener("load", this._eventListener.loadTimeCollector, false);
          window.removeEventListener("mousemove", this._eventListener.mouseCollector, false);
          window.removeEventListener("keypress", this._eventListener.keyboardCollector, false);
          window.removeEventListener("devicemotion", this._eventListener.accelerometerCollector, false);
          window.removeEventListener("touchmove", this._eventListener.touchCollector, false);
        } else if (document.detachEvent) {
          document.detachEvent("onload", this._eventListener.loadTimeCollector);
          document.detachEvent("onmousemove", this._eventListener.mouseCollector);
          document.detachEvent("keypress", this._eventListener.keyboardCollector);
        }
        this._collectorsStarted = false;
      },
      /* use a cookie to store entropy.
      useCookie: function (all_cookies) {
          throw new sjcl.exception.bug("random: useCookie is unimplemented");
      },*/
      /** add an event listener for progress or seeded-ness. */
      addEventListener: function(name, callback) {
        this._callbacks[name][this._callbackI++] = callback;
      },
      /** remove an event listener for progress or seeded-ness */
      removeEventListener: function(name, cb) {
        var i, j2, cbs = this._callbacks[name], jsTemp = [];
        for (j2 in cbs) {
          if (cbs.hasOwnProperty(j2) && cbs[j2] === cb) {
            jsTemp.push(j2);
          }
        }
        for (i = 0; i < jsTemp.length; i++) {
          j2 = jsTemp[i];
          delete cbs[j2];
        }
      },
      _bind: function(func) {
        var that = this;
        return function() {
          func.apply(that, arguments);
        };
      },
      /** Generate 4 random words, no reseed, no gate.
       * @private
       */
      _gen4words: function() {
        for (var i = 0; i < 4; i++) {
          this._counter[i] = this._counter[i] + 1 | 0;
          if (this._counter[i]) {
            break;
          }
        }
        return this._cipher.encrypt(this._counter);
      },
      /* Rekey the AES instance with itself after a request, or every _MAX_WORDS_PER_BURST words.
       * @private
       */
      _gate: function() {
        this._key = this._gen4words().concat(this._gen4words());
        this._cipher = new sjcl.cipher.aes(this._key);
      },
      /** Reseed the generator with the given words
       * @private
       */
      _reseed: function(seedWords) {
        this._key = sjcl.hash.sha256.hash(this._key.concat(seedWords));
        this._cipher = new sjcl.cipher.aes(this._key);
        for (var i = 0; i < 4; i++) {
          this._counter[i] = this._counter[i] + 1 | 0;
          if (this._counter[i]) {
            break;
          }
        }
      },
      /** reseed the data from the entropy pools
       * @param full If set, use all the entropy pools in the reseed.
       */
      _reseedFromPools: function(full) {
        var reseedData = [], strength = 0, i;
        this._nextReseed = reseedData[0] = (/* @__PURE__ */ new Date()).valueOf() + this._MILLISECONDS_PER_RESEED;
        for (i = 0; i < 16; i++) {
          reseedData.push(Math.random() * 4294967296 | 0);
        }
        for (i = 0; i < this._pools.length; i++) {
          reseedData = reseedData.concat(this._pools[i].finalize());
          strength += this._poolEntropy[i];
          this._poolEntropy[i] = 0;
          if (!full && this._reseedCount & 1 << i) {
            break;
          }
        }
        if (this._reseedCount >= 1 << this._pools.length) {
          this._pools.push(new sjcl.hash.sha256());
          this._poolEntropy.push(0);
        }
        this._poolStrength -= strength;
        if (strength > this._strength) {
          this._strength = strength;
        }
        this._reseedCount++;
        this._reseed(reseedData);
      },
      _keyboardCollector: function() {
        this._addCurrentTimeToEntropy(1);
      },
      _mouseCollector: function(ev) {
        var x, y;
        try {
          x = ev.x || ev.clientX || ev.offsetX || 0;
          y = ev.y || ev.clientY || ev.offsetY || 0;
        } catch (err) {
          x = 0;
          y = 0;
        }
        if (x != 0 && y != 0) {
          this.addEntropy([x, y], 2, "mouse");
        }
        this._addCurrentTimeToEntropy(0);
      },
      _touchCollector: function(ev) {
        var touch = ev.touches[0] || ev.changedTouches[0];
        var x = touch.pageX || touch.clientX, y = touch.pageY || touch.clientY;
        this.addEntropy([x, y], 1, "touch");
        this._addCurrentTimeToEntropy(0);
      },
      _loadTimeCollector: function() {
        this._addCurrentTimeToEntropy(2);
      },
      _addCurrentTimeToEntropy: function(estimatedEntropy) {
        if (typeof window !== "undefined" && window.performance && typeof window.performance.now === "function") {
          this.addEntropy(window.performance.now(), estimatedEntropy, "loadtime");
        } else {
          this.addEntropy((/* @__PURE__ */ new Date()).valueOf(), estimatedEntropy, "loadtime");
        }
      },
      _accelerometerCollector: function(ev) {
        var ac = ev.accelerationIncludingGravity.x || ev.accelerationIncludingGravity.y || ev.accelerationIncludingGravity.z;
        if (window.orientation) {
          var or = window.orientation;
          if (typeof or === "number") {
            this.addEntropy(or, 1, "accelerometer");
          }
        }
        if (ac) {
          this.addEntropy(ac, 2, "accelerometer");
        }
        this._addCurrentTimeToEntropy(0);
      },
      _fireEvent: function(name, arg) {
        var j2, cbs = sjcl.random._callbacks[name], cbsTemp = [];
        for (j2 in cbs) {
          if (cbs.hasOwnProperty(j2)) {
            cbsTemp.push(cbs[j2]);
          }
        }
        for (j2 = 0; j2 < cbsTemp.length; j2++) {
          cbsTemp[j2](arg);
        }
      }
    };
    sjcl.random = new sjcl.prng(6);
    (function() {
      function getCryptoModule() {
        try {
          return __require("crypto");
        } catch (e) {
          return null;
        }
      }
      try {
        var buf, crypt, ab;
        if (typeof module !== "undefined" && module.exports && (crypt = getCryptoModule()) && crypt.randomBytes) {
          buf = crypt.randomBytes(1024 / 8);
          buf = new Uint32Array(new Uint8Array(buf).buffer);
          sjcl.random.addEntropy(buf, 1024, "crypto.randomBytes");
        } else if (typeof window !== "undefined" && typeof Uint32Array !== "undefined") {
          ab = new Uint32Array(32);
          if (window.crypto && window.crypto.getRandomValues) {
            window.crypto.getRandomValues(ab);
          } else if (window.msCrypto && window.msCrypto.getRandomValues) {
            window.msCrypto.getRandomValues(ab);
          } else {
            return;
          }
          sjcl.random.addEntropy(ab, 1024, "crypto.getRandomValues");
        } else {
        }
      } catch (e) {
        if (typeof window !== "undefined" && window.console) {
          console.log("There was an error collecting entropy from the browser:");
          console.log(e);
        }
      }
    })();
    sjcl.json = {
      /** Default values for encryption */
      defaults: { v: 1, iter: 1e4, ks: 128, ts: 64, mode: "ccm", adata: "", cipher: "aes" },
      /** Simple encryption function.
       * @param {String|bitArray} password The password or key.
       * @param {String} plaintext The data to encrypt.
       * @param {Object} [params] The parameters including tag, iv and salt.
       * @param {Object} [rp] A returned version with filled-in parameters.
       * @return {Object} The cipher raw data.
       * @throws {sjcl.exception.invalid} if a parameter is invalid.
       */
      _encrypt: function(password, plaintext, params, rp) {
        params = params || {};
        rp = rp || {};
        var j2 = sjcl.json, p = j2._add({ iv: sjcl.random.randomWords(4, 0) }, j2.defaults), tmp, prp, adata;
        j2._add(p, params);
        adata = p.adata;
        if (typeof p.salt === "string") {
          p.salt = sjcl.codec.base64.toBits(p.salt);
        }
        if (typeof p.iv === "string") {
          p.iv = sjcl.codec.base64.toBits(p.iv);
        }
        if (!sjcl.mode[p.mode] || !sjcl.cipher[p.cipher] || typeof password === "string" && p.iter <= 100 || p.ts !== 64 && p.ts !== 96 && p.ts !== 128 || p.ks !== 128 && p.ks !== 192 && p.ks !== 256 || (p.iv.length < 2 || p.iv.length > 4)) {
          throw new sjcl.exception.invalid("json encrypt: invalid parameters");
        }
        if (typeof password === "string") {
          tmp = sjcl.misc.cachedPbkdf2(password, p);
          password = tmp.key.slice(0, p.ks / 32);
          p.salt = tmp.salt;
        } else if (sjcl.ecc && password instanceof sjcl.ecc.elGamal.publicKey) {
          tmp = password.kem();
          p.kemtag = tmp.tag;
          password = tmp.key.slice(0, p.ks / 32);
        }
        if (typeof plaintext === "string") {
          plaintext = sjcl.codec.utf8String.toBits(plaintext);
        }
        if (typeof adata === "string") {
          p.adata = adata = sjcl.codec.utf8String.toBits(adata);
        }
        prp = new sjcl.cipher[p.cipher](password);
        j2._add(rp, p);
        rp.key = password;
        if (p.mode === "ccm" && sjcl.arrayBuffer && sjcl.arrayBuffer.ccm && plaintext instanceof ArrayBuffer) {
          p.ct = sjcl.arrayBuffer.ccm.encrypt(prp, plaintext, p.iv, adata, p.ts);
        } else {
          p.ct = sjcl.mode[p.mode].encrypt(prp, plaintext, p.iv, adata, p.ts);
        }
        return p;
      },
      /** Simple encryption function.
       * @param {String|bitArray} password The password or key.
       * @param {String} plaintext The data to encrypt.
       * @param {Object} [params] The parameters including tag, iv and salt.
       * @param {Object} [rp] A returned version with filled-in parameters.
       * @return {String} The ciphertext serialized data.
       * @throws {sjcl.exception.invalid} if a parameter is invalid.
       */
      encrypt: function(password, plaintext, params, rp) {
        var j2 = sjcl.json, p = j2._encrypt.apply(j2, arguments);
        return j2.encode(p);
      },
      /** Simple decryption function.
       * @param {String|bitArray} password The password or key.
       * @param {Object} ciphertext The cipher raw data to decrypt.
       * @param {Object} [params] Additional non-default parameters.
       * @param {Object} [rp] A returned object with filled parameters.
       * @return {String} The plaintext.
       * @throws {sjcl.exception.invalid} if a parameter is invalid.
       * @throws {sjcl.exception.corrupt} if the ciphertext is corrupt.
       */
      _decrypt: function(password, ciphertext, params, rp) {
        params = params || {};
        rp = rp || {};
        var j2 = sjcl.json, p = j2._add(j2._add(j2._add({}, j2.defaults), ciphertext), params, true), ct, tmp, prp, adata = p.adata;
        if (typeof p.salt === "string") {
          p.salt = sjcl.codec.base64.toBits(p.salt);
        }
        if (typeof p.iv === "string") {
          p.iv = sjcl.codec.base64.toBits(p.iv);
        }
        if (!sjcl.mode[p.mode] || !sjcl.cipher[p.cipher] || typeof password === "string" && p.iter <= 100 || p.ts !== 64 && p.ts !== 96 && p.ts !== 128 || p.ks !== 128 && p.ks !== 192 && p.ks !== 256 || !p.iv || (p.iv.length < 2 || p.iv.length > 4)) {
          throw new sjcl.exception.invalid("json decrypt: invalid parameters");
        }
        if (typeof password === "string") {
          tmp = sjcl.misc.cachedPbkdf2(password, p);
          password = tmp.key.slice(0, p.ks / 32);
          p.salt = tmp.salt;
        } else if (sjcl.ecc && password instanceof sjcl.ecc.elGamal.secretKey) {
          password = password.unkem(sjcl.codec.base64.toBits(p.kemtag)).slice(0, p.ks / 32);
        }
        if (typeof adata === "string") {
          adata = sjcl.codec.utf8String.toBits(adata);
        }
        prp = new sjcl.cipher[p.cipher](password);
        if (p.mode === "ccm" && sjcl.arrayBuffer && sjcl.arrayBuffer.ccm && p.ct instanceof ArrayBuffer) {
          ct = sjcl.arrayBuffer.ccm.decrypt(prp, p.ct, p.iv, p.tag, adata, p.ts);
        } else {
          ct = sjcl.mode[p.mode].decrypt(prp, p.ct, p.iv, adata, p.ts);
        }
        j2._add(rp, p);
        rp.key = password;
        if (params.raw === 1) {
          return ct;
        } else {
          return sjcl.codec.utf8String.fromBits(ct);
        }
      },
      /** Simple decryption function.
       * @param {String|bitArray} password The password or key.
       * @param {String} ciphertext The ciphertext to decrypt.
       * @param {Object} [params] Additional non-default parameters.
       * @param {Object} [rp] A returned object with filled parameters.
       * @return {String} The plaintext.
       * @throws {sjcl.exception.invalid} if a parameter is invalid.
       * @throws {sjcl.exception.corrupt} if the ciphertext is corrupt.
       */
      decrypt: function(password, ciphertext, params, rp) {
        var j2 = sjcl.json;
        return j2._decrypt(password, j2.decode(ciphertext), params, rp);
      },
      /** Encode a flat structure into a JSON string.
       * @param {Object} obj The structure to encode.
       * @return {String} A JSON string.
       * @throws {sjcl.exception.invalid} if obj has a non-alphanumeric property.
       * @throws {sjcl.exception.bug} if a parameter has an unsupported type.
       */
      encode: function(obj) {
        var i, out = "{", comma = "";
        for (i in obj) {
          if (obj.hasOwnProperty(i)) {
            if (!i.match(/^[a-z0-9]+$/i)) {
              throw new sjcl.exception.invalid("json encode: invalid property name");
            }
            out += comma + '"' + i + '":';
            comma = ",";
            switch (typeof obj[i]) {
              case "number":
              case "boolean":
                out += obj[i];
                break;
              case "string":
                out += '"' + escape(obj[i]) + '"';
                break;
              case "object":
                out += '"' + sjcl.codec.base64.fromBits(obj[i], 0) + '"';
                break;
              default:
                throw new sjcl.exception.bug("json encode: unsupported type");
            }
          }
        }
        return out + "}";
      },
      /** Decode a simple (flat) JSON string into a structure.  The ciphertext,
       * adata, salt and iv will be base64-decoded.
       * @param {String} str The string.
       * @return {Object} The decoded structure.
       * @throws {sjcl.exception.invalid} if str isn't (simple) JSON.
       */
      decode: function(str) {
        str = str.replace(/\s/g, "");
        if (!str.match(/^\{.*\}$/)) {
          throw new sjcl.exception.invalid("json decode: this isn't json!");
        }
        var a = str.replace(/^\{|\}$/g, "").split(/,/), out = {}, i, m;
        for (i = 0; i < a.length; i++) {
          if (!(m = a[i].match(/^\s*(?:(["']?)([a-z][a-z0-9]*)\1)\s*:\s*(?:(-?\d+)|"([a-z0-9+\/%*_.@=\-]*)"|(true|false))$/i))) {
            throw new sjcl.exception.invalid("json decode: this isn't json!");
          }
          if (m[3] != null) {
            out[m[2]] = parseInt(m[3], 10);
          } else if (m[4] != null) {
            out[m[2]] = m[2].match(/^(ct|adata|salt|iv)$/) ? sjcl.codec.base64.toBits(m[4]) : unescape(m[4]);
          } else if (m[5] != null) {
            out[m[2]] = m[5] === "true";
          }
        }
        return out;
      },
      /** Insert all elements of src into target, modifying and returning target.
       * @param {Object} target The object to be modified.
       * @param {Object} src The object to pull data from.
       * @param {boolean} [requireSame=false] If true, throw an exception if any field of target differs from corresponding field of src.
       * @return {Object} target.
       * @private
       */
      _add: function(target, src, requireSame) {
        if (target === void 0) {
          target = {};
        }
        if (src === void 0) {
          return target;
        }
        var i;
        for (i in src) {
          if (src.hasOwnProperty(i)) {
            if (requireSame && target[i] !== void 0 && target[i] !== src[i]) {
              throw new sjcl.exception.invalid("required parameter overridden");
            }
            target[i] = src[i];
          }
        }
        return target;
      },
      /** Remove all elements of minus from plus.  Does not modify plus.
       * @private
       */
      _subtract: function(plus, minus) {
        var out = {}, i;
        for (i in plus) {
          if (plus.hasOwnProperty(i) && plus[i] !== minus[i]) {
            out[i] = plus[i];
          }
        }
        return out;
      },
      /** Return only the specified elements of src.
       * @private
       */
      _filter: function(src, filter) {
        var out = {}, i;
        for (i = 0; i < filter.length; i++) {
          if (src[filter[i]] !== void 0) {
            out[filter[i]] = src[filter[i]];
          }
        }
        return out;
      }
    };
    sjcl.encrypt = sjcl.json.encrypt;
    sjcl.decrypt = sjcl.json.decrypt;
    sjcl.misc._pbkdf2Cache = {};
    sjcl.misc.cachedPbkdf2 = function(password, obj) {
      var cache = sjcl.misc._pbkdf2Cache, c, cp, str, salt, iter;
      obj = obj || {};
      iter = obj.iter || 1e3;
      cp = cache[password] = cache[password] || {};
      c = cp[iter] = cp[iter] || { firstSalt: obj.salt && obj.salt.length ? obj.salt.slice(0) : sjcl.random.randomWords(2, 0) };
      salt = obj.salt === void 0 ? c.firstSalt : obj.salt;
      c[salt] = c[salt] || sjcl.misc.pbkdf2(password, salt, obj.iter);
      return { key: c[salt].slice(0), salt: salt.slice(0) };
    };
    sjcl.bn = function(it) {
      this.initWith(it);
    };
    sjcl.bn.prototype = {
      radix: 24,
      maxMul: 8,
      _class: sjcl.bn,
      copy: function() {
        return new this._class(this);
      },
      /**
       * Initializes this with it, either as a bn, a number, or a hex string.
       */
      initWith: function(it) {
        var i = 0, k;
        switch (typeof it) {
          case "object":
            this.limbs = it.limbs.slice(0);
            break;
          case "number":
            this.limbs = [it];
            this.normalize();
            break;
          case "string":
            it = it.replace(/^0x/, "");
            this.limbs = [];
            k = this.radix / 4;
            for (i = 0; i < it.length; i += k) {
              this.limbs.push(parseInt(it.substring(Math.max(it.length - i - k, 0), it.length - i), 16));
            }
            break;
          default:
            this.limbs = [0];
        }
        return this;
      },
      /**
       * Returns true if "this" and "that" are equal.  Calls fullReduce().
       * Equality test is in constant time.
       */
      equals: function(that) {
        if (typeof that === "number") {
          that = new this._class(that);
        }
        var difference = 0, i;
        this.fullReduce();
        that.fullReduce();
        for (i = 0; i < this.limbs.length || i < that.limbs.length; i++) {
          difference |= this.getLimb(i) ^ that.getLimb(i);
        }
        return difference === 0;
      },
      /**
       * Get the i'th limb of this, zero if i is too large.
       */
      getLimb: function(i) {
        return i >= this.limbs.length ? 0 : this.limbs[i];
      },
      /**
       * Constant time comparison function.
       * Returns 1 if this >= that, or zero otherwise.
       */
      greaterEquals: function(that) {
        if (typeof that === "number") {
          that = new this._class(that);
        }
        var less = 0, greater = 0, i, a, b;
        i = Math.max(this.limbs.length, that.limbs.length) - 1;
        for (; i >= 0; i--) {
          a = this.getLimb(i);
          b = that.getLimb(i);
          greater |= b - a & ~less;
          less |= a - b & ~greater;
        }
        return (greater | ~less) >>> 31;
      },
      /**
       * Convert to a hex string.
       */
      toString: function() {
        this.fullReduce();
        var out = "", i, s, l = this.limbs;
        for (i = 0; i < this.limbs.length; i++) {
          s = l[i].toString(16);
          while (i < this.limbs.length - 1 && s.length < 6) {
            s = "0" + s;
          }
          out = s + out;
        }
        return "0x" + out;
      },
      /** this += that.  Does not normalize. */
      addM: function(that) {
        if (typeof that !== "object") {
          that = new this._class(that);
        }
        var i, l = this.limbs, ll = that.limbs;
        for (i = l.length; i < ll.length; i++) {
          l[i] = 0;
        }
        for (i = 0; i < ll.length; i++) {
          l[i] += ll[i];
        }
        return this;
      },
      /** this *= 2.  Requires normalized; ends up normalized. */
      doubleM: function() {
        var i, carry = 0, tmp, r = this.radix, m = this.radixMask, l = this.limbs;
        for (i = 0; i < l.length; i++) {
          tmp = l[i];
          tmp = tmp + tmp + carry;
          l[i] = tmp & m;
          carry = tmp >> r;
        }
        if (carry) {
          l.push(carry);
        }
        return this;
      },
      /** this /= 2, rounded down.  Requires normalized; ends up normalized. */
      halveM: function() {
        var i, carry = 0, tmp, r = this.radix, l = this.limbs;
        for (i = l.length - 1; i >= 0; i--) {
          tmp = l[i];
          l[i] = tmp + carry >> 1;
          carry = (tmp & 1) << r;
        }
        if (!l[l.length - 1]) {
          l.pop();
        }
        return this;
      },
      /** this -= that.  Does not normalize. */
      subM: function(that) {
        if (typeof that !== "object") {
          that = new this._class(that);
        }
        var i, l = this.limbs, ll = that.limbs;
        for (i = l.length; i < ll.length; i++) {
          l[i] = 0;
        }
        for (i = 0; i < ll.length; i++) {
          l[i] -= ll[i];
        }
        return this;
      },
      mod: function(that) {
        var neg = !this.greaterEquals(new sjcl.bn(0));
        that = new sjcl.bn(that).normalize();
        var out = new sjcl.bn(this).normalize(), ci = 0;
        if (neg)
          out = new sjcl.bn(0).subM(out).normalize();
        for (; out.greaterEquals(that); ci++) {
          that.doubleM();
        }
        if (neg)
          out = that.sub(out).normalize();
        for (; ci > 0; ci--) {
          that.halveM();
          if (out.greaterEquals(that)) {
            out.subM(that).normalize();
          }
        }
        return out.trim();
      },
      /** return inverse mod prime p.  p must be odd. Binary extended Euclidean algorithm mod p. */
      inverseMod: function(p) {
        var a = new sjcl.bn(1), b = new sjcl.bn(0), x = new sjcl.bn(this), y = new sjcl.bn(p), tmp, i, nz = 1;
        if (!(p.limbs[0] & 1)) {
          throw new sjcl.exception.invalid("inverseMod: p must be odd");
        }
        do {
          if (x.limbs[0] & 1) {
            if (!x.greaterEquals(y)) {
              tmp = x;
              x = y;
              y = tmp;
              tmp = a;
              a = b;
              b = tmp;
            }
            x.subM(y);
            x.normalize();
            if (!a.greaterEquals(b)) {
              a.addM(p);
            }
            a.subM(b);
          }
          x.halveM();
          if (a.limbs[0] & 1) {
            a.addM(p);
          }
          a.normalize();
          a.halveM();
          for (i = nz = 0; i < x.limbs.length; i++) {
            nz |= x.limbs[i];
          }
        } while (nz);
        if (!y.equals(1)) {
          throw new sjcl.exception.invalid("inverseMod: p and x must be relatively prime");
        }
        return b;
      },
      /** this + that.  Does not normalize. */
      add: function(that) {
        return this.copy().addM(that);
      },
      /** this - that.  Does not normalize. */
      sub: function(that) {
        return this.copy().subM(that);
      },
      /** this * that.  Normalizes and reduces. */
      mul: function(that) {
        if (typeof that === "number") {
          that = new this._class(that);
        } else {
          that.normalize();
        }
        this.normalize();
        var i, j2, a = this.limbs, b = that.limbs, al = a.length, bl = b.length, out = new this._class(), c = out.limbs, ai, ii = this.maxMul;
        for (i = 0; i < this.limbs.length + that.limbs.length + 1; i++) {
          c[i] = 0;
        }
        for (i = 0; i < al; i++) {
          ai = a[i];
          for (j2 = 0; j2 < bl; j2++) {
            c[i + j2] += ai * b[j2];
          }
          if (!--ii) {
            ii = this.maxMul;
            out.cnormalize();
          }
        }
        return out.cnormalize().reduce();
      },
      /** this ^ 2.  Normalizes and reduces. */
      square: function() {
        return this.mul(this);
      },
      /** this ^ n.  Uses square-and-multiply.  Normalizes and reduces. */
      power: function(l) {
        l = new sjcl.bn(l).normalize().trim().limbs;
        var i, j2, out = new this._class(1), pow = this;
        for (i = 0; i < l.length; i++) {
          for (j2 = 0; j2 < this.radix; j2++) {
            if (l[i] & 1 << j2) {
              out = out.mul(pow);
            }
            if (i == l.length - 1 && l[i] >> j2 + 1 == 0) {
              break;
            }
            pow = pow.square();
          }
        }
        return out;
      },
      /** this * that mod N */
      mulmod: function(that, N) {
        return this.mod(N).mul(that.mod(N)).mod(N);
      },
      /** this ^ x mod N */
      powermod: function(x, N) {
        x = new sjcl.bn(x);
        N = new sjcl.bn(N);
        if ((N.limbs[0] & 1) == 1) {
          var montOut = this.montpowermod(x, N);
          if (montOut != false) {
            return montOut;
          }
        }
        var i, j2, l = x.normalize().trim().limbs, out = new this._class(1), pow = this;
        for (i = 0; i < l.length; i++) {
          for (j2 = 0; j2 < this.radix; j2++) {
            if (l[i] & 1 << j2) {
              out = out.mulmod(pow, N);
            }
            if (i == l.length - 1 && l[i] >> j2 + 1 == 0) {
              break;
            }
            pow = pow.mulmod(pow, N);
          }
        }
        return out;
      },
      /** this ^ x mod N with Montomery reduction */
      montpowermod: function(x, N) {
        x = new sjcl.bn(x).normalize().trim();
        N = new sjcl.bn(N);
        var i, j2, radix = this.radix, out = new this._class(1), pow = this.copy();
        var R, s, wind, bitsize = x.bitLength();
        R = new sjcl.bn({
          limbs: N.copy().normalize().trim().limbs.map(function() {
            return 0;
          })
        });
        for (s = this.radix; s > 0; s--) {
          if ((N.limbs[N.limbs.length - 1] >> s & 1) == 1) {
            R.limbs[R.limbs.length - 1] = 1 << s;
            break;
          }
        }
        if (bitsize == 0) {
          return this;
        } else if (bitsize < 18) {
          wind = 1;
        } else if (bitsize < 48) {
          wind = 3;
        } else if (bitsize < 144) {
          wind = 4;
        } else if (bitsize < 768) {
          wind = 5;
        } else {
          wind = 6;
        }
        var RR = R.copy(), NN = N.copy(), RP = new sjcl.bn(1), NP = new sjcl.bn(0), RT = R.copy();
        while (RT.greaterEquals(1)) {
          RT.halveM();
          if ((RP.limbs[0] & 1) == 0) {
            RP.halveM();
            NP.halveM();
          } else {
            RP.addM(NN);
            RP.halveM();
            NP.halveM();
            NP.addM(RR);
          }
        }
        RP = RP.normalize();
        NP = NP.normalize();
        RR.doubleM();
        var R2 = RR.mulmod(RR, N);
        if (!RR.mul(RP).sub(N.mul(NP)).equals(1)) {
          return false;
        }
        var montIn = function(c) {
          return montMul(c, R2);
        }, montMul = function(a, b) {
          var k, ab, right, abBar, mask = (1 << s + 1) - 1;
          ab = a.mul(b);
          right = ab.mul(NP);
          right.limbs = right.limbs.slice(0, R.limbs.length);
          if (right.limbs.length == R.limbs.length) {
            right.limbs[R.limbs.length - 1] &= mask;
          }
          right = right.mul(N);
          abBar = ab.add(right).normalize().trim();
          abBar.limbs = abBar.limbs.slice(R.limbs.length - 1);
          for (k = 0; k < abBar.limbs.length; k++) {
            if (k > 0) {
              abBar.limbs[k - 1] |= (abBar.limbs[k] & mask) << radix - s - 1;
            }
            abBar.limbs[k] = abBar.limbs[k] >> s + 1;
          }
          if (abBar.greaterEquals(N)) {
            abBar.subM(N);
          }
          return abBar;
        }, montOut = function(c) {
          return montMul(c, 1);
        };
        pow = montIn(pow);
        out = montIn(out);
        var h, precomp = {}, cap = (1 << wind - 1) - 1;
        precomp[1] = pow.copy();
        precomp[2] = montMul(pow, pow);
        for (h = 1; h <= cap; h++) {
          precomp[2 * h + 1] = montMul(precomp[2 * h - 1], precomp[2]);
        }
        var getBit = function(exp, i2) {
          var off = i2 % exp.radix;
          return (exp.limbs[Math.floor(i2 / exp.radix)] & 1 << off) >> off;
        };
        for (i = x.bitLength() - 1; i >= 0; ) {
          if (getBit(x, i) == 0) {
            out = montMul(out, out);
            i = i - 1;
          } else {
            var l = i - wind + 1;
            while (getBit(x, l) == 0) {
              l++;
            }
            var indx = 0;
            for (j2 = l; j2 <= i; j2++) {
              indx += getBit(x, j2) << j2 - l;
              out = montMul(out, out);
            }
            out = montMul(out, precomp[indx]);
            i = l - 1;
          }
        }
        return montOut(out);
      },
      trim: function() {
        var l = this.limbs, p;
        do {
          p = l.pop();
        } while (l.length && p === 0);
        l.push(p);
        return this;
      },
      /** Reduce mod a modulus.  Stubbed for subclassing. */
      reduce: function() {
        return this;
      },
      /** Reduce and normalize. */
      fullReduce: function() {
        return this.normalize();
      },
      /** Propagate carries. */
      normalize: function() {
        var carry = 0, i, pv = this.placeVal, ipv = this.ipv, l, m, limbs = this.limbs, ll = limbs.length, mask = this.radixMask;
        for (i = 0; i < ll || carry !== 0 && carry !== -1; i++) {
          l = (limbs[i] || 0) + carry;
          m = limbs[i] = l & mask;
          carry = (l - m) * ipv;
        }
        if (carry === -1) {
          limbs[i - 1] -= pv;
        }
        this.trim();
        return this;
      },
      /** Constant-time normalize. Does not allocate additional space. */
      cnormalize: function() {
        var carry = 0, i, ipv = this.ipv, l, m, limbs = this.limbs, ll = limbs.length, mask = this.radixMask;
        for (i = 0; i < ll - 1; i++) {
          l = limbs[i] + carry;
          m = limbs[i] = l & mask;
          carry = (l - m) * ipv;
        }
        limbs[i] += carry;
        return this;
      },
      /** Serialize to a bit array */
      toBits: function(len) {
        this.fullReduce();
        len = len || this.exponent || this.bitLength();
        var i = Math.floor((len - 1) / 24), w = sjcl.bitArray, e = (len + 7 & -8) % this.radix || this.radix, out = [w.partial(e, this.getLimb(i))];
        for (i--; i >= 0; i--) {
          out = w.concat(out, [w.partial(Math.min(this.radix, len), this.getLimb(i))]);
          len -= this.radix;
        }
        return out;
      },
      /** Return the length in bits, rounded up to the nearest byte. */
      bitLength: function() {
        this.fullReduce();
        var out = this.radix * (this.limbs.length - 1), b = this.limbs[this.limbs.length - 1];
        for (; b; b >>>= 1) {
          out++;
        }
        return out + 7 & -8;
      }
    };
    sjcl.bn.fromBits = function(bits) {
      var Class = this, out = new Class(), words = [], w = sjcl.bitArray, t = this.prototype, l = Math.min(this.bitLength || 4294967296, w.bitLength(bits)), e = l % t.radix || t.radix;
      words[0] = w.extract(bits, 0, e);
      for (; e < l; e += t.radix) {
        words.unshift(w.extract(bits, e, t.radix));
      }
      out.limbs = words;
      return out;
    };
    sjcl.bn.prototype.ipv = 1 / (sjcl.bn.prototype.placeVal = Math.pow(2, sjcl.bn.prototype.radix));
    sjcl.bn.prototype.radixMask = (1 << sjcl.bn.prototype.radix) - 1;
    sjcl.bn.pseudoMersennePrime = function(exponent, coeff) {
      function p(it) {
        this.initWith(it);
      }
      var ppr = p.prototype = new sjcl.bn(), i, tmp, mo;
      mo = ppr.modOffset = Math.ceil(tmp = exponent / ppr.radix);
      ppr.exponent = exponent;
      ppr.offset = [];
      ppr.factor = [];
      ppr.minOffset = mo;
      ppr.fullMask = 0;
      ppr.fullOffset = [];
      ppr.fullFactor = [];
      ppr.modulus = p.modulus = new sjcl.bn(Math.pow(2, exponent));
      ppr.fullMask = 0 | -Math.pow(2, exponent % ppr.radix);
      for (i = 0; i < coeff.length; i++) {
        ppr.offset[i] = Math.floor(coeff[i][0] / ppr.radix - tmp);
        ppr.fullOffset[i] = Math.floor(coeff[i][0] / ppr.radix) - mo + 1;
        ppr.factor[i] = coeff[i][1] * Math.pow(1 / 2, exponent - coeff[i][0] + ppr.offset[i] * ppr.radix);
        ppr.fullFactor[i] = coeff[i][1] * Math.pow(1 / 2, exponent - coeff[i][0] + ppr.fullOffset[i] * ppr.radix);
        ppr.modulus.addM(new sjcl.bn(Math.pow(2, coeff[i][0]) * coeff[i][1]));
        ppr.minOffset = Math.min(ppr.minOffset, -ppr.offset[i]);
      }
      ppr._class = p;
      ppr.modulus.cnormalize();
      ppr.reduce = function() {
        var i2, k, l, mo2 = this.modOffset, limbs = this.limbs, off = this.offset, ol = this.offset.length, fac = this.factor, ll;
        i2 = this.minOffset;
        while (limbs.length > mo2) {
          l = limbs.pop();
          ll = limbs.length;
          for (k = 0; k < ol; k++) {
            limbs[ll + off[k]] -= fac[k] * l;
          }
          i2--;
          if (!i2) {
            limbs.push(0);
            this.cnormalize();
            i2 = this.minOffset;
          }
        }
        this.cnormalize();
        return this;
      };
      ppr._strongReduce = ppr.fullMask === -1 ? ppr.reduce : function() {
        var limbs = this.limbs, i2 = limbs.length - 1, k, l;
        this.reduce();
        if (i2 === this.modOffset - 1) {
          l = limbs[i2] & this.fullMask;
          limbs[i2] -= l;
          for (k = 0; k < this.fullOffset.length; k++) {
            limbs[i2 + this.fullOffset[k]] -= this.fullFactor[k] * l;
          }
          this.normalize();
        }
      };
      ppr.fullReduce = function() {
        var greater, i2;
        this._strongReduce();
        this.addM(this.modulus);
        this.addM(this.modulus);
        this.normalize();
        this._strongReduce();
        for (i2 = this.limbs.length; i2 < this.modOffset; i2++) {
          this.limbs[i2] = 0;
        }
        greater = this.greaterEquals(this.modulus);
        for (i2 = 0; i2 < this.limbs.length; i2++) {
          this.limbs[i2] -= this.modulus.limbs[i2] * greater;
        }
        this.cnormalize();
        return this;
      };
      ppr.inverse = function() {
        return this.power(this.modulus.sub(2));
      };
      p.fromBits = sjcl.bn.fromBits;
      return p;
    };
    var sbp = sjcl.bn.pseudoMersennePrime;
    sjcl.bn.prime = {
      p127: sbp(127, [[0, -1]]),
      // Bernstein's prime for Curve25519
      p25519: sbp(255, [[0, -19]]),
      // Koblitz primes
      p192k: sbp(192, [[32, -1], [12, -1], [8, -1], [7, -1], [6, -1], [3, -1], [0, -1]]),
      p224k: sbp(224, [[32, -1], [12, -1], [11, -1], [9, -1], [7, -1], [4, -1], [1, -1], [0, -1]]),
      p256k: sbp(256, [[32, -1], [9, -1], [8, -1], [7, -1], [6, -1], [4, -1], [0, -1]]),
      // NIST primes
      p192: sbp(192, [[0, -1], [64, -1]]),
      p224: sbp(224, [[0, 1], [96, -1]]),
      p256: sbp(256, [[0, -1], [96, 1], [192, 1], [224, -1]]),
      p384: sbp(384, [[0, -1], [32, 1], [96, -1], [128, -1]]),
      p521: sbp(521, [[0, -1]])
    };
    sjcl.bn.random = function(modulus, paranoia) {
      if (typeof modulus !== "object") {
        modulus = new sjcl.bn(modulus);
      }
      var words, i, l = modulus.limbs.length, m = modulus.limbs[l - 1] + 1, out = new sjcl.bn();
      while (true) {
        do {
          words = sjcl.random.randomWords(l, paranoia);
          if (words[l - 1] < 0) {
            words[l - 1] += 4294967296;
          }
        } while (Math.floor(words[l - 1] / m) === Math.floor(4294967296 / m));
        words[l - 1] %= m;
        for (i = 0; i < l - 1; i++) {
          words[i] &= modulus.radixMask;
        }
        out.limbs = words;
        if (!out.greaterEquals(modulus)) {
          return out;
        }
      }
    };
    sjcl.ecc = {};
    sjcl.ecc.point = function(curve, x, y) {
      if (x === void 0) {
        this.isIdentity = true;
      } else {
        if (x instanceof sjcl.bn) {
          x = new curve.field(x);
        }
        if (y instanceof sjcl.bn) {
          y = new curve.field(y);
        }
        this.x = x;
        this.y = y;
        this.isIdentity = false;
      }
      this.curve = curve;
    };
    sjcl.ecc.point.prototype = {
      toJac: function() {
        return new sjcl.ecc.pointJac(this.curve, this.x, this.y, new this.curve.field(1));
      },
      mult: function(k) {
        return this.toJac().mult(k, this).toAffine();
      },
      /**
       * Multiply this point by k, added to affine2*k2, and return the answer in Jacobian coordinates.
       * @param {bigInt} k The coefficient to multiply this by.
       * @param {bigInt} k2 The coefficient to multiply affine2 this by.
       * @param {sjcl.ecc.point} affine The other point in affine coordinates.
       * @return {sjcl.ecc.pointJac} The result of the multiplication and addition, in Jacobian coordinates.
       */
      mult2: function(k, k2, affine2) {
        return this.toJac().mult2(k, this, k2, affine2).toAffine();
      },
      multiples: function() {
        var m, i, j2;
        if (this._multiples === void 0) {
          j2 = this.toJac().doubl();
          m = this._multiples = [new sjcl.ecc.point(this.curve), this, j2.toAffine()];
          for (i = 3; i < 16; i++) {
            j2 = j2.add(this);
            m.push(j2.toAffine());
          }
        }
        return this._multiples;
      },
      negate: function() {
        var newY = new this.curve.field(0).sub(this.y).normalize().reduce();
        return new sjcl.ecc.point(this.curve, this.x, newY);
      },
      isValid: function() {
        return this.y.square().equals(this.curve.b.add(this.x.mul(this.curve.a.add(this.x.square()))));
      },
      toBits: function() {
        return sjcl.bitArray.concat(this.x.toBits(), this.y.toBits());
      }
    };
    sjcl.ecc.pointJac = function(curve, x, y, z) {
      if (x === void 0) {
        this.isIdentity = true;
      } else {
        this.x = x;
        this.y = y;
        this.z = z;
        this.isIdentity = false;
      }
      this.curve = curve;
    };
    sjcl.ecc.pointJac.prototype = {
      /**
       * Adds S and T and returns the result in Jacobian coordinates. Note that S must be in Jacobian coordinates and T must be in affine coordinates.
       * @param {sjcl.ecc.pointJac} S One of the points to add, in Jacobian coordinates.
       * @param {sjcl.ecc.point} T The other point to add, in affine coordinates.
       * @return {sjcl.ecc.pointJac} The sum of the two points, in Jacobian coordinates.
       */
      add: function(T) {
        var S = this, sz2, c, d, c2, x1, x2, x, y1, y2, y, z;
        if (S.curve !== T.curve) {
          throw new sjcl.exception.invalid("sjcl.ecc.add(): Points must be on the same curve to add them!");
        }
        if (S.isIdentity) {
          return T.toJac();
        } else if (T.isIdentity) {
          return S;
        }
        sz2 = S.z.square();
        c = T.x.mul(sz2).subM(S.x);
        if (c.equals(0)) {
          if (S.y.equals(T.y.mul(sz2.mul(S.z)))) {
            return S.doubl();
          } else {
            return new sjcl.ecc.pointJac(S.curve);
          }
        }
        d = T.y.mul(sz2.mul(S.z)).subM(S.y);
        c2 = c.square();
        x1 = d.square();
        x2 = c.square().mul(c).addM(S.x.add(S.x).mul(c2));
        x = x1.subM(x2);
        y1 = S.x.mul(c2).subM(x).mul(d);
        y2 = S.y.mul(c.square().mul(c));
        y = y1.subM(y2);
        z = S.z.mul(c);
        return new sjcl.ecc.pointJac(this.curve, x, y, z);
      },
      /**
       * doubles this point.
       * @return {sjcl.ecc.pointJac} The doubled point.
       */
      doubl: function() {
        if (this.isIdentity) {
          return this;
        }
        var y2 = this.y.square(), a = y2.mul(this.x.mul(4)), b = y2.square().mul(8), z2 = this.z.square(), c = this.curve.a.toString() == new sjcl.bn(-3).toString() ? this.x.sub(z2).mul(3).mul(this.x.add(z2)) : this.x.square().mul(3).add(z2.square().mul(this.curve.a)), x = c.square().subM(a).subM(a), y = a.sub(x).mul(c).subM(b), z = this.y.add(this.y).mul(this.z);
        return new sjcl.ecc.pointJac(this.curve, x, y, z);
      },
      /**
       * Returns a copy of this point converted to affine coordinates.
       * @return {sjcl.ecc.point} The converted point.
       */
      toAffine: function() {
        if (this.isIdentity || this.z.equals(0)) {
          return new sjcl.ecc.point(this.curve);
        }
        var zi = this.z.inverse(), zi2 = zi.square();
        return new sjcl.ecc.point(this.curve, this.x.mul(zi2).fullReduce(), this.y.mul(zi2.mul(zi)).fullReduce());
      },
      /**
       * Multiply this point by k and return the answer in Jacobian coordinates.
       * @param {bigInt} k The coefficient to multiply by.
       * @param {sjcl.ecc.point} affine This point in affine coordinates.
       * @return {sjcl.ecc.pointJac} The result of the multiplication, in Jacobian coordinates.
       */
      mult: function(k, affine) {
        if (typeof k === "number") {
          k = [k];
        } else if (k.limbs !== void 0) {
          k = k.normalize().limbs;
        }
        var i, j2, out = new sjcl.ecc.point(this.curve).toJac(), multiples = affine.multiples();
        for (i = k.length - 1; i >= 0; i--) {
          for (j2 = sjcl.bn.prototype.radix - 4; j2 >= 0; j2 -= 4) {
            out = out.doubl().doubl().doubl().doubl().add(multiples[k[i] >> j2 & 15]);
          }
        }
        return out;
      },
      /**
       * Multiply this point by k, added to affine2*k2, and return the answer in Jacobian coordinates.
       * @param {bigInt} k The coefficient to multiply this by.
       * @param {sjcl.ecc.point} affine This point in affine coordinates.
       * @param {bigInt} k2 The coefficient to multiply affine2 this by.
       * @param {sjcl.ecc.point} affine The other point in affine coordinates.
       * @return {sjcl.ecc.pointJac} The result of the multiplication and addition, in Jacobian coordinates.
       */
      mult2: function(k1, affine, k2, affine2) {
        if (typeof k1 === "number") {
          k1 = [k1];
        } else if (k1.limbs !== void 0) {
          k1 = k1.normalize().limbs;
        }
        if (typeof k2 === "number") {
          k2 = [k2];
        } else if (k2.limbs !== void 0) {
          k2 = k2.normalize().limbs;
        }
        var i, j2, out = new sjcl.ecc.point(this.curve).toJac(), m1 = affine.multiples(), m2 = affine2.multiples(), l1, l2;
        for (i = Math.max(k1.length, k2.length) - 1; i >= 0; i--) {
          l1 = k1[i] | 0;
          l2 = k2[i] | 0;
          for (j2 = sjcl.bn.prototype.radix - 4; j2 >= 0; j2 -= 4) {
            out = out.doubl().doubl().doubl().doubl().add(m1[l1 >> j2 & 15]).add(m2[l2 >> j2 & 15]);
          }
        }
        return out;
      },
      negate: function() {
        return this.toAffine().negate().toJac();
      },
      isValid: function() {
        var z2 = this.z.square(), z4 = z2.square(), z6 = z4.mul(z2);
        return this.y.square().equals(this.curve.b.mul(z6).add(this.x.mul(this.curve.a.mul(z4).add(this.x.square()))));
      }
    };
    sjcl.ecc.curve = function(Field, r, a, b, x, y) {
      this.field = Field;
      this.r = new sjcl.bn(r);
      this.a = new Field(a);
      this.b = new Field(b);
      this.G = new sjcl.ecc.point(this, new Field(x), new Field(y));
    };
    sjcl.ecc.curve.prototype.fromBits = function(bits) {
      var w = sjcl.bitArray, l = this.field.prototype.exponent + 7 & -8, p = new sjcl.ecc.point(this, this.field.fromBits(w.bitSlice(bits, 0, l)), this.field.fromBits(w.bitSlice(bits, l, 2 * l)));
      if (!p.isValid()) {
        throw new sjcl.exception.corrupt("not on the curve!");
      }
      return p;
    };
    sjcl.ecc.curves = {
      c192: new sjcl.ecc.curve(sjcl.bn.prime.p192, "0xffffffffffffffffffffffff99def836146bc9b1b4d22831", -3, "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811"),
      c224: new sjcl.ecc.curve(sjcl.bn.prime.p224, "0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", -3, "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),
      c256: new sjcl.ecc.curve(sjcl.bn.prime.p256, "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", -3, "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
      c384: new sjcl.ecc.curve(sjcl.bn.prime.p384, "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", -3, "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
      c521: new sjcl.ecc.curve(sjcl.bn.prime.p521, "0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", -3, "0x051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", "0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", "0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"),
      k192: new sjcl.ecc.curve(sjcl.bn.prime.p192k, "0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d", 0, 3, "0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d", "0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d"),
      k224: new sjcl.ecc.curve(sjcl.bn.prime.p224k, "0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7", 0, 5, "0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c", "0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5"),
      k256: new sjcl.ecc.curve(sjcl.bn.prime.p256k, "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 0, 7, "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    };
    sjcl.ecc.curveName = function(curve) {
      var curcurve;
      for (curcurve in sjcl.ecc.curves) {
        if (sjcl.ecc.curves.hasOwnProperty(curcurve)) {
          if (sjcl.ecc.curves[curcurve] === curve) {
            return curcurve;
          }
        }
      }
      throw new sjcl.exception.invalid("no such curve");
    };
    sjcl.ecc.deserialize = function(key) {
      var types = ["elGamal", "ecdsa"];
      if (!key || !key.curve || !sjcl.ecc.curves[key.curve]) {
        throw new sjcl.exception.invalid("invalid serialization");
      }
      if (types.indexOf(key.type) === -1) {
        throw new sjcl.exception.invalid("invalid type");
      }
      var curve = sjcl.ecc.curves[key.curve];
      if (key.secretKey) {
        if (!key.exponent) {
          throw new sjcl.exception.invalid("invalid exponent");
        }
        var exponent = new sjcl.bn(key.exponent);
        return new sjcl.ecc[key.type].secretKey(curve, exponent);
      } else {
        if (!key.point) {
          throw new sjcl.exception.invalid("invalid point");
        }
        var point = curve.fromBits(sjcl.codec.hex.toBits(key.point));
        return new sjcl.ecc[key.type].publicKey(curve, point);
      }
    };
    sjcl.ecc.basicKey = {
      /** ecc publicKey.
      * @constructor
      * @param {curve} curve the elliptic curve
      * @param {point} point the point on the curve
      */
      publicKey: function(curve, point) {
        this._curve = curve;
        this._curveBitLength = curve.r.bitLength();
        if (point instanceof Array) {
          this._point = curve.fromBits(point);
        } else {
          this._point = point;
        }
        this.serialize = function() {
          var curveName = sjcl.ecc.curveName(curve);
          return {
            type: this.getType(),
            secretKey: false,
            point: sjcl.codec.hex.fromBits(this._point.toBits()),
            curve: curveName
          };
        };
        this.get = function() {
          var pointbits = this._point.toBits();
          var len = sjcl.bitArray.bitLength(pointbits);
          var x = sjcl.bitArray.bitSlice(pointbits, 0, len / 2);
          var y = sjcl.bitArray.bitSlice(pointbits, len / 2);
          return { x, y };
        };
      },
      /** ecc secretKey
      * @constructor
      * @param {curve} curve the elliptic curve
      * @param exponent
      */
      secretKey: function(curve, exponent) {
        this._curve = curve;
        this._curveBitLength = curve.r.bitLength();
        this._exponent = exponent;
        this.serialize = function() {
          var exponent2 = this.get();
          var curveName = sjcl.ecc.curveName(curve);
          return {
            type: this.getType(),
            secretKey: true,
            exponent: sjcl.codec.hex.fromBits(exponent2),
            curve: curveName
          };
        };
        this.get = function() {
          return this._exponent.toBits();
        };
      }
    };
    sjcl.ecc.basicKey.generateKeys = function(cn) {
      return function generateKeys(curve, paranoia, sec) {
        curve = curve || 256;
        if (typeof curve === "number") {
          curve = sjcl.ecc.curves["c" + curve];
          if (curve === void 0) {
            throw new sjcl.exception.invalid("no such curve");
          }
        }
        sec = sec || sjcl.bn.random(curve.r, paranoia);
        var pub = curve.G.mult(sec);
        return {
          pub: new sjcl.ecc[cn].publicKey(curve, pub),
          sec: new sjcl.ecc[cn].secretKey(curve, sec)
        };
      };
    };
    sjcl.ecc.elGamal = {
      /** generate keys
      * @function
      * @param curve
      * @param {int} paranoia Paranoia for generation (default 6)
      * @param {secretKey} sec secret Key to use. used to get the publicKey for ones secretKey
      */
      generateKeys: sjcl.ecc.basicKey.generateKeys("elGamal"),
      /** elGamal publicKey.
      * @constructor
      * @augments sjcl.ecc.basicKey.publicKey
      */
      publicKey: function(curve, point) {
        sjcl.ecc.basicKey.publicKey.apply(this, arguments);
      },
      /** elGamal secretKey
      * @constructor
      * @augments sjcl.ecc.basicKey.secretKey
      */
      secretKey: function(curve, exponent) {
        sjcl.ecc.basicKey.secretKey.apply(this, arguments);
      }
    };
    sjcl.ecc.elGamal.publicKey.prototype = {
      /** Kem function of elGamal Public Key
      * @param paranoia paranoia to use for randomization.
      * @return {object} key and tag. unkem(tag) with the corresponding secret key results in the key returned.
      */
      kem: function(paranoia) {
        var sec = sjcl.bn.random(this._curve.r, paranoia), tag = this._curve.G.mult(sec).toBits(), key = sjcl.hash.sha256.hash(this._point.mult(sec).toBits());
        return { key, tag };
      },
      getType: function() {
        return "elGamal";
      }
    };
    sjcl.ecc.elGamal.secretKey.prototype = {
      /** UnKem function of elGamal Secret Key
      * @param {bitArray} tag The Tag to decrypt.
      * @return {bitArray} decrypted key.
      */
      unkem: function(tag) {
        return sjcl.hash.sha256.hash(this._curve.fromBits(tag).mult(this._exponent).toBits());
      },
      /** Diffie-Hellmann function
      * @param {elGamal.publicKey} pk The Public Key to do Diffie-Hellmann with
      * @return {bitArray} diffie-hellmann result for this key combination.
      */
      dh: function(pk) {
        return sjcl.hash.sha256.hash(pk._point.mult(this._exponent).toBits());
      },
      /** Diffie-Hellmann function, compatible with Java generateSecret
      * @param {elGamal.publicKey} pk The Public Key to do Diffie-Hellmann with
      * @return {bitArray} undigested X value, diffie-hellmann result for this key combination,
      * compatible with Java generateSecret().
      */
      dhJavaEc: function(pk) {
        return pk._point.mult(this._exponent).x.toBits();
      },
      getType: function() {
        return "elGamal";
      }
    };
    sjcl.ecc.ecdsa = {
      /** generate keys
      * @function
      * @param curve
      * @param {int} paranoia Paranoia for generation (default 6)
      * @param {secretKey} sec secret Key to use. used to get the publicKey for ones secretKey
      */
      generateKeys: sjcl.ecc.basicKey.generateKeys("ecdsa")
    };
    sjcl.ecc.ecdsa.publicKey = function(curve, point) {
      sjcl.ecc.basicKey.publicKey.apply(this, arguments);
    };
    sjcl.ecc.ecdsa.publicKey.prototype = {
      /** Diffie-Hellmann function
      * @param {bitArray} hash hash to verify.
      * @param {bitArray} rs signature bitArray.
      * @param {boolean}  fakeLegacyVersion use old legacy version
      */
      verify: function(hash, rs, fakeLegacyVersion) {
        if (sjcl.bitArray.bitLength(hash) > this._curveBitLength) {
          hash = sjcl.bitArray.clamp(hash, this._curveBitLength);
        }
        var w = sjcl.bitArray, R = this._curve.r, l = this._curveBitLength, r = sjcl.bn.fromBits(w.bitSlice(rs, 0, l)), ss = sjcl.bn.fromBits(w.bitSlice(rs, l, 2 * l)), s = fakeLegacyVersion ? ss : ss.inverseMod(R), hG = sjcl.bn.fromBits(hash).mul(s).mod(R), hA = r.mul(s).mod(R), r2 = this._curve.G.mult2(hG, hA, this._point).x;
        if (r.equals(0) || ss.equals(0) || r.greaterEquals(R) || ss.greaterEquals(R) || !r2.equals(r)) {
          if (fakeLegacyVersion === void 0) {
            return this.verify(hash, rs, true);
          } else {
            throw new sjcl.exception.corrupt("signature didn't check out");
          }
        }
        return true;
      },
      getType: function() {
        return "ecdsa";
      }
    };
    sjcl.ecc.ecdsa.secretKey = function(curve, exponent) {
      sjcl.ecc.basicKey.secretKey.apply(this, arguments);
    };
    sjcl.ecc.ecdsa.secretKey.prototype = {
      /** Diffie-Hellmann function
      * @param {bitArray} hash hash to sign.
      * @param {int} paranoia paranoia for random number generation
      * @param {boolean} fakeLegacyVersion use old legacy version
      */
      sign: function(hash, paranoia, fakeLegacyVersion, fixedKForTesting) {
        if (sjcl.bitArray.bitLength(hash) > this._curveBitLength) {
          hash = sjcl.bitArray.clamp(hash, this._curveBitLength);
        }
        var R = this._curve.r, l = R.bitLength(), k = fixedKForTesting || sjcl.bn.random(R.sub(1), paranoia).add(1), r = this._curve.G.mult(k).x.mod(R), ss = sjcl.bn.fromBits(hash).add(r.mul(this._exponent)), s = fakeLegacyVersion ? ss.inverseMod(R).mul(k).mod(R) : ss.mul(k.inverseMod(R)).mod(R);
        return sjcl.bitArray.concat(r.toBits(l), s.toBits(l));
      },
      getType: function() {
        return "ecdsa";
      }
    };
    if (typeof ArrayBuffer === "undefined") {
      (function(globals) {
        "use strict";
        globals.ArrayBuffer = function() {
        };
        globals.DataView = function() {
        };
      })(exports);
    }
    sjcl.codec.arrayBuffer = {
      /** Convert from a bitArray to an ArrayBuffer.
       * Will default to 8byte padding if padding is undefined*/
      fromBits: function(arr, padding, padding_count) {
        var out, i, ol, tmp, smallest;
        padding = padding == void 0 ? true : padding;
        padding_count = padding_count || 8;
        if (arr.length === 0) {
          return new ArrayBuffer(0);
        }
        ol = sjcl.bitArray.bitLength(arr) / 8;
        if (sjcl.bitArray.bitLength(arr) % 8 !== 0) {
          throw new sjcl.exception.invalid("Invalid bit size, must be divisble by 8 to fit in an arraybuffer correctly");
        }
        if (padding && ol % padding_count !== 0) {
          ol += padding_count - ol % padding_count;
        }
        tmp = new DataView(new ArrayBuffer(arr.length * 4));
        for (i = 0; i < arr.length; i++) {
          tmp.setUint32(i * 4, arr[i] << 32);
        }
        out = new DataView(new ArrayBuffer(ol));
        if (out.byteLength === tmp.byteLength) {
          return tmp.buffer;
        }
        smallest = tmp.byteLength < out.byteLength ? tmp.byteLength : out.byteLength;
        for (i = 0; i < smallest; i++) {
          out.setUint8(i, tmp.getUint8(i));
        }
        return out.buffer;
      },
      /** Convert from an ArrayBuffer to a bitArray. */
      toBits: function(buffer) {
        var i, out = [], len, inView, tmp;
        if (buffer.byteLength === 0) {
          return [];
        }
        inView = new DataView(buffer);
        len = inView.byteLength - inView.byteLength % 4;
        for (var i = 0; i < len; i += 4) {
          out.push(inView.getUint32(i));
        }
        if (inView.byteLength % 4 != 0) {
          tmp = new DataView(new ArrayBuffer(4));
          for (var i = 0, l = inView.byteLength % 4; i < l; i++) {
            tmp.setUint8(i + 4 - l, inView.getUint8(len + i));
          }
          out.push(sjcl.bitArray.partial(inView.byteLength % 4 * 8, tmp.getUint32(0)));
        }
        return out;
      },
      /** Prints a hex output of the buffer contents, akin to hexdump **/
      hexDumpBuffer: function(buffer) {
        var stringBufferView = new DataView(buffer);
        var string = "";
        var pad = function(n, width) {
          n = n + "";
          return n.length >= width ? n : new Array(width - n.length + 1).join("0") + n;
        };
        for (var i = 0; i < stringBufferView.byteLength; i += 2) {
          if (i % 16 == 0)
            string += "\n" + i.toString(16) + "	";
          string += pad(stringBufferView.getUint16(i).toString(16), 4) + " ";
        }
        if (typeof console === void 0) {
          console = console || { log: function() {
          } };
        }
        console.log(string.toUpperCase());
      }
    };
    exports.default = sjcl;
  }
});

// node_modules/@cloudflare/voprf-ts/lib/cjs/src/groupSjcl.js
var require_groupSjcl = __commonJS({
  "node_modules/@cloudflare/voprf-ts/lib/cjs/src/groupSjcl.js"(exports) {
    "use strict";
    init_polyfills();
    var __classPrivateFieldGet = exports && exports.__classPrivateFieldGet || function(receiver, state, kind, f) {
      if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
      if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
      return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
    };
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    var _a;
    var _GroupSj_cache;
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.GroupConsSjcl = void 0;
    var util_js_1 = require_util();
    var index_js_1 = __importDefault(require_sjcl());
    var groupTypes_js_1 = require_groupTypes();
    function hashParams(hash) {
      switch (hash) {
        case "SHA-1":
          return { outLenBytes: 20, blockLenBytes: 64 };
        case "SHA-256":
          return { outLenBytes: 32, blockLenBytes: 64 };
        case "SHA-384":
          return { outLenBytes: 48, blockLenBytes: 128 };
        case "SHA-512":
          return { outLenBytes: 64, blockLenBytes: 128 };
        default:
          throw new Error(`invalid hash name: ${hash}`);
      }
    }
    async function expandXMD(hash, msg, dst, numBytes) {
      const { outLenBytes, blockLenBytes } = hashParams(hash);
      const ell = Math.ceil(numBytes / outLenBytes);
      if (ell > 255) {
        throw new Error("too big");
      }
      let dstPrime = dst;
      if (dst.length > 255) {
        const te = new TextEncoder();
        const input = (0, util_js_1.joinAll)([te.encode("H2C-OVERSIZE-DST-"), dst]);
        dstPrime = new Uint8Array(await crypto.subtle.digest(hash, input));
      }
      dstPrime = (0, util_js_1.joinAll)([dstPrime, new Uint8Array([dstPrime.length])]);
      const zPad = new Uint8Array(blockLenBytes);
      const libStr = new Uint8Array(2);
      libStr[0] = numBytes >> 8 & 255;
      libStr[1] = numBytes & 255;
      const b0Input = (0, util_js_1.joinAll)([zPad, msg, libStr, new Uint8Array([0]), dstPrime]);
      const b0 = new Uint8Array(await crypto.subtle.digest(hash, b0Input));
      const b1Input = (0, util_js_1.joinAll)([b0, new Uint8Array([1]), dstPrime]);
      let bi = new Uint8Array(await crypto.subtle.digest(hash, b1Input));
      let pseudo = (0, util_js_1.joinAll)([bi]);
      for (let i = 2; i <= ell; i++) {
        const biInput = (0, util_js_1.joinAll)([(0, util_js_1.xor)(bi, b0), new Uint8Array([i]), dstPrime]);
        bi = new Uint8Array(await crypto.subtle.digest(hash, biInput));
        pseudo = (0, util_js_1.joinAll)([pseudo, bi]);
      }
      return pseudo.slice(0, numBytes);
    }
    function getCurve(gid) {
      switch (gid) {
        case groupTypes_js_1.GROUP.P256:
          return index_js_1.default.ecc.curves.c256;
        case groupTypes_js_1.GROUP.P384:
          return index_js_1.default.ecc.curves.c384;
        case groupTypes_js_1.GROUP.P521:
          return index_js_1.default.ecc.curves.c521;
        case groupTypes_js_1.GROUP.DECAF448:
        case groupTypes_js_1.GROUP.RISTRETTO255:
          throw new Error("group: non-supported ciphersuite");
        default:
          throw (0, groupTypes_js_1.errBadGroup)(gid);
      }
    }
    var ScalarSj = class _ScalarSj {
      constructor(g, k) {
        this.g = g;
        this.k = k;
        this.order = getCurve(this.g.id).r;
      }
      static create(g) {
        return new _ScalarSj(g, new index_js_1.default.bn(0));
      }
      isEqual(s) {
        return this.k.equals(s.k);
      }
      isZero() {
        return this.k.equals(0);
      }
      add(s) {
        (0, util_js_1.compat)(this, s);
        const c = this.k.add(s.k).mod(this.order);
        c.normalize();
        return new _ScalarSj(this.g, c);
      }
      sub(s) {
        (0, util_js_1.compat)(this, s);
        const c = this.k.sub(s.k).mod(this.order);
        c.normalize();
        return new _ScalarSj(this.g, c);
      }
      mul(s) {
        (0, util_js_1.compat)(this, s);
        const c = this.k.mulmod(s.k, this.order);
        c.normalize();
        return new _ScalarSj(this.g, c);
      }
      inv() {
        return new _ScalarSj(this.g, this.k.inverseMod(this.order));
      }
      serialize() {
        const k = this.k.mod(this.order);
        k.normalize();
        const ab = index_js_1.default.codec.arrayBuffer.fromBits(k.toBits(), false);
        const unpaded = new Uint8Array(ab);
        const serScalar = new Uint8Array(this.g.size);
        serScalar.set(unpaded, this.g.size - unpaded.length);
        return serScalar;
      }
      static size(g) {
        return g.size;
      }
      static deserialize(g, bytes) {
        (0, util_js_1.checkSize)(bytes, _ScalarSj, g);
        const array = Array.from(bytes.subarray(0, g.size));
        const k = index_js_1.default.bn.fromBits(index_js_1.default.codec.bytes.toBits(array));
        k.normalize();
        if (k.greaterEquals(getCurve(g.id).r)) {
          throw (0, util_js_1.errDeserialization)(_ScalarSj);
        }
        return new _ScalarSj(g, k);
      }
      static async hash(g, msg, dst) {
        const { hash, L } = getHashParams(g.id);
        const bytes = await expandXMD(hash, msg, dst, L);
        const array = Array.from(bytes);
        const bitArr = index_js_1.default.codec.bytes.toBits(array);
        const k = index_js_1.default.bn.fromBits(bitArr).mod(getCurve(g.id).r);
        return new _ScalarSj(g, k);
      }
    };
    function getSSWUParams(gid) {
      const curve = getCurve(gid);
      let Z;
      let c2;
      switch (gid) {
        case groupTypes_js_1.GROUP.P256:
          Z = -10;
          c2 = "0x25ac71c31e27646736870398ae7f554d8472e008b3aa2a49d332cbd81bcc3b80";
          break;
        case groupTypes_js_1.GROUP.P384:
          Z = -12;
          c2 = "0x2accb4a656b0249c71f0500e83da2fdd7f98e383d68b53871f872fcb9ccb80c53c0de1f8a80f7e1914e2ec69f5a626b3";
          break;
        case groupTypes_js_1.GROUP.P521:
          Z = -4;
          c2 = "0x2";
          break;
        default:
          throw (0, groupTypes_js_1.errBadGroup)(gid);
      }
      const p = curve.field.modulus;
      const c1 = p.sub(new index_js_1.default.bn(3)).halveM().halveM();
      Z = new curve.field(Z);
      c2 = new curve.field(c2);
      return { Z, c1, c2 };
    }
    function getHashParams(gid) {
      switch (gid) {
        case groupTypes_js_1.GROUP.P256:
          return { hash: "SHA-256", L: 48 };
        case groupTypes_js_1.GROUP.P384:
          return { hash: "SHA-384", L: 72 };
        case groupTypes_js_1.GROUP.P521:
          return { hash: "SHA-512", L: 98 };
        default:
          throw (0, groupTypes_js_1.errBadGroup)(gid);
      }
    }
    var EltSj = class _EltSj {
      constructor(g, p) {
        this.g = g;
        this.p = p;
      }
      static create(g) {
        return new _EltSj(g, new index_js_1.default.ecc.point(getCurve(g.id)));
      }
      static gen(g) {
        return new _EltSj(g, getCurve(g.id).G);
      }
      isIdentity() {
        return this.p.isIdentity;
      }
      isEqual(a) {
        (0, util_js_1.compat)(this, a);
        if (this.p.isIdentity && a.p.isIdentity) {
          return true;
        } else if (this.p.isIdentity || a.p.isIdentity) {
          return false;
        }
        const { x: x1, y: y1 } = this.p;
        const { x: x2, y: y2 } = a.p;
        return x1.equals(x2) && y1.equals(y2);
      }
      neg() {
        return this.p.negate();
      }
      add(a) {
        (0, util_js_1.compat)(this, a);
        return new _EltSj(this.g, this.p.toJac().add(a.p).toAffine());
      }
      mul(s) {
        (0, util_js_1.compat)(this, s);
        return new _EltSj(this.g, this.p.mult(s.k));
      }
      mul2(k1, a, k2) {
        (0, util_js_1.compat)(this, k1);
        (0, util_js_1.compat)(this, k2);
        (0, util_js_1.compat)(this, a);
        return new _EltSj(this.g, this.p.mult2(k1.k, k2.k, a.p));
      }
      // Serializes an element in uncompressed form.
      serUnComp(a) {
        const xy = index_js_1.default.codec.arrayBuffer.fromBits(a.toBits(), false);
        const bytes = new Uint8Array(xy);
        if (bytes.length !== 2 * this.g.size) {
          throw new Error("error serializing element");
        }
        const serElt = new Uint8Array(1 + 2 * this.g.size);
        serElt[0] = 4;
        serElt.set(bytes, 1);
        return serElt;
      }
      // Serializes an element in compressed form.
      serComp(a) {
        const x = new Uint8Array(index_js_1.default.codec.arrayBuffer.fromBits(a.x.toBits(null), false));
        const serElt = new Uint8Array(1 + this.g.size);
        serElt[0] = 2 | a.y.getLimb(0) & 1;
        serElt.set(x, 1 + this.g.size - x.length);
        return serElt;
      }
      serialize(compressed = true) {
        if (this.p.isIdentity) {
          return Uint8Array.from([0]);
        }
        const p = this.p;
        p.x.fullReduce();
        p.y.fullReduce();
        return compressed ? this.serComp(p) : this.serUnComp(p);
      }
      // size returns the number of bytes of a non-zero element in compressed or uncompressed form.
      static size(g, compressed = true) {
        return 1 + (compressed ? g.size : g.size * 2);
      }
      // Deserializes an element in compressed form.
      static deserComp(g, bytes) {
        const array = Array.from(bytes.subarray(1));
        const bits = index_js_1.default.codec.bytes.toBits(array);
        const curve = getCurve(g.id);
        const x = new curve.field(index_js_1.default.bn.fromBits(bits));
        const p = curve.field.modulus;
        const exp = p.add(new index_js_1.default.bn(1)).halveM().halveM();
        let y = x.square().add(curve.a).mul(x).add(curve.b).power(exp);
        y.fullReduce();
        if ((bytes[0] & 1) !== (y.getLimb(0) & 1)) {
          y = p.sub(y).mod(p);
        }
        const point = new index_js_1.default.ecc.point(curve, new curve.field(x), new curve.field(y));
        if (!point.isValid()) {
          throw (0, util_js_1.errDeserialization)(_EltSj);
        }
        return new _EltSj(g, point);
      }
      // Deserializes an element in uncompressed form.
      static deserUnComp(g, bytes) {
        const array = Array.from(bytes.subarray(1));
        const b = index_js_1.default.codec.bytes.toBits(array);
        const curve = getCurve(g.id);
        const point = curve.fromBits(b);
        point.x.fullReduce();
        point.y.fullReduce();
        return new _EltSj(g, point);
      }
      // Deserializes an element, handles both compressed and uncompressed forms.
      static deserialize(g, bytes) {
        const len = bytes.length;
        switch (true) {
          case (len === 1 && bytes[0] === 0):
            return g.identity();
          case (len === 1 + g.size && (bytes[0] === 2 || bytes[0] === 3)):
            return _EltSj.deserComp(g, bytes);
          case (len === 1 + 2 * g.size && bytes[0] === 4):
            return _EltSj.deserUnComp(g, bytes);
          default:
            throw (0, util_js_1.errDeserialization)(_EltSj);
        }
      }
      static async hashToField(g, msg, dst, count) {
        const curve = getCurve(g.id);
        const { hash, L } = getHashParams(g.id);
        const bytes = await expandXMD(hash, msg, dst, count * L);
        const u = new Array();
        for (let i = 0; i < count; i++) {
          const j2 = i * L;
          const array = Array.from(bytes.slice(j2, j2 + L));
          const bitArr = index_js_1.default.codec.bytes.toBits(array);
          u.push(new curve.field(index_js_1.default.bn.fromBits(bitArr)));
        }
        return u;
      }
      static sswu(g, u) {
        const curve = getCurve(g.id);
        const { a: A, b: B } = curve;
        const { Z, c1, c2 } = getSSWUParams(g.id);
        const zero = new curve.field(0);
        const one = new curve.field(1);
        function sgn(x2) {
          x2.fullReduce();
          return x2.getLimb(0) & 1;
        }
        function cmov(x2, y2, b) {
          return b ? y2 : x2;
        }
        function sqrt_ratio_3mod4(u2, v) {
          let tv12 = v.square();
          const tv22 = u2.mul(v);
          tv12 = tv12.mul(tv22);
          let y12 = tv12.power(c1);
          y12 = y12.mul(tv22);
          const y2 = y12.mul(c2);
          let tv32 = y12.square();
          tv32 = tv32.mul(v);
          const isQR2 = tv32.equals(u2);
          const y3 = cmov(y2, y12, isQR2);
          return { isQR: isQR2, root: y3 };
        }
        let tv1 = u.square();
        tv1 = Z.mul(tv1);
        let tv2 = tv1.square();
        tv2 = tv2.add(tv1);
        let tv3 = tv2.add(one);
        tv3 = B.mul(tv3);
        let tv4 = cmov(Z, zero.sub(tv2), !tv2.equals(zero));
        tv4 = A.mul(tv4);
        tv2 = tv3.square();
        let tv6 = tv4.square();
        let tv5 = A.mul(tv6);
        tv2 = tv2.add(tv5);
        tv2 = tv2.mul(tv3);
        tv6 = tv6.mul(tv4);
        tv5 = B.mul(tv6);
        tv2 = tv2.add(tv5);
        let x = tv1.mul(tv3);
        const { isQR, root: y1 } = sqrt_ratio_3mod4(tv2, tv6);
        let y = tv1.mul(u);
        y = y.mul(y1);
        x = cmov(x, tv3, isQR);
        y = cmov(y, y1, isQR);
        const e1 = sgn(u) === sgn(y);
        y = cmov(zero.sub(y), y, e1);
        const z = tv4;
        x = x.mul(z);
        tv1 = z.square();
        tv1 = tv1.mul(z);
        y = y.mul(tv1);
        const point = new index_js_1.default.ecc.pointJac(curve, x, y, z).toAffine();
        if (!point.isValid()) {
          throw new Error("point not in curve");
        }
        return new _EltSj(g, point);
      }
      static async hash(g, msg, dst) {
        const u = await _EltSj.hashToField(g, msg, dst, 2);
        const Q0 = _EltSj.sswu(g, u[0]);
        const Q1 = _EltSj.sswu(g, u[1]);
        return Q0.add(Q1);
      }
    };
    var GroupSj = class {
      static get(gid) {
        var _b, _c;
        return (_b = __classPrivateFieldGet(this, _a, "f", _GroupSj_cache))[_c = `${gid}`] ?? (_b[_c] = new this(gid));
      }
      constructor(gid) {
        switch (gid) {
          case groupTypes_js_1.GROUP.P256:
            this.size = 32;
            break;
          case groupTypes_js_1.GROUP.P384:
            this.size = 48;
            break;
          case groupTypes_js_1.GROUP.P521:
            this.size = 66;
            break;
          default:
            throw (0, groupTypes_js_1.errBadGroup)(gid);
        }
        this.id = gid;
      }
      newScalar() {
        return ScalarSj.create(this);
      }
      newElt() {
        return this.identity();
      }
      identity() {
        return EltSj.create(this);
      }
      generator() {
        return EltSj.gen(this);
      }
      mulGen(s) {
        return EltSj.gen(this).mul(s);
      }
      randomScalar() {
        const msg = crypto.getRandomValues(new Uint8Array(this.size));
        return ScalarSj.hash(this, msg, new Uint8Array());
      }
      hashToGroup(msg, dst) {
        return EltSj.hash(this, msg, dst);
      }
      hashToScalar(msg, dst) {
        return ScalarSj.hash(this, msg, dst);
      }
      get eltDes() {
        return {
          size: (compressed) => EltSj.size(this, compressed),
          deserialize: (b) => EltSj.deserialize(this, b)
        };
      }
      get scalarDes() {
        return {
          size: () => ScalarSj.size(this),
          deserialize: (b) => ScalarSj.deserialize(this, b)
        };
      }
      desElt(bytes) {
        return EltSj.deserialize(this, bytes);
      }
      desScalar(bytes) {
        return ScalarSj.deserialize(this, bytes);
      }
      eltSize(compressed) {
        return EltSj.size(this, compressed);
      }
      scalarSize() {
        return ScalarSj.size(this);
      }
    };
    _a = GroupSj;
    GroupSj.supportedGroups = [groupTypes_js_1.GROUP.P256, groupTypes_js_1.GROUP.P384, groupTypes_js_1.GROUP.P521];
    _GroupSj_cache = { value: {} };
    exports.GroupConsSjcl = GroupSj;
  }
});

// node_modules/@cloudflare/voprf-ts/lib/cjs/src/cryptoSjcl.js
var require_cryptoSjcl = __commonJS({
  "node_modules/@cloudflare/voprf-ts/lib/cjs/src/cryptoSjcl.js"(exports) {
    "use strict";
    init_polyfills();
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.CryptoSjcl = void 0;
    var groupSjcl_js_1 = require_groupSjcl();
    exports.CryptoSjcl = {
      id: "sjcl",
      Group: groupSjcl_js_1.GroupConsSjcl,
      async hash(hashID, input) {
        return new Uint8Array(await crypto.subtle.digest(hashID, input));
      }
    };
  }
});

// node_modules/@cloudflare/voprf-ts/lib/cjs/src/buildSettings.js
var require_buildSettings = __commonJS({
  "node_modules/@cloudflare/voprf-ts/lib/cjs/src/buildSettings.js"(exports) {
    "use strict";
    init_polyfills();
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.DEFAULT_CRYPTO_PROVIDER = exports.CRYPTO_PROVIDER_ARG_REQUIRED = void 0;
    var cryptoSjcl_js_1 = require_cryptoSjcl();
    exports.CRYPTO_PROVIDER_ARG_REQUIRED = false;
    exports.DEFAULT_CRYPTO_PROVIDER = cryptoSjcl_js_1.CryptoSjcl;
  }
});

// node_modules/@cloudflare/voprf-ts/lib/cjs/src/cryptoImpl.js
var require_cryptoImpl = __commonJS({
  "node_modules/@cloudflare/voprf-ts/lib/cjs/src/cryptoImpl.js"(exports) {
    "use strict";
    init_polyfills();
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getCrypto = getCrypto;
    exports.getGroup = getGroup;
    exports.getSuiteGroup = getSuiteGroup;
    exports.setCryptoProvider = setCryptoProvider;
    exports.getCryptoProvider = getCryptoProvider;
    var oprf_js_1 = require_oprf();
    var buildSettings_js_1 = require_buildSettings();
    var REQUIRED = buildSettings_js_1.CRYPTO_PROVIDER_ARG_REQUIRED;
    var configured = buildSettings_js_1.DEFAULT_CRYPTO_PROVIDER;
    function getCrypto(arg) {
      const [provider] = arg;
      if (!provider && REQUIRED) {
        throw new Error(`Undefined crypto arg`);
      }
      return provider ?? configured;
    }
    function getGroup(groupID, arg) {
      const provider = getCrypto(arg);
      return provider.Group.get(groupID);
    }
    function getSuiteGroup(suite, arg) {
      return getGroup((0, oprf_js_1.getOprfParams)(suite)[1], arg);
    }
    function setCryptoProvider(provider) {
      configured = provider;
    }
    function getCryptoProvider() {
      return configured;
    }
  }
});

// node_modules/@cloudflare/voprf-ts/lib/cjs/src/dleq.js
var require_dleq = __commonJS({
  "node_modules/@cloudflare/voprf-ts/lib/cjs/src/dleq.js"(exports) {
    "use strict";
    init_polyfills();
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.DLEQProver = exports.DLEQVerifier = exports.DLEQProof = void 0;
    var util_js_1 = require_util();
    var cryptoImpl_js_1 = require_cryptoImpl();
    var LABELS = {
      Seed: "Seed-",
      Challenge: "Challenge",
      Composite: "Composite",
      HashToScalar: "HashToScalar-"
    };
    async function computeComposites(params, b, cd, key, ...arg) {
      const crypto2 = (0, cryptoImpl_js_1.getCrypto)(arg);
      const group = crypto2.Group.get(params.group);
      const te = new TextEncoder();
      const Bm = b.serialize();
      const seedDST = (0, util_js_1.joinAll)([te.encode(LABELS.Seed), params.dst]);
      const h1Input = (0, util_js_1.joinAll)([...(0, util_js_1.toU16LenPrefix)(Bm), ...(0, util_js_1.toU16LenPrefix)(seedDST)]);
      const seed = await crypto2.hash(params.hash, h1Input);
      const compositeLabel = te.encode(LABELS.Composite);
      const h2sDST = (0, util_js_1.joinAll)([te.encode(LABELS.HashToScalar), params.dst]);
      let M = group.identity();
      let Z = group.identity();
      let i = 0;
      for (const [c, d] of cd) {
        const Ci = c.serialize();
        const Di = d.serialize();
        const h2Input = (0, util_js_1.joinAll)([
          ...(0, util_js_1.toU16LenPrefix)(seed),
          (0, util_js_1.to16bits)(i++),
          ...(0, util_js_1.toU16LenPrefix)(Ci),
          ...(0, util_js_1.toU16LenPrefix)(Di),
          compositeLabel
        ]);
        const di = await group.hashToScalar(h2Input, h2sDST);
        M = M.add(c.mul(di));
        if (!key) {
          Z = Z.add(d.mul(di));
        }
      }
      if (key) {
        Z = M.mul(key);
      }
      return { M, Z };
    }
    function challenge(group, params, points) {
      let h2Input = new Uint8Array();
      for (const p of points) {
        const P = p.serialize();
        h2Input = (0, util_js_1.joinAll)([h2Input, ...(0, util_js_1.toU16LenPrefix)(P)]);
      }
      const te = new TextEncoder();
      h2Input = (0, util_js_1.joinAll)([h2Input, te.encode(LABELS.Challenge)]);
      const h2sDST = (0, util_js_1.joinAll)([te.encode(LABELS.HashToScalar), params.dst]);
      return group.hashToScalar(h2Input, h2sDST);
    }
    var DLEQProof = class _DLEQProof {
      constructor(c, s) {
        this.c = c;
        this.s = s;
      }
      isEqual(p) {
        return this.c.isEqual(p.c) && this.s.isEqual(p.s);
      }
      serialize() {
        return (0, util_js_1.joinAll)([this.c.serialize(), this.s.serialize()]);
      }
      static size(group) {
        return 2 * group.scalarSize();
      }
      static deserialize(groupID, bytes, ...arg) {
        const group = (0, cryptoImpl_js_1.getGroup)(groupID, arg);
        (0, util_js_1.checkSize)(bytes, _DLEQProof, group);
        const n = group.scalarSize();
        const c = group.desScalar(bytes.subarray(0, n));
        const s = group.desScalar(bytes.subarray(n, 2 * n));
        return new _DLEQProof(c, s);
      }
    };
    exports.DLEQProof = DLEQProof;
    var DLEQVerifier = class {
      constructor(params, ...arg) {
        this.params = params;
        this.crypto = (0, cryptoImpl_js_1.getCrypto)(arg);
        this.group = this.crypto.Group.get(params.group);
      }
      verify(p0, p1, proof) {
        return this.verify_batch(p0, [p1], proof);
      }
      // verify_batch implements the VerifyProof function
      // from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#name-discrete-logarithm-equivale
      // The argument p0 corresponds to the elements A, B, and the argument p1s
      // corresponds to the arrays of elements C and D from the specification.
      async verify_batch(p0, p1s, proof) {
        const { M, Z } = await computeComposites(this.params, p0[1], p1s, void 0, this.crypto);
        const t2 = p0[0].mul2(proof.s, p0[1], proof.c);
        const t3 = M.mul2(proof.s, Z, proof.c);
        const c = await challenge(this.group, this.params, [p0[1], M, Z, t2, t3]);
        return proof.c.isEqual(c);
      }
    };
    exports.DLEQVerifier = DLEQVerifier;
    var DLEQProver = class extends DLEQVerifier {
      prove(k, p0, p1, r) {
        return this.prove_batch(k, p0, [p1], r);
      }
      randomScalar() {
        return this.group.randomScalar();
      }
      // prove_batch implements the GenerateProof function
      // from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#name-discrete-logarithm-equivale
      // The argument p0 corresponds to the elements A, B, and the argument p1s
      // corresponds to the arrays of elements C and D from the specification.
      async prove_batch(key, p0, p1s, r) {
        const rnd = r ? r : await this.randomScalar();
        const { M, Z } = await computeComposites(this.params, p0[1], p1s, key, this.crypto);
        const t2 = p0[0].mul(rnd);
        const t3 = M.mul(rnd);
        const c = await challenge(this.group, this.params, [p0[1], M, Z, t2, t3]);
        const s = rnd.sub(c.mul(key));
        return new DLEQProof(c, s);
      }
    };
    exports.DLEQProver = DLEQProver;
  }
});

// node_modules/@cloudflare/voprf-ts/lib/cjs/src/client.js
var require_client = __commonJS({
  "node_modules/@cloudflare/voprf-ts/lib/cjs/src/client.js"(exports) {
    "use strict";
    init_polyfills();
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.POPRFClient = exports.VOPRFClient = exports.OPRFClient = void 0;
    var oprf_js_1 = require_oprf();
    var util_js_1 = require_util();
    var dleq_js_1 = require_dleq();
    var baseClient = class extends oprf_js_1.Oprf {
      randomBlinder() {
        return this.group.randomScalar();
      }
      async blind(inputs) {
        const eltList = [];
        const blinds = [];
        for (const input of inputs) {
          const scalar = await this.randomBlinder();
          const inputElement = await this.group.hashToGroup(input, this.getDST(oprf_js_1.Oprf.LABELS.HashToGroupDST));
          if (inputElement.isIdentity()) {
            throw new Error("InvalidInputError");
          }
          eltList.push(inputElement.mul(scalar));
          blinds.push(scalar);
        }
        const evalReq = new oprf_js_1.EvaluationRequest(eltList);
        const finData = new oprf_js_1.FinalizeData(inputs, blinds, evalReq);
        return [finData, evalReq];
      }
      async doFinalize(finData, evaluation, info = new Uint8Array(0)) {
        const n = finData.inputs.length;
        if (finData.blinds.length !== n || evaluation.evaluated.length !== n) {
          throw new Error("mismatched lengths");
        }
        const outputList = [];
        for (let i = 0; i < n; i++) {
          const blindInv = finData.blinds[i].inv();
          const N = evaluation.evaluated[i].mul(blindInv);
          const unblinded = N.serialize();
          outputList.push(await this.coreFinalize(finData.inputs[i], unblinded, info));
        }
        return outputList;
      }
    };
    var OPRFClient = class extends baseClient {
      constructor(suite, ...arg) {
        super(oprf_js_1.Oprf.Mode.OPRF, suite, ...arg);
      }
      finalize(finData, evaluation) {
        return super.doFinalize(finData, evaluation);
      }
    };
    exports.OPRFClient = OPRFClient;
    var VOPRFClient = class extends baseClient {
      constructor(suite, pubKeyServer, ...arg) {
        super(oprf_js_1.Oprf.Mode.VOPRF, suite, ...arg);
        this.pubKeyServer = pubKeyServer;
      }
      async finalize(finData, evaluation) {
        if (!evaluation.proof) {
          throw new Error("no proof provided");
        }
        const pkS = this.group.desElt(this.pubKeyServer);
        const n = finData.inputs.length;
        if (evaluation.evaluated.length !== n) {
          throw new Error("mismatched lengths");
        }
        const verifier = new dleq_js_1.DLEQVerifier(this.getDLEQParams(), this.crypto);
        if (!await verifier.verify_batch([this.group.generator(), pkS], (0, util_js_1.zip)(finData.evalReq.blinded, evaluation.evaluated), evaluation.proof)) {
          throw new Error("proof failed");
        }
        return super.doFinalize(finData, evaluation);
      }
    };
    exports.VOPRFClient = VOPRFClient;
    var POPRFClient = class extends baseClient {
      constructor(suite, pubKeyServer, ...arg) {
        super(oprf_js_1.Oprf.Mode.POPRF, suite, ...arg);
        this.pubKeyServer = pubKeyServer;
      }
      async pointFromInfo(info) {
        const m = await this.scalarFromInfo(info);
        const T = this.group.mulGen(m);
        const pkS = this.group.desElt(this.pubKeyServer);
        const tw = pkS.add(T);
        if (tw.isIdentity()) {
          throw new Error("invalid info");
        }
        return tw;
      }
      async finalize(finData, evaluation, info = new Uint8Array(0)) {
        if (!evaluation.proof) {
          throw new Error("no proof provided");
        }
        const tw = await this.pointFromInfo(info);
        const n = finData.inputs.length;
        if (evaluation.evaluated.length !== n) {
          throw new Error("mismatched lengths");
        }
        const verifier = new dleq_js_1.DLEQVerifier(this.getDLEQParams(), this.crypto);
        if (!await verifier.verify_batch([this.group.generator(), tw], (0, util_js_1.zip)(evaluation.evaluated, finData.evalReq.blinded), evaluation.proof)) {
          throw new Error("proof failed");
        }
        return super.doFinalize(finData, evaluation, info);
      }
    };
    exports.POPRFClient = POPRFClient;
  }
});

// node_modules/@cloudflare/voprf-ts/lib/cjs/src/server.js
var require_server = __commonJS({
  "node_modules/@cloudflare/voprf-ts/lib/cjs/src/server.js"(exports) {
    "use strict";
    init_polyfills();
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.POPRFServer = exports.VOPRFServer = exports.OPRFServer = void 0;
    var dleq_js_1 = require_dleq();
    var oprf_js_1 = require_oprf();
    var util_js_1 = require_util();
    var baseServer = class extends oprf_js_1.Oprf {
      constructor(mode, suite, privateKey, ...arg) {
        super(mode, suite, ...arg);
        this.prover = new dleq_js_1.DLEQProver(this.getDLEQParams(), this.crypto);
        this.supportsWebCryptoOPRF = false;
        this.privateKey = privateKey;
      }
      doBlindEvaluation(blinded, key) {
        return this.supportsWebCryptoOPRF ? this.blindEvaluateWebCrypto(blinded, key) : Promise.resolve(this.blindEvaluateGroup(blinded, key));
      }
      async blindEvaluateWebCrypto(blinded, key) {
        const crKey = await crypto.subtle.importKey("raw", key, {
          name: "OPRF",
          namedCurve: this.group.id
        }, true, ["sign"]);
        const compressed = blinded.serialize(true);
        const evalBytes = new Uint8Array(await crypto.subtle.sign("OPRF", crKey, compressed));
        return this.group.desElt(evalBytes);
      }
      blindEvaluateGroup(blinded, key) {
        return blinded.mul(this.group.desScalar(key));
      }
      async secretFromInfo(info) {
        const m = await this.scalarFromInfo(info);
        const skS = this.group.desScalar(this.privateKey);
        const t = m.add(skS);
        if (t.isZero()) {
          throw new Error("inverse of zero");
        }
        const tInv = t.inv();
        return [t, tInv];
      }
      async doEvaluate(input, info = new Uint8Array(0)) {
        let secret = this.privateKey;
        if (this.mode === oprf_js_1.Oprf.Mode.POPRF) {
          const [, evalSecret] = await this.secretFromInfo(info);
          secret = evalSecret.serialize();
        }
        const P = await this.group.hashToGroup(input, this.getDST(oprf_js_1.Oprf.LABELS.HashToGroupDST));
        if (P.isIdentity()) {
          throw new Error("InvalidInputError");
        }
        const evaluated = await this.doBlindEvaluation(P, secret);
        return this.coreFinalize(input, evaluated.serialize(true), info);
      }
    };
    var OPRFServer = class extends baseServer {
      constructor(suite, privateKey, ...arg) {
        super(oprf_js_1.Oprf.Mode.OPRF, suite, privateKey, ...arg);
      }
      async blindEvaluate(req) {
        return new oprf_js_1.Evaluation(this.mode, await Promise.all(req.blinded.map((b) => this.doBlindEvaluation(b, this.privateKey))));
      }
      async evaluate(input) {
        return this.doEvaluate(input);
      }
      async verifyFinalize(input, output) {
        return (0, util_js_1.ctEqual)(output, await this.doEvaluate(input));
      }
    };
    exports.OPRFServer = OPRFServer;
    var VOPRFServer2 = class extends baseServer {
      constructor(suite, privateKey, ...arg) {
        super(oprf_js_1.Oprf.Mode.VOPRF, suite, privateKey, ...arg);
      }
      async blindEvaluate(req) {
        const evalList = await Promise.all(req.blinded.map((b) => this.doBlindEvaluation(b, this.privateKey)));
        const skS = this.group.desScalar(this.privateKey);
        const pkS = this.group.mulGen(skS);
        const proof = await this.prover.prove_batch(skS, [this.group.generator(), pkS], (0, util_js_1.zip)(req.blinded, evalList));
        return new oprf_js_1.Evaluation(this.mode, evalList, proof);
      }
      async evaluate(input) {
        return this.doEvaluate(input);
      }
      async verifyFinalize(input, output) {
        return (0, util_js_1.ctEqual)(output, await this.doEvaluate(input));
      }
    };
    exports.VOPRFServer = VOPRFServer2;
    var POPRFServer = class extends baseServer {
      constructor(suite, privateKey, ...arg) {
        super(oprf_js_1.Oprf.Mode.POPRF, suite, privateKey, ...arg);
      }
      async blindEvaluate(req, info = new Uint8Array(0)) {
        const [keyProof, evalSecret] = await this.secretFromInfo(info);
        const secret = evalSecret.serialize();
        const evalList = await Promise.all(req.blinded.map((b) => this.doBlindEvaluation(b, secret)));
        const kG = this.group.mulGen(keyProof);
        const proof = await this.prover.prove_batch(keyProof, [this.group.generator(), kG], (0, util_js_1.zip)(evalList, req.blinded));
        return new oprf_js_1.Evaluation(this.mode, evalList, proof);
      }
      async evaluate(input, info = new Uint8Array(0)) {
        return this.doEvaluate(input, info);
      }
      async verifyFinalize(input, output, info = new Uint8Array(0)) {
        return (0, util_js_1.ctEqual)(output, await this.doEvaluate(input, info));
      }
    };
    exports.POPRFServer = POPRFServer;
  }
});

// node_modules/@cloudflare/voprf-ts/lib/cjs/src/keys.js
var require_keys = __commonJS({
  "node_modules/@cloudflare/voprf-ts/lib/cjs/src/keys.js"(exports) {
    "use strict";
    init_polyfills();
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getKeySizes = getKeySizes;
    exports.validatePrivateKey = validatePrivateKey;
    exports.validatePublicKey = validatePublicKey;
    exports.randomPrivateKey = randomPrivateKey2;
    exports.derivePrivateKey = derivePrivateKey;
    exports.generatePublicKey = generatePublicKey2;
    exports.generateKeyPair = generateKeyPair;
    exports.deriveKeyPair = deriveKeyPair;
    var oprf_js_1 = require_oprf();
    var util_js_1 = require_util();
    var cryptoImpl_js_1 = require_cryptoImpl();
    function getKeySizes(id, ...arg) {
      const gg = (0, cryptoImpl_js_1.getSuiteGroup)(id, arg);
      return { Nsk: gg.scalarSize(), Npk: gg.eltSize(true) };
    }
    function validatePrivateKey(id, privateKey, ...arg) {
      try {
        const gg = (0, cryptoImpl_js_1.getSuiteGroup)(id, arg);
        const s = gg.desScalar(privateKey);
        return !s.isZero();
      } catch (_) {
        return false;
      }
    }
    function validatePublicKey(id, publicKey, ...arg) {
      try {
        const gg = (0, cryptoImpl_js_1.getSuiteGroup)(id, arg);
        const P = gg.desElt(publicKey);
        return !P.isIdentity();
      } catch (_) {
        return false;
      }
    }
    async function randomPrivateKey2(id, ...arg) {
      let priv;
      do {
        const gg = (0, cryptoImpl_js_1.getSuiteGroup)(id, arg);
        priv = await gg.randomScalar();
      } while (priv.isZero());
      return priv.serialize();
    }
    async function derivePrivateKey(mode, id, seed, info, ...arg) {
      const gg = (0, cryptoImpl_js_1.getSuiteGroup)(id, arg);
      const deriveInput = (0, util_js_1.joinAll)([seed, ...(0, util_js_1.toU16LenPrefix)(info)]);
      let counter = 0;
      let priv;
      do {
        if (counter > 255) {
          throw new Error("DeriveKeyPairError");
        }
        const hashInput = (0, util_js_1.joinAll)([deriveInput, Uint8Array.from([counter])]);
        priv = await gg.hashToScalar(hashInput, oprf_js_1.Oprf.getDST(mode, id, oprf_js_1.Oprf.LABELS.DeriveKeyPairDST));
        counter++;
      } while (priv.isZero());
      return priv.serialize();
    }
    function generatePublicKey2(id, privateKey, ...arg) {
      const gg = (0, cryptoImpl_js_1.getSuiteGroup)(id, arg);
      const priv = gg.desScalar(privateKey);
      const pub = gg.mulGen(priv);
      return pub.serialize(true);
    }
    async function generateKeyPair(id, ...arg) {
      const privateKey = await randomPrivateKey2(id, ...arg);
      const publicKey = generatePublicKey2(id, privateKey, ...arg);
      return { privateKey, publicKey };
    }
    async function deriveKeyPair(mode, id, seed, info, ...arg) {
      const privateKey = await derivePrivateKey(mode, id, seed, info, ...arg);
      const publicKey = generatePublicKey2(id, privateKey, ...arg);
      return { privateKey, publicKey };
    }
  }
});

// node_modules/@cloudflare/voprf-ts/lib/cjs/src/cryptoTypes.js
var require_cryptoTypes = __commonJS({
  "node_modules/@cloudflare/voprf-ts/lib/cjs/src/cryptoTypes.js"(exports) {
    "use strict";
    init_polyfills();
    Object.defineProperty(exports, "__esModule", { value: true });
  }
});

// node_modules/@cloudflare/voprf-ts/lib/cjs/src/index.js
var require_src = __commonJS({
  "node_modules/@cloudflare/voprf-ts/lib/cjs/src/index.js"(exports) {
    "use strict";
    init_polyfills();
    var __createBinding = exports && exports.__createBinding || (Object.create ? (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      var desc = Object.getOwnPropertyDescriptor(m, k);
      if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
        desc = { enumerable: true, get: function() {
          return m[k];
        } };
      }
      Object.defineProperty(o, k2, desc);
    }) : (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      o[k2] = m[k];
    }));
    var __exportStar = exports && exports.__exportStar || function(m, exports2) {
      for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports2, p)) __createBinding(exports2, m, p);
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    __exportStar(require_groupTypes(), exports);
    __exportStar(require_dleq(), exports);
    __exportStar(require_oprf(), exports);
    __exportStar(require_client(), exports);
    __exportStar(require_server(), exports);
    __exportStar(require_keys(), exports);
    __exportStar(require_cryptoTypes(), exports);
  }
});

// worker.ts
init_polyfills();
var import_voprf_ts = __toESM(require_src());
var SUITE = import_voprf_ts.Oprf.Suite.P256_SHA256;
var b64 = (u8) => btoa(String.fromCharCode(...u8));
var u8a = (b) => Uint8Array.from(atob(b), (c) => c.charCodeAt(0));
var j = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json" } });
var withCORS = (r) => {
  const h = new Headers(r.headers);
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  h.set("Access-Control-Allow-Headers", "content-type");
  return new Response(r.body, { status: r.status, headers: h });
};
async function loadOrInitKey(env) {
  if (!env?.KV_KEYS) throw new Error("KV binding KV_KEYS missing");
  const rec = await env.KV_KEYS.get("currentKey", { type: "json" });
  if (rec?.priv && rec?.pub && rec?.kid) return { priv: u8a(rec.priv), pub: rec.pub, kid: rec.kid };
  const priv = await (0, import_voprf_ts.randomPrivateKey)(SUITE);
  const pubU8 = (0, import_voprf_ts.generatePublicKey)(SUITE, priv);
  const kid = b64(pubU8.slice(0, 4));
  await env.KV_KEYS.put("currentKey", JSON.stringify({ priv: b64(priv), pub: b64(pubU8), kid }));
  return { priv, pub: b64(pubU8), kid };
}
var worker_default = {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return withCORS(new Response(null, { status: 204 }));
    try {
      if (req.method === "GET" && url.pathname === "/.well-known/private-token-issuer-directory") {
        const key = await loadOrInitKey(env);
        return withCORS(j({
          issuerName: "brass-issuer-pro",
          "issuer-request-uri": new URL("/token-request", url.origin).toString(),
          "token-keys": [{ "token-type": 2, "token-key": key.pub, "token-key-id": key.kid }]
        }));
      }
      if (req.method === "POST" && url.pathname === "/token-request") {
        const ct = req.headers.get("content-type") || "";
        if (!ct.includes("application/private-token-request")) return withCORS(j({ ok: false, reason: "wrong_content_type" }, 400));
        const blindReq = new Uint8Array(await req.arrayBuffer());
        const key = await loadOrInitKey(env);
        const server = new import_voprf_ts.VOPRFServer(SUITE, key.priv);
        const evaluation = await server.blindEvaluate(blindReq);
        return withCORS(new Response(evaluation, { headers: { "content-type": "application/private-token-response" } }));
      }
      if (req.method === "POST" && url.pathname === "/admin/rotate") {
        const priv = await (0, import_voprf_ts.randomPrivateKey)(SUITE);
        const pubU8 = (0, import_voprf_ts.generatePublicKey)(SUITE, priv);
        const kid = b64(pubU8.slice(0, 4));
        await env.KV_KEYS.put("currentKey", JSON.stringify({ priv: b64(priv), pub: b64(pubU8), kid }));
        return withCORS(j({ ok: true, kid }));
      }
      return withCORS(j({ ok: false, reason: "not_found" }, 404));
    } catch (e) {
      console.error("issuer error:", e);
      return withCORS(j({ ok: false, reason: "exception", message: String(e) }, 500));
    }
  }
};
export {
  worker_default as default
};
