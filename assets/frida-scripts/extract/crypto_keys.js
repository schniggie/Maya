// crypto_keys.js — Observe Cipher, SecretKeySpec, and Mac keys created in-process. Output stays in the local Frida session.
// category: extract
// platform: android
// usage: frida_run_named_script("<package>", "extract/crypto_keys")
// maya-frida-message: { tag, event, data }
//
// AndroidKeyStore keys often return null from getEncoded(); that is reported
// as exportable:false instead of throwing. Key material is not sent off-device.
'use strict';

var MAYA = (function () {
  var tag = "crypto_keys";

  function emit(event, data) {
    var message = { tag: tag, event: event, data: data || {} };
    send(message);
    console.log(JSON.stringify(message));
    return message;
  }

  function fail(hook, error) {
    var message = error && error.message ? String(error.message) : String(error);
    return emit("error", { hook: hook, message: message });
  }

  function guard(hook, fn) {
    try {
      return fn();
    } catch (error) {
      fail(hook, error);
      return null;
    }
  }

  function optional(hook, fn) {
    try {
      return fn();
    } catch (error) {
      var message = error && error.message ? String(error.message) : String(error);
      var absent = message.indexOf("ClassNotFound") !== -1
        || message.indexOf("Didn't find class") !== -1
        || message.indexOf("not found") !== -1
        || message.indexOf("has no method") !== -1
        || message.indexOf("undefined") !== -1;
      if (absent) emit("miss", { hook: hook, message: message });
      else fail(hook, error);
      return null;
    }
  }

  function text(value, limit) {
    if (value === null || value === undefined) return null;
    var rendered = String(value);
    var cap = limit || 240;
    if (rendered.length <= cap) return rendered;
    return rendered.slice(0, cap) + "...";
  }

  function callOriginal(method, receiver, args) {
    var count = args.length;
    if (count === 0) return method.call(receiver);
    if (count === 1) return method.call(receiver, args[0]);
    if (count === 2) return method.call(receiver, args[0], args[1]);
    if (count === 3) return method.call(receiver, args[0], args[1], args[2]);
    if (count === 4) return method.call(receiver, args[0], args[1], args[2], args[3]);
    if (count === 5) return method.call(receiver, args[0], args[1], args[2], args[3], args[4]);
    if (count === 6) return method.call(receiver, args[0], args[1], args[2], args[3], args[4], args[5]);
    if (count === 7) return method.call(receiver, args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
    if (count === 8) return method.call(receiver, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
    fail("callOriginal", "unsupported arity " + count);
    return null;
  }

  return {
    emit: emit,
    fail: fail,
    guard: guard,
    optional: optional,
    text: text,
    callOriginal: callOriginal
  };
})();

var hits = 0;
var HIT_CAP = 60;

function observe(data) {
  hits += 1;
  if (hits <= HIT_CAP) {
    MAYA.emit("hit", data);
    return;
  }
  if (hits === HIT_CAP + 1) MAYA.emit("hit", { truncated: true, reported: HIT_CAP });
}

function bytesToHex(bytes) {
  if (!bytes) return null;
  var hex = "";
  var index;
  for (index = 0; index < bytes.length; index += 1) {
    var byte = (bytes[index] & 0xff).toString(16);
    hex += byte.length === 1 ? "0" + byte : byte;
  }
  return hex;
}

function encodedKey(key) {
  if (!key) return { key_hex: null, key_bytes: 0, exportable: false };
  var encoded = null;
  try {
    encoded = key.getEncoded();
  } catch (error) {
    return { key_hex: null, key_bytes: 0, exportable: false, message: String(error) };
  }
  if (!encoded) return { key_hex: null, key_bytes: 0, exportable: false };
  return { key_hex: bytesToHex(encoded), key_bytes: encoded.length, exportable: true };
}

function cipherMode(mode) {
  if (mode === 1) return "ENCRYPT";
  if (mode === 2) return "DECRYPT";
  if (mode === 3) return "WRAP";
  if (mode === 4) return "UNWRAP";
  return String(mode);
}

function hookCipher() {
  MAYA.guard("javax.crypto.Cipher.init", function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    var signatures = [
      ["int", "java.security.Key"],
      ["int", "java.security.Key", "java.security.SecureRandom"],
      ["int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec"],
      ["int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec", "java.security.SecureRandom"],
      ["int", "java.security.cert.Certificate"],
      ["int", "java.security.cert.Certificate", "java.security.SecureRandom"]
    ];
    signatures.forEach(function (signature) {
      MAYA.optional("javax.crypto.Cipher.init(" + signature.join(",") + ")", function () {
        var method = Cipher.init.overload.apply(Cipher.init, signature);
        method.implementation = function () {
          var algorithm = "";
          try {
            algorithm = String(this.getAlgorithm());
          } catch (error) {
            algorithm = "";
          }
          var keyInfo = signature[1].indexOf("Key") !== -1 ? encodedKey(arguments[1]) : { key_hex: null, exportable: false };
          observe({
            hook: "Cipher.init",
            algorithm: algorithm,
            mode: cipherMode(arguments[0]),
            key_hex: keyInfo.key_hex,
            key_bytes: keyInfo.key_bytes || 0,
            exportable: keyInfo.exportable
          });
          return MAYA.callOriginal(method, this, arguments);
        };
        MAYA.emit("hook", { hook: "Cipher.init", signature: signature });
      });
    });
  });
}

function hookSecretKeySpec() {
  MAYA.guard("javax.crypto.spec.SecretKeySpec", function () {
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    var full = SecretKeySpec.$init.overload("[B", "java.lang.String");
    full.implementation = function (key, algorithm) {
      observe({
        hook: "SecretKeySpec",
        algorithm: String(algorithm),
        key_hex: bytesToHex(key),
        key_bytes: key ? key.length : 0,
        exportable: true
      });
      return full.call(this, key, algorithm);
    };
    MAYA.optional("SecretKeySpec.$init(offset)", function () {
      var slice = SecretKeySpec.$init.overload("[B", "int", "int", "java.lang.String");
      slice.implementation = function (key, offset, length, algorithm) {
        observe({
          hook: "SecretKeySpec",
          algorithm: String(algorithm),
          key_bytes: length,
          offset: offset,
          exportable: true
        });
        return slice.call(this, key, offset, length, algorithm);
      };
    });
    MAYA.emit("hook", { hook: "javax.crypto.spec.SecretKeySpec" });
  });
}

function hookMac() {
  MAYA.guard("javax.crypto.Mac.init", function () {
    var Mac = Java.use("javax.crypto.Mac");
    var init = Mac.init.overload("java.security.Key");
    init.implementation = function (key) {
      var info = encodedKey(key);
      var algorithm = "";
      try {
        algorithm = String(this.getAlgorithm());
      } catch (error) {
        algorithm = "";
      }
      observe({
        hook: "Mac.init",
        algorithm: algorithm,
        key_hex: info.key_hex,
        key_bytes: info.key_bytes,
        exportable: info.exportable
      });
      return init.call(this, key);
    };
    MAYA.emit("hook", { hook: "javax.crypto.Mac.init" });
  });
}

if (!Java.available) {
  MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
} else {
  Java.perform(function () {
    try {
      hookCipher();
      hookSecretKeySpec();
      hookMac();
      MAYA.emit("ready", { script: "crypto_keys" });
    } catch (error) {
      MAYA.fail("main", error);
    }
  });
}
