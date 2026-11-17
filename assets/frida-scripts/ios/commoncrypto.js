// commoncrypto.js — Log CCCrypt operation, algorithm, options, and lengths. Does not copy key, IV, or data bytes.
// category: ios
// platform: ios
// usage: frida_run_named_script("<bundle-id>", "ios/commoncrypto")
// maya-frida-message: { tag, event, data }
//
// Observation only. Interceptor.attach leaves the original function in place.
// Key and IV pointers are not read.
'use strict';

var MAYA = (function () {
  var tag = "commoncrypto";

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
var HIT_CAP = 80;
var CC_OP = { 0: "encrypt", 1: "decrypt" };
var CC_ALG = { 0: "AES", 1: "DES", 2: "3DES", 3: "CAST", 4: "RC4", 5: "RC2", 6: "Blowfish" };
var WEAK_ALGS = { DES: true, "3DES": true, CAST: true, RC4: true, RC2: true, Blowfish: true };
var CC_ECB = 2;

function observe(data) {
  hits += 1;
  if (hits <= HIT_CAP) {
    MAYA.emit("hit", data);
    return;
  }
  if (hits === HIT_CAP + 1) MAYA.emit("hit", { truncated: true, reported: HIT_CAP });
}

function findExport(name) {
  var address = Module.findExportByName("libcommonCrypto.dylib", name);
  if (address) return address;
  return Module.findExportByName(null, name);
}

function describe(op, alg, options, keyLength) {
  var operation = CC_OP[op] || ("op_" + op);
  var algorithm = CC_ALG[alg] || ("alg_" + alg);
  var ecb = (options & CC_ECB) === CC_ECB;
  return {
    operation: operation,
    algorithm: algorithm,
    ecb: ecb,
    key_length: keyLength,
    weak: WEAK_ALGS[algorithm] === true || ecb,
    copies_key: false
  };
}

function hook(name, onEnter) {
  MAYA.optional(name, function () {
    var address = findExport(name);
    if (!address) {
      MAYA.emit("miss", { hook: name });
      return;
    }
    Interceptor.attach(address, {
      onEnter: function (args) {
        observe(onEnter(args));
      }
    });
    MAYA.emit("hook", { hook: name });
  });
}

if (!ObjC.available) {
  MAYA.emit("error", { hook: "ObjC", message: "Objective-C runtime is not available" });
} else {
  hook("CCCrypt", function (args) {
    var detail = describe(args[0].toInt32(), args[1].toInt32(), args[2].toUInt32(), args[4].toUInt32());
    detail.hook = "CCCrypt";
    detail.input_length = args[7].toUInt32();
    return detail;
  });
  hook("CCCryptorCreate", function (args) {
    var detail = describe(args[0].toInt32(), args[1].toInt32(), args[2].toUInt32(), args[4].toUInt32());
    detail.hook = "CCCryptorCreate";
    return detail;
  });
  MAYA.emit("ready", { script: "commoncrypto", copies_key: false });
}
