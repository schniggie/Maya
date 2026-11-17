// ssl_pinning_flutter.js — Bypass Flutter BoringSSL custom verify by hooking SSL_CTX_set_custom_verify when libflutter.so exports it.
// category: bypass
// platform: android
// usage: frida_run_named_script("<package>", "bypass/ssl_pinning_flutter")
// maya-frida-message: { tag, event, data }
//
// Flutter statically links BoringSSL and often loads libflutter.so after spawn.
// This script hooks the exported custom-verify setter and replaces the callback
// with one that returns ssl_verify_ok (0). It does not scan byte patterns.
// If the build strips the export, the script reports "miss" instead of patching
// an unrelated function. Java pinning is covered by bypass/ssl_pinning_universal.
'use strict';

var MAYA = (function () {
  var tag = "ssl_pinning_flutter";

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

var FLUTTER_EXPORTS = ["SSL_CTX_set_custom_verify", "SSL_set_custom_verify"];
var hookedExports = {};
var permissiveVerify = new NativeCallback(function () {
  return 0;
}, "int", ["pointer", "pointer"]);

function findFlutterExport(exportName) {
  var direct = Module.findExportByName("libflutter.so", exportName);
  if (direct) return direct;
  var module = Process.findModuleByName("libflutter.so");
  if (!module) return null;
  var exports = [];
  try {
    exports = module.enumerateExports();
  } catch (error) {
    MAYA.fail("libflutter.so.enumerateExports", error);
    exports = [];
  }
  var index;
  for (index = 0; index < exports.length; index += 1) {
    if (exports[index].name === exportName) return exports[index].address;
  }
  try {
    var symbols = module.enumerateSymbols();
    for (index = 0; index < symbols.length; index += 1) {
      if (symbols[index].name.indexOf(exportName) !== -1) return symbols[index].address;
    }
  } catch (error) {
    MAYA.emit("miss", { hook: "libflutter.so.enumerateSymbols", message: String(error) });
  }
  return null;
}

function attachCustomVerify(exportName) {
  if (hookedExports[exportName]) return true;
  var address = findFlutterExport(exportName);
  if (!address) return false;
  Interceptor.attach(address, {
    onEnter: function (args) {
      args[2] = permissiveVerify;
      MAYA.emit("hit", {
        hook: exportName,
        module: "libflutter.so",
        address: address.toString()
      });
    }
  });
  hookedExports[exportName] = true;
  MAYA.emit("hook", { hook: exportName, module: "libflutter.so", address: address.toString() });
  return true;
}

function tryAttachAll() {
  var found = 0;
  FLUTTER_EXPORTS.forEach(function (name) {
    if (attachCustomVerify(name)) found += 1;
  });
  return found;
}

function watchFlutterLoad() {
  ["android_dlopen_ext", "dlopen"].forEach(function (name) {
    MAYA.guard(name, function () {
      var address = Module.findExportByName(null, name);
      if (!address) {
        MAYA.emit("miss", { hook: name });
        return;
      }
      Interceptor.attach(address, {
        onEnter: function (args) {
          this.path = "";
          try {
            if (args[0] && !args[0].isNull()) this.path = args[0].readUtf8String() || "";
          } catch (error) {
            this.path = "";
          }
        },
        onLeave: function () {
          if (this.path && this.path.indexOf("libflutter.so") !== -1) tryAttachAll();
        }
      });
      MAYA.emit("hook", { hook: name });
    });
  });
}

var attempts = 0;
watchFlutterLoad();
var timer = setInterval(function () {
  attempts += 1;
  var found = 0;
  try {
    found = tryAttachAll();
  } catch (error) {
    MAYA.fail("libflutter.so", error);
  }
  if (found > 0 || attempts >= 20) {
    clearInterval(timer);
    if (found === 0) {
      MAYA.emit("miss", {
        hook: "SSL_CTX_set_custom_verify",
        message: "libflutter.so did not export SSL_CTX_set_custom_verify or SSL_set_custom_verify"
      });
    }
    MAYA.emit("done", { attempts: attempts, hooked: Object.keys(hookedExports) });
  }
}, 500);
