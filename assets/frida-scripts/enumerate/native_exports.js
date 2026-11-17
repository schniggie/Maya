// native_exports.js — List native modules and, when LIB_NAME is set, their exported symbols.
// category: enumerate
// platform: android
// usage: frida_run_named_script("<package>", "enumerate/native_exports")
// maya-frida-message: { tag, event, data }
//
// With LIB_NAME empty, app modules under /data/app or /data/data are summarized
// with export counts. Set LIB_NAME to a module name or path substring to print
// export names. A module that cannot be enumerated emits "error" and is skipped.
'use strict';

var LIB_NAME = "";
var EXPORT_CAP = 200;

var MAYA = (function () {
  var tag = "native_exports";

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

function isAppModule(module) {
  var path = module.path || "";
  if (path.indexOf("/data/app/") !== -1) return true;
  if (path.indexOf("/data/data/") !== -1) return true;
  if (module.name === "libflutter.so" || module.name === "libapp.so") return true;
  return false;
}

function matchesFilter(module) {
  if (!LIB_NAME) return isAppModule(module);
  if (module.name.indexOf(LIB_NAME) !== -1) return true;
  return (module.path || "").indexOf(LIB_NAME) !== -1;
}

function exportsOf(module) {
  try {
    return module.enumerateExports();
  } catch (error) {
    MAYA.fail(module.name, error);
    return [];
  }
}

MAYA.emit("ready", { script: "native_exports", lib_name: LIB_NAME });

var modules = [];
try {
  modules = Process.enumerateModules();
} catch (error) {
  MAYA.fail("Process.enumerateModules", error);
}

var summarized = 0;
modules.forEach(function (module) {
  if (!matchesFilter(module)) return;
  summarized += 1;
  var exports = exportsOf(module);
  var names = [];
  if (LIB_NAME) {
    var index;
    for (index = 0; index < exports.length && index < EXPORT_CAP; index += 1) {
      names.push({
        name: exports[index].name,
        type: exports[index].type,
        address: exports[index].address.toString()
      });
    }
  }
  MAYA.emit("hit", {
    module: module.name,
    path: MAYA.text(module.path, 300),
    base: module.base.toString(),
    size: module.size,
    export_count: exports.length,
    exports: names,
    export_names_included: Boolean(LIB_NAME),
    truncated: Boolean(LIB_NAME) && exports.length > EXPORT_CAP
  });
});

if (summarized === 0) {
  MAYA.emit("miss", {
    hook: "native_exports",
    message: LIB_NAME
      ? "no module matched LIB_NAME"
      : "no app-scoped module found; set LIB_NAME to a loaded module"
  });
}

MAYA.emit("done", { modules: summarized, lib_name: LIB_NAME });
