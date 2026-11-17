// rasp_detection.js — Report known RASP or packer classes, anti-instrumentation probes, and a rough obfuscation ratio.
// category: enumerate
// platform: android
// usage: frida_run_named_script("<package>", "enumerate/rasp_detection")
// maya-frida-message: { tag, event, data }
//
// Detection only. This script does not disable RASP, hide Frida, or change
// the values those checks read. Class matches are capped per library prefix.
'use strict';

var MAYA = (function () {
  var tag = "rasp_detection";

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

var RASP_LIBRARIES = {
  "com.guardsquare.dexguard": "DexGuard (GuardSquare)",
  "com.guardsquare.ixguard": "iXGuard (GuardSquare)",
  "com.arxan": "Arxan/Digital.ai",
  "com.verimatrix": "Verimatrix",
  "com.promon": "Promon SHIELD",
  "com.licel.dexprotector": "DexProtector",
  "com.app.sealing": "AppSealing",
  "com.tencent.bugly": "Tencent Bugly",
  "com.secneo": "Bangcle/SecNeo",
  "com.baidu.protect": "Baidu Protector",
  "com.qihoo.util": "Qihoo 360 Protector",
  "com.pairip": "PairIP (Google Play Integrity)",
  "com.scottyab.rootbeer": "RootBeer",
  "org.freerasp": "FreeRASP (Talsec)",
  "com.appdome": "Appdome",
  "com.zimperium": "Zimperium"
};

function scanLibraries() {
  var names = Java.enumerateLoadedClassesSync();
  var counts = {};
  var classes = 0;
  var shortNames = 0;
  names.forEach(function (className) {
    var prefix;
    for (prefix in RASP_LIBRARIES) {
      if (!Object.prototype.hasOwnProperty.call(RASP_LIBRARIES, prefix)) continue;
      if (className.indexOf(prefix) !== 0) continue;
      counts[prefix] = (counts[prefix] || 0) + 1;
      if (counts[prefix] <= 5) {
        MAYA.emit("hit", {
          hook: "rasp_library",
          library: RASP_LIBRARIES[prefix],
          prefix: prefix,
          class: className
        });
      }
      break;
    }
    if (className.indexOf("java.") === 0 || className.indexOf("android.") === 0) return;
    if (className.indexOf("androidx.") === 0 || className.indexOf("com.google.") === 0) return;
    classes += 1;
    var simple = className.split(".").pop();
    if (simple.length <= 2) shortNames += 1;
  });
  var ratio = classes ? Math.round((shortNames / classes) * 100) : 0;
  var libraries = [];
  var key;
  for (key in counts) {
    if (Object.prototype.hasOwnProperty.call(counts, key)) {
      libraries.push({ prefix: key, library: RASP_LIBRARIES[key], classes: counts[key] });
    }
  }
  MAYA.emit("done", {
    hook: "class_scan",
    libraries: libraries,
    app_classes: classes,
    short_name_classes: shortNames,
    short_name_percent: ratio,
    obfuscation_level: ratio > 60 ? "high" : ratio > 30 ? "medium" : "low"
  });
}

function hookPortBind() {
  MAYA.optional("java.net.ServerSocket", function () {
    var ServerSocket = Java.use("java.net.ServerSocket");
    var init = ServerSocket.$init.overload("int");
    init.implementation = function (port) {
      if (port === 27042 || port === 27043) {
        MAYA.emit("hit", { hook: "ServerSocket", signal: "frida_port_bind", port: port });
      }
      return init.call(this, port);
    };
    MAYA.emit("hook", { hook: "java.net.ServerSocket" });
  });
}

function hookProcessProbe() {
  MAYA.optional("java.lang.Runtime.exec", function () {
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var command = "";
        try {
          var raw = arguments[0];
          if (raw && typeof raw.join === "function") command = raw.join(" ");
          else if (raw && raw.length !== undefined && typeof raw !== "string") {
            var parts = [];
            var index;
            for (index = 0; index < raw.length; index += 1) parts.push(String(raw[index]));
            command = parts.join(" ");
          } else command = String(raw);
        } catch (error) {
          command = "";
        }
        var lowered = command.toLowerCase();
        if (lowered.indexOf("frida") !== -1 || lowered.indexOf("xposed") !== -1
          || lowered.indexOf("substrate") !== -1 || lowered.indexOf("magisk") !== -1) {
          MAYA.emit("hit", {
            hook: "Runtime.exec",
            signal: "anti_instrumentation_command",
            command: MAYA.text(command, 180)
          });
        }
        return MAYA.callOriginal(overload, this, arguments);
      };
    });
    MAYA.emit("hook", { hook: "java.lang.Runtime.exec" });
  });
}

function hookProcReads() {
  MAYA.guard("fopen", function () {
    var fopen = Module.findExportByName(null, "fopen");
    if (!fopen) {
      MAYA.emit("miss", { hook: "fopen" });
      return;
    }
    Interceptor.attach(fopen, {
      onEnter: function (args) {
        var path = "";
        try {
          if (args[0] && !args[0].isNull()) path = args[0].readUtf8String() || "";
        } catch (error) {
          path = "";
        }
        if (!path) return;
        if (path.indexOf("/proc/self/maps") !== -1 || path.indexOf("/proc/self/status") !== -1
          || path.indexOf("/proc/self/task") !== -1) {
          MAYA.emit("hit", { hook: "fopen", signal: "proc_inspection", path: path });
        }
      }
    });
    MAYA.emit("hook", { hook: "fopen" });
  });
}

if (!Java.available) {
  MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
} else {
  Java.perform(function () {
    try {
      scanLibraries();
      hookPortBind();
      hookProcessProbe();
      hookProcReads();
      MAYA.emit("ready", { script: "rasp_detection", disables_rasp: false });
    } catch (error) {
      MAYA.fail("main", error);
    }
  });
}
