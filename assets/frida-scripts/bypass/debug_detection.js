// debug_detection.js — Neutralize common debugger checks (Debug, FLAG_DEBUGGABLE, ptrace TRACEME, TracerPid) for authorized lab testing.
// category: bypass
// platform: android
// usage: frida_run_named_script("<package>", "bypass/debug_detection")
// maya-frida-message: { tag, event, data }
//
// Native hooks attach only when the export exists. TracerPid is rewritten to 0
// for /proc status reads. Other ptrace requests are left unchanged.
'use strict';

var MAYA = (function () {
  var tag = "debug_detection";

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

var FLAG_DEBUGGABLE = 2;
var statusStreams = {};

function clearDebuggable(info) {
  if (!info) return info;
  try {
    var flags = info.flags.value;
    if ((flags & FLAG_DEBUGGABLE) !== 0) {
      info.flags.value = flags & ~FLAG_DEBUGGABLE;
      MAYA.emit("hit", { hook: "ApplicationInfo.flags", cleared: "FLAG_DEBUGGABLE" });
    }
  } catch (error) {
    MAYA.fail("ApplicationInfo.flags", error);
  }
  return info;
}

function hookDebuggerFlags() {
  if (!Java.available) {
    MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
    return;
  }
  Java.perform(function () {
    MAYA.optional("android.os.Debug.isDebuggerConnected", function () {
      var Debug = Java.use("android.os.Debug");
      Debug.isDebuggerConnected.implementation = function () {
        MAYA.emit("hit", { hook: "Debug.isDebuggerConnected" });
        return false;
      };
      if (Debug.waitingForDebugger) {
        Debug.waitingForDebugger.implementation = function () {
          MAYA.emit("hit", { hook: "Debug.waitingForDebugger" });
          return false;
        };
      }
      MAYA.emit("hook", { hook: "android.os.Debug.isDebuggerConnected" });
    });

    ["android.app.ContextImpl", "android.app.Application", "android.app.ApplicationPackageManager"].forEach(function (className) {
      MAYA.optional(className + ".getApplicationInfo", function () {
        var cls = Java.use(className);
        if (!cls.getApplicationInfo) {
          MAYA.emit("miss", { hook: className + ".getApplicationInfo" });
          return;
        }
        cls.getApplicationInfo.overloads.forEach(function (overload) {
          overload.implementation = function () {
            return clearDebuggable(MAYA.callOriginal(overload, this, arguments));
          };
        });
        MAYA.emit("hook", { hook: className + ".getApplicationInfo" });
      });
    });

    MAYA.optional("java.io.BufferedReader.readLine", function () {
      var BufferedReader = Java.use("java.io.BufferedReader");
      var readLine = BufferedReader.readLine.overload();
      readLine.implementation = function () {
        var line = readLine.call(this);
        if (line && String(line).indexOf("TracerPid:") === 0) {
          MAYA.emit("hit", { hook: "BufferedReader.readLine", field: "TracerPid" });
          return "TracerPid:\t0";
        }
        return line;
      };
      MAYA.emit("hook", { hook: "java.io.BufferedReader.readLine" });
    });

    MAYA.emit("ready", { script: "debug_detection", layer: "java" });
  });
}

function hookPtrace() {
  MAYA.guard("ptrace", function () {
    var address = Module.findExportByName(null, "ptrace");
    if (!address) {
      MAYA.emit("miss", { hook: "ptrace" });
      return;
    }
    Interceptor.attach(address, {
      onEnter: function (args) {
        this.request = args[0].toInt32();
      },
      onLeave: function (retval) {
        if (this.request === 0) {
          retval.replace(0);
          MAYA.emit("hit", { hook: "ptrace", request: "PTRACE_TRACEME" });
        }
      }
    });
    MAYA.emit("hook", { hook: "ptrace" });
  });
}

function hookTracerPid() {
  MAYA.guard("fopen", function () {
    var fopen = Module.findExportByName(null, "fopen");
    var fgets = Module.findExportByName(null, "fgets");
    var fclose = Module.findExportByName(null, "fclose");
    if (!fopen || !fgets) {
      MAYA.emit("miss", { hook: "fopen", fopen: Boolean(fopen), fgets: Boolean(fgets) });
      return;
    }
    Interceptor.attach(fopen, {
      onEnter: function (args) {
        this.path = "";
        try {
          if (args[0] && !args[0].isNull()) this.path = args[0].readUtf8String() || "";
        } catch (error) {
          this.path = "";
        }
      },
      onLeave: function (retval) {
        if (retval.isNull()) return;
        if (this.path.indexOf("/proc/") !== -1 && this.path.indexOf("status") !== -1) {
          statusStreams[retval.toString()] = true;
        }
      }
    });
    Interceptor.attach(fgets, {
      onEnter: function (args) {
        this.buf = args[0];
        this.capacity = args[1].toInt32();
        this.stream = args[2];
      },
      onLeave: function (retval) {
        if (retval.isNull() || !this.stream) return;
        if (!statusStreams[this.stream.toString()]) return;
        var line = "";
        try {
          line = this.buf.readUtf8String() || "";
        } catch (error) {
          return;
        }
        var replacement = "TracerPid:\t0\n";
        if (line.indexOf("TracerPid:") === 0 && this.capacity > replacement.length) {
          this.buf.writeUtf8String(replacement);
          MAYA.emit("hit", { hook: "fgets", field: "TracerPid" });
        }
      }
    });
    if (fclose) {
      Interceptor.attach(fclose, {
        onEnter: function (args) {
          if (args[0] && !args[0].isNull()) delete statusStreams[args[0].toString()];
        }
      });
    }
    MAYA.emit("hook", { hook: "fopen" });
  });
}

hookPtrace();
hookTracerPid();
hookDebuggerFlags();
