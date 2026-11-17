// root_detection_universal.js — Hide common root signals (su paths, su exec, Build.TAGS, RootBeer, root packages) during authorized testing.
// category: bypass
// platform: android
// usage: frida_run_named_script("<package>", "bypass/root_detection_universal")
// maya-frida-message: { tag, event, data }
//
// File.exists and Runtime.exec are replaced for this session. Do not concatenate
// this script with another that hooks the same methods; the later hook wins.
// Only commands that look like su, magisk, or busybox probes are blocked.
'use strict';

var MAYA = (function () {
  var tag = "root_detection_universal";

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

var ROOT_PATHS = {
  "/system/app/Superuser.apk": true,
  "/sbin/su": true,
  "/system/bin/su": true,
  "/system/xbin/su": true,
  "/data/local/xbin/su": true,
  "/data/local/bin/su": true,
  "/system/sd/xbin/su": true,
  "/system/bin/failsafe/su": true,
  "/data/local/su": true,
  "/su/bin/su": true,
  "/system/xbin/busybox": true,
  "/data/adb/magisk": true,
  "/data/adb/ksu": true,
  "/sbin/magisk": true
};

var ROOT_PACKAGES = {
  "com.topjohnwu.magisk": true,
  "io.github.vvb2060.magisk": true,
  "com.topjohnwu.magisk.alpha": true,
  "eu.chainfire.supersu": true,
  "com.noshufou.android.su": true,
  "com.koushikdutta.superuser": true,
  "com.thirdparty.superuser": true,
  "com.kingroot.kinguser": true,
  "com.kingo.root": true,
  "com.devadvance.rootcloak": true,
  "de.robv.android.xposed.installer": true,
  "me.weishu.kernelsu": true
};

function isRootPath(path) {
  if (!path) return false;
  if (Object.prototype.hasOwnProperty.call(ROOT_PATHS, path)) return true;
  if (path.indexOf("/magisk") !== -1) return true;
  if (path.length >= 3 && path.indexOf("/su") === path.length - 3) return true;
  return false;
}

function isRootProbe(command) {
  var text = String(command);
  if (text.indexOf("magisk") !== -1) return true;
  if (text.indexOf("busybox") !== -1) return true;
  if (text.indexOf("which su") !== -1) return true;
  return /(^|[\s;|&`/])su([\s;|&`]|$)/.test(text);
}

function commandText(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  var index;
  try {
    if (typeof value.join === "function") return value.join(" ");
  } catch (error) { /* Java arrays have no join */ }
  try {
    if (value.size) {
      var listed = [];
      for (index = 0; index < value.size(); index += 1) listed.push(String(value.get(index)));
      return listed.join(" ");
    }
  } catch (error) { /* not a java.util.List */ }
  try {
    if (value.length !== undefined) {
      var items = [];
      for (index = 0; index < value.length; index += 1) items.push(String(value[index]));
      return items.join(" ");
    }
  } catch (error) { /* not array-like */ }
  return String(value);
}

function hookFileExists() {
  MAYA.guard("java.io.File.exists", function () {
    var File = Java.use("java.io.File");
    var exists = File.exists;
    exists.implementation = function () {
      var path = "";
      try {
        path = String(this.getAbsolutePath());
      } catch (error) {
        return exists.call(this);
      }
      if (isRootPath(path)) {
        MAYA.emit("hit", { hook: "java.io.File.exists", path: path });
        return false;
      }
      return exists.call(this);
    };
    MAYA.emit("hook", { hook: "java.io.File.exists" });
  });
}

function hookRuntimeExec() {
  MAYA.guard("java.lang.Runtime.exec", function () {
    var Runtime = Java.use("java.lang.Runtime");
    var IOException = Java.use("java.io.IOException");
    Runtime.exec.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var command = commandText(arguments[0]);
        if (isRootProbe(command)) {
          MAYA.emit("hit", { hook: "java.lang.Runtime.exec", command: MAYA.text(command, 180) });
          throw IOException.$new("blocked root probe");
        }
        return MAYA.callOriginal(overload, this, arguments);
      };
    });
    MAYA.emit("hook", { hook: "java.lang.Runtime.exec" });
  });
}

function hookProcessBuilder() {
  MAYA.optional("java.lang.ProcessBuilder.start", function () {
    var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
    var IOException = Java.use("java.io.IOException");
    var start = ProcessBuilder.start;
    start.implementation = function () {
      var command = "";
      try {
        command = commandText(this.command());
      } catch (error) {
        command = "";
      }
      if (isRootProbe(command)) {
        MAYA.emit("hit", { hook: "java.lang.ProcessBuilder.start", command: MAYA.text(command, 180) });
        throw IOException.$new("blocked root probe");
      }
      return start.call(this);
    };
    MAYA.emit("hook", { hook: "java.lang.ProcessBuilder.start" });
  });
}

function hookBuildTags() {
  MAYA.guard("android.os.Build.TAGS", function () {
    var Build = Java.use("android.os.Build");
    Build.TAGS.value = "release-keys";
    MAYA.emit("hook", { hook: "android.os.Build.TAGS", value: "release-keys" });
  });
}

function hookRootBeer() {
  var methods = [
    "isRooted",
    "isRootedWithoutBusyBoxCheck",
    "detectRootManagementApps",
    "detectPotentiallyDangerousApps",
    "detectTestKeys",
    "checkForBusyBoxBinary",
    "checkForSuBinary",
    "checkSuExists",
    "checkForRWPaths",
    "checkForDangerousProps",
    "checkForRootNative",
    "detectRootCloakingApps"
  ];
  MAYA.optional("com.scottyab.rootbeer.RootBeer", function () {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    var hooked = 0;
    methods.forEach(function (name) {
      MAYA.optional("com.scottyab.rootbeer.RootBeer." + name, function () {
        if (!RootBeer[name]) {
          MAYA.emit("miss", { hook: "RootBeer." + name });
          return;
        }
        RootBeer[name].overloads.forEach(function (overload) {
          overload.implementation = function () {
            MAYA.emit("hit", { hook: "RootBeer." + name });
            return false;
          };
        });
        hooked += 1;
      });
    });
    MAYA.emit("hook", { hook: "com.scottyab.rootbeer.RootBeer", methods: hooked });
  });
}

function hookPackageLookup() {
  MAYA.optional("android.app.ApplicationPackageManager.getPackageInfo", function () {
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    var NameNotFound = Java.use("android.content.pm.PackageManager$NameNotFoundException");
    PackageManager.getPackageInfo.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var packageName = arguments.length ? String(arguments[0]) : "";
        if (Object.prototype.hasOwnProperty.call(ROOT_PACKAGES, packageName)) {
          MAYA.emit("hit", { hook: "getPackageInfo", package: packageName });
          throw NameNotFound.$new(packageName);
        }
        return MAYA.callOriginal(overload, this, arguments);
      };
    });
    MAYA.emit("hook", { hook: "ApplicationPackageManager.getPackageInfo" });
  });
}

if (!Java.available) {
  MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
} else {
  Java.perform(function () {
    try {
      hookFileExists();
      hookRuntimeExec();
      hookProcessBuilder();
      hookBuildTags();
      hookRootBeer();
      hookPackageLookup();
      MAYA.emit("ready", { script: "root_detection_universal" });
    } catch (error) {
      MAYA.fail("main", error);
    }
  });
}
