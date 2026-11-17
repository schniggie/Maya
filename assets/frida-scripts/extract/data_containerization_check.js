// data_containerization_check.js — Report sandbox paths, world-readable preference modes, and writes outside the app sandbox.
// category: extract
// platform: android
// usage: frida_run_named_script("<package>", "extract/data_containerization_check")
// maya-frida-message: { tag, event, data }
//
// Attach after Application.onCreate. currentApplication() is null earlier and
// is reported as "miss". Writes inside /data/data or /data/user are not logged.
'use strict';

var MAYA = (function () {
  var tag = "data_containerization_check";

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

function insideSandbox(path) {
  if (!path) return false;
  return path.indexOf("/data/data/") === 0 || path.indexOf("/data/user/") === 0;
}

function reportDirectories() {
  MAYA.guard("app_directories", function () {
    var application = Java.use("android.app.ActivityThread").currentApplication();
    if (!application) {
      MAYA.emit("miss", { hook: "app_directories", message: "currentApplication() is null; attach after startup" });
      return;
    }
    var context = application.getApplicationContext();
    var externalPath = null;
    try {
      var external = context.getExternalFilesDir(null);
      externalPath = external ? String(external.getAbsolutePath()) : null;
    } catch (error) {
      externalPath = null;
    }
    MAYA.emit("hit", {
      hook: "app_directories",
      data_dir: String(context.getDataDir().getAbsolutePath()),
      files_dir: String(context.getFilesDir().getAbsolutePath()),
      cache_dir: String(context.getCacheDir().getAbsolutePath()),
      external_files_dir: externalPath
    });
  });
}

function hookFileWrites() {
  MAYA.optional("java.io.FileOutputStream", function () {
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    var fromFile = FileOutputStream.$init.overload("java.io.File");
    fromFile.implementation = function (file) {
      var path = "";
      try {
        path = String(file.getAbsolutePath());
      } catch (error) {
        path = "";
      }
      if (path && !insideSandbox(path)) {
        var external = path.indexOf("/sdcard/") === 0 || path.indexOf("/storage/emulated/") === 0;
        observe({
          hook: "FileOutputStream",
          path: MAYA.text(path, 240),
          external_storage: external,
          compliant: false
        });
      }
      return fromFile.call(this, file);
    };
    MAYA.emit("hook", { hook: "java.io.FileOutputStream" });
  });
}

function preferenceMode(mode) {
  if (mode === 0) return "PRIVATE";
  if (mode === 1) return "MODE_WORLD_READABLE";
  if (mode === 2) return "MODE_WORLD_WRITABLE";
  if (mode === 4) return "MODE_MULTI_PROCESS";
  return "mode_" + mode;
}

function hookPreferences() {
  MAYA.optional("android.content.ContextWrapper.getSharedPreferences", function () {
    var ContextWrapper = Java.use("android.content.ContextWrapper");
    var method = ContextWrapper.getSharedPreferences.overload("java.lang.String", "int");
    method.implementation = function (name, mode) {
      observe({
        hook: "getSharedPreferences",
        name: MAYA.text(name, 120),
        mode: preferenceMode(mode),
        compliant: mode === 0
      });
      return method.call(this, name, mode);
    };
    MAYA.emit("hook", { hook: "ContextWrapper.getSharedPreferences" });
  });
}

function hookDatabases() {
  MAYA.optional("android.database.sqlite.SQLiteOpenHelper.getWritableDatabase", function () {
    var Helper = Java.use("android.database.sqlite.SQLiteOpenHelper");
    var method = Helper.getWritableDatabase.overload();
    method.implementation = function () {
      var db = method.call(this);
      var path = "";
      try {
        path = String(db.getPath());
      } catch (error) {
        path = "";
      }
      observe({
        hook: "SQLiteOpenHelper.getWritableDatabase",
        path: MAYA.text(path, 240),
        compliant: insideSandbox(path)
      });
      return db;
    };
    MAYA.emit("hook", { hook: "SQLiteOpenHelper.getWritableDatabase" });
  });
}

function reportEncryptedPrefs() {
  try {
    Java.use("androidx.security.crypto.EncryptedSharedPreferences");
    MAYA.emit("hit", { hook: "EncryptedSharedPreferences", present: true });
  } catch (error) {
    MAYA.emit("miss", { hook: "EncryptedSharedPreferences", present: false });
  }
}

function hookKeyStore() {
  MAYA.optional("java.security.KeyStore.getInstance", function () {
    var KeyStore = Java.use("java.security.KeyStore");
    var method = KeyStore.getInstance.overload("java.lang.String");
    method.implementation = function (type) {
      var name = String(type);
      observe({
        hook: "KeyStore.getInstance",
        keystore_type: name,
        hardware_backed: name === "AndroidKeyStore"
      });
      return method.call(this, type);
    };
    MAYA.emit("hook", { hook: "KeyStore.getInstance" });
  });
}

if (!Java.available) {
  MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
} else {
  Java.perform(function () {
    try {
      reportDirectories();
      hookFileWrites();
      hookPreferences();
      hookDatabases();
      reportEncryptedPrefs();
      hookKeyStore();
      MAYA.emit("ready", { script: "data_containerization_check" });
    } catch (error) {
      MAYA.fail("main", error);
    }
  });
}
