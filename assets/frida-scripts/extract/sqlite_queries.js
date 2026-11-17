// sqlite_queries.js — Observe SQLite query, exec, insert, update, and delete calls. SQL text is truncated.
// category: extract
// platform: android
// usage: frida_run_named_script("<package>", "extract/sqlite_queries")
// maya-frida-message: { tag, event, data }
//
// Each overload is optional. The original statement still runs. Bind arguments
// are counted and truncated; the script does not change the database.
'use strict';

var MAYA = (function () {
  var tag = "sqlite_queries";

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

function observe(data) {
  hits += 1;
  if (hits <= HIT_CAP) {
    MAYA.emit("hit", data);
    return;
  }
  if (hits === HIT_CAP + 1) MAYA.emit("hit", { truncated: true, reported: HIT_CAP });
}

function argCount(value) {
  if (!value) return 0;
  try {
    return value.length || 0;
  } catch (error) {
    return 0;
  }
}

function hookSql(methodName, signature, sqlIndex) {
  var label = "SQLiteDatabase." + methodName;
  MAYA.optional(label + "(" + signature.join(",") + ")", function () {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    var method = SQLiteDatabase[methodName].overload.apply(SQLiteDatabase[methodName], signature);
    method.implementation = function () {
      var sql = arguments.length > sqlIndex ? arguments[sqlIndex] : null;
      var binds = null;
      var index;
      for (index = 0; index < arguments.length; index += 1) {
        if (index === sqlIndex) continue;
        if (arguments[index] && arguments[index].length !== undefined && typeof arguments[index] !== "string") {
          binds = arguments[index];
          break;
        }
      }
      observe({
        hook: label,
        operation: methodName,
        sql: MAYA.text(sql, 300),
        bind_count: argCount(binds)
      });
      return MAYA.callOriginal(method, this, arguments);
    };
    MAYA.emit("hook", { hook: label, signature: signature });
  });
}

if (!Java.available) {
  MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
} else {
  Java.perform(function () {
    try {
      hookSql("rawQuery", ["java.lang.String", "[Ljava.lang.String;"], 0);
      hookSql("execSQL", ["java.lang.String"], 0);
      hookSql("execSQL", ["java.lang.String", "[Ljava.lang.Object;"], 0);
      hookSql("insert", ["java.lang.String", "java.lang.String", "android.content.ContentValues"], 0);
      hookSql("insertOrThrow", ["java.lang.String", "java.lang.String", "android.content.ContentValues"], 0);
      hookSql("update", ["java.lang.String", "android.content.ContentValues", "java.lang.String", "[Ljava.lang.String;"], 0);
      hookSql("delete", ["java.lang.String", "java.lang.String", "[Ljava.lang.String;"], 0);
      hookSql("query", [
        "java.lang.String",
        "[Ljava.lang.String;",
        "java.lang.String",
        "[Ljava.lang.String;",
        "java.lang.String",
        "java.lang.String",
        "java.lang.String"
      ], 0);
      MAYA.emit("ready", { script: "sqlite_queries" });
    } catch (error) {
      MAYA.fail("main", error);
    }
  });
}
