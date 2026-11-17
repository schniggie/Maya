// ssl_pinning_universal.js — Bypass common Android TLS pinning in OkHttp3, TrustManager, Conscrypt, and WebView for an authorized lab app.
// category: bypass
// platform: android
// usage: frida_run_named_script("<package>", "bypass/ssl_pinning_universal")
// maya-frida-message: { tag, event, data }
//
// Hooks are installed individually. A missing class or overload emits "miss"
// and the rest of the script keeps running. Output stays in the Frida session.
'use strict';

var MAYA = (function () {
  var tag = "ssl_pinning_universal";

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

function typeName(typeObj) {
  if (!typeObj) return "";
  try {
    if (typeObj.className) return String(typeObj.className);
  } catch (error) {
    return "";
  }
  return String(typeObj);
}

function certsToList(certs) {
  var ArrayList = Java.use("java.util.ArrayList");
  var list = ArrayList.$new();
  if (!certs) return list;
  var index;
  for (index = 0; index < certs.length; index += 1) list.add(certs[index]);
  return list;
}

function permissiveTrustManager() {
  var name = "com.maya.lab.PermissiveTrustManager";
  try {
    return Java.use(name);
  } catch (error) {
    /* first injection in this process */
  }
  var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
  return Java.registerClass({
    name: name,
    implements: [TrustManager],
    methods: {
      checkClientTrusted: function (chain, authType) {},
      checkServerTrusted: function (chain, authType) {},
      getAcceptedIssuers: function () {
        return Java.array("java.security.cert.X509Certificate", []);
      }
    }
  });
}

function hookSslContext() {
  MAYA.guard("javax.net.ssl.SSLContext.init", function () {
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var init = SSLContext.init.overload(
      "[Ljavax.net.ssl.KeyManager;",
      "[Ljavax.net.ssl.TrustManager;",
      "java.security.SecureRandom"
    );
    var Manager = permissiveTrustManager();
    init.implementation = function (keyManagers, trustManagers, random) {
      MAYA.emit("hit", { hook: "SSLContext.init", trust_managers: trustManagers ? trustManagers.length : 0 });
      var replacement = Java.array("javax.net.ssl.TrustManager", [Manager.$new()]);
      return init.call(this, keyManagers, replacement, random);
    };
    var context = SSLContext.getInstance("TLS");
    context.init(null, Java.array("javax.net.ssl.TrustManager", [Manager.$new()]), null);
    SSLContext.setDefault(context);
    MAYA.emit("hook", { hook: "SSLContext.init" });
  });
}

function hookHostnameVerifier() {
  MAYA.guard("javax.net.ssl.HostnameVerifier", function () {
    var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
    var Permissive = null;
    try {
      Permissive = Java.use("com.maya.lab.PermissiveHostnameVerifier");
    } catch (error) {
      Permissive = Java.registerClass({
        name: "com.maya.lab.PermissiveHostnameVerifier",
        implements: [HostnameVerifier],
        methods: {
          verify: function () {
            return true;
          }
        }
      });
    }
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    var setDefault = HttpsURLConnection.setDefaultHostnameVerifier.overload("javax.net.ssl.HostnameVerifier");
    setDefault.implementation = function () {
      MAYA.emit("hit", { hook: "HttpsURLConnection.setDefaultHostnameVerifier" });
      return setDefault.call(this, Permissive.$new());
    };
    setDefault.call(HttpsURLConnection, Permissive.$new());
    MAYA.emit("hook", { hook: "HttpsURLConnection.setDefaultHostnameVerifier" });
  });
}

function hookBooleanVerify(className) {
  MAYA.optional(className + ".verify", function () {
    var cls = Java.use(className);
    if (!cls.verify) {
      MAYA.emit("miss", { hook: className + ".verify" });
      return;
    }
    var hooked = 0;
    cls.verify.overloads.forEach(function (overload) {
      if (typeName(overload.returnType) !== "boolean") return;
      overload.implementation = function () {
        MAYA.emit("hit", { hook: className + ".verify" });
        return true;
      };
      hooked += 1;
    });
    if (hooked === 0) MAYA.emit("miss", { hook: className + ".verify" });
    else MAYA.emit("hook", { hook: className + ".verify", overloads: hooked });
  });
}

function hookCertificatePinner() {
  ["check", "check$okhttp"].forEach(function (methodName) {
    var label = "okhttp3.CertificatePinner." + methodName;
    MAYA.optional(label, function () {
      var Pinner = Java.use("okhttp3.CertificatePinner");
      if (!Pinner[methodName]) {
        MAYA.emit("miss", { hook: label });
        return;
      }
      var hooked = 0;
      Pinner[methodName].overloads.forEach(function (overload) {
        overload.implementation = function () {
          var host = arguments.length ? MAYA.text(arguments[0], 180) : null;
          MAYA.emit("hit", { hook: label, host: host });
        };
        hooked += 1;
      });
      MAYA.emit("hook", { hook: label, overloads: hooked });
    });
  });
}

function hookConscryptMethod(className, methodName) {
  var label = className + "." + methodName;
  MAYA.optional(label, function () {
    var cls = Java.use(className);
    if (!cls[methodName]) {
      MAYA.emit("miss", { hook: label });
      return;
    }
    var hooked = 0;
    cls[methodName].overloads.forEach(function (overload) {
      var ret = typeName(overload.returnType);
      var first = overload.argumentTypes.length ? typeName(overload.argumentTypes[0]) : "";
      var returnsChain = ret !== "void";
      var knownChain = first.indexOf("X509Certificate") !== -1 || first.indexOf("java.util.List") !== -1;
      if (returnsChain && !knownChain) return;
      overload.implementation = function () {
        MAYA.emit("hit", { hook: label });
        if (!returnsChain) return;
        if (first.indexOf("java.util.List") !== -1) return arguments[0];
        return certsToList(arguments[0]);
      };
      hooked += 1;
    });
    if (hooked === 0) MAYA.emit("miss", { hook: label });
    else MAYA.emit("hook", { hook: label, overloads: hooked });
  });
}

function hookWebViewSsl() {
  MAYA.optional("WebViewClient.onReceivedSslError", function () {
    var names = Java.enumerateLoadedClassesSync();
    var hooked = 0;
    names.forEach(function (name) {
      if (hooked >= 20) return;
      if (name.indexOf("WebViewClient") === -1) return;
      MAYA.optional(name + ".onReceivedSslError", function () {
        var cls = Java.use(name);
        if (!cls.onReceivedSslError) return;
        cls.onReceivedSslError.overloads.forEach(function (overload) {
          overload.implementation = function (view, handler) {
            try {
              if (handler) handler.proceed();
            } catch (error) {
              MAYA.fail(name + ".onReceivedSslError", error);
            }
            MAYA.emit("hit", { hook: name + ".onReceivedSslError" });
          };
        });
        hooked += 1;
        MAYA.emit("hook", { hook: name + ".onReceivedSslError" });
      });
    });
    if (hooked === 0) MAYA.emit("miss", { hook: "WebViewClient.onReceivedSslError" });
  });
}

function hookNetworkSecurityPins() {
  var label = "android.security.net.config.NetworkSecurityTrustManager.checkPins";
  MAYA.optional(label, function () {
    var Cls = Java.use("android.security.net.config.NetworkSecurityTrustManager");
    if (!Cls.checkPins) {
      MAYA.emit("miss", { hook: label });
      return;
    }
    Cls.checkPins.overloads.forEach(function (overload) {
      overload.implementation = function () {
        MAYA.emit("hit", { hook: label });
      };
    });
    MAYA.emit("hook", { hook: label });
  });
}

if (!Java.available) {
  MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
} else {
  Java.perform(function () {
    try {
      hookSslContext();
      hookHostnameVerifier();
      hookBooleanVerify("okhttp3.internal.tls.OkHostnameVerifier");
      hookBooleanVerify("com.android.okhttp.internal.tls.OkHostnameVerifier");
      hookCertificatePinner();
      hookConscryptMethod("com.android.org.conscrypt.TrustManagerImpl", "checkServerTrusted");
      hookConscryptMethod("com.android.org.conscrypt.TrustManagerImpl", "checkClientTrusted");
      hookConscryptMethod("com.android.org.conscrypt.TrustManagerImpl", "verifyChain");
      hookConscryptMethod("com.android.org.conscrypt.Platform", "checkServerTrusted");
      hookNetworkSecurityPins();
      hookWebViewSsl();
      MAYA.emit("ready", { script: "ssl_pinning_universal" });
    } catch (error) {
      MAYA.fail("main", error);
    }
  });
}
