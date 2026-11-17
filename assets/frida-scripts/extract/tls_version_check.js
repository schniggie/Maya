// tls_version_check.js — Report negotiated TLS versions, enabled protocols, and cleartext HTTP URLs.
// category: extract
// platform: android
// usage: frida_run_named_script("<package>", "extract/tls_version_check")
// maya-frida-message: { tag, event, data }
//
// Hooks call the original method. A missing socket class emits "miss".
// "compliant" means the observed protocol is TLSv1.2 or TLSv1.3, or the
// enabled set does not include SSLv3, TLSv1, or TLSv1.1.
'use strict';

var MAYA = (function () {
  var tag = "tls_version_check";

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

var WEAK = { SSLv3: true, TLSv1: true, "TLSv1.1": true };

function protocolList(protocols) {
  var values = [];
  if (!protocols) return values;
  var index;
  for (index = 0; index < protocols.length; index += 1) values.push(String(protocols[index]));
  return values;
}

function hasWeak(protocols) {
  var index;
  for (index = 0; index < protocols.length; index += 1) {
    if (WEAK[protocols[index]]) return true;
  }
  return false;
}

function hookHandshake(className) {
  MAYA.optional(className + ".startHandshake", function () {
    var cls = Java.use(className);
    if (!cls.startHandshake) {
      MAYA.emit("miss", { hook: className + ".startHandshake" });
      return;
    }
    var method = cls.startHandshake.overload();
    method.implementation = function () {
      method.call(this);
      var protocol = null;
      var cipher = null;
      var peer = null;
      try {
        var session = this.getSession();
        protocol = session ? String(session.getProtocol()) : null;
        cipher = session ? String(session.getCipherSuite()) : null;
        peer = session ? String(session.getPeerHost()) : null;
      } catch (error) {
        MAYA.fail(className + ".getSession", error);
      }
      MAYA.emit("hit", {
        hook: className + ".startHandshake",
        protocol: protocol,
        cipher_suite: cipher,
        peer_host: MAYA.text(peer, 180),
        compliant: protocol === "TLSv1.2" || protocol === "TLSv1.3"
      });
    };
    MAYA.emit("hook", { hook: className + ".startHandshake" });
  });
}

function hookSslContext() {
  MAYA.optional("javax.net.ssl.SSLContext.getInstance", function () {
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var getInstance = SSLContext.getInstance.overload("java.lang.String");
    getInstance.implementation = function (protocol) {
      var name = String(protocol);
      MAYA.emit("hit", {
        hook: "SSLContext.getInstance",
        requested_protocol: name,
        compliant: name === "TLS" || name === "TLSv1.2" || name === "TLSv1.3"
      });
      return getInstance.call(this, protocol);
    };
    MAYA.emit("hook", { hook: "SSLContext.getInstance" });
  });
}

function hookEnabledProtocols() {
  ["javax.net.ssl.SSLSocket", "javax.net.ssl.SSLEngine"].forEach(function (className) {
    MAYA.optional(className + ".setEnabledProtocols", function () {
      var cls = Java.use(className);
      var method = cls.setEnabledProtocols.overload("[Ljava.lang.String;");
      method.implementation = function (protocols) {
        var values = protocolList(protocols);
        MAYA.emit("hit", {
          hook: className + ".setEnabledProtocols",
          enabled_protocols: values,
          has_weak_protocol: hasWeak(values),
          compliant: !hasWeak(values)
        });
        return method.call(this, protocols);
      };
      MAYA.emit("hook", { hook: className + ".setEnabledProtocols" });
    });
  });
}

function hookCleartext() {
  MAYA.optional("java.net.URL.openConnection", function () {
    var URL = Java.use("java.net.URL");
    var open = URL.openConnection.overload();
    open.implementation = function () {
      var url = "";
      try {
        url = String(this.toString());
      } catch (error) {
        url = "";
      }
      if (url.indexOf("http://") === 0) {
        MAYA.emit("hit", {
          hook: "URL.openConnection",
          url: MAYA.text(url, 300),
          compliant: false,
          risk: "cleartext_http"
        });
      }
      return open.call(this);
    };
    MAYA.emit("hook", { hook: "java.net.URL.openConnection" });
  });
}

if (!Java.available) {
  MAYA.emit("error", { hook: "Java", message: "Java runtime is not available" });
} else {
  Java.perform(function () {
    try {
      hookHandshake("com.android.org.conscrypt.ConscryptFileDescriptorSocket");
      hookHandshake("com.android.org.conscrypt.ConscryptEngineSocket");
      hookHandshake("com.android.org.conscrypt.OpenSSLSocketImpl");
      hookSslContext();
      hookEnabledProtocols();
      hookCleartext();
      MAYA.emit("ready", { script: "tls_version_check" });
    } catch (error) {
      MAYA.fail("main", error);
    }
  });
}
