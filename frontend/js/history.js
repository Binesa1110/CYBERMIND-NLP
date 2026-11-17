/* ==========================================================
   CYBERMIND — local scan history
   Stored ONLY in this browser's localStorage.
   ========================================================== */

(function (global) {
  "use strict";

  var STORAGE_KEY = "cybermind:scan-history:v1";
  var MAX_ENTRIES = 20;

  function storageAvailable() {
    try {
      var testKey = "__cybermind_test__";
      global.localStorage.setItem(testKey, "1");
      global.localStorage.removeItem(testKey);
      return true;
    } catch (error) {
      return false;
    }
  }

  function isPlainObject(value) {
    return (
      typeof value === "object" &&
      value !== null &&
      !Array.isArray(value)
    );
  }

  function isValidEntry(entry) {
    return (
      isPlainObject(entry) &&
      typeof entry.id === "string" &&
      entry.id.length > 0 &&
      typeof entry.timestamp === "string" &&
      !Number.isNaN(Date.parse(entry.timestamp)) &&
      typeof entry.text === "string" &&
      isPlainObject(entry.result) &&
      isPlainObject(entry.result.final_assessment)
    );
  }

  function load() {
    try {
      var raw = global.localStorage.getItem(STORAGE_KEY);

      if (!raw) {
        return [];
      }

      var parsed = JSON.parse(raw);

      if (!Array.isArray(parsed)) {
        return [];
      }

      return parsed.filter(isValidEntry).slice(0, MAX_ENTRIES);
    } catch (error) {
      return [];
    }
  }

  function save(entries) {
    try {
      global.localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify(entries.slice(0, MAX_ENTRIES))
      );
      return true;
    } catch (error) {
      return false;
    }
  }

  function makeId() {
    if (
      global.crypto &&
      typeof global.crypto.randomUUID === "function"
    ) {
      return global.crypto.randomUUID();
    }

    return (
      "scan-" +
      Date.now() +
      "-" +
      Math.random().toString(36).slice(2, 10)
    );
  }

  function add(text, result) {
    var entry = {
      id: makeId(),
      timestamp: new Date().toISOString(),
      text: text,
      result: result
    };

    var entries = load();
    entries.unshift(entry);
    entries = entries.slice(0, MAX_ENTRIES);

    return {
      entry: entry,
      entries: entries,
      saved: save(entries)
    };
  }

  function getById(entryId) {
    var entries = load();

    for (var index = 0; index < entries.length; index += 1) {
      if (entries[index].id === entryId) {
        return entries[index];
      }
    }

    return null;
  }

  function clear() {
    try {
      global.localStorage.removeItem(STORAGE_KEY);
      return true;
    } catch (error) {
      return false;
    }
  }

  global.CyberMindHistory = {
    maxEntries: MAX_ENTRIES,
    isAvailable: storageAvailable,
    load: load,
    add: add,
    getById: getById,
    clear: clear
  };
})(window);
