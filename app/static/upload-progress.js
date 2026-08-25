(function () {
  var API_ROOT = "/api/chunked-uploads";
  var STORAGE_KEY = "vpk.chunkedUploads.v1";
  var MAX_RETRIES = 3;

  function setProgress(progress, percent, label) {
    var safePercent = Math.max(0, Math.min(100, Math.round(percent)));
    var bar = progress.querySelector(".upload-progress__bar");
    var track = progress.querySelector(".upload-progress__track");
    var labelEl = progress.querySelector(".upload-progress__label");
    var percentEl = progress.querySelector(".upload-progress__percent");

    progress.hidden = false;
    bar.style.width = safePercent + "%";
    track.setAttribute("aria-valuenow", String(safePercent));
    labelEl.textContent = label;
    percentEl.textContent = safePercent + "%";
  }

  function currentPercent(progress) {
    var track = progress.querySelector(".upload-progress__track");
    return Number(track.getAttribute("aria-valuenow") || 0);
  }

  function responseError(response, data) {
    var detail = data && data.detail;
    var error = new Error(typeof detail === "string" ? detail : response.statusText || "上传失败");
    error.status = response.status;
    return error;
  }

  async function apiJson(url, options) {
    var requestOptions = options || {};
    requestOptions.headers = Object.assign({ "Accept": "application/json" }, requestOptions.headers || {});
    var response = await fetch(url, requestOptions);
    var data = null;
    try {
      data = await response.json();
    } catch (err) {
      data = null;
    }
    if (!response.ok) {
      throw responseError(response, data);
    }
    return data;
  }

  function loadRecords() {
    try {
      var records = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
      return records && typeof records === "object" ? records : {};
    } catch (err) {
      return {};
    }
  }

  function saveRecord(key, record) {
    try {
      var records = loadRecords();
      records[key] = record;
      var keys = Object.keys(records);
      if (keys.length > 20) {
        keys.sort(function (a, b) {
          return (records[b].saved_at || 0) - (records[a].saved_at || 0);
        }).slice(20).forEach(function (oldKey) {
          delete records[oldKey];
        });
      }
      localStorage.setItem(STORAGE_KEY, JSON.stringify(records));
      return true;
    } catch (err) {
      return false;
    }
  }

  function removeRecord(key) {
    try {
      var records = loadRecords();
      delete records[key];
      localStorage.setItem(STORAGE_KEY, JSON.stringify(records));
    } catch (err) {
      return;
    }
  }

  function uploadRole(form) {
    return new URL(form.action, window.location.href).pathname === "/admin/upload" ? "admin" : "guest";
  }

  function uploadTtl(form) {
    var ttlInput = form.querySelector("input[name='ttl_hours']");
    return ttlInput ? Number(ttlInput.value || 0) : null;
  }

  function recordKey(form, file) {
    var path = new URL(form.action, window.location.href).pathname;
    return [uploadRole(form), path, file.name, file.size, file.lastModified, uploadTtl(form)].join("|");
  }

  function recordMatches(record, form, file) {
    return record && record.filename === file.name && record.size === file.size &&
      record.last_modified === file.lastModified && record.role === uploadRole(form) &&
      record.ttl_hours === uploadTtl(form);
  }

  function createCancelButton(form, progress) {
    var button = document.createElement("button");
    button.type = "button";
    button.className = "secondary upload-cancel";
    button.textContent = "取消";
    button.title = "取消上传并删除服务器上的分片";
    button.hidden = true;
    form.insertBefore(button, progress);
    return button;
  }

  function setBusy(form, cancelButton, busy) {
    form.querySelectorAll("input, button").forEach(function (control) {
      if (control !== cancelButton) {
        control.disabled = busy;
      }
    });
    cancelButton.hidden = !busy;
    cancelButton.disabled = false;
  }

  function expectedChunkSize(session, chunkIndex) {
    if (chunkIndex === session.total_chunks - 1) {
      return session.size - chunkIndex * session.chunk_size;
    }
    return session.chunk_size;
  }

  function delay(milliseconds) {
    return new Promise(function (resolve) {
      window.setTimeout(resolve, milliseconds);
    });
  }

  function tokenHeaders(record, extra) {
    return Object.assign({ "X-Upload-Token": record.token }, extra || {});
  }

  async function loadSession(record) {
    return apiJson(API_ROOT + "/" + record.upload_id, {
      headers: tokenHeaders(record)
    });
  }

  async function createSession(form, file) {
    var role = uploadRole(form);
    try {
      return await apiJson(API_ROOT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          filename: file.name,
          size: file.size,
          role: role,
          ttl_hours: uploadTtl(form)
        })
      });
    } catch (err) {
      if (err.status === 404 || err.status === 405) {
        err.useLegacyUpload = true;
      }
      throw err;
    }
  }

  function makeRecord(form, file, session) {
    return {
      upload_id: session.upload_id,
      token: session.token,
      filename: file.name,
      size: file.size,
      last_modified: file.lastModified,
      role: uploadRole(form),
      ttl_hours: uploadTtl(form),
      saved_at: Date.now()
    };
  }

  async function getOrCreateSession(form, file, key) {
    var saved = loadRecords()[key];
    if (recordMatches(saved, form, file)) {
      try {
        var resumed = await loadSession(saved);
        saved.saved_at = Date.now();
        saveRecord(key, saved);
        return { record: saved, session: resumed, resumed: true };
      } catch (err) {
        var invalidToken = err.status === 401 && err.message.indexOf("凭据") !== -1;
        if (err.status !== 404 && !invalidToken) {
          throw err;
        }
        removeRecord(key);
      }
    }

    var created = await createSession(form, file);
    var record = makeRecord(form, file, created);
    if (!saveRecord(key, record)) {
      try {
        await apiJson(API_ROOT + "/" + record.upload_id, {
          method: "DELETE",
          headers: tokenHeaders(record)
        });
      } catch (cleanupError) {
        // Server-side expiry remains the fallback.
      }
      throw new Error("浏览器无法保存断点信息，请检查本地存储设置");
    }
    return { record: record, session: created, resumed: false };
  }

  function parseXhrError(xhr) {
    try {
      var data = JSON.parse(xhr.responseText);
      return responseError({ status: xhr.status, statusText: xhr.statusText }, data);
    } catch (err) {
      var error = new Error(xhr.statusText || "上传失败");
      error.status = xhr.status;
      return error;
    }
  }

  function sendChunk(record, session, file, chunkIndex, state, onProgress) {
    return new Promise(function (resolve, reject) {
      if (state.cancelled || state.failed) {
        var stopped = new Error(state.cancelled ? "上传已取消" : "上传已停止");
        stopped.cancelled = state.cancelled;
        stopped.superseded = state.failed;
        reject(stopped);
        return;
      }
      var start = chunkIndex * session.chunk_size;
      var end = Math.min(file.size, start + session.chunk_size);
      var xhr = new XMLHttpRequest();
      state.xhrs.add(xhr);

      xhr.upload.addEventListener("progress", function (event) {
        if (event.lengthComputable) {
          onProgress(event.loaded);
        }
      });
      xhr.addEventListener("load", function () {
        state.xhrs.delete(xhr);
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve();
        } else {
          reject(parseXhrError(xhr));
        }
      });
      xhr.addEventListener("error", function () {
        state.xhrs.delete(xhr);
        var error = new Error("网络错误");
        error.status = 0;
        reject(error);
      });
      xhr.addEventListener("abort", function () {
        state.xhrs.delete(xhr);
        var error = new Error("上传已取消");
        error.cancelled = state.cancelled;
        error.superseded = state.failed && !state.cancelled;
        reject(error);
      });
      xhr.addEventListener("timeout", function () {
        state.xhrs.delete(xhr);
        var error = new Error("分片上传超时");
        error.status = 408;
        reject(error);
      });
      xhr.open("PUT", API_ROOT + "/" + record.upload_id + "/chunks/" + chunkIndex);
      xhr.timeout = 10 * 60 * 1000;
      xhr.setRequestHeader("X-Upload-Token", record.token);
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.send(file.slice(start, end));
    });
  }

  function isRetryable(error) {
    return !error.cancelled && (error.status === 0 || error.status === 408 ||
      error.status === 425 || error.status === 429 || error.status >= 500);
  }

  async function uploadMissingChunks(record, session, file, state, progress) {
    var uploaded = new Set(session.uploaded_chunks || []);
    var queue = [];
    var committedBytes = 0;
    for (var index = 0; index < session.total_chunks; index += 1) {
      if (uploaded.has(index)) {
        committedBytes += expectedChunkSize(session, index);
      } else {
        queue.push(index);
      }
    }

    var inFlightBytes = new Map();
    var parallelism = Math.max(1, Math.min(session.parallelism || 4, queue.length || 1));
    var cursor = 0;

    function updateProgress(label) {
      var activeBytes = 0;
      inFlightBytes.forEach(function (value) { activeBytes += value; });
      setProgress(progress, (committedBytes + activeBytes) / file.size * 100, label);
    }

    if (committedBytes > 0) {
      updateProgress("正在恢复上传...");
    }

    async function worker() {
      while (!state.failed && !state.cancelled) {
        var queueIndex = cursor;
        cursor += 1;
        if (queueIndex >= queue.length) {
          return;
        }
        var chunkIndex = queue[queueIndex];
        var attempt = 0;
        while (true) {
          inFlightBytes.set(chunkIndex, 0);
          try {
            await sendChunk(record, session, file, chunkIndex, state, function (loaded) {
              inFlightBytes.set(chunkIndex, loaded);
              updateProgress("正在上传（" + parallelism + " 路并发）...");
            });
            inFlightBytes.delete(chunkIndex);
            committedBytes += expectedChunkSize(session, chunkIndex);
            updateProgress("正在上传（" + parallelism + " 路并发）...");
            break;
          } catch (err) {
            inFlightBytes.delete(chunkIndex);
            if (state.cancelled || err.cancelled) {
              throw err;
            }
            if (state.failed && state.primaryError) {
              return;
            }
            attempt += 1;
            if (attempt >= MAX_RETRIES || !isRetryable(err)) {
              state.primaryError = state.primaryError || err;
              state.failed = true;
              state.xhrs.forEach(function (xhr) { xhr.abort(); });
              throw state.primaryError;
            }
            updateProgress("网络波动，正在重试分片...");
            await delay(400 * Math.pow(2, attempt - 1));
            if (state.failed && state.primaryError) {
              return;
            }
          }
        }
      }
    }

    var workers = [];
    for (var workerIndex = 0; workerIndex < parallelism; workerIndex += 1) {
      workers.push(worker());
    }
    await Promise.all(workers);
  }

  async function completeSession(record) {
    return apiJson(API_ROOT + "/" + record.upload_id + "/complete", {
      method: "POST",
      headers: tokenHeaders(record)
    });
  }

  async function waitForProcessing(record, state, progress) {
    var deadline = Date.now() + 30 * 60 * 1000;
    while (!state.cancelled) {
      if (Date.now() >= deadline) {
        throw new Error("服务器处理时间过长，请稍后重新提交以查询结果");
      }
      setProgress(progress, 100, "服务器正在校验并生成服务器版...");
      await delay(2000);
      var status = await loadSession(record);
      if (status.status !== "processing") {
        return status;
      }
    }
    var error = new Error("上传已取消");
    error.cancelled = true;
    throw error;
  }

  function appendTextElement(parent, tagName, text, className) {
    var element = document.createElement(tagName);
    element.textContent = text;
    if (className) {
      element.className = className;
    }
    parent.appendChild(element);
    return element;
  }

  function renderBatchResults(form, result) {
    var container = form.closest(".card") || form.parentElement;
    container.querySelectorAll(".batch-results").forEach(function (previous) { previous.remove(); });
    var section = document.createElement("section");
    section.className = "batch-results";
    section.dataset.clientGenerated = "1";
    appendTextElement(section, "h3", "批量上传结果");
    appendTextElement(
      section,
      "p",
      "成功 " + result.uploaded.length + " 个，失败 " + result.failed.length + " 个",
      "muted"
    );

    if (result.uploaded.length) {
      var table = document.createElement("table");
      table.className = "table";
      var head = table.createTHead().insertRow();
      ["文件名", "大小(MB)", "操作"].forEach(function (label) {
        appendTextElement(head, "th", label);
      });
      var body = table.createTBody();
      result.uploaded.forEach(function (item) {
        var row = body.insertRow();
        appendTextElement(row, "td", item.original_name);
        appendTextElement(row, "td", item.size_label);
        var action = row.insertCell();
        var link = appendTextElement(action, "a", "查看", "btn");
        link.href = item.detail_url;
      });
      section.appendChild(table);
    }

    if (result.failed.length) {
      var details = document.createElement("details");
      details.open = true;
      appendTextElement(details, "summary", "失败列表");
      var list = document.createElement("ul");
      list.className = "batch-failures";
      result.failed.forEach(function (item) {
        appendTextElement(list, "li", item.name + "：" + item.error);
      });
      details.appendChild(list);
      section.appendChild(details);
    }
    container.appendChild(section);
  }

  function handleCompleted(form, result) {
    if (!result || !Array.isArray(result.uploaded) || !Array.isArray(result.failed)) {
      throw new Error("服务器返回的上传结果不完整");
    }
    if (result.redirect_url && result.failed.length === 0) {
      window.location.href = result.redirect_url;
      return;
    }
    renderBatchResults(form, result);
  }

  async function runChunkedUpload(form, file, key, state, progress, cancelButton) {
    var restored = await getOrCreateSession(form, file, key);
    state.record = restored.record;
    var session = restored.session;

    if (state.cancelled) {
      try {
        await apiJson(API_ROOT + "/" + restored.record.upload_id, {
          method: "DELETE",
          headers: tokenHeaders(restored.record)
        });
        removeRecord(key);
      } catch (err) {
        state.cancelled = false;
        throw err;
      }
      return;
    }

    if (session.status === "completed") {
      removeRecord(key);
      handleCompleted(form, session.result);
      return;
    }
    if (session.status === "processing") {
      cancelButton.disabled = true;
      session = await waitForProcessing(restored.record, state, progress);
      cancelButton.disabled = false;
      if (session.status === "completed") {
        removeRecord(key);
        handleCompleted(form, session.result);
        return;
      }
    }
    if (session.status === "failed" && session.detail) {
      setProgress(progress, 100, session.detail + "，正在重新处理...");
    }

    await uploadMissingChunks(restored.record, session, file, state, progress);
    if (state.cancelled) {
      return;
    }
    progress.classList.add("is-processing");
    cancelButton.disabled = true;
    setProgress(progress, 100, "上传完成，正在校验并生成服务器版...");
    try {
      var result = await completeSession(restored.record);
      if (result.status === "processing") {
        var completedStatus = await waitForProcessing(restored.record, state, progress);
        if (completedStatus.status === "completed") {
          result = completedStatus.result;
        } else {
          throw new Error(completedStatus.detail || "服务器处理未完成，请稍后重试");
        }
      }
      removeRecord(key);
      setProgress(progress, 100, "处理完成，正在打开结果...");
      handleCompleted(form, result);
    } catch (err) {
      throw err;
    }
  }

  function legacyUpload(form, file, state, progress) {
    var formData = new FormData(form);
    formData.set("file", file, file.name);
    var ttlInput = form.querySelector("input[name='ttl_hours']");
    if (ttlInput) {
      formData.set("ttl_hours", ttlInput.value || "0");
    }
    var xhr = new XMLHttpRequest();
    state.xhrs.add(xhr);

    xhr.upload.addEventListener("progress", function (event) {
      if (event.lengthComputable) {
        setProgress(progress, event.loaded / event.total * 100, "正在上传...");
      }
    });
    return new Promise(function (resolve, reject) {
      xhr.addEventListener("load", function () {
        state.xhrs.delete(xhr);
        if (xhr.status >= 200 && xhr.status < 400) {
          if (xhr.responseURL && xhr.responseURL !== form.action) {
            window.location.href = xhr.responseURL;
          } else {
            document.open();
            document.write(xhr.responseText);
            document.close();
          }
          resolve();
        } else {
          reject(parseXhrError(xhr));
        }
      });
      xhr.addEventListener("error", function () {
        state.xhrs.delete(xhr);
        reject(new Error("网络错误，上传未完成"));
      });
      xhr.addEventListener("abort", function () {
        state.xhrs.delete(xhr);
        var error = new Error("上传已取消");
        error.cancelled = true;
        reject(error);
      });
      xhr.open(form.method || "POST", form.action);
      xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
      xhr.send(formData);
    });
  }

  function bindUploadForm(form) {
    var progress = form.querySelector(".upload-progress");
    var submitButton = form.querySelector("button[type='submit']");
    var fileInput = form.querySelector("input[type='file'][name='file']");
    if (!progress || !submitButton || !fileInput) {
      return;
    }
    var cancelButton = createCancelButton(form, progress);
    var activeTask = null;

    cancelButton.addEventListener("click", async function () {
      if (!activeTask || activeTask.finished) {
        return;
      }
      var task = activeTask;
      task.cancelled = true;
      cancelButton.disabled = true;
      task.xhrs.forEach(function (xhr) { xhr.abort(); });
      task.cancelPromise = (async function () {
        try {
          if (task.record) {
            await apiJson(API_ROOT + "/" + task.record.upload_id, {
              method: "DELETE",
              headers: tokenHeaders(task.record)
            });
            removeRecord(task.key);
          }
          progress.classList.add("is-error");
          setProgress(progress, currentPercent(progress), "上传已取消");
        } catch (err) {
          task.cancelled = false;
          progress.classList.add("is-error");
          setProgress(progress, currentPercent(progress), err.message);
        }
      })();
      await task.cancelPromise;
    });

    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      if (activeTask && !activeTask.finished) {
        return;
      }
      var file = fileInput.files && fileInput.files[0];
      if (!file) {
        return;
      }
      var key = recordKey(form, file);
      var uploadState = {
        cancelled: false,
        failed: false,
        finished: false,
        primaryError: null,
        cancelPromise: null,
        xhrs: new Set(),
        record: null,
        key: key
      };
      activeTask = uploadState;
      progress.classList.remove("is-error", "is-processing");
      setBusy(form, cancelButton, true);
      setProgress(progress, 0, "正在建立上传会话...");

      try {
        await runChunkedUpload(form, file, key, uploadState, progress, cancelButton);
      } catch (err) {
        if (err.useLegacyUpload) {
          try {
            await legacyUpload(form, file, uploadState, progress);
          } catch (legacyError) {
            if (!legacyError.cancelled) {
              progress.classList.add("is-error");
              setProgress(progress, currentPercent(progress), legacyError.message);
            }
          }
          return;
        }
        if (!err.cancelled && !uploadState.cancelled) {
          progress.classList.add("is-error");
          var suffix = err.status === 400 ? "" : "；重新提交可从已完成分片继续";
          setProgress(progress, currentPercent(progress), err.message + suffix);
        }
      } finally {
        if (uploadState.cancelPromise) {
          await uploadState.cancelPromise;
        }
        uploadState.finished = true;
        if (activeTask === uploadState) {
          setBusy(form, cancelButton, false);
          activeTask = null;
        }
      }
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".upload-form").forEach(bindUploadForm);
  });
})();
