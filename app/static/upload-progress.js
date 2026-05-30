(function () {
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

  function getErrorMessage(xhr) {
    try {
      var data = JSON.parse(xhr.responseText);
      if (data && data.detail) {
        return typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
      }
    } catch (err) {
      return xhr.statusText || "上传失败";
    }
    return xhr.statusText || "上传失败";
  }

  function showReturnedHtml(html) {
    document.open();
    document.write(html);
    document.close();
  }

  function bindUploadForm(form) {
    var progress = form.querySelector(".upload-progress");
    var submitButton = form.querySelector("button[type='submit']");

    if (!progress || !submitButton) {
      return;
    }

    form.addEventListener("submit", function (event) {
      event.preventDefault();

      var formData = new FormData(form);
      var xhr = new XMLHttpRequest();

      progress.classList.remove("is-error", "is-processing");
      submitButton.disabled = true;
      setProgress(progress, 0, "开始上传...");

      xhr.upload.addEventListener("progress", function (uploadEvent) {
        if (!uploadEvent.lengthComputable) {
          setProgress(progress, 0, "正在上传...");
          return;
        }

        var percent = uploadEvent.loaded / uploadEvent.total * 100;
        setProgress(progress, percent, "正在上传...");

        if (percent >= 100) {
          progress.classList.add("is-processing");
          setProgress(progress, 100, "上传完成，正在校验并生成服务器版...");
        }
      });

      xhr.addEventListener("load", function () {
        submitButton.disabled = false;

        if (xhr.status >= 200 && xhr.status < 400) {
          setProgress(progress, 100, "处理完成，正在打开结果...");

          if (xhr.responseURL && xhr.responseURL !== form.action) {
            window.location.href = xhr.responseURL;
            return;
          }

          showReturnedHtml(xhr.responseText);
          return;
        }

        progress.classList.add("is-error");
        setProgress(progress, 100, getErrorMessage(xhr));
      });

      xhr.addEventListener("error", function () {
        submitButton.disabled = false;
        progress.classList.add("is-error");
        setProgress(progress, 100, "网络错误，上传未完成");
      });

      xhr.addEventListener("abort", function () {
        submitButton.disabled = false;
        progress.classList.add("is-error");
        setProgress(progress, 100, "上传已取消");
      });

      xhr.open(form.method || "POST", form.action);
      xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
      xhr.send(formData);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".upload-form").forEach(bindUploadForm);
  });
})();
