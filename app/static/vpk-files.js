(function () {
  function renderFiles(list, status, files, query) {
    var normalizedQuery = query.trim().toLowerCase();
    var filtered = normalizedQuery
      ? files.filter(function (file) { return file.toLowerCase().indexOf(normalizedQuery) !== -1; })
      : files;
    var visibleFiles = filtered.slice(0, 500);

    list.textContent = "";
    visibleFiles.forEach(function (file) {
      var item = document.createElement("li");
      item.textContent = file;
      list.appendChild(item);
    });

    var suffix = filtered.length > visibleFiles.length ? "，仅显示前 500 个" : "";
    status.textContent = "共 " + files.length + " 个文件，当前显示 " + filtered.length + " 个" + suffix;
  }

  function bindFileList(section) {
    var url = section.getAttribute("data-files-url");
    var search = section.querySelector(".file-list-search");
    var status = section.querySelector(".file-list-status");
    var list = section.querySelector(".file-list");

    if (!url || !search || !status || !list) {
      return;
    }

    fetch(url, { headers: { "Accept": "application/json" } })
      .then(function (response) {
        if (!response.ok) {
          throw new Error("HTTP " + response.status);
        }
        return response.json();
      })
      .then(function (data) {
        var files = Array.isArray(data.files) ? data.files : [];
        renderFiles(list, status, files, "");
        search.addEventListener("input", function () {
          renderFiles(list, status, files, search.value);
        });
      })
      .catch(function () {
        status.textContent = "文件列表加载失败";
      });
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".vpk-files").forEach(bindFileList);
  });
})();
