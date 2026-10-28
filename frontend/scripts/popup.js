const urlInput = document.querySelector("#urlInput");
const analyzeButton = document.querySelector("#analyzeButton");
const status = document.querySelector("#status");

analyzeButton.addEventListener("click", () => {
  const raw = urlInput.value.trim();
  if (!raw) {
    status.textContent = "Enter a URL first.";
    return;
  }
  try {
    const parsed = new URL(raw);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      status.textContent = "Only HTTP and HTTPS URLs are supported.";
      return;
    }
    status.textContent = "URL parsed successfully. Detection engine is not implemented yet.";
  } catch {
    status.textContent = "Enter a valid absolute URL, including https:// or http://.";
  }
});
