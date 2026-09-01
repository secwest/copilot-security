const TARGET_ORIGIN = "*";
export function publishSession() {
  const accessToken = window.localStorage.getItem("access_token");
  window.parent.postMessage(
    { type: "session", accessToken },
    { targetOrigin: TARGET_ORIGIN },
  );
}
