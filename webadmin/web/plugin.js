// web/plugin.jsx
import { platform } from "@oie/web-shell";

// web/enrollments.js
function decodeEnrollments(response) {
  let value = response;
  if (value && typeof value === "object" && typeof value.string === "string") {
    value = value.string;
  }
  if (typeof value === "string") value = JSON.parse(value);
  const users = Array.isArray(value) ? value : value?.users;
  if (!Array.isArray(users) || users.some((user) => !user || !Number.isSafeInteger(user.id) || user.id <= 0 || typeof user.username !== "string" || !user.username || typeof user.generation !== "string" || !user.generation)) {
    throw new Error("The engine returned an invalid enrollment list.");
  }
  return [...users].sort((a, b) => a.username.localeCompare(b.username));
}
var initialEnrollmentState = {
  users: [],
  loading: true,
  error: null,
  resettingId: null
};
function loadError(error) {
  if (error?.status === 403) return "You do not have permission to manage two-factor authentication.";
  if (error?.status === 404 || error?.status === 501) {
    return "The TOTP MFA engine plugin is not installed on this engine.";
  }
  return error?.message || "Failed to load enrollments.";
}
function createEnrollmentController({ api: api2, confirmDialog: confirmDialog2, toast: toast2, onChange }) {
  const endpoint = "/extensions/totpmfa";
  let state = initialEnrollmentState;
  let alive = true;
  let sequence = 0;
  let mutating = false;
  const update = (patch) => {
    if (!alive) return;
    state = { ...state, ...patch };
    onChange(state);
  };
  async function load() {
    if (!alive || mutating) return;
    const request = ++sequence;
    update({ loading: true });
    try {
      const users = decodeEnrollments(await api2.get(`${endpoint}/enrolled`));
      if (alive && request === sequence) update({ users, error: null, loading: false });
    } catch (error) {
      if (alive && request === sequence) {
        update({ users: [], error: loadError(error), loading: false });
      }
    }
  }
  async function reset(user) {
    if (!alive || state.resettingId !== null || !state.users.includes(user)) return;
    update({ resettingId: user.id });
    try {
      const confirmed = await confirmDialog2(
        "Reset Two-Factor Authentication",
        `Remove the authenticator enrollment for "${user.username}"? They will be prompted to set up two-factor authentication again on their next login.`,
        { danger: true, okLabel: "Reset" }
      );
      if (!alive || !confirmed) return;
      if (!state.users.includes(user)) {
        toast2("The enrollment list changed. Review the current user and retry the reset.", "warn");
        return;
      }
      mutating = true;
      ++sequence;
      try {
        await api2.post(`${endpoint}/reset/${encodeURIComponent(user.id)}?generation=${encodeURIComponent(user.generation)}`);
        if (alive) toast2(`Reset two-factor authentication for "${user.username}".`, "success");
      } catch (error) {
        if (alive) toast2(error?.status === 409 ? "This enrollment changed. Review the refreshed list before resetting it." : error?.message || "Reset failed.", "error");
      } finally {
        mutating = false;
      }
      await load();
    } catch (error) {
      if (alive) toast2(error?.message || "Reset failed.", "error");
    } finally {
      update({ resettingId: null });
    }
  }
  return { load, reset, dispose() {
    alive = false;
    ++sequence;
  } };
}

// web/plugin.jsx
var React = platform.React;
var api = platform.api;
var { toast, confirmDialog, taskButton } = platform.ui;
var TASK_GROUP = "settings_Two-Factor Authentication";
function TotpAdminPanel({ setTasks }) {
  const [state, setState] = React.useState(initialEnrollmentState);
  const controller = React.useRef(null);
  const { users, loading, error, resettingId } = state;
  React.useEffect(() => {
    const current = createEnrollmentController({ api, confirmDialog, toast, onChange: setState });
    controller.current = current;
    current.load();
    setTasks("Two-Factor Authentication Tasks", [
      taskButton("Refresh", "refresh", current.load, { group: TASK_GROUP, task: "doRefresh" })
    ]);
    return () => current.dispose();
  }, [setTasks]);
  return /* @__PURE__ */ React.createElement("div", { className: "p-4", style: { maxWidth: 640 } }, /* @__PURE__ */ React.createElement("div", { className: "text-text-dim mb-3" }, "Users enrolled in TOTP two-factor authentication. Resetting a user clears their authenticator secret, so their next login restarts enrollment \u2014 use it when someone loses or changes their device."), loading ? /* @__PURE__ */ React.createElement("div", { className: "text-text-faint" }, "Loading\u2026") : error ? /* @__PURE__ */ React.createElement("div", { role: "alert", style: { color: "var(--err)" } }, error) : users.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: "text-text-faint" }, "No users are currently enrolled.") : /* @__PURE__ */ React.createElement("table", { className: "dt", style: { width: "100%" } }, /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("th", null, "User"), /* @__PURE__ */ React.createElement("th", { style: { width: 120 } }))), /* @__PURE__ */ React.createElement("tbody", null, users.map((user) => /* @__PURE__ */ React.createElement("tr", { key: user.id }, /* @__PURE__ */ React.createElement("td", { className: "mono" }, user.username), /* @__PURE__ */ React.createElement("td", null, platform.checkTask(TASK_GROUP, "doReset") && /* @__PURE__ */ React.createElement(
    "button",
    {
      type: "button",
      className: "btn btn-danger",
      disabled: resettingId !== null,
      onClick: () => {
        if (platform.checkTask(TASK_GROUP, "doReset")) controller.current?.reset(user);
      }
    },
    resettingId === user.id ? "Resetting\u2026" : "Reset"
  )))))));
}
async function register(host) {
  try {
    await api.get("/extensions/totpmfa/enrolled");
  } catch (error) {
    if (error?.status === 403) return;
  }
  host.registerSettingsPanel({ label: "Two-Factor Authentication", component: TotpAdminPanel });
}
export {
  register
};
