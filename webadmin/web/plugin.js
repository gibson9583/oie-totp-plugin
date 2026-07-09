// web/plugin.jsx
import { platform } from "@oie/web-shell";
var React = platform.React;
var api = platform.api;
var { h, toast, confirmDialog, taskButton } = platform.ui;
var EXT = "/extensions/totpmfa";
var notInstalled = (e) => e && (e.status === 404 || e.status === 501);
function TotpAdminPanel({ setTasks }) {
  const [users, setUsers] = React.useState([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(null);
  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get(`${EXT}/enrolled`);
      setUsers(api.asList(res && res.users).map(String).sort());
      setError(null);
    } catch (e) {
      setError(notInstalled(e) ? "The TOTP MFA engine plugin is not installed on this engine." : e.message || "Failed to load enrollments.");
      setUsers([]);
    } finally {
      setLoading(false);
    }
  }, []);
  React.useEffect(() => {
    load();
    setTasks("Two-Factor Authentication Tasks", [
      taskButton({ label: "Refresh", icon: "refresh", onClick: () => load() })
    ]);
  }, [load, setTasks]);
  const reset = async (username) => {
    const ok = await confirmDialog(
      "Reset Two-Factor Authentication",
      `Remove the authenticator enrollment for "${username}"? They will be prompted to set up two-factor authentication again on their next login.`,
      { danger: true, okLabel: "Reset" }
    );
    if (!ok) return;
    try {
      await api.post(`${EXT}/reset/${encodeURIComponent(username)}`);
      toast(`Reset two-factor authentication for "${username}".`, "success");
      load();
    } catch (e) {
      toast(e.message || "Reset failed.", "error");
    }
  };
  return /* @__PURE__ */ React.createElement("div", { className: "p-4", style: { maxWidth: 640 } }, /* @__PURE__ */ React.createElement("div", { className: "text-text-dim mb-3" }, "Users enrolled in TOTP two-factor authentication. Resetting a user clears their authenticator secret, so their next login restarts enrollment \u2014 use it when someone loses or changes their device."), loading ? /* @__PURE__ */ React.createElement("div", { className: "text-text-faint" }, "Loading\u2026") : error ? /* @__PURE__ */ React.createElement("div", { style: { color: "var(--err)" } }, error) : users.length === 0 ? /* @__PURE__ */ React.createElement("div", { className: "text-text-faint" }, "No users are currently enrolled.") : /* @__PURE__ */ React.createElement("table", { className: "dt", style: { width: "100%" } }, /* @__PURE__ */ React.createElement("thead", null, /* @__PURE__ */ React.createElement("tr", null, /* @__PURE__ */ React.createElement("th", null, "User"), /* @__PURE__ */ React.createElement("th", { style: { width: 120 } }))), /* @__PURE__ */ React.createElement("tbody", null, users.map((u) => /* @__PURE__ */ React.createElement("tr", { key: u }, /* @__PURE__ */ React.createElement("td", { className: "mono" }, u), /* @__PURE__ */ React.createElement("td", null, /* @__PURE__ */ React.createElement("button", { className: "btn btn-danger", onClick: () => reset(u) }, "Reset")))))));
}
function register(platform2) {
  platform2.registerSettingsPanel({
    label: "Two-Factor Authentication",
    component: TotpAdminPanel
  });
}
export {
  register
};
