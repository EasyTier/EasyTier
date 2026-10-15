# Windows installer process handling

NSIS remains a current-user installer. Its helper requests elevation only
when a running service or GUI requires it, and restores service startup and
running state after installation. During an update it temporarily disables
service startup because released EasyTier versions can trigger SCM recovery
even after an explicit stop.

Run `test-installer-processes.ps1` with Windows PowerShell as administrator
on a test machine without an existing `easytier-gui` service. The test uses
isolated executables and a service that reproduces the old exit behavior
with failure recovery enabled. Run it with `-GuiOnly` from an unelevated
shell to check the path that needs no elevation.

## Known limitation

If preparation on the welcome page has already started a helper, it is
reused at installation time. Changing to another directory containing a
running GUI, or relaunching the GUI between those pages, may still cause
Tauri's default process check to fail. Rechecking those processes is a
separate follow-up; it was recorded as a minor finding in the final review.
