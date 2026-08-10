from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from safe_backup.setup import artifact_digest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
ARTIFACT = artifact_digest(ROOT)


def powershells():
    return [exe for exe in (shutil.which("pwsh"), shutil.which("powershell")) if exe]


def run_ps(args):
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(args, text=True, encoding="utf-8", errors="replace", capture_output=True, env=env)


class TaskScriptTests(unittest.TestCase):
    def test_update_discovery_and_transition_run_against_both_powershell_engines(self):
        engines = powershells()
        self.assertEqual({Path(exe).stem.casefold() for exe in engines}, {"pwsh", "powershell"})
        common = str(SCRIPTS / "task_common.ps1").replace("'", "''")
        update = str(SCRIPTS / "update_task.ps1").replace("'", "''")
        launcher = str(SCRIPTS / "task_launcher.ps1").replace("'", "''")
        historic = "e" * 64
        old = json.dumps(["--astrbot-root", r"C:\root", "--destination", r"C:\old",
                          "--python-path", r"C:\python.exe", "--keep", "5", "--week-start",
                          "0", "--schedule-time", "12:00", "--artifact-digest", historic, "--scheduled"])
        new = json.dumps(["--astrbot-root", r"C:\root", "--destination", r"C:\new",
                          "--python-path", r"C:\python.exe", "--keep", "5", "--week-start",
                          "0", "--schedule-time", "13:00", "--artifact-digest", ARTIFACT, "--scheduled"])
        base = (
            ". '" + common + "';"
            "function New-ScheduledTaskAction { param($Execute,$Argument) [pscustomobject]@{Execute=$Execute;Arguments=$Argument} };"
            "function New-ScheduledTaskTrigger { param([switch]$Daily,$At) [pscustomobject]@{Type='Daily';DaysInterval=1;StartBoundary=('2026-08-09T'+$At.ToString('HH:mm:ss'))} };"
            "function New-ScheduledTaskPrincipal { param($UserId,$LogonType,$RunLevel) [pscustomobject]@{UserId=$UserId;LogonType=$LogonType;RunLevel=$RunLevel} };"
            "function New-ScheduledTaskSettingsSet { param($MultipleInstances,[switch]$StartWhenAvailable,$WakeToRun,$ExecutionTimeLimit) [pscustomobject]@{MultipleInstances=$MultipleInstances;StartWhenAvailable=[bool]$StartWhenAvailable;WakeToRun=[bool]$WakeToRun;ExecutionTimeLimit='PT0S'} };"
            "$id=Get-TaskIdentity '0123456789ab';$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name;"
            "$old=@(" + ",".join("'" + v.replace("'", "''") + "'" for v in json.loads(old)) + ");"
            "$new=@(" + ",".join("'" + v.replace("'", "''") + "'" for v in json.loads(new)) + ");"
            "$launcher='" + launcher + "';"
            "$oldResolved=Resolve-TaskInputs $id.Name $id.Description $id.Fingerprint $launcher '" + old.replace("'", "''") + "';$newResolved=Resolve-TaskInputs $id.Name $id.Description $id.Fingerprint $launcher '" + new.replace("'", "''") + "';"
            "function Make-Task { param($r,[string]$description,[string]$state='Ready')$p=[pscustomobject]@{UserId=$user;RunLevel='Limited';LogonType='Interactive'};$a=[pscustomobject]@{Execute=(Get-WindowsPowerShellPath);Arguments=(New-LauncherArgumentString $r.LauncherPath $r.LauncherArguments)};[pscustomobject]@{TaskName=$id.Name;Description=$description;State=$state;Principal=$p;Actions=@($a);Triggers=@([pscustomobject]@{Type='Daily';DaysInterval=1;StartBoundary=('2026-08-09T'+$r.ScheduleTime+':00')});Settings=[pscustomobject]@{MultipleInstances='IgnoreNew';StartWhenAvailable=$true;WakeToRun=$false;ExecutionTimeLimit='PT0S'}}};"
            "$global:setCount=0;$global:disableCount=0;function Get-ScheduledTask { [CmdletBinding()]param($TaskName) return $global:syntheticTask };"
            "function Set-ScheduledTask { param($TaskName,$Action,$Trigger,$Principal,$Settings)$global:setCount++;if($global:mode -eq 'normal'){$global:syntheticTask=Make-Task $newResolved $id.Description}elseif($global:mode -eq 'missing'){$global:syntheticTask=$null}};"
            "function Disable-ScheduledTask { param($TaskName)$global:disableCount++;$global:syntheticTask.State='Disabled';return $global:syntheticTask };"
        )
        invoke = (
            "& '" + update + "' -TaskName $id.Name -Description $id.Description -TaskFingerprint $id.Fingerprint "
            "-ExpectedLauncherPath $launcher -ExpectedLauncherArgumentsJson '" + old.replace("'", "''") + "' "
            "-LauncherPath $launcher -LauncherArgumentsJson '" + new.replace("'", "''") + "' -OutputJson;"
            "[pscustomobject]@{set=$global:setCount;disable=$global:disableCount;state=if($null -eq $global:syntheticTask){$null}else{[string]$global:syntheticTask.State}}|ConvertTo-Json -Compress"
        )
        discover = (
            "& '" + update + "' -TaskName $id.Name -Description $id.Description -TaskFingerprint $id.Fingerprint -Discover -OutputJson"
        )
        inspect_historic = (
            "& '" + update + "' -TaskName $id.Name -Description $id.Description -TaskFingerprint $id.Fingerprint "
            "-LauncherPath $launcher -LauncherArgumentsJson '" + old.replace("'", "''") + "' -Operation inspect -OutputJson"
        )
        cases = {
            "discover_missing": "$global:syntheticTask=$null;" + discover,
            "discover_exact": "$global:syntheticTask=Make-Task $oldResolved $id.Description;" + discover,
            "discover_foreign": "$global:syntheticTask=Make-Task $oldResolved 'foreign';" + discover,
            "inspect_historic": "$global:syntheticTask=Make-Task $oldResolved $id.Description;" + inspect_historic,
            "transition": "$global:mode='normal';$global:syntheticTask=Make-Task $oldResolved $id.Description;" + invoke,
            "transition_disabled": "$global:mode='normal';$global:syntheticTask=Make-Task $oldResolved $id.Description 'Disabled';" + invoke,
            "old_mismatch": "$global:mode='normal';$global:syntheticTask=Make-Task $newResolved $id.Description;" + invoke,
            "after_wrong": "$global:mode='wrong';$global:syntheticTask=Make-Task $oldResolved $id.Description;" + invoke,
            "after_missing": "$global:mode='missing';$global:syntheticTask=Make-Task $oldResolved $id.Description;" + invoke,
        }
        for exe in engines:
            for name, command in cases.items():
                with self.subTest(engine=exe, case=name):
                    result = run_ps([exe, "-NoProfile", "-Command", base + command])
                    self.assertIn("{", result.stdout, result.stdout + result.stderr)
                    records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
                    value = records[0]
                    if name == "discover_missing":
                        self.assertEqual((result.returncode, value["status"]), (0, "missing"))
                    elif name == "discover_exact":
                        self.assertEqual((result.returncode, value["status"]), (0, "exact"))
                    elif name == "discover_foreign":
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(value["status"], "foreign")
                    elif name == "inspect_historic":
                        self.assertEqual((result.returncode, value["status"]), (0, "inspected"))
                    elif name in {"transition", "transition_disabled"}:
                        self.assertEqual((result.returncode, value["status"]), (0, "updated"))
                        self.assertEqual(records[-1]["set"], 1)
                        self.assertEqual(records[-1]["disable"], 1 if name == "transition_disabled" else 0)
                        self.assertEqual(records[-1]["state"], "Disabled" if name == "transition_disabled" else "Ready")
                    else:
                        self.assertEqual(value["status"], "failed")
                        self.assertEqual(records[-1]["set"], 0 if name == "old_mismatch" else 1)

    def test_scripts_parse(self):
        for exe in powershells():
            for name in ("task_common.ps1", "install_task.ps1", "update_task.ps1", "remove_task.ps1", "start_task.ps1"):
                path = SCRIPTS / name
                command = (
                    "$e=$null;$t=$null;[void][Management.Automation.Language.Parser]::ParseFile("
                    + "'" + str(path).replace("'", "''") + "',[ref]$t,[ref]$e);"
                    + "if($e.Count){$e|% Message;exit 1}"
                )
                result = run_ps([exe, "-NoProfile", "-Command", command])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_task_scripts_only_register_hidden_launcher_and_typed_json(self):
        install = (SCRIPTS / "install_task.ps1").read_text(encoding="utf-8-sig")
        update = (SCRIPTS / "update_task.ps1").read_text(encoding="utf-8-sig")
        remove = (SCRIPTS / "remove_task.ps1").read_text(encoding="utf-8-sig")
        common = (SCRIPTS / "task_common.ps1").read_text(encoding="utf-8-sig")
        all_text = install + update + remove
        self.assertNotIn("Start-ScheduledTask", all_text)
        self.assertNotIn("Stop-Process", all_text)
        self.assertNotIn("Remove-Item", all_text)
        self.assertNotIn("PythonPath", all_text)
        self.assertIn("Register-ScheduledTask", install)
        self.assertIn("New-HiddenLauncherAction", common)
        self.assertIn("'-WindowStyle', 'Hidden'", common)
        self.assertIn("$OutputJson", all_text)
        self.assertIn("ConvertTo-Json -Compress", common)

    def test_internal_start_script_only_checks_and_starts_an_exact_existing_task(self):
        start = (SCRIPTS / "start_task.ps1").read_text(encoding="utf-8-sig")
        for forbidden in ("Register-ScheduledTask", "Set-ScheduledTask", "Unregister-ScheduledTask",
                          "Enable-ScheduledTask", "Disable-ScheduledTask", "Stop-Process"):
            self.assertNotIn(forbidden, start)
        self.assertLess(start.index("Test-OwnedTask"), start.index("Start-ScheduledTask"))
        self.assertIn("Test-OwnedTask $after", start)

    def test_update_and_remove_check_exact_ownership_before_mutation(self):
        for name, operation in (("update_task.ps1", "Set-ScheduledTask"),
                                ("remove_task.ps1", "Unregister-ScheduledTask")):
            text = (SCRIPTS / name).read_text(encoding="utf-8-sig")
            self.assertLess(text.index("Test-OwnedTask"), text.index(operation))

    def test_install_refuses_existing_task_before_registration(self):
        text = (SCRIPTS / "install_task.ps1").read_text(encoding="utf-8-sig")
        self.assertLess(text.index("Get-ScheduledTask"), text.index("Register-ScheduledTask"))
        self.assertIn("refusing to overwrite", text)

    @unittest.skipUnless(powershells(), "PowerShell unavailable")
    def test_quoting_round_trips_spaces_quotes_trailing_slashes_and_volume_root(self):
        common = str(SCRIPTS / "task_common.ps1").replace("'", "''")
        command = (
            ". '" + common + "';"
            "$values=@('C:\\space path\\x','C:\\quote\"here','C:\\trailing\\','C:\\');"
            "$joined=($values|% { Quote-TaskArgument $_ }) -join ' ';"
            "$round=ConvertFrom-TaskArgumentString $joined;"
            "$launcher=ConvertFrom-TaskArgumentString (New-LauncherArgumentString 'C:\\task launcher.ps1' @('--scheduled'));"
            "$root=Get-AbsolutePath 'C:\\' 'root';"
            "[pscustomobject]@{round=@($round);launcher=@($launcher);root=$root}|ConvertTo-Json -Compress"
        )
        for exe in powershells():
            with self.subTest(exe=exe):
                result = run_ps([exe, "-NoProfile", "-Command", command])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                value = json.loads(result.stdout.strip())
                self.assertEqual(value["round"], ["C:\\space path\\x", 'C:\\quote"here', "C:\\trailing\\", "C:\\"])
                self.assertEqual(value["launcher"], ["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-File", "C:\\task launcher.ps1", "--scheduled"])
                self.assertEqual(value["root"], "C:\\")

    @unittest.skipUnless(powershells(), "PowerShell unavailable")
    def test_unc_inputs_are_rejected(self):
        exe = powershells()[0]
        common = str(SCRIPTS / "task_common.ps1").replace("'", "''")
        result = run_ps([exe, "-NoProfile", "-Command", ". '" + common + "';Get-AbsolutePath '\\\\server\\share' 'synthetic'"])
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(r"\\server\share", result.stdout)

    @unittest.skipUnless(powershells(), "PowerShell unavailable")
    def test_owned_task_rejects_identity_launcher_actions_triggers_and_settings_mismatches(self):
        common = str(SCRIPTS / "task_common.ps1").replace("'", "''")
        command = (
            ". '" + common + "';"
            "$id=Get-TaskIdentity '0123456789ab';$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name;"
            "$r=[pscustomobject]@{Identity=$id;LauncherPath='C:\\plugin path\\task_launcher.ps1';LauncherArguments=@('--astrbot-root','C:\\root','--schedule-time','12:00','--artifact-digest','" + ARTIFACT + "','--scheduled');ScheduleTime='12:00'};"
            "$p=[pscustomobject]@{UserId=$user;RunLevel='Limited';LogonType='Interactive'};"
            "$a=[pscustomobject]@{Execute=(Get-WindowsPowerShellPath);Arguments=(New-LauncherArgumentString $r.LauncherPath $r.LauncherArguments)};"
            "$t=[pscustomobject]@{TaskName=$id.Name;Description=$id.Description;State='Ready';Principal=$p;Actions=@($a);Triggers=@([pscustomobject]@{Type='Daily';DaysInterval=1;StartBoundary='2026-08-09T12:00:00'});Settings=[pscustomobject]@{MultipleInstances='IgnoreNew';StartWhenAvailable=$true;WakeToRun=$false;ExecutionTimeLimit='PT0S'}};"
            "$wrongUser=[pscustomobject]@{TaskName=$id.Name;Description=$id.Description;Principal=[pscustomobject]@{UserId='other';RunLevel='Limited';LogonType='Interactive'};Actions=$t.Actions;Triggers=$t.Triggers;Settings=$t.Settings};"
            "$wrongLauncher=[pscustomobject]@{TaskName=$id.Name;Description=$id.Description;Principal=$p;Actions=@([pscustomobject]@{Execute=(Get-WindowsPowerShellPath);Arguments='-NoProfile -WindowStyle Hidden -File C:\\foreign.ps1'});Triggers=$t.Triggers;Settings=$t.Settings};"
            "$extraAction=[pscustomobject]@{TaskName=$id.Name;Description=$id.Description;Principal=$p;Actions=@($a,$a);Triggers=$t.Triggers;Settings=$t.Settings};"
            "$extraTrigger=[pscustomobject]@{TaskName=$id.Name;Description=$id.Description;Principal=$p;Actions=$t.Actions;Triggers=@($t.Triggers[0],$t.Triggers[0]);Settings=$t.Settings};"
            "$foreign=[pscustomobject]@{TaskName=$id.Name;Description='foreign';Principal=$p;Actions=$t.Actions;Triggers=$t.Triggers;Settings=$t.Settings};"
            "$instances=[pscustomobject]@{TaskName=$id.Name;Description=$id.Description;Principal=$p;Actions=$t.Actions;Triggers=$t.Triggers;Settings=[pscustomobject]@{MultipleInstances='Queue';StartWhenAvailable=$true;WakeToRun=$false;ExecutionTimeLimit='PT0S'}};"
            "$wake=[pscustomobject]@{TaskName=$id.Name;Description=$id.Description;Principal=$p;Actions=$t.Actions;Triggers=$t.Triggers;Settings=[pscustomobject]@{MultipleInstances='IgnoreNew';StartWhenAvailable=$true;WakeToRun=$true;ExecutionTimeLimit='PT0S'}};"
            "$limit=[pscustomobject]@{TaskName=$id.Name;Description=$id.Description;Principal=$p;Actions=$t.Actions;Triggers=$t.Triggers;Settings=[pscustomobject]@{MultipleInstances='IgnoreNew';StartWhenAvailable=$true;WakeToRun=$false;ExecutionTimeLimit='PT1S'}};"
            "[pscustomobject]@{good=(Test-OwnedTask $t $r);user=(Test-OwnedTask $wrongUser $r);launcher=(Test-OwnedTask $wrongLauncher $r);actions=(Test-OwnedTask $extraAction $r);triggers=(Test-OwnedTask $extraTrigger $r);foreign=(Test-OwnedTask $foreign $r);instances=(Test-OwnedTask $instances $r);wake=(Test-OwnedTask $wake $r);limit=(Test-OwnedTask $limit $r)}|ConvertTo-Json -Compress"
        )
        for exe in powershells():
            with self.subTest(exe=exe):
                result = run_ps([exe, "-NoProfile", "-Command", command])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                value = json.loads(result.stdout.strip())
                self.assertEqual(value, {"good": True, "user": False, "launcher": False,
                                         "actions": False, "triggers": False, "foreign": False,
                                         "instances": False, "wake": False, "limit": False})

    @unittest.skipUnless(powershells(), "PowerShell unavailable")
    def test_task_inputs_require_the_fixed_launcher_grammar_and_trusted_system_path(self):
        common = str(SCRIPTS / "task_common.ps1").replace("'", "''")
        launcher = str(SCRIPTS / "task_launcher.ps1").replace("'", "''")
        command = (
            ". '" + common + "';"
            "$id=Get-TaskIdentity '0123456789ab';"
            "$args='[\"--astrbot-root\",\"C:\\\\root\",\"--destination\",\"C:\\\\backup\",\"--python-path\",\"C:\\\\python.exe\",\"--keep\",\"5\",\"--week-start\",\"0\",\"--schedule-time\",\"12:00\",\"--artifact-digest\",\"" + ARTIFACT + "\",\"--scheduled\"]';"
            "$badLauncher=$false;$attacker=$false;$badGrammar=$false;"
            "try { Resolve-TaskInputs $id.Name $id.Description $id.Fingerprint 'C:\\plugin\\other.ps1' $args | Out-Null } catch { $badLauncher=$true };"
            "try { Resolve-TaskInputs $id.Name $id.Description $id.Fingerprint 'C:\\attacker\\scripts\\task_launcher.ps1' $args | Out-Null } catch { $attacker=$true };"
            "try { Resolve-TaskInputs $id.Name $id.Description $id.Fingerprint '" + launcher + "' ($args -replace ',\"--scheduled\"','') | Out-Null } catch { $badGrammar=$true };"
            "$env:WINDIR='C:\\attacker';$system=Get-WindowsPowerShellPath;"
            "[pscustomobject]@{badLauncher=$badLauncher;attacker=$attacker;badGrammar=$badGrammar;system=$system}|ConvertTo-Json -Compress"
        )
        for exe in powershells():
            with self.subTest(exe=exe):
                result = run_ps([exe, "-NoProfile", "-Command", command])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                value = json.loads(result.stdout.strip())
                self.assertTrue(value["badLauncher"])
                self.assertTrue(value["attacker"])
                self.assertTrue(value["badGrammar"])
                self.assertNotIn(r"C:\\attacker", value["system"])

    @unittest.skipUnless(powershells(), "PowerShell unavailable")
    def test_install_existing_and_update_remove_validate_only_never_mutate(self):
        fingerprint = "0123456789ab"
        common = str(SCRIPTS / "task_common.ps1").replace("'", "''")
        launcher = str(SCRIPTS / "task_launcher.ps1").replace("'", "''")
        arguments = json.dumps(["--astrbot-root", r"C:\root", "--destination", r"C:\backup",
                                "--python-path", r"C:\python.exe", "--keep", "5", "--week-start",
                                "0", "--schedule-time", "12:00", "--artifact-digest", ARTIFACT, "--scheduled"])
        install_script = str(SCRIPTS / "install_task.ps1").replace("'", "''")
        base = (
            ". '" + common + "';"
            "$id=Get-TaskIdentity '" + fingerprint + "';$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name;"
            "$r=[pscustomobject]@{Identity=$id;LauncherPath='" + launcher + "';LauncherArguments=@('--astrbot-root','C:\\root','--destination','C:\\backup','--python-path','C:\\python.exe','--keep','5','--week-start','0','--schedule-time','12:00','--artifact-digest','" + ARTIFACT + "','--scheduled');ScheduleTime='12:00'};"
            "$p=[pscustomobject]@{UserId=$user;RunLevel='Limited';LogonType='Interactive'};"
            "$a=[pscustomobject]@{Execute=(Get-WindowsPowerShellPath);Arguments=(New-LauncherArgumentString $r.LauncherPath $r.LauncherArguments)};"
            "$global:syntheticTask=[pscustomobject]@{TaskName=$id.Name;Description=$id.Description;State='Ready';Principal=$p;Actions=@($a);Triggers=@([pscustomobject]@{Type='Daily';DaysInterval=1;StartBoundary='2026-08-09T12:00:00'});Settings=[pscustomobject]@{MultipleInstances='IgnoreNew';StartWhenAvailable=$true;WakeToRun=$false;ExecutionTimeLimit='PT0S'}};"
            "function Get-ScheduledTask { [CmdletBinding()]param([string]$TaskName) return $global:syntheticTask };"
            "function Set-ScheduledTask { return }; function Unregister-ScheduledTask { return };"
        )
        install = (
            "function Register-ScheduledTask { return }; function Get-ScheduledTask { [CmdletBinding()]param([string]$TaskName) return [pscustomobject]@{} };"
            f"& '{install_script}' -TaskName 'AstrBot Safe Backup {fingerprint}' "
            f"-Description 'AstrBotSafeBackup:v1:{fingerprint}' -TaskFingerprint '{fingerprint}' "
            "-LauncherPath '" + launcher + "' -LauncherArgumentsJson '"
            + arguments.replace("'", "''") + "' -OutputJson"
        )
        for exe in powershells():
            with self.subTest(exe=exe, operation="install"):
                result = run_ps([exe, "-NoProfile", "-Command", install])
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout.strip())["status"], "failed")
            for operation, script in (("update", "update_task.ps1"), ("remove", "remove_task.ps1")):
                script_path = str(SCRIPTS / script).replace("'", "''")
                command = (
                    base + f"& '{script_path}' "
                    f"-TaskName 'AstrBot Safe Backup {fingerprint}' -Description 'AstrBotSafeBackup:v1:{fingerprint}' "
                    f"-TaskFingerprint '{fingerprint}' -LauncherPath '{launcher}' "
                    "-LauncherArgumentsJson '" + arguments + "' -ValidateOnly -OutputJson"
                )
                with self.subTest(exe=exe, operation=operation):
                    result = run_ps([exe, "-NoProfile", "-Command", command])
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(json.loads(result.stdout.strip())["status"], "validated")

    @unittest.skipUnless(powershells(), "PowerShell unavailable")
    def test_install_validate_only_emits_typed_result_without_registering(self):
        exe = powershells()[0]
        fingerprint = "0123456789ab"
        with tempfile.TemporaryDirectory() as temporary:
            launcher = SCRIPTS / "task_launcher.ps1"
            install_script = str(SCRIPTS / "install_task.ps1").replace("'", "''")
            launcher_script = str(launcher).replace("'", "''")
            command = (
                "function Get-ScheduledTask { [CmdletBinding()] param([string]$TaskName) return $null }; "
                "function Register-ScheduledTask { throw 'must not register' }; "
                f"& '{install_script}' "
                f"-TaskName 'AstrBot Safe Backup {fingerprint}' -Description 'AstrBotSafeBackup:v1:{fingerprint}' "
                f"-TaskFingerprint '{fingerprint}' -LauncherPath '{launcher_script}' "
                "-LauncherArgumentsJson '" + json.dumps([
                    "--astrbot-root", r"C:\root", "--destination", r"C:\backup",
                    "--python-path", r"C:\python.exe", "--keep", "5", "--week-start", "0",
                    "--schedule-time", "12:00", "--artifact-digest", ARTIFACT, "--scheduled",
                ]) + "' -ValidateOnly -OutputJson"
            )
            result = run_ps([exe, "-NoProfile", "-Command", command])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = json.loads(result.stdout.strip())
        self.assertEqual(value, {"operation": "install", "fingerprint": fingerprint,
                                 "status": "validated", "code": 0})

    @unittest.skipUnless(powershells(), "PowerShell unavailable")
    def test_install_validate_only_rejects_a_nonzero_digest_not_matching_local_artifacts(self):
        exe = powershells()[0]
        fingerprint = "0123456789ab"
        launcher = SCRIPTS / "task_launcher.ps1"
        install_path = str(SCRIPTS / "install_task.ps1").replace("'", "''")
        launcher_path = str(launcher).replace("'", "''")
        arguments = json.dumps([
            "--astrbot-root", r"C:\root", "--destination", r"C:\backup",
            "--python-path", r"C:\python.exe", "--keep", "5", "--week-start", "0",
            "--schedule-time", "12:00", "--artifact-digest", "f" * 64, "--scheduled",
        ])
        command = (
            "function Get-ScheduledTask { [CmdletBinding()] param([string]$TaskName) return $null }; "
            "function Register-ScheduledTask { throw 'must not register' }; "
            f"& '{install_path}' "
            f"-TaskName 'AstrBot Safe Backup {fingerprint}' -Description 'AstrBotSafeBackup:v1:{fingerprint}' "
            f"-TaskFingerprint '{fingerprint}' -LauncherPath '{launcher_path}' "
            "-LauncherArgumentsJson '" + arguments + "' -ValidateOnly -OutputJson"
        )
        result = run_ps([exe, "-NoProfile", "-Command", command])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout.strip())["status"], "failed")


if __name__ == "__main__":
    unittest.main()
