# Find-PuppetGpoConflicts

Finds Windows settings that Puppet and Group Policy are both managing. When both manage the same thing they take turns overwriting each other, and whichever ran last wins until the other one runs again. This tells you where that's happening and which GPO is involved.

## What you need

**PowerShell 5.1.** Already on Windows Server 2016 and newer. Nothing to install.

**Admin rights.** Windows won't hand over the computer's Group Policy results otherwise.

**A Puppet agent that's done at least one real run.** The script reads the catalog the agent saved last time it ran, so run it on the server you want to check (the agent), not the Puppet server.

> Noop runs don't update that saved catalog. If the last run was a noop, you're looking at older data. The script prints the catalog's date when it starts so you can tell.

## Running it

Download `Find-PuppetGpoConflicts.ps1` onto the server.

Open PowerShell as admin. Start -> type PowerShell -> right-click it -> Run as administrator.

`cd` to wherever you put the script, then:

```powershell
.\Find-PuppetGpoConflicts.ps1
```

> If Windows refuses to run it because it came from the internet, run `Unblock-File .\Find-PuppetGpoConflicts.ps1` once and try again.

You get one row per setting both of them manage, with Puppet's value, the winning GPO and its value, and whether the two agree. Disagreements are listed first.

A few other ways to run it:

```powershell
# save the results to a CSV as well
.\Find-PuppetGpoConflicts.ps1 -CsvPath C:\temp\conflicts.csv

# only the ones that disagree
.\Find-PuppetGpoConflicts.ps1 -PassThru | Where-Object Agrees -eq $false

# puppet isn't on your PATH
.\Find-PuppetGpoConflicts.ps1 -Puppet 'C:\path\to\puppet.bat'

# check a catalog file you copied from another server
.\Find-PuppetGpoConflicts.ps1 -CatalogPath .\node.json
```

It exits with `0` if nothing overlaps and `1` if something does, so it drops straight into a scheduled task or your monitoring.

## What it checks

| Puppet resource | What it's compared against |
|---|---|
| `registry_value` (puppetlabs-registry) | Administrative Templates and security options |
| `dsc_registry`, `dsc_xregistry` | Same as above |
| `local_security_policy` | Password and lockout policy, user rights, security options, old-style audit |
| `dsc_auditpolicycsv` | Advanced Audit Policy (it reads the CSV that the resource applies) |

A setting shows up even when both sides agree. Two tools managing the same thing is a fight waiting to happen. Change one and they start overwriting each other.

## Warnings you might see

**Old-style audit settings from Puppet.** Settings like "Audit logon events". Once any advanced audit setting is in place, Windows ignores the old-style ones (unless "Audit: Force audit policy subcategory settings..." has been turned off). So Puppet thinks it's set them, and they're doing nothing.

**Puppet audit CSVs.** Applying one of these replaces the whole audit policy, not just the lines in the file. Anything a GPO sets that isn't in the CSV gets wiped until Group Policy refreshes. The script tells you how many settings that affects.

**Not checked.** Anything it recognizes but can't compare gets listed here, so it never quietly skips something.

## About "Agrees"

It's best effort. Puppet and Windows often write the same value differently. One side says `enabled`, the other says `1`. One lists account names, the other lists SIDs. The script evens out the common cases, but if a row says they disagree and it looks like they shouldn't, eyeball it.

User rights set with `merge:` are left blank. A merge only adds accounts, so comparing the full list doesn't mean anything.

## Potential hazards

So far it's been tested against simulated data, not a live domain. If it does something odd on yours, say so.

There are several versions of the `local_security_policy` module floating around (cannonps, kpn, simp, and a few others). The script asks whichever one you have installed how its names map to Windows' names, so it should work with any of them. How each one formats its values can differ, though, which mostly affects the Agrees column.

The audit CSV is read using the column names from Windows' standard audit backup format. If your CSV uses different ones, you'll get a warning that it found nothing in the file rather than a pass.

## Not covered (yet)

Group Policy Preferences registry items, the `advanced_security_policy` and `advanced_audit_policy` modules, and other `dsc_*` security types. The last two show up under Not checked, so at least you'll know they're there.

User policy isn't covered either. It only looks at computer policy, which is what Puppet normally manages on Windows.

## Changes to your system

None. It only reads. It writes one temporary file (the `gpresult` report) and deletes it afterward.

Nothing leaves the box, except the normal lookups to your domain controller when it turns account names into SIDs.

## How it works, roughly

Puppet keeps a copy of the last catalog it applied under `client_datadir\catalog\<certname>.json`, which lists every resource it manages on that server. Windows keeps a record of which Group Policy settings won (the same data `gpresult` shows) in WMI. Advanced audit isn't in there, so that part comes from `gpresult /x` instead.

Most manifests name security policies the way the Local Security Policy tool does ("Minimum password length"), while Windows uses its own internal names. The script runs `puppet resource local_security_policy` to get the mapping, then puts both sides into the same format and matches them up.
