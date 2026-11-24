# Windows Permissions Investigation: Unresolved Service SID in Downloads

**Author:** Jamie Urena  
**Date:** November 24, 2026  
**Category:** Windows security / access-control review  
**Environment:** Personal Windows computer  
**Status:** Initial investigation complete; originating service unresolved

## Executive summary

Guided learning case study: I investigated an unfamiliar Windows permission on my own computer using AI-assisted PowerShell queries. AI helped develop the investigation steps, explain results, and draft this report. This project documents introductory hands-on practice, not an independently conducted incident response.

I investigated an “Account Unknown” entry discovered in the security permissions of a PDF in my Downloads folder. The objective was to identify the associated security principal, determine the scope of its permissions, and assess whether the available evidence established malicious activity.

Using PowerShell and Windows service-management utilities, I attempted to resolve the security identifier (SID), compared it against registered service names, and examined folder access-control rules.

The investigation identified an explicit Allow entry on Downloads granting `ReadAndExecute, Synchronize`. The entry was configured for inheritance by files and subfolders. However, Windows could not translate the SID into an account name, and comparisons against registered service names produced no match.

The checks did not establish malicious activity. They also did not establish that the computer was free of malware. The originating service and the reason the permission was created remain unknown.

## Objective and scope

The investigation addressed four questions:

1. Could Windows resolve the unfamiliar SID into a readable account name?
2. Did it match a currently registered service or driver name?
3. Was the permission limited to the PDF or also present on its parent folders?
4. What conclusions could reasonably be drawn from the available evidence?

All commands were executed on my own computer. The investigation used read-only queries and did not modify permissions, registry entries, or service configurations. Personal profile paths are represented as `C:\Users\<user>` in this report.

## Initial observation

While reviewing a PDF’s Security tab in File Explorer, I observed an unfamiliar entry:

```text
Account Unknown
S-1-5-80-647175514-1941694907-1950418227-3506304766-2634054687
```

The entry displayed a SID rather than a readable account name. Its unfamiliar appearance prompted investigation; it was not treated as proof of unauthorized access.

## Tools and methods

- File Explorer security properties
- Windows PowerShell
- .NET `SecurityIdentifier.Translate()`
- `Get-CimInstance Win32_Service`
- `sc.exe showsid`
- `Get-ChildItem` and `Get-ItemProperty`
- `Get-Acl`

## Investigation

### 1. Attempted SID-to-account translation

I attempted to translate the SID into a readable account name:

```powershell
([System.Security.Principal.SecurityIdentifier]'S-1-5-80-647175514-1941694907-1950418227-3506304766-2634054687').Translate([System.Security.Principal.NTAccount]).Value
```

Result (excerpt):

```text
Some or all identity references could not be translated.
FullyQualifiedErrorId : IdentityNotMappedException
```

The lookup did not resolve the SID. This result did not determine why resolution failed or establish whether the entry was benign or malicious.

### 2. Compared the SID against enumerated Windows services

I enumerated services through `Win32_Service`, generated a SID for each service name using `sc.exe showsid`, and compared the results against the target SID.

```powershell
$targetSID = 'S-1-5-80-647175514-1941694907-1950418227-3506304766-2634054687'

$found = @(
    Get-CimInstance Win32_Service | ForEach-Object {
        $sidOutput = sc.exe showsid $_.Name
        if (($sidOutput -join "`n").Contains($targetSID)) {
            $_ | Select-Object Name, DisplayName, State, StartMode, PathName
        }
    }
)

if ($found.Count -gt 0) {
    $found | Format-List
} else {
    Write-Output 'No matching SID found among the installed Windows services.'
}
```

Result:

```text
No matching SID found among the installed Windows services.
```

No matching SID was found among the service names returned by this query. This was not a comprehensive check for malicious processes or persistence mechanisms.

### 3. Expanded the comparison to Services registry names

I repeated the comparison using names under `HKLM:\SYSTEM\CurrentControlSet\Services`. This broadened the check beyond the names returned by `Win32_Service`.

```powershell
$targetSID = 'S-1-5-80-647175514-1941694907-1950418227-3506304766-2634054687'

$matches = @(
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
        $serviceName = $_.PSChildName
        $sidOutput = sc.exe showsid $serviceName 2>&1

        if (($sidOutput -join "`n").Contains($targetSID)) {
            $details = Get-ItemProperty -LiteralPath $_.PSPath
            [PSCustomObject]@{
                Name        = $serviceName
                DisplayName = $details.DisplayName
                ImagePath   = $details.ImagePath
                Type        = $details.Type
            }
        }
    }
)

if ($matches.Count -gt 0) {
    $matches | Format-List
} else {
    'No matching SID found in the registered service and driver names.'
}
```

Result:

```text
No matching SID found in the registered service and driver names.
```

The expanded comparison did not identify the originating service. The result did not prove that a service had been removed or that an unregistered service was running.

### 4. Examined Downloads and user-profile permissions

I checked whether the SID was present in the access rules for Downloads and its parent user-profile folder.

```powershell
$targetSID = 'S-1-5-80-647175514-1941694907-1950418227-3506304766-2634054687'

foreach ($folder in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE")) {
    Write-Output "`nChecking: $folder"
    try {
        $rules = @(
            (Get-Acl -LiteralPath $folder -ErrorAction Stop).Access |
                Where-Object { $_.IdentityReference.Value -eq $targetSID }
        )
        if ($rules.Count -gt 0) {
            $rules |
                Select-Object IdentityReference, FileSystemRights,
                    AccessControlType, IsInherited |
                Format-List
        } else {
            Write-Output 'This SID is not listed on this folder.'
        }
    } catch {
        Write-Output $_.Exception.Message
    }
}
```

Result (personal path redacted):

```text
Checking: C:\Users\<user>\Downloads

IdentityReference : S-1-5-80-647175514-1941694907-1950418227-3506304766-2634054687
FileSystemRights  : ReadAndExecute, Synchronize
AccessControlType : Allow
IsInherited       : False

Checking: C:\Users\<user>
This SID is not listed on this folder.
```

The entry was explicitly set on Downloads rather than inherited from its parent. The SID was not listed in the user-profile folder’s access rules. These results located the permission at the Downloads level but did not identify who or what created it.

### 5. Examined inheritance settings

I inspected the inheritance settings for the Downloads entry:

```powershell
(Get-Acl -LiteralPath "$env:USERPROFILE\Downloads").Access |
    Where-Object {
        $_.IdentityReference.Value -eq 'S-1-5-80-647175514-1941694907-1950418227-3506304766-2634054687'
    } |
    Format-List IdentityReference, FileSystemRights, AccessControlType,
        IsInherited, InheritanceFlags, PropagationFlags
```

Result:

```text
IdentityReference : S-1-5-80-647175514-1941694907-1950418227-3506304766-2634054687
FileSystemRights  : ReadAndExecute, Synchronize
AccessControlType : Allow
IsInherited       : False
InheritanceFlags  : ContainerInherit, ObjectInherit
PropagationFlags  : None
```

The entry was configured to pass down to files and subfolders. This provided a plausible explanation for the SID’s appearance on the PDF. The PDF’s own `IsInherited` value was not collected, so inheritance from Downloads was not independently confirmed for that specific file.

## Findings

| Finding | Evidence |
| --- | --- |
| Windows did not resolve the SID into an account name. | Translation returned `IdentityNotMappedException`. |
| Neither service-name comparison produced a match. | Both comparison scripts returned no-match output. |
| The SID had an explicit Allow entry on Downloads. | `AccessControlType: Allow`; `IsInherited: False`. |
| The inspected entry granted read-and-execute access, not Write or Full Control. | `FileSystemRights: ReadAndExecute, Synchronize`. |
| The rule was configured for inheritance by files and subfolders. | `ContainerInherit, ObjectInherit`; `PropagationFlags: None`. |
| The SID was not listed on the user-profile folder. | No matching entry was returned for that folder. |

## Assessment

The available evidence supports classifying this as an unresolved access-control finding, not a confirmed security incident.

A permission left behind by previously installed software is one possible explanation. However, the investigation did not identify the originating service, establish when the rule was created, or confirm that software removal caused it.

The rule’s presence does not demonstrate that a process used it to access files. Likewise, the absence of a matching service name does not establish that no malicious activity exists on the computer.

No permission changes were made because the purpose and origin of the entry remained unresolved.

## Limitations

This investigation did not include:

- Access-audit or historical event-log analysis.
- Identification of the process that created the permission.
- Process, network, or comprehensive persistence analysis.
- Effective-access analysis across all identities and group memberships.
- Confirmation of inheritance on the original PDF.
- A completed and documented antivirus scan.
- Verification of every `sc.exe` invocation’s exit status.

The conclusions apply only to the permissions and service-name comparisons examined. The no-match results are limited by the coverage and successful execution of those queries.

## Potential follow-up work — not completed

1. Inspect the original PDF’s access rules to confirm whether its entry is inherited.
2. Run and document an antivirus scan.
3. Review relevant audit records, if suitable auditing was enabled and records are available.
4. Investigate installed-software history for a possible association with the permission.

Any remediation would require a separate decision; removing the entry would not, by itself, explain its origin.

## Lessons learned

- An unfamiliar SID warrants investigation but is not automatically evidence of compromise.
- Failed account-name resolution leaves an identification gap; it does not establish a cause.
- Parent-folder access rules can help explain permissions observed on individual files.
- Negative query results must be described within the limits of the query.
- An investigation can produce useful findings without identifying a malicious actor or fully resolving the original question.

## Assistance disclosure

AI assistance was used to develop PowerShell queries, interpret output, and draft this report. I executed the commands on my own computer. Observations in this case study are based on the resulting output; explanations that were not confirmed are identified as possibilities or limitations.
