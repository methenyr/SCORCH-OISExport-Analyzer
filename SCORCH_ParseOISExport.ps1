<#
.SYNOPSIS
    Inspect, sanitize, and modify SCORCH .ois_export files via GUI or CLI.

.DESCRIPTION
    OIS Export Analyzer v1.0.0

    Launches a WPF GUI when run without parameters.
    Runs headless when any CLI switch is provided — no GUI is shown.

    All write operations support -WhatIf to preview changes without writing files.
    Output paths are auto-generated with a timestamp prefix if -OutputPath is omitted.

.PARAMETER HealthCheck
    Scans the export and reports warnings for policies with no activities,
    unreferenced global variables, and empty folders.
    Exit code 0 = success. Exit code 1 = file not found.

.PARAMETER PolicyVariableInventory
    Scans all policy activities for Orchestrator published data token references.
    Outputs a table of policy, folder path, activity, variable name, and link var flag.
    Variable names only resolve if Global Variables were included in the export.

.PARAMETER Sanitize
    Removes unreferenced globals and empty folders in a single pass.
    Use -Strict to remove all supported types. Use -WhatIf to preview.
    Writes a sidecar removal log unless -NoLog is specified.

.PARAMETER RemoveGlobals
    Removes unreferenced global variables, configurations, schedules,
    counters, and computer groups. Use -WhatIf to preview.

.PARAMETER RemoveFolders
    Removes empty folders (no policies or sub-folders). Multi-pass —
    folders that become empty after child removal are caught in subsequent passes.
    Use -WhatIf to preview.

.PARAMETER ApplyLinkBestPractices
    Color-codes and labels all link objects based on inferred type:
    Success (green), Failure (red), Delay (orange), Condition (blue).
    Use -WhatIf to preview the link count.

.PARAMETER SetMaxParallel
    Sets the MaxParallelRequests value on all policies, or a single named
    policy if -PolicyName is specified. Use -MaxParallelValue to set the count.
    Use -WhatIf to preview affected policy count.

.PARAMETER SetLogging
    Enables or disables object-specific or generic logging on policy activities.
    Use -LoggingType (Object, Generic, Both) and -LoggingAction (Enable, Disable).
    Optionally filter to one policy with -PolicyName. Use -WhatIf to preview.

.PARAMETER CreateHandoffPackage
    Bundles the export and its sidecar sanitize log (if present) into a
    timestamped zip for deployment. Use -Environment to set BASELINE or PROD.

.PARAMETER OutputPath
    Explicit output file path for write operations.
    If omitted, an auto-generated timestamped filename is used in the same
    directory as the input file.

.PARAMETER Environment
    Target environment label for handoff packages. Accepted values: BASELINE, PROD.
    Defaults to BASELINE. Prefixed to the output zip filename.

.PARAMETER MaxParallelValue
    Integer value to set for -SetMaxParallel. Defaults to 1.

.PARAMETER LoggingType
    Logging type for -SetLogging. Accepted values: Object, Generic, Both.
    Defaults to Both.

.PARAMETER LoggingAction
    Logging action for -SetLogging. Accepted values: Enable, Disable.
    Defaults to Enable.

.PARAMETER PolicyName
    Filters -SetMaxParallel and -SetLogging to a single named policy.
    Must match the policy Name field exactly.

.PARAMETER Strict
    Used with -Sanitize. Removes all supported unreferenced global types
    and all empty folders in a single pass.

.PARAMETER NoLog
    Suppresses the sidecar audit log file on write operations.

.PARAMETER WhatIf
    Previews what would be changed without writing any files or modifying the export.

.EXAMPLE
    .\SCORCH_ParseOISExport.ps1
    Launches the GUI.

.EXAMPLE
    .\SCORCH_ParseOISExport.ps1 -HealthCheck ".\MyExport.ois_export"
    Runs a health check and prints any warnings.

.EXAMPLE
    .\SCORCH_ParseOISExport.ps1 -Sanitize ".\MyExport.ois_export" -Strict -WhatIf
    Previews what a strict sanitize would remove without writing anything.

.EXAMPLE
    .\SCORCH_ParseOISExport.ps1 -Sanitize ".\MyExport.ois_export" -Strict
    Sanitizes the export and writes a timestamped output file.

.EXAMPLE
    .\SCORCH_ParseOISExport.ps1 -ApplyLinkBestPractices ".\MyExport.ois_export"
    Applies color coding to all link objects.

.EXAMPLE
    .\SCORCH_ParseOISExport.ps1 -SetMaxParallel ".\MyExport.ois_export" -MaxParallelValue 2
    Sets MaxParallelRequests to 2 on all policies.

.EXAMPLE
    .\SCORCH_ParseOISExport.ps1 -SetLogging ".\MyExport.ois_export" -LoggingType Both -LoggingAction Enable -PolicyName "My Runbook"
    Enables object and generic logging on a single named policy.

.EXAMPLE
    .\SCORCH_ParseOISExport.ps1 -CreateHandoffPackage ".\Clean.ois_export" -Environment PROD
    Creates a PROD deployment zip.

.EXAMPLE
    $clean = ".\Clean.ois_export"
    .\SCORCH_ParseOISExport.ps1 -Sanitize ".\MyExport.ois_export" -Strict -OutputPath $clean
    .\SCORCH_ParseOISExport.ps1 -CreateHandoffPackage $clean -Environment BASELINE
    Full pipeline: sanitize then package for BASELINE.

.NOTES
    GUI mode requires PowerShell 5.1 and STA:
    powershell.exe -STA -File .\SCORCH_ParseOISExport.ps1

    CLI mode works from any standard PowerShell prompt — no STA required.
    Exit code 0 = success. Exit code 1 = input file not found or error.
#>

[CmdletBinding(DefaultParameterSetName='GUI')]
param(
  # ---- Input / Output ----
  [Parameter(ParameterSetName='Sanitize',    Mandatory)][string]$Sanitize,
  [Parameter(ParameterSetName='RemoveGlobals',Mandatory)][string]$RemoveGlobals,
  [Parameter(ParameterSetName='RemoveFolders',Mandatory)][string]$RemoveFolders,
  [Parameter(ParameterSetName='ApplyLBP',    Mandatory)][string]$ApplyLinkBestPractices,
  [Parameter(ParameterSetName='SetParallel', Mandatory)][string]$SetMaxParallel,
  [Parameter(ParameterSetName='Logging',     Mandatory)][string]$SetLogging,
  [Parameter(ParameterSetName='HealthCheck', Mandatory)][string]$HealthCheck,
  [Parameter(ParameterSetName='VarInventory',Mandatory)][string]$PolicyVariableInventory,
  [Parameter(ParameterSetName='Package',     Mandatory)][string]$CreateHandoffPackage,
  [Parameter(ParameterSetName='Compare',     Mandatory)][string]$Compare,
  [Parameter(ParameterSetName='Compare',     Mandatory)][string]$Against,
  [Parameter(ParameterSetName='BulkRename',  Mandatory)][string]$BulkRename,
  [Parameter(ParameterSetName='BulkRename',  Mandatory)][string]$CsvPath,
  [Parameter(ParameterSetName='ExportReport', Mandatory)][string]$ExportReport,
  [Parameter(ParameterSetName='SearchCodebase', Mandatory)][string]$SearchCodebase,
  [string]$SourcegraphUrl,
  [string]$SourcegraphToken,


  # ---- Common options ----
  [string]$OutputPath,
  [string]$Environment  = 'BASELINE',    # BASELINE or PROD (for packaging)
  [int]$MaxParallelValue = 1,             # for -SetMaxParallel
  [ValidateSet('Object','Generic','Both')]
  [string]$LoggingType  = 'Both',         # for -SetLogging
  [ValidateSet('Enable','Disable')]
  [string]$LoggingAction = 'Enable',      # for -SetLogging
  [string]$PolicyName,                    # filter -SetLogging/-SetMaxParallel to one policy
  [switch]$Strict,                        # sanitize strict mode
  [switch]$Force,                         # skip confirmation prompts
  [switch]$NoLog,                         # skip sidecar log file
  [switch]$WhatIf,                        # preview only, no writes
  [switch]$Help
)

#Requires -Version 5.1
# Run with: powershell.exe -STA -File .\SCORCH_ParseOISExport.ps1
# If execution policy blocks the script: powershell.exe -STA -ExecutionPolicy RemoteSigned -File ...
# Note: ExecutionPolicy Bypass is not needed if the script is locally authored and unblocked.

# CHANGELOG
# 1.0.0 - 2026-03-24 - Initial release
#       - GUI with tree navigation, XML viewer, properties editor, XML tab
#       - Sanitize, global cleanup, folder cleanup, link best practices
#       - Object and generic logging controls, max parallel setting
#       - Staged edit workflow with Save / Save As / handoff packaging
#       - Policy variable inventory with link var detection
#       - Export diff / comparison with property-level change detail
#       - Bulk rename via CSV
#       - CLI mode with full feature parity and WhatIf support
#       - Comment-based help, -Help switch, health check on load
#       - Security hardening: XXE, Zip Slip, XPath injection, temp cleanup


Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Bootstrap
if ($PSBoundParameters.ContainsKey('Help')) {
  Get-Help $PSCommandPath -Detailed
  exit 0
}
$script:CliMode            = ($PSCmdlet.ParameterSetName -ne 'GUI')
$script:ActiveParameterSet = $PSCmdlet.ParameterSetName

# Compression always needed — CLI and GUI both use zip functions
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# WPF only needed for GUI — loading in non-STA can cause issues
if (-not $script:CliMode) {
  if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    throw "GUI mode requires STA. Run: powershell.exe -STA -File .\SCORCH_ParseOISExport.ps1"
  }
  Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
  Add-Type -AssemblyName System.Windows.Forms
}

function Test-IsElevated {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = [Security.Principal.WindowsPrincipal]::new($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}
$script:IsElevated = Test-IsElevated
#endregion Bootstrap

#region Constants & Script-Scope Variables

$script:AppVersion = "1.0.0"

# GUI controls — pre-initialized so StrictMode does not throw in CLI mode
$win                     = $null
$txtPath                 = $null
$btnBrowse               = $null
$txtSearch               = $null
$btnClearSearch          = $null
$tvFolders               = $null
$txtTreeSummary          = $null
$txtDropHint             = $null
$txtUniqueId             = $null
$txtType                 = $null
$txtName                 = $null
$txtSourceXml            = $null
$dgObjects               = $null
$tabInspector            = $null
$tabXml                  = $null
$miRecentFiles           = $null
$miToolsOpenXml          = $null
$btnAnalyze              = $null
$btnParse                = $null
$btnSanitize             = $null
$btnFindEmptyFolders     = $null
$btnRemoveEmptyFolders   = $null
$btnFindUnreferencedGlobals   = $null
$btnRemoveUnreferencedGlobals = $null
$btnFindPolicyVars       = $null
$btnModifyName           = $null
$btnSetMaxPar            = $null
$btnApplyLBP             = $null
$btnOnObjLog             = $null
$btnOffObjLog            = $null
$btnOnGenLog             = $null
$btnOffGenLog            = $null
$txtStatus               = $null
$txtCounts               = $null
$overlay                 = $null
$txtOverlay              = $null
$btnCloseFile            = $null
$txtMetricFolders        = $null
$txtMetricRunbooks       = $null
$txtMetricPolicies       = $null
$txtMetricObjects        = $null
$txtMetricGlobals        = $null
$txtXmlPreview           = $null
$txtSelectionSummary     = $null
$btnExpandAll            = $null
$btnCollapseAll          = $null
$miFileOpen              = $null
$miFileReload            = $null
$miFileSave              = $null
$miFileSaveAs            = $null
$miFileSanitize          = $null
$miFileExit              = $null
$miViewExpandAll         = $null
$miViewCollapseAll       = $null
$miViewOverview          = $null
$miViewObjects           = $null
$miViewXml               = $null
$miViewActions           = $null
$miToolsRename           = $null
$miToolsMaxParallel      = $null
$miToolsApplyLBP         = $null
$miToolsFindUnrefGlobals = $null
$miToolsRemoveUnrefGlobals = $null
$miToolsFindEmptyFolders = $null
$miToolsRemoveEmptyFolders = $null
$miToolsFindPolicyVars   = $null
$miToolsCopyUniqueId     = $null
$miToolsCopyPath         = $null
$miToolsCopyXml          = $null
$miHelpAbout             = $null
$miHelpUsage             = $null
$miHelpRules             = $null
$miHelpShortcuts         = $null
$dgProperties            = $null
$btnApplyProperties      = $null
$txtPropertiesHint       = $null
$txtPropertyDetail       = $null
$txtPropertyDetailLabel  = $null
$btnPopoutPropertyDetail = $null
$btnSearchCodebase       = $null


# COLORREF format is 0x00BBGGRR (little-endian BGR, not RGB)
$script:ColorRefGreen  = 65280     # 0x0000FF00 -> Green
$script:ColorRefRed    = 255       # 0x000000FF -> Red
$script:ColorRefBlue   = 16711680  # 0x00FF0000 -> Blue
$script:ColorRefOrange = 42495     # 0x0000A5FF -> Orange

# Candidate field names for policy properties (update if your export uses different names)
$script:MaxParallelCandidateNames    = @('MaxPolicyRequests','MaxParallel','MaxConcurrentPolicyInstances')
$script:ObjectLoggingCandidateNames  = @('EnableObjectSpecificLogging','EnableObjectLogging','LogSpecificData')
$script:GenericLoggingCandidateNames = @('EnableGenericLogging','EnablePublishedDataLogging','LogPublishedData')

# Recent files
$script:RecentFilesMax  = 8
$script:RecentFilesDir  = Join-Path $env:APPDATA 'ParseOisExportGui'
$script:RecentFilesPath = Join-Path $script:RecentFilesDir 'recent-files.json'
$script:RecentFiles     = @()

# Staged export state
$script:LastStagedAction = $null   # tracks what kind of edit is staged
$script:StagedExportPath    = $null
$script:HasUnsavedChanges   = $false

# Sanitize result tracking
$script:LastSanitizeRemovedItems        = @()

# In-memory tree model
$script:NodeIndex = @{}
$script:AllNodes  = $null
$script:Filtered  = $null

# Sourcegraph config
$script:SourcegraphConfigPath = Join-Path $script:RecentFilesDir 'sourcegraph.json'
$script:SourcegraphConfig     = $null

# AI provider config
$script:AiConfigPath = Join-Path $script:RecentFilesDir 'ai-config.json'
$script:AiConfig     = $null


$script:BackupBeforeSave = $true   # set to $false to skip zip backups on Save

$script:WindowSettingsPath = Join-Path $script:RecentFilesDir 'window-settings.json'

$script:HelpSections = [ordered]@{

  'Overview' = @'
## OIS Export Analyzer

The **OIS Export Analyzer** is an administrative utility for inspecting, sanitizing, and modifying Microsoft System Center Orchestrator (SCORCH) `.ois_export` files without needing access to the Orchestrator console.

It provides a structured view of your export content and a suite of targeted cleanup and modification tools, all operating on the XML file directly.

---

### Core Capabilities

**Tree Navigation** — Browse the full folder and policy hierarchy of an export, including Global Settings and Global Configurations.

**Object Inspection** — View all activities, links, and objects within any selected policy, with their Unique IDs and paths.

**XML Viewer** — Inspect the raw XML of any selected node or object directly within the tool.

**Sanitize Export** — Remove unreferenced global variables, configurations, schedules, counters, computer groups, and empty folders from an export.

**Staged Edit Workflow** — All edits are staged as a preview before any file is written. Use Save or Save As to commit changes.

**Handoff Packaging** — Bundle a cleaned export and its audit log into a timestamped BASELINE or PROD zip for deployment.
'@

  'Getting Started' = @'
## Getting Started

### Requirements

- Windows PowerShell 5.1 or later
- .NET Framework 4.7.2 or later
- Must be launched in STA (Single Thread Apartment) mode

### Launching the Tool

Run the following from PowerShell:

    powershell.exe -STA -File .\SCORCH_ParseOISExport.ps1

If your execution policy blocks the script:

    powershell.exe -STA -ExecutionPolicy RemoteSigned -File .\SCORCH_ParseOISExport.ps1

### Elevation Warning

Running as Administrator disables drag and drop due to a Windows UAC integrity level restriction. Launch PowerShell without elevation for full functionality.
'@

  'Loading an Export' = @'
## Loading an Export

### Browse

Click **Browse** in the file bar and select a `.ois_export` or `.zip` file. If a zip is selected, the tool automatically extracts the first `.ois_export` it finds.

### Drag and Drop

Drag a `.ois_export` or `.zip` file directly onto the window or the navigation tree. Drop is disabled when running elevated.

### Recent Files

Use **File → Recent Files** to quickly reopen a previously loaded export. Up to 8 recent files are remembered across sessions.

### Load and Analyze

After selecting a file, click **Load and Analyze** or press **Ctrl+R**. The tool parses the export and populates the navigation tree and summary metrics.

### Health Check

After loading, the status bar displays warnings for common issues detected in the export:

- Policies with no activities
- Unreferenced global variables
- Empty folders
'@

  'Navigation' = @'
## Navigation

### Tree Panel

The left panel shows the full folder and policy hierarchy. Expanding a folder shows its child policies. Global Settings and Global Configurations appear as separate root-level buckets.

### Search and Filter

Type in the search box to filter the tree in real time. The filter matches against node names, types, Unique IDs, and object names. Press **Escape** to clear the search, or click the **✕** button inside the search box.

### Expand and Collapse

Use **Expand All** and **Collapse All** to control the entire tree at once. These are also accessible from the **View** menu.

### Selection

Clicking a tree node populates the right panel with details for that node across all tabs.
'@

  'Inspecting Exports' = @'
## Inspecting Exports

### Overview Tab

Displays the Unique ID, type, name, and source file path for the selected node, along with a summary of its child count and related object count.

### Objects Tab

Lists all objects within the selected node — activities, links, variables, and folders — in a sortable, resizable grid. Double-click a row to jump to its XML in the XML tab.

### XML Tab

Shows the pretty-printed XML for the selected node or object. Use **Ctrl+3** to jump directly to this tab.

### Copying Data

Use the **Tools** menu or keyboard shortcuts to copy the Unique ID, path, or full XML of the current selection to the clipboard.
'@

  'Actions Tab' = @'
## Actions Tab

The Actions tab provides targeted edit and cleanup tools. All edits are staged as a preview — no file is modified until you Save or Save As.

### Rename Selected

Renames the selected folder, policy, or global item by updating its Name element in the XML. Select a tree node first.

### Set Max Parallel

Sets the maximum concurrent execution count on the selected policy. The tool searches for known field name variants used across different Orchestrator versions.

### Apply Link Best Practices

Applies color coding and labels to all link objects in the export based on inferred link type: Success (green), Failure (red), Delay (orange), Condition (blue).

### Reload Current Export

Re-parses the currently loaded file from disk without changing the active path. Useful after external edits.

### Object Logging

Enable or disable object-specific logging on all activities within the selected policy.

### Generic Logging

Enable or disable generic published data logging on all activities within the selected policy.
'@

  'Cleanup Tools' = @'
## Cleanup Tools

### Find / Remove Unreferenced Globals

Scans the export for global variables, configurations, schedules, counters, and computer groups that are not referenced by any policy. Results are listed on the Objects tab.

**Find** previews candidates without modifying anything. **Remove** prompts for a save path and writes a cleaned copy with an audit log.

### Find / Remove Empty Folders

Identifies folders that contain no policies or sub-folders. Removal is multi-pass — folders that become empty after a child is removed are caught in the next pass.

### Policy Variable Inventory

Scans all policy activities for Orchestrator published data token references. Results show which policy and activity contains each reference, and attempts to resolve the GUID to a variable name if globals were included in the export. Variables with names matching common link/connection patterns are flagged in the IsLinkVar column.

**Note:** Variable names only resolve when Global Variables are included in the export. Raw GUIDs indicate unresolved references — re-export with globals included for full resolution.
'@

  'Sanitize Export' = @'
## Sanitize Export

Sanitize performs a combined cleanup pass — removing unreferenced globals and empty folders — in a single operation.

### Strict Mode

Removes all supported unreferenced global types and all empty folders. This is the recommended option for a full pre-deployment cleanup.

### Custom Mode

Lets you choose which types to include: variables, configurations, schedules, counters, computer groups, and empty folders independently.

### Staged Result

After sanitizing, the result is loaded as a staged preview. Review the changes in the tree and Objects tab before committing.

### Committing

Use **Save** (Ctrl+S) to overwrite the current file, or **Save As** (Ctrl+Shift+S) to write a new file. A sidecar audit log is written next to the saved file listing every removed item.
'@

  'Save and Handoff' = @'
## Save and Handoff

### Staged Workflow

Every edit operation — rename, max parallel, logging, link best practices, sanitize — stages a preview rather than writing to disk immediately. The title bar shows **[Unsaved Changes]** while a staged edit is pending.

### Save

**Ctrl+S** or **File → Save** overwrites the currently loaded file with the staged content. The original file is automatically backed up as a timestamped zip in the same directory before overwriting.

### Save As

**Ctrl+Shift+S** or **File → Save As** writes the staged content to a new file and switches the active path to the new file.

### Handoff Package

After either Save or Save As, the tool offers to create a deployment package zip. The package contains the saved `.ois_export` and its sidecar audit log (if present). You choose the target environment label — BASELINE or PROD — which is prepended to the zip filename:

    BASELINE_ExportName_20250401_1430.zip
    PROD_ExportName_20250401_1430.zip

### Opening the Output Folder

After a handoff package is created, the tool offers to open the containing folder in Windows Explorer with the zip file selected.
'@

'Keyboard Shortcuts' = @'
## Keyboard Shortcuts

### File

| Shortcut | Action |
| Ctrl+O | Open Export |
| Ctrl+R / F5 | Reload Current Export |
| Ctrl+S | Save |
| Ctrl+Shift+S | Save As |
| Ctrl+Alt+S | Sanitize Export |

### Navigation

| Shortcut | Action |
| Ctrl+1 | Go to Overview tab |
| Ctrl+2 | Go to Objects tab |
| Ctrl+3 | Go to XML tab |
| Ctrl+4 | Go to Actions tab |
| Escape | Clear search box |
| F1 | Open User Guide |

### Tools

| Shortcut | Action |
| Ctrl+Shift+I | Copy Unique ID |
| Ctrl+Shift+P | Copy Path |
| Ctrl+Shift+X | Copy XML |
'@

'Properties Tab' = @'
## Properties Tab

The Properties tab shows all scalar XML properties for the selected tree node in an editable grid.

### Viewing Properties

Click any node in the navigation tree to populate the Properties tab with its direct child elements. Container nodes (sub-folders, policies, objects) are excluded — only scalar fields like Name, Description, Enabled, and MaxParallelRequests are shown.

### Editing Properties

Double-click a Value cell to edit it inline. Read-only fields (UniqueID, ObjectType, ParentID, CreationTime, LastModified, CreatedBy, LastModifiedBy) are dimmed and italic and cannot be edited.

### Selected Value Pane

The pane below the grid shows the full value of the selected row. For long values such as script content, this pane is scrollable. Drag the splitter between the grid and the pane to resize both areas.

### Pop Out

Click **Pop Out** to open the selected value in a separate resizable window. For editable fields, the popout window allows editing with an **Apply and Close** button that pushes the value back to the grid.

### Applying Changes

After editing one or more values, click **Apply Changes** to stage all edits. Changes follow the same staged workflow as all other edits — nothing is written to disk until you Save or Save As.

### Read-Only Fields

The following fields are protected and cannot be edited:

- UniqueID / UniqueId
- ObjectType / ObjectTypeName
- SourceObject / TargetObject
- ParentID / ParentId
- CreationTime / LastModified / CreatedBy / LastModifiedBy
'@

  'CLI Usage' = @'
## CLI Usage

The tool supports headless command-line operation for use in SCORCH runbooks, scheduled tasks, and automation pipelines. No GUI is launched when CLI parameters are provided.

### Requirements

CLI mode does not require STA. Run from a standard PowerShell prompt:

    powershell.exe -File .\SCORCH_ParseOISExport.ps1 -HealthCheck ".\MyExport.ois_export"

### Common Options

These options apply to all write operations:

| Option | Description |
| -OutputPath | Explicit output file path. Auto-generated if omitted. |
| -WhatIf | Preview what would change without writing any files. |
| -NoLog | Skip the sidecar audit log file on write operations. |
| -Force | Reserved for future use (skip prompts where applicable). |

### Health Check

    .\SCORCH_ParseOISExport.ps1 -HealthCheck ".\Export.ois_export"

Scans the export and reports warnings for policies with no activities, unreferenced global variables, and empty folders. Exit code 0 = clean or warnings only. Exit code 1 = file not found.

### Policy Variable Inventory

    .\SCORCH_ParseOISExport.ps1 -PolicyVariableInventory ".\Export.ois_export"

Scans all policy activities for Orchestrator published data token references and outputs a table showing policy, folder path, activity, variable name, and whether it matches common link/connection naming patterns.

### Sanitize Export

    .\SCORCH_ParseOISExport.ps1 -Sanitize ".\Export.ois_export" -Strict
    .\SCORCH_ParseOISExport.ps1 -Sanitize ".\Export.ois_export" -Strict -OutputPath ".\Clean.ois_export"
    .\SCORCH_ParseOISExport.ps1 -Sanitize ".\Export.ois_export" -Strict -WhatIf

Removes unreferenced globals and empty folders. Use -Strict for all types. A sidecar removal log is written next to the output file unless -NoLog is specified.

### Remove Unreferenced Globals

    .\SCORCH_ParseOISExport.ps1 -RemoveGlobals ".\Export.ois_export"
    .\SCORCH_ParseOISExport.ps1 -RemoveGlobals ".\Export.ois_export" -WhatIf

### Remove Empty Folders

    .\SCORCH_ParseOISExport.ps1 -RemoveFolders ".\Export.ois_export"
    .\SCORCH_ParseOISExport.ps1 -RemoveFolders ".\Export.ois_export" -WhatIf

### Apply Link Best Practices

    .\SCORCH_ParseOISExport.ps1 -ApplyLinkBestPractices ".\Export.ois_export"
    .\SCORCH_ParseOISExport.ps1 -ApplyLinkBestPractices ".\Export.ois_export" -WhatIf

Color-codes and labels all link objects. Prints a count of links found, updated, and broken down by type.

### Set Max Parallel

    .\SCORCH_ParseOISExport.ps1 -SetMaxParallel ".\Export.ois_export" -MaxParallelValue 2
    .\SCORCH_ParseOISExport.ps1 -SetMaxParallel ".\Export.ois_export" -MaxParallelValue 1 -PolicyName "My Runbook"

Sets the maximum concurrent execution count on all policies, or a single named policy. Defaults to 1 if -MaxParallelValue is not specified.

### Set Logging

    .\SCORCH_ParseOISExport.ps1 -SetLogging ".\Export.ois_export" -LoggingType Object -LoggingAction Enable
    .\SCORCH_ParseOISExport.ps1 -SetLogging ".\Export.ois_export" -LoggingType Generic -LoggingAction Disable
    .\SCORCH_ParseOISExport.ps1 -SetLogging ".\Export.ois_export" -LoggingType Both -LoggingAction Enable -PolicyName "My Runbook"

LoggingType accepts: Object, Generic, Both. LoggingAction accepts: Enable, Disable.

### Create Handoff Package

    .\SCORCH_ParseOISExport.ps1 -CreateHandoffPackage ".\Export.ois_export" -Environment BASELINE
    .\SCORCH_ParseOISExport.ps1 -CreateHandoffPackage ".\Export.ois_export" -Environment PROD

Bundles the export and its sidecar sanitize log (if present) into a timestamped zip. Environment defaults to BASELINE.

Output filename format:

    BASELINE_ExportName_20250401_1430.zip
    PROD_ExportName_20250401_1430.zip

### Pipeline Example

    $clean = ".\Clean_Export.ois_export"
    .\SCORCH_ParseOISExport.ps1 -Sanitize ".\Export.ois_export" -Strict -OutputPath $clean
    .\SCORCH_ParseOISExport.ps1 -CreateHandoffPackage $clean -Environment BASELINE

### Exit Codes

| Code | Meaning |
| 0 | Success |
| 1 | Input file not found or unhandled error |

### Bulk Rename CSV Format

The -BulkRename switch requires a CSV file with exactly two columns — OldName and NewName. Names must match the Name field in the export exactly, including case.

    OldName,NewName
    Assign Owner to Single Alert,SCOM_AssignOwner_SingleAlert
    Assign Owners to Unassigned Alerts,SCOM_AssignOwner_Unassigned
    Create HPSM Ticket,HPSM_CreateTicket

Leading and trailing spaces in the CSV are trimmed automatically. If a name is not found in the export it is reported as NotFound in the results table but does not cause an error.

### Compare Exports

    .\SCORCH_ParseOISExport.ps1 -Compare ".\Original.ois_export" -Against ".\Modified.ois_export"

Compares two exports and reports added, removed, and modified items by Unique ID. Modified items show a property-level diff of what changed between the two files. The GUI version is accessible from Tools menu and includes an Export Report button to save the diff as a text file.

### SCORCH Integration

To call from a SCORCH runbook, use a Run .Net Script activity with System.Diagnostics.Process to invoke powershell.exe with the appropriate parameters. Capture stdout as published data and check the exit code to determine success or failure.
'@

  'Security Considerations' = @'
## Security Considerations

### File Validation

The tool validates that dropped or browsed files have an `.ois_export` or `.zip` extension before loading. Files larger than 512 MB are rejected to prevent memory exhaustion from malformed exports.

### XML Safety

All XML documents are loaded with the external entity resolver disabled. This prevents XXE (XML External Entity) attacks where a crafted export could attempt to read local files or contact external servers.

### Zip Safety

When extracting from a zip archive, the tool validates that the entry path cannot escape the temp directory. Entry names containing path traversal sequences are rejected.

### Temp Files

Staged exports are written to the system temp directory with a random GUID filename. They are deleted automatically when the window closes or when staged state is reset.

### Recent Files

The recent files list is stored in your AppData folder and validated on load. Only absolute paths ending in `.ois_export` or `.zip` are accepted from the stored list.

### Elevation

Running as Administrator disables drag and drop. It does not grant the tool any additional permissions beyond what the script itself requires.
'@

  'Troubleshooting' = @'
## Troubleshooting

### Export will not load

Verify the file is a valid Orchestrator `.ois_export` with `<ExportData>` as the XML root. Exports from non-standard Orchestrator versions may use a different root element.

### Policy Variable Inventory shows only GUIDs

The export does not include Global Variables. Re-export from the Orchestrator console with Global Variables checked to enable name resolution.

### Sanitize removes nothing

The export may have no unreferenced globals, or all globals are referenced by at least one policy. Use **Find Unreferenced Globals** first to confirm candidates before running sanitize.

### Drag and drop does not work

The tool is running as Administrator. Restart PowerShell without elevation. Drag and drop from a non-elevated Explorer to an elevated process is blocked by Windows UAC integrity levels.

### Backup zip not created on Save

The save directory may not be writable. Check folder permissions. The backup is skipped silently if the directory cannot be written — the save itself still proceeds.

### Handoff package prompt does not appear

Ensure the `New-OisHandoffPackage` function is defined in the script. If it is missing, the Save flow will complete without offering the packaging step.

### CLI mode opens the GUI instead of running headless

Ensure no other parameters are missing or mistyped. If the parameter set does not match any CLI set, PowerShell defaults to the GUI parameter set and launches the window. Run with -WhatIf first to confirm the correct parameter set is being matched.

### CLI exit code is always 0 even on error

Unhandled exceptions inside Invoke-CliMode may be caught by the outer error handler before exit 1 is reached. Wrap the call in a try/catch in your automation script and check both $LASTEXITCODE and $Error to detect failures.

### Logging fields show 0 updated

The export activities do not contain the expected field names for your Orchestrator version. Inspect an activity's XML to find the actual field name and update the candidate arrays at the top of the script: $script:ObjectLoggingCandidateNames and $script:GenericLoggingCandidateNames.

'@
}


#endregion Constants & Script-Scope Variables

#region XAML Strings

$script:MainXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:Shell="clr-namespace:System.Windows.Shell;assembly=PresentationFramework"
        Title="OIS Export Analyzer"
        Height="820"
        Width="1320"
        MinHeight="720"
        MinWidth="960"
        WindowStartupLocation="CenterScreen"
        Background="#111315"
        Foreground="#F5F7FA"
        AllowDrop="True">

<Window.TaskbarItemInfo>
    <Shell:TaskbarItemInfo/>
  </Window.TaskbarItemInfo>

  <Window.Resources>

    <!-- Brushes -->
    <SolidColorBrush x:Key="Brush.WindowBg"          Color="#111315"/>
    <SolidColorBrush x:Key="Brush.CardBg"            Color="#1B1D21"/>
    <SolidColorBrush x:Key="Brush.CardBgAlt"         Color="#15171A"/>
    <SolidColorBrush x:Key="Brush.InnerCardBg"       Color="#14161A"/>
    <SolidColorBrush x:Key="Brush.InnerCardBorder"   Color="#2F343B"/>
    <SolidColorBrush x:Key="Brush.CardBorder"        Color="#2B2F36"/>
    <SolidColorBrush x:Key="Brush.InputBg"           Color="#14161A"/>
    <SolidColorBrush x:Key="Brush.InputBorder"       Color="#3A3F47"/>
    <SolidColorBrush x:Key="Brush.Text"              Color="#F5F7FA"/>
    <SolidColorBrush x:Key="Brush.SubtleText"        Color="#A9B1BC"/>
    <SolidColorBrush x:Key="Brush.Accent"            Color="#0078D4"/>
    <SolidColorBrush x:Key="Brush.AccentHover"       Color="#1890F1"/>
    <SolidColorBrush x:Key="Brush.Warning"           Color="#F5B301"/>
    <SolidColorBrush x:Key="Brush.Danger"            Color="#B00020"/>
    <SolidColorBrush x:Key="Brush.TreeSelected"      Color="#143A5A"/>
    <SolidColorBrush x:Key="Brush.MenuBg"            Color="#181B20"/>
    <SolidColorBrush x:Key="Brush.MenuHover"         Color="#23272E"/>
    <SolidColorBrush x:Key="Brush.MenuDropBg"        Color="#1B1D21"/>
    <SolidColorBrush x:Key="Brush.MenuDropHover"     Color="#2A2F36"/>
    <SolidColorBrush x:Key="Brush.MenuBorder"        Color="#252A31"/>
    <SolidColorBrush x:Key="Brush.TabBg"             Color="#23272E"/>
    <SolidColorBrush x:Key="Brush.TabHover"          Color="#2C3138"/>
    <SolidColorBrush x:Key="Brush.TabSelectedBg"     Color="#0078D4"/>
    <SolidColorBrush x:Key="Brush.TabSelectedBorder" Color="#1890F1"/>
    <SolidColorBrush x:Key="Brush.TabSelectedText"   Color="#FFFFFF"/>

    <!-- System highlight overrides -->
    <SolidColorBrush x:Key="{x:Static SystemColors.HighlightBrushKey}"                      Color="#143A5A"/>
    <SolidColorBrush x:Key="{x:Static SystemColors.InactiveSelectionHighlightBrushKey}"     Color="#143A5A"/>
    <SolidColorBrush x:Key="{x:Static SystemColors.HighlightTextBrushKey}"                  Color="#F5F7FA"/>
    <SolidColorBrush x:Key="{x:Static SystemColors.InactiveSelectionHighlightTextBrushKey}" Color="#F5F7FA"/>

    <!-- Base text -->
    <Style TargetType="TextBlock">
      <Setter Property="Foreground" Value="{StaticResource Brush.Text}"/>
    </Style>

    <Style x:Key="MutedTextBlockStyle" TargetType="TextBlock" BasedOn="{StaticResource {x:Type TextBlock}}">
      <Setter Property="Foreground" Value="{StaticResource Brush.SubtleText}"/>
    </Style>

    <!-- Buttons -->
    <Style TargetType="Button">
      <Setter Property="FontFamily"         Value="Segoe UI"/>
      <Setter Property="Foreground"         Value="White"/>
      <Setter Property="Background"         Value="#2A2D33"/>
      <Setter Property="BorderBrush"        Value="#3A3F47"/>
      <Setter Property="BorderThickness"    Value="1"/>
      <Setter Property="Height"             Value="34"/>
      <Setter Property="MinWidth"           Value="90"/>
      <Setter Property="Padding"            Value="14,0"/>
      <Setter Property="Margin"             Value="0,0,8,0"/>
      <Setter Property="Cursor"             Value="Hand"/>
      <Setter Property="FocusVisualStyle"   Value="{x:Null}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="Bd"
                    Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}"
                    CornerRadius="7"
                    SnapsToDevicePixels="True">
              <ContentPresenter HorizontalAlignment="Center"
                                VerticalAlignment="Center"
                                Margin="{TemplateBinding Padding}"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Opacity" Value="0.92"/>
              </Trigger>
              <Trigger Property="IsPressed" Value="True">
                <Setter TargetName="Bd" Property="Opacity" Value="0.78"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter TargetName="Bd" Property="Opacity" Value="0.5"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="PrimaryButtonStyle" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background"  Value="{StaticResource Brush.Accent}"/>
      <Setter Property="BorderBrush" Value="{StaticResource Brush.Accent}"/>
    </Style>

    <Style x:Key="DangerButtonStyle" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background"  Value="#3A1E24"/>
      <Setter Property="BorderBrush" Value="#6E2B37"/>
    </Style>

    <!-- Menu / MenuItem -->
    <Style TargetType="Menu">
      <Setter Property="Background"       Value="Transparent"/>
      <Setter Property="Foreground"       Value="{StaticResource Brush.Text}"/>
      <Setter Property="BorderBrush"      Value="Transparent"/>
      <Setter Property="BorderThickness"  Value="0"/>
      <Setter Property="Padding"          Value="2,2"/>
      <Setter Property="FontFamily"       Value="Segoe UI"/>
    </Style>

    <ControlTemplate x:Key="TopLevelMenuItemTemplate" TargetType="MenuItem">
      <Grid SnapsToDevicePixels="True">
        <Border x:Name="HeaderBorder"
                Background="Transparent"
                CornerRadius="4"
                Padding="6,2"
                Margin="0,0">
          <ContentPresenter ContentSource="Header" RecognizesAccessKey="True"/>
        </Border>
        <Popup x:Name="PART_Popup"
               Placement="Bottom"
               AllowsTransparency="True"
               Focusable="False"
               IsOpen="{Binding IsSubmenuOpen, RelativeSource={RelativeSource TemplatedParent}}"
               PopupAnimation="Fade">
          <Border Background="{StaticResource Brush.MenuDropBg}"
                  BorderBrush="{StaticResource Brush.MenuBorder}"
                  BorderThickness="1"
                  CornerRadius="6"
                  Padding="0">
            <StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Cycle"/>
          </Border>
        </Popup>
      </Grid>
      <ControlTemplate.Triggers>
        <Trigger Property="IsHighlighted" Value="True">
          <Setter TargetName="HeaderBorder" Property="Background" Value="{StaticResource Brush.MenuHover}"/>
        </Trigger>
        <Trigger Property="IsSubmenuOpen" Value="True">
          <Setter TargetName="HeaderBorder" Property="Background" Value="{StaticResource Brush.MenuHover}"/>
        </Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate>

    <ControlTemplate x:Key="SubmenuMenuItemTemplate" TargetType="MenuItem">
      <Border x:Name="ItemBorder"
              Background="Transparent"
              CornerRadius="4"
              Padding="10,5">
        <Grid>
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="Auto"/>
          </Grid.ColumnDefinitions>
          <ContentPresenter Grid.Column="0" ContentSource="Header" RecognizesAccessKey="True"/>
          <TextBlock Grid.Column="1"
                     Margin="12,0,0,0"
                     Foreground="{StaticResource Brush.SubtleText}"
                     VerticalAlignment="Center"
                     Text="{TemplateBinding InputGestureText}"/>
        </Grid>
      </Border>
      <ControlTemplate.Triggers>
        <Trigger Property="IsHighlighted" Value="True">
          <Setter TargetName="ItemBorder" Property="Background" Value="{StaticResource Brush.MenuDropHover}"/>
        </Trigger>
      </ControlTemplate.Triggers>
    </ControlTemplate>

    <Style TargetType="MenuItem">
      <Setter Property="Foreground"            Value="{StaticResource Brush.Text}"/>
      <Setter Property="Background"            Value="Transparent"/>
      <Setter Property="BorderBrush"           Value="Transparent"/>
      <Setter Property="BorderThickness"       Value="0"/>
      <Setter Property="FontFamily"            Value="Segoe UI"/>
      <Setter Property="OverridesDefaultStyle" Value="True"/>
      <Setter Property="Template"              Value="{StaticResource SubmenuMenuItemTemplate}"/>
      <Style.Triggers>
        <Trigger Property="Role" Value="TopLevelHeader">
          <Setter Property="Template" Value="{StaticResource TopLevelMenuItemTemplate}"/>
        </Trigger>
        <Trigger Property="Role" Value="TopLevelItem">
          <Setter Property="Template" Value="{StaticResource TopLevelMenuItemTemplate}"/>
        </Trigger>
        <Trigger Property="Role" Value="SubmenuItem">
          <Setter Property="Template" Value="{StaticResource SubmenuMenuItemTemplate}"/>
        </Trigger>
      </Style.Triggers>
    </Style>

<Style TargetType="ContextMenu">
  <Setter Property="Background"      Value="#1E2228"/>
  <Setter Property="BorderBrush"     Value="#2B2F36"/>
  <Setter Property="BorderThickness" Value="1"/>
  <Setter Property="Padding"         Value="0,4"/>
  <Setter Property="Template">
    <Setter.Value>
      <ControlTemplate TargetType="ContextMenu">
        <Border Background="#1E2228"
                BorderBrush="#2B2F36"
                BorderThickness="1"
                CornerRadius="6"
                Padding="0,4">
          <StackPanel IsItemsHost="True"/>
        </Border>
      </ControlTemplate>
    </Setter.Value>
  </Setter>
</Style>

    <!-- Inputs -->
    <Style TargetType="TextBox">
      <Setter Property="FontFamily"              Value="Segoe UI"/>
      <Setter Property="Foreground"              Value="{StaticResource Brush.Text}"/>
      <Setter Property="Background"              Value="{StaticResource Brush.InputBg}"/>
      <Setter Property="BorderBrush"             Value="{StaticResource Brush.InputBorder}"/>
      <Setter Property="BorderThickness"         Value="1"/>
      <Setter Property="Height"                  Value="32"/>
      <Setter Property="Padding"                 Value="8,4"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>

    <Style x:Key="ReadOnlyTextBoxStyle" TargetType="TextBox" BasedOn="{StaticResource {x:Type TextBox}}">
      <Setter Property="IsReadOnly"  Value="True"/>
      <Setter Property="Background"  Value="#101215"/>
      <Setter Property="BorderBrush" Value="#2F343B"/>
    </Style>

    <!-- ComboBox -->
    <Style TargetType="ComboBox">
      <Setter Property="FontFamily"     Value="Segoe UI"/>
      <Setter Property="Foreground"     Value="{StaticResource Brush.Text}"/>
      <Setter Property="Background"     Value="{StaticResource Brush.InputBg}"/>
      <Setter Property="BorderBrush"    Value="{StaticResource Brush.InputBorder}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Height"         Value="32"/>
      <Setter Property="Padding"        Value="8,4"/>
    </Style>

    <!-- Border cards -->
    <Style x:Key="CardBorderStyle" TargetType="Border">
      <Setter Property="Background"       Value="{StaticResource Brush.CardBg}"/>
      <Setter Property="BorderBrush"      Value="{StaticResource Brush.CardBorder}"/>
      <Setter Property="BorderThickness"  Value="1"/>
      <Setter Property="CornerRadius"     Value="12"/>
      <Setter Property="Padding"          Value="12"/>
    </Style>

    <Style x:Key="InnerCardBorderStyle" TargetType="Border">
      <Setter Property="Background"      Value="{StaticResource Brush.InnerCardBg}"/>
      <Setter Property="BorderBrush"     Value="{StaticResource Brush.InnerCardBorder}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius"    Value="8"/>
      <Setter Property="Padding"         Value="12"/>
    </Style>

    <!-- TreeView / TreeViewItem -->
    <Style TargetType="TreeView">
      <Setter Property="Background"       Value="Transparent"/>
      <Setter Property="BorderThickness"  Value="0"/>
      <Setter Property="Foreground"       Value="{StaticResource Brush.Text}"/>
    </Style>

    <Style TargetType="TreeViewItem">
      <Setter Property="Foreground"  Value="{StaticResource Brush.Text}"/>
      <Setter Property="Padding"     Value="2"/>
      <Setter Property="Margin"      Value="0,1,0,1"/>
    </Style>

    <Style x:Key="TreeIconStyle" TargetType="TextBlock">
      <Setter Property="FontFamily"       Value="Segoe MDL2 Assets"/>
      <Setter Property="FontSize"         Value="14"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="Margin"           Value="0,0,6,0"/>
      <Setter Property="Foreground"       Value="#60BDFF"/>
    </Style>

    <Style x:Key="TreeLabelStyle" TargetType="TextBlock">
      <Setter Property="FontFamily"       Value="Segoe UI"/>
      <Setter Property="FontSize"         Value="13"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>

    <!-- DataGrid cell helpers -->
    <Style x:Key="GridCellStyle" TargetType="DataGridCell">
      <Setter Property="Padding"          Value="6,4"/>
      <Setter Property="BorderThickness"  Value="0"/>
      <Setter Property="Background"       Value="Transparent"/>
      <Setter Property="Foreground"       Value="{StaticResource Brush.Text}"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
    </Style>

    <Style x:Key="GridTextStyle" TargetType="TextBlock">
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="TextTrimming"      Value="CharacterEllipsis"/>
      <Setter Property="TextWrapping"      Value="NoWrap"/>
    </Style>

    <Style x:Key="GridPathTextStyle" TargetType="TextBlock" BasedOn="{StaticResource GridTextStyle}">
      <Setter Property="FontFamily" Value="Consolas"/>
    </Style>

    <!-- DataGrid -->
    <Style TargetType="DataGrid">
      <Setter Property="Background"                              Value="#121417"/>
      <Setter Property="Foreground"                              Value="{StaticResource Brush.Text}"/>
      <Setter Property="BorderBrush"                             Value="{StaticResource Brush.CardBorder}"/>
      <Setter Property="BorderThickness"                         Value="1"/>
      <Setter Property="RowBackground"                           Value="#15181C"/>
      <Setter Property="AlternatingRowBackground"                Value="#111316"/>
      <Setter Property="GridLinesVisibility"                     Value="Horizontal"/>
      <Setter Property="HorizontalGridLinesBrush"                Value="#2A2E35"/>
      <Setter Property="VerticalGridLinesBrush"                  Value="#2A2E35"/>
      <Setter Property="HeadersVisibility"                       Value="Column"/>
      <Setter Property="CanUserAddRows"                          Value="False"/>
      <Setter Property="CanUserDeleteRows"                       Value="False"/>
      <Setter Property="CanUserResizeRows"                       Value="False"/>
      <Setter Property="CanUserResizeColumns"                    Value="True"/>
      <Setter Property="IsReadOnly"                              Value="True"/>
      <Setter Property="RowHeaderWidth"                          Value="0"/>
      <Setter Property="ScrollViewer.HorizontalScrollBarVisibility" Value="Auto"/>
      <Setter Property="ScrollViewer.VerticalScrollBarVisibility"   Value="Auto"/>
    </Style>

    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background"       Value="#1F2329"/>
      <Setter Property="Foreground"       Value="{StaticResource Brush.Text}"/>
      <Setter Property="BorderBrush"      Value="#2E333A"/>
      <Setter Property="BorderThickness"  Value="0,0,0,1"/>
      <Setter Property="Padding"          Value="8,6"/>
      <Setter Property="FontWeight"       Value="SemiBold"/>
    </Style>

    <!-- TabControl / TabItem -->
    <Style TargetType="TabControl">
      <Setter Property="Background"      Value="Transparent"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding"         Value="0"/>
    </Style>

    <Style TargetType="TabItem">
      <Setter Property="Foreground"       Value="{StaticResource Brush.Text}"/>
      <Setter Property="Background"       Value="{StaticResource Brush.TabBg}"/>
      <Setter Property="BorderBrush"      Value="#353A42"/>
      <Setter Property="BorderThickness"  Value="1"/>
      <Setter Property="Padding"          Value="14,8"/>
      <Setter Property="Margin"           Value="0,0,6,0"/>
      <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="Bd"
                    Background="{TemplateBinding Background}"
                    BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}"
                    CornerRadius="8,8,0,0"
                    Padding="{TemplateBinding Padding}"
                    SnapsToDevicePixels="True">
              <ContentPresenter x:Name="ContentSite"
                                ContentSource="Header"
                                HorizontalAlignment="Center"
                                VerticalAlignment="Center"
                                RecognizesAccessKey="True"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="{StaticResource Brush.TabHover}"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="Bd" Property="Background"  Value="{StaticResource Brush.TabSelectedBg}"/>
                <Setter TargetName="Bd" Property="BorderBrush" Value="{StaticResource Brush.TabSelectedBorder}"/>
                <Setter Property="Foreground" Value="{StaticResource Brush.TabSelectedText}"/>
                <Setter Property="Panel.ZIndex" Value="10"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False">
                <Setter Property="Foreground" Value="#7D8590"/>
                <Setter TargetName="Bd" Property="Opacity" Value="0.65"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- StatusBar -->
    <Style TargetType="StatusBar">
      <Setter Property="Background"      Value="#181B20"/>
      <Setter Property="Foreground"      Value="{StaticResource Brush.Text}"/>
      <Setter Property="BorderBrush"     Value="#2B2F36"/>
      <Setter Property="BorderThickness" Value="1"/>
    </Style>

  </Window.Resources>

  <Grid Margin="14">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="12"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="10"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Menu Bar -->
    <Menu Grid.Row="0" Margin="0,0,0,8">
      <Menu.Resources>
        <Style x:Key="{x:Static MenuItem.SeparatorStyleKey}" TargetType="Separator">
          <Setter Property="Margin" Value="0,4"/>
          <Setter Property="Template">
            <Setter.Value>
              <ControlTemplate TargetType="Separator">
                <Grid Margin="-28,0,0,0">
                  <Border Height="1"
                          Background="#39404A"
                          HorizontalAlignment="Stretch"
                          SnapsToDevicePixels="True"/>
                </Grid>
              </ControlTemplate>
            </Setter.Value>
          </Setter>
        </Style>
      </Menu.Resources>

      <MenuItem Header="_File">
        <MenuItem x:Name="miFileOpen"     Header="_Open Export"          InputGestureText="Ctrl+O"/>
        <MenuItem x:Name="miFileReload"   Header="_Reload Current Export" InputGestureText="Ctrl+R"/>
        <MenuItem x:Name="miFileSave"     Header="_Save"                 InputGestureText="Ctrl+S"/>
        <MenuItem x:Name="miFileSaveAs"   Header="Save _As"              InputGestureText="Ctrl+Shift+S"/>
        <Separator/>
        <MenuItem x:Name="miRecentFiles"  Header="_Recent Files"/>
        <Separator/>
        <MenuItem x:Name="miFileSanitize" Header="_Sanitize Export"      InputGestureText="Ctrl+Alt+S"/>
        <Separator/>
        <MenuItem x:Name="miFileExit"     Header="E_xit"                 InputGestureText="Alt+F4"/>
      </MenuItem>

      <MenuItem Header="_View">
        <MenuItem x:Name="miViewExpandAll"   Header="_Expand All"/>
        <MenuItem x:Name="miViewCollapseAll" Header="_Collapse All"/>
        <Separator/>
        <MenuItem x:Name="miViewOverview" Header="Go to _Overview" InputGestureText="Ctrl+1"/>
        <MenuItem x:Name="miViewObjects"  Header="Go to _Objects"  InputGestureText="Ctrl+2"/>
        <MenuItem x:Name="miViewXml"      Header="Go to _XML"      InputGestureText="Ctrl+3"/>
        <MenuItem x:Name="miViewActions"  Header="Go to _Actions"  InputGestureText="Ctrl+4"/>
      </MenuItem>

      <MenuItem Header="_Tools">
        <MenuItem x:Name="miToolsRename"             Header="_Rename Selected"/>
        <MenuItem x:Name="miToolsMaxParallel"        Header="Set _Max Parallel"/>
        <MenuItem x:Name="miToolsApplyLBP"           Header="_Apply Link Best Practices"/>
        <Separator/>
        <MenuItem x:Name="miToolsFindUnrefGlobals"   Header="Find _Unreferenced Globals"/>
        <MenuItem x:Name="miToolsFindPolicyVars" Header="Find _Policy Variables"/>
        <MenuItem x:Name="miToolsRemoveUnrefGlobals" Header="Remove U_nreferenced Globals"/>
        <Separator/>
        <MenuItem x:Name="miToolsFindEmptyFolders"   Header="Find _Empty Folders"/>
        <MenuItem x:Name="miToolsRemoveEmptyFolders" Header="Remove Empt_y Folders"/>
        <Separator/>
        <MenuItem x:Name="miToolsOpenXml"      Header="_Open XML"/>
        <MenuItem x:Name="miToolsCopyUniqueId" Header="Copy _Unique ID"/>
        <MenuItem x:Name="miToolsCopyPath"     Header="Copy _Path"/>
        <MenuItem x:Name="miToolsCopyXml"      Header="Copy _XML"/>
        <Separator/>
        <MenuItem x:Name="miToolsCompare" Header="Compare Exports..."/>
        <MenuItem x:Name="miToolsExportReport" Header="Export Report..."/>
        <Separator/>
        <MenuItem x:Name="miToolsSourcegraph" Header="Sourcegraph Search..."/>
        <MenuItem x:Name="miToolsSourcegraphSettings" Header="Sourcegraph Settings..."/>
      </MenuItem>

      <MenuItem Header="_Help">
        <MenuItem x:Name="miHelpAbout"     Header="_About"/>
        <MenuItem x:Name="miHelpUsage"     Header="_Usage Notes"/>
        <MenuItem x:Name="miHelpRules"     Header="_Naming / Cleanup Rules"/>
        <MenuItem x:Name="miHelpShortcuts" Header="_Keyboard Shortcuts"/>
        <MenuItem x:Name="miHelpGuide" Header="_User Guide" InputGestureText="F1"/>
      </MenuItem>
    </Menu>

    <!-- Header -->
    <Border Grid.Row="1"
            Background="#0078D4"
            CornerRadius="12"
            Padding="16">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel>
          <TextBlock Text="OIS Export Analyzer"
                     FontSize="24"
                     FontWeight="Bold"
                     Foreground="White"/>
          <TextBlock Text="Inspect, sanitize, and modify SCORCH .ois_export files"
                     Margin="0,4,0,0"
                     Foreground="#EAF4FF"/>
        </StackPanel>
        <Border Grid.Column="1"
                Background="#1B4F7A"
                BorderBrush="#7AB7ED"
                BorderThickness="1"
                CornerRadius="14"
                Padding="10,4"
                VerticalAlignment="Top">
          <TextBlock x:Name="txtElevationBadge"
                     Text="Standard Mode"
                     FontWeight="SemiBold"
                     Foreground="White"/>
        </Border>
      </Grid>
    </Border>

    <!-- File action card -->
    <Border Grid.Row="2"
            Style="{StaticResource CardBorderStyle}"
            Margin="0,12,0,0">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="110"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>

        <TextBlock Grid.Row="0" Grid.Column="0"
                   Text="Export File:"
                   VerticalAlignment="Center"
                   FontWeight="SemiBold"/>

        <TextBox x:Name="txtPath"
                 Grid.Row="0"
                 Grid.Column="1"
                 Margin="0,0,10,0"
                 ToolTip="Browse to or drag in a .ois_export file."/>

        <Button x:Name="btnBrowse"
        Grid.Row="0" Grid.Column="2"
        Content="Browse"
        ToolTip="Browse for a .ois_export or .zip file to open."/>
        
        <Button x:Name="btnCloseFile"
        Grid.Row="0"
        Grid.Column="3"
        Content="Close Export"
        ToolTip="Close the current export and reset the workspace."
        Style="{StaticResource DangerButtonStyle}"/>

        <Button x:Name="btnAnalyze"  Grid.Row="0" Grid.Column="4"
                Content="Load &amp; Analyze"
                Style="{StaticResource PrimaryButtonStyle}"
                MinWidth="140"
                ToolTip="Parse the selected export and populate the navigation tree."/>

        <Button x:Name="btnSanitize" Grid.Row="0" Grid.Column="5"
                Content="Sanitize Export"
                MinWidth="130"
                ToolTip="Remove unreferenced globals and empty folders. Changes are staged for review."/>

        <TextBlock Grid.Row="1" Grid.Column="1" Grid.ColumnSpan="5"
                   Margin="0,10,0,0"
                   Style="{StaticResource MutedTextBlockStyle}"
                   Text="Tip: Open an export, inspect folders/runbooks/objects, then sanitize or apply targeted edits from the Actions tab."/>
      </Grid>
    </Border>

    <!-- Main content -->
    <Grid Grid.Row="4">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="2.6*" MinWidth="320"/>
        <ColumnDefinition Width="10"/>
        <ColumnDefinition Width="4*" MinWidth="520"/>
      </Grid.ColumnDefinitions>

      <GridSplitter Grid.Column="1"
                    Width="10"
                    HorizontalAlignment="Stretch"
                    VerticalAlignment="Stretch"
                    ResizeBehavior="PreviousAndNext"
                    ResizeDirection="Columns"
                    Background="#1E2228"/>

<!-- LEFT: Navigation card -->
      <Border Grid.Column="0" Style="{StaticResource CardBorderStyle}">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="8"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>

          <Grid Grid.Row="0">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*"/>
              <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <StackPanel>
              <TextBlock Text="Navigation" FontSize="15" FontWeight="SemiBold"/>
              <TextBlock x:Name="txtTreeSummary"
                         Margin="0,4,0,0"
                         Style="{StaticResource MutedTextBlockStyle}"
                         Text="Search folders, policies, IDs, and object names."/>
            </StackPanel>
            <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
<Button x:Name="btnExpandAll"
        Content="Expand All"
        MinWidth="95" Height="30" Margin="0,0,8,0"
        ToolTip="Expand all nodes in the navigation tree."/>

<Button x:Name="btnCollapseAll"
        Content="Collapse All"
        MinWidth="95" Height="30" Margin="0"
        ToolTip="Collapse all nodes in the navigation tree."/>
            </StackPanel>
          </Grid>

          <DockPanel Grid.Row="1" Margin="0,12,0,0" LastChildFill="True">
            <Button x:Name="btnClearSearch"
                    DockPanel.Dock="Right"
                    Content="&#x2715;"
                    Width="30"
                    Height="32"
                    Margin="4,0,0,0"
                    Padding="0"
                    MinWidth="0"
                    Background="Transparent"
                    BorderBrush="{StaticResource Brush.InputBorder}"
                    BorderThickness="1"
                    Foreground="{StaticResource Brush.SubtleText}"
                    ToolTip="Clear search"
                    Visibility="Collapsed"/>
            <TextBox x:Name="txtSearch"
                     Padding="8,4"
                     ToolTip="Filter the tree by name, type, unique ID, or path."/>
          </DockPanel>

          <Border Grid.Row="3"
                  Background="{StaticResource Brush.InnerCardBg}"
                  BorderBrush="{StaticResource Brush.InnerCardBorder}"
                  BorderThickness="1"
                  CornerRadius="10"
                  Padding="6">
            <TreeView x:Name="tvFolders"
                      ScrollViewer.VerticalScrollBarVisibility="Auto"
                      ScrollViewer.HorizontalScrollBarVisibility="Auto"/>
          </Border>

          <TextBlock x:Name="txtDropHint"
                     Grid.Row="4"
                     Margin="0,10,0,0"
                     HorizontalAlignment="Center"
                     Foreground="#9AA0A6"
                     FontStyle="Italic"
                     Text="Tip: Drag &amp; drop a .ois_export file here"/>
        </Grid>
      </Border>

      <!-- RIGHT: Inspector -->
      <Grid Grid.Column="2">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="10"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- Summary metrics -->
        <Border Grid.Row="0" Style="{StaticResource CardBorderStyle}">
<Grid>
  <Grid.ColumnDefinitions>
    <ColumnDefinition Width="*"/>
    <ColumnDefinition Width="*"/>
    <ColumnDefinition Width="*"/>
    <ColumnDefinition Width="*"/>
    <ColumnDefinition Width="*"/>
    <ColumnDefinition Width="Auto"/>
  </Grid.ColumnDefinitions>

  <StackPanel>
    <TextBlock Text="Folders" Style="{StaticResource MutedTextBlockStyle}"/>
    <TextBlock x:Name="txtMetricFolders" Text="0" FontSize="22" FontWeight="Bold"/>
  </StackPanel>

  <StackPanel Grid.Column="1">
    <TextBlock Text="Runbooks" Style="{StaticResource MutedTextBlockStyle}"/>
    <TextBlock x:Name="txtMetricRunbooks" Text="0" FontSize="22" FontWeight="Bold"/>
  </StackPanel>

  <StackPanel Grid.Column="2">
    <TextBlock Text="Activities" Style="{StaticResource MutedTextBlockStyle}"/>
    <TextBlock x:Name="txtMetricObjects" Text="0" FontSize="22" FontWeight="Bold"/>
  </StackPanel>

  <StackPanel Grid.Column="3">
    <TextBlock Text="Variables" Style="{StaticResource MutedTextBlockStyle}"/>
    <TextBlock x:Name="txtMetricPolicies" Text="0" FontSize="22" FontWeight="Bold"/>
  </StackPanel>

  <StackPanel Grid.Column="4">
    <TextBlock Text="Globals" Style="{StaticResource MutedTextBlockStyle}"/>
    <TextBlock x:Name="txtMetricGlobals" Text="0" FontSize="22" FontWeight="Bold"/>
  </StackPanel>

  <Button x:Name="btnCopySummary"
          Grid.Column="5"
          Content="Copy"
          Width="50"
          Height="28"
          Margin="12,0,0,0"
          VerticalAlignment="Center"
          ToolTip="Copy export summary and health warnings to clipboard."/>
</Grid>
        </Border>

        <!-- Inspector tabs -->
        <Border Grid.Row="2" Style="{StaticResource CardBorderStyle}">
          <Grid>
            <TabControl x:Name="tabInspector">

              <!-- Overview -->
              <TabItem Header="Overview">
                <Grid Margin="8">
                  <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                  </Grid.RowDefinitions>
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="120"/>
                    <ColumnDefinition Width="*"/>
                  </Grid.ColumnDefinitions>

                  <TextBlock Grid.Row="0" Grid.Column="0" Text="Unique ID:"  VerticalAlignment="Center"/>
                  <TextBox   x:Name="txtUniqueId" Grid.Row="0" Grid.Column="1" Style="{StaticResource ReadOnlyTextBoxStyle}"/>

                  <TextBlock Grid.Row="1" Grid.Column="0" Margin="0,8,0,0" Text="Type:"        VerticalAlignment="Center"/>
                  <TextBox   x:Name="txtType"     Grid.Row="1" Grid.Column="1" Margin="0,8,0,0" Style="{StaticResource ReadOnlyTextBoxStyle}"/>

                  <TextBlock Grid.Row="2" Grid.Column="0" Margin="0,8,0,0" Text="Name:"        VerticalAlignment="Center"/>
                  <TextBox   x:Name="txtName"     Grid.Row="2" Grid.Column="1" Margin="0,8,0,0" Style="{StaticResource ReadOnlyTextBoxStyle}"/>

                  <TextBlock Grid.Row="3" Grid.Column="0" Margin="0,8,0,0" Text="Source File:" VerticalAlignment="Center"/>
                  <TextBox   x:Name="txtSourceXml" Grid.Row="3" Grid.Column="1" Margin="0,8,0,0" Style="{StaticResource ReadOnlyTextBoxStyle}"/>

                  <Border Grid.Row="4"
                          Grid.ColumnSpan="2"
                          Margin="0,12,0,0"
                          Style="{StaticResource InnerCardBorderStyle}">
                    <StackPanel>
                      <TextBlock Text="Selection Notes" FontWeight="SemiBold"/>
                      <TextBlock x:Name="txtSelectionSummary"
                                 Margin="0,6,0,0"
                                 TextWrapping="Wrap"
                                 Style="{StaticResource MutedTextBlockStyle}"
                                 Text="Select a folder, policy, or object group to inspect its details and related objects."/>
                    </StackPanel>
                  </Border>
                </Grid>
              </TabItem>

              <!-- Objects -->
              <TabItem Header="Objects">
                <Grid Margin="8">
                  <DataGrid x:Name="dgObjects"
                            AutoGenerateColumns="False"
                            IsReadOnly="True"
                            CanUserSortColumns="True"
                            CanUserResizeColumns="True"
                            CanUserReorderColumns="True"
                            SelectionMode="Extended"
                            SelectionUnit="FullRow"
                            ClipboardCopyMode="IncludeHeader"
                            FrozenColumnCount="1"
                            CellStyle="{StaticResource GridCellStyle}"
                            ScrollViewer.HorizontalScrollBarVisibility="Auto"
                            ScrollViewer.VerticalScrollBarVisibility="Auto">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Name"      Binding="{Binding Name}"      Width="220" SortMemberPath="Name">
                        <DataGridTextColumn.ElementStyle>
                          <Style TargetType="TextBlock" BasedOn="{StaticResource GridTextStyle}">
                            <Setter Property="ToolTip" Value="{Binding Name}"/>
                          </Style>
                        </DataGridTextColumn.ElementStyle>
                      </DataGridTextColumn>
                      <DataGridTextColumn Header="Type"      Binding="{Binding Type}"      Width="130" SortMemberPath="Type">
                        <DataGridTextColumn.ElementStyle>
                          <Style TargetType="TextBlock" BasedOn="{StaticResource GridTextStyle}">
                            <Setter Property="ToolTip" Value="{Binding Type}"/>
                          </Style>
                        </DataGridTextColumn.ElementStyle>
                      </DataGridTextColumn>
                      <DataGridTextColumn Header="Unique ID" Binding="{Binding UniqueId}"  Width="260" SortMemberPath="UniqueId">
                        <DataGridTextColumn.ElementStyle>
                          <Style TargetType="TextBlock" BasedOn="{StaticResource GridTextStyle}">
                            <Setter Property="FontFamily" Value="Consolas"/>
                            <Setter Property="ToolTip"    Value="{Binding UniqueId}"/>
                          </Style>
                        </DataGridTextColumn.ElementStyle>
                      </DataGridTextColumn>
                      <DataGridTemplateColumn Header="Path"  Width="600" SortMemberPath="Path">
                        <DataGridTemplateColumn.CellTemplate>
                          <DataTemplate>
                            <TextBlock Text="{Binding Path}"
                                       Style="{StaticResource GridPathTextStyle}"
                                       ToolTip="{Binding Path}"/>
                          </DataTemplate>
                        </DataGridTemplateColumn.CellTemplate>
                      </DataGridTemplateColumn>
                    </DataGrid.Columns>
                  </DataGrid>
                </Grid>
              </TabItem>

              <!-- XML -->
              <TabItem x:Name="tabXml" Header="XML">
                <Grid Margin="8">
                  <TextBox x:Name="txtXmlPreview"
                           Style="{StaticResource ReadOnlyTextBoxStyle}"
                           FontFamily="Consolas"
                           FontSize="12"
                           AcceptsReturn="True"
                           AcceptsTab="True"
                           IsReadOnly="True"
                           Padding="10"
                           VerticalScrollBarVisibility="Auto"
                           HorizontalScrollBarVisibility="Auto"
                           TextWrapping="NoWrap"
                           Height="Auto"/>
                </Grid>
              </TabItem>

<!-- Properties -->
<TabItem Header="Properties">
  <Grid Margin="8">
    <Grid.RowDefinitions>
      <RowDefinition Height="*" MinHeight="80"/>
      <RowDefinition Height="5"/>
      <RowDefinition Height="160" MinHeight="60"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <DataGrid x:Name="dgProperties"
              Grid.Row="0"
              IsReadOnly="False"
              AutoGenerateColumns="False"
              CanUserAddRows="False"
              CanUserDeleteRows="False"
              CanUserResizeRows="False"
              CanUserSortColumns="False"
              CanUserResizeColumns="True"
              HeadersVisibility="Column"
              RowHeaderWidth="0"
              BorderThickness="1"
              GridLinesVisibility="Horizontal"
              SelectionMode="Single"
              SelectionUnit="FullRow">
<DataGrid.RowStyle>
  <Style TargetType="DataGridRow">
    <Setter Property="MaxHeight" Value="52"/>
    <Style.Triggers>
      <DataTrigger Binding="{Binding ReadOnly}" Value="True">
        <Setter Property="Foreground" Value="#555A63"/>
        <Setter Property="FontStyle"  Value="Italic"/>
      </DataTrigger>
      <DataTrigger Binding="{Binding ReadOnly}" Value="False">
        <Setter Property="Foreground" Value="#F5F7FA"/>
      </DataTrigger>
    </Style.Triggers>
  </Style>
</DataGrid.RowStyle>

      <DataGrid.Columns>
        <DataGridTextColumn Header="Property"
                            Binding="{Binding LocalName}"
                            Width="200"
                            IsReadOnly="True">
          <DataGridTextColumn.ElementStyle>
            <Style TargetType="TextBlock" BasedOn="{StaticResource GridTextStyle}">
              <Setter Property="Foreground"   Value="{StaticResource Brush.SubtleText}"/>
              <Setter Property="FontFamily"   Value="Consolas"/>
              <Setter Property="FontSize"     Value="12"/>
              <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
            </Style>
          </DataGridTextColumn.ElementStyle>
        </DataGridTextColumn>

        <DataGridTextColumn Header="Value"
                            Binding="{Binding Value, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}"
                            Width="*">
          <DataGridTextColumn.ElementStyle>
            <Style TargetType="TextBlock" BasedOn="{StaticResource GridTextStyle}">
              <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
              <Setter Property="TextWrapping" Value="NoWrap"/>
            </Style>
          </DataGridTextColumn.ElementStyle>
          <DataGridTextColumn.EditingElementStyle>
            <Style TargetType="TextBox">
              <Setter Property="Background"    Value="#1A1D22"/>
              <Setter Property="Foreground"    Value="#F5F7FA"/>
              <Setter Property="BorderBrush"   Value="#0078D4"/>
              <Setter Property="Padding"       Value="4,2"/>
              <Setter Property="FontFamily"    Value="Segoe UI"/>
              <Setter Property="MaxHeight"     Value="52"/>
              <Setter Property="AcceptsReturn" Value="False"/>
            </Style>
          </DataGridTextColumn.EditingElementStyle>
        </DataGridTextColumn>

        <DataGridTextColumn Header="Datatype"
                            Binding="{Binding Datatype}"
                            Width="100"
                            IsReadOnly="True">
          <DataGridTextColumn.ElementStyle>
            <Style TargetType="TextBlock" BasedOn="{StaticResource GridTextStyle}">
              <Setter Property="Foreground" Value="{StaticResource Brush.SubtleText}"/>
              <Setter Property="FontSize"   Value="11"/>
            </Style>
          </DataGridTextColumn.ElementStyle>
        </DataGridTextColumn>
      </DataGrid.Columns>
    </DataGrid>

    <!-- Drag to resize detail pane -->
    <GridSplitter Grid.Row="1"
                  Height="5"
                  HorizontalAlignment="Stretch"
                  VerticalAlignment="Stretch"
                  ResizeBehavior="PreviousAndNext"
                  ResizeDirection="Rows"
                  Background="#2B2F36"
                  Cursor="SizeNS"
                  ToolTip="Drag to resize"/>

<!-- Full value viewer -->
<Grid Grid.Row="2" Margin="0,4,0,0">
  <Grid.RowDefinitions>
    <RowDefinition Height="Auto"/>
    <RowDefinition Height="*"/>
  </Grid.RowDefinitions>

  <!-- Detail pane header with label and buttons -->
  <Grid Grid.Row="0" Margin="0,0,0,4">
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="*"/>
      <ColumnDefinition Width="Auto"/>
      <ColumnDefinition Width="Auto"/>
    </Grid.ColumnDefinitions>

    <TextBlock x:Name="txtPropertyDetailLabel"
               Grid.Column="0"
               VerticalAlignment="Center"
               Style="{StaticResource MutedTextBlockStyle}"
               FontSize="11"
               Text="Selected value:"/>

<Button x:Name="btnSearchCodebase"
        Grid.Column="1"
        Content="Search Codebase"
        Height="22"
        Padding="8,0"
        Margin="8,0,0,0"
        MinWidth="0"
        FontSize="11"
        IsEnabled="False"
        ToolTip="Search Sourcegraph for references to this script content"/>

    <Button x:Name="btnPopoutPropertyDetail"
            Grid.Column="2"
            Content="Pop Out"
            Height="22"
            Padding="8,0"
            Margin="8,0,0,0"
            MinWidth="0"
            FontSize="11"
            ToolTip="Open value in a separate window"/>
  </Grid>

  <TextBox x:Name="txtPropertyDetail"
           Grid.Row="1"
           Style="{StaticResource ReadOnlyTextBoxStyle}"
           IsReadOnly="False"
           Background="#14161A"
           BorderBrush="#2F343B"
           BorderThickness="1"
           FontFamily="Consolas"
           FontSize="11"
           AcceptsReturn="True"
           TextWrapping="Wrap"
           VerticalScrollBarVisibility="Auto"
           HorizontalScrollBarVisibility="Auto"
           Padding="8,6"
           Height="Auto"/>
</Grid>

    <!-- Apply button row -->
    <StackPanel Grid.Row="3"
                Orientation="Horizontal"
                HorizontalAlignment="Right"
                Margin="0,8,0,0">
      <TextBlock x:Name="txtPropertiesHint"
                 VerticalAlignment="Center"
                 Margin="0,0,12,0"
                 Style="{StaticResource MutedTextBlockStyle}"
                 Text="Edit a value and click Apply to stage the change."/>
      <Button x:Name="btnApplyProperties"
              Content="Apply Changes"
              Style="{StaticResource PrimaryButtonStyle}"
              MinWidth="130"
              IsEnabled="False"/>
    </StackPanel>
  </Grid>
</TabItem>

<!-- Actions -->
              <TabItem Header="Actions">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                  <StackPanel Margin="8">

                    <TextBlock Text="Toolbox" FontSize="15" FontWeight="SemiBold"/>
                    <TextBlock Margin="0,6,0,14"
                               Style="{StaticResource MutedTextBlockStyle}"
                               Text="Use grouped actions to inspect, edit, and clean exports without crowding the lower pane."/>

                    <!-- Reload / Editing Tools -->
                    <Border Style="{StaticResource InnerCardBorderStyle}" Margin="0,0,0,12">
                      <StackPanel>
                        <TextBlock Text="Reload / Editing Tools" FontWeight="SemiBold"/>
                        <Grid Margin="0,10,0,0">
                          <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                          </Grid.RowDefinitions>
                          <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                          </Grid.ColumnDefinitions>

                          <Button x:Name="btnModifyName"
                                  Grid.Row="0" Grid.Column="0"
                                  Content="Rename Selected"
                                  ToolTip="Rename the selected folder, policy, or global item."
                                  Margin="0,0,10,10"/>

                          <Button x:Name="btnSetMaxPar"
                                  Grid.Row="0" Grid.Column="1"
                                  Content="Set Max Parallel"
                                  ToolTip="Set the maximum concurrent execution count on the selected policy."
                                  Margin="0,0,0,10"/>

                          <Button x:Name="btnApplyLBP"
                                  Grid.Row="1" Grid.Column="0"
                                  Content="Apply Link Best Practices"
                                  ToolTip="Color-code and label all link objects based on inferred type."
                                  Margin="0,0,10,10"/>

                          <Button x:Name="btnParse"
                                  Grid.Row="1" Grid.Column="1"
                                  Content="Reload Current Export"
                                  ToolTip="Re-parse the current file from disk without changing the active path."
                                  Margin="0,0,0,10"/>

                          <Button x:Name="btnOnObjLog"
                                  Grid.Row="2" Grid.Column="0"
                                  Content="Enable Object Logging"
                                  ToolTip="Enable object-specific logging on all activities in the selected policy."
                                  Margin="0,0,10,10"/>

                          <Button x:Name="btnOffObjLog"
                                  Grid.Row="2" Grid.Column="1"
                                  Content="Disable Object Logging"
                                  ToolTip="Disable object-specific logging on all activities in the selected policy."
                                  Margin="0,0,0,10"/>

                          <Button x:Name="btnOnGenLog"
                                  Grid.Row="3" Grid.Column="0"
                                  Content="Enable Generic Logging"
                                  ToolTip="Enable published data logging on all activities in the selected policy."
                                  Margin="0,0,10,10"/>

                          <Button x:Name="btnOffGenLog"
                                  Grid.Row="3" Grid.Column="1"
                                  Content="Disable Generic Logging"
                                  ToolTip="Disable published data logging on all activities in the selected policy."
                                  Margin="0,0,0,10"/>

                          <Button x:Name="btnBulkRename"
                                  Grid.Row="4" Grid.Column="0" Grid.ColumnSpan="2"
                                  Content="Bulk Rename from CSV..."
                                  ToolTip="Rename multiple items at once using an OldName,NewName CSV file."
                                  HorizontalAlignment="Stretch"
                                  Margin="0,10,0,0"/>
                        </Grid>
                      </StackPanel>
                    </Border>

                    <!-- Global Cleanup -->
                    <Border Style="{StaticResource InnerCardBorderStyle}" Margin="0,0,0,12">
                      <StackPanel>
                        <TextBlock Text="Global Cleanup" FontWeight="SemiBold"/>
                        <TextBlock Margin="0,6,0,10"
                                   Style="{StaticResource MutedTextBlockStyle}"
                                   Text="Preview or remove unreferenced variables, configurations, schedules, counters, and groups."/>
                        <Grid>
                          <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                          </Grid.ColumnDefinitions>
                          <Button x:Name="btnFindUnreferencedGlobals"
                                  Grid.Column="0"
                                  Content="Find Unreferenced Globals"
                                  ToolTip="Preview globals not referenced by any policy. Results appear on the Objects tab."
                                  Margin="0,0,10,0"/>
                          <Button x:Name="btnRemoveUnreferencedGlobals"
                                  Grid.Column="1"
                                  Content="Remove Unreferenced Globals"
                                  ToolTip="Save a cleaned copy with unreferenced globals removed."
                                  Margin="0,0,0,0"/>
                        </Grid>
                      </StackPanel>
                    </Border>

                    <!-- Folder Cleanup -->
                    <Border Style="{StaticResource InnerCardBorderStyle}" Margin="0,0,0,12">
                      <StackPanel>
                        <TextBlock Text="Folder Cleanup" FontWeight="SemiBold"/>
                        <TextBlock Margin="0,6,0,10"
                                   Style="{StaticResource MutedTextBlockStyle}"
                                   Text="Preview or remove empty folders after export pruning."/>
                        <Grid>
                          <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                          </Grid.ColumnDefinitions>
                          <Button x:Name="btnFindEmptyFolders"
                                  Grid.Column="0"
                                  Content="Find Empty Folders"
                                  ToolTip="Preview folders with no policies or sub-folders."
                                  Margin="0,0,10,0"/>
                          <Button x:Name="btnRemoveEmptyFolders"
                                  Grid.Column="1"
                                  Content="Remove Empty Folders"
                                  ToolTip="Save a cleaned copy with empty folders removed."
                                  Margin="0,0,0,0"/>
                        </Grid>
                      </StackPanel>
                    </Border>

                    <!-- Policy Variable Inventory -->
                    <Border Style="{StaticResource InnerCardBorderStyle}" Margin="0,0,0,12">
                      <StackPanel>
                        <TextBlock Text="Policy Variable Inventory" FontWeight="SemiBold"/>
                        <TextBlock Margin="0,6,0,10"
                                   Style="{StaticResource MutedTextBlockStyle}"
                                   Text="Find all runbook-level variables across policies, including potential link variables."/>
                        <Button x:Name="btnFindPolicyVars"
                                Content="Find Policy Variables"
                                HorizontalAlignment="Left"
                                MinWidth="200"
                                ToolTip="Scan all policies for published data variable references and flag possible link variables."/>
                      </StackPanel>
                    </Border>

                    <!-- Duplicate Policy Detection -->
                    <Border Style="{StaticResource InnerCardBorderStyle}" Margin="0,0,0,12">
                      <StackPanel>
                        <TextBlock Text="Duplicate Policy Detection" FontWeight="SemiBold"/>
                        <TextBlock Margin="0,6,0,10"
                                   Style="{StaticResource MutedTextBlockStyle}"
                                   Text="Find policies with identical names across different folders."/>
                        <Button x:Name="btnFindDuplicatePolicies"
                                Content="Find Duplicate Policies"
                                HorizontalAlignment="Left"
                                MinWidth="200"
                                ToolTip="Scan for policies sharing the same name across different folders."/>
                      </StackPanel>
                    </Border>

                    <!-- Workflow hint -->
                    <Border Style="{StaticResource InnerCardBorderStyle}" Padding="10">
                      <StackPanel>
                        <TextBlock Text="Workflow hint" FontWeight="SemiBold"/>
                        <TextBlock Margin="0,6,0,0"
                                   TextWrapping="Wrap"
                                   Style="{StaticResource MutedTextBlockStyle}"
                                   Text="Suggested flow: Load export → inspect folders/policies → apply edits or sanitize → review the staged preview → Save or Save As to commit."/>
                      </StackPanel>
                    </Border>

                  </StackPanel>
                </ScrollViewer>
              </TabItem>

            </TabControl>
          </Grid>
        </Border>
      </Grid>
    </Grid>

    <!-- Status bar -->
    <StatusBar Grid.Row="6">
      <StatusBarItem>
        <TextBlock x:Name="txtStatus" Text="Ready."/>
      </StatusBarItem>
      <Separator/>
      <StatusBarItem>
        <TextBlock x:Name="txtCounts" Text="Folders: 0   Runbooks: 0   Policies: 0   Objects: 0   Globals: 0"/>
      </StatusBarItem>
    </StatusBar>

    <!-- Overlay -->
    <Grid x:Name="overlay"
          Grid.RowSpan="7"
          Background="#88000000"
          Visibility="Collapsed">
      <Border Background="{StaticResource Brush.CardBg}"
              BorderBrush="{StaticResource Brush.CardBorder}"
              BorderThickness="1"
              CornerRadius="12"
              Padding="18"
              HorizontalAlignment="Center"
              VerticalAlignment="Center"
              Width="380">
        <StackPanel>
          <TextBlock x:Name="txtOverlay" Text="Parsing export..." FontSize="15" FontWeight="SemiBold"/>
          <ProgressBar IsIndeterminate="True" Height="14" Margin="0,12,0,0"/>
          <TextBlock Text="This may take a bit on large exports."
                     Margin="0,10,0,0"
                     Style="{StaticResource MutedTextBlockStyle}"/>
        </StackPanel>
      </Border>
    </Grid>

  </Grid>
</Window>
'@

$script:SanitizeXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Sanitize Export Options"
        Height="420"
        Width="520"
        WindowStartupLocation="CenterOwner"
        ResizeMode="NoResize"
        Background="#111315"
        Foreground="#F5F7FA">
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="12"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="12"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="16"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <TextBlock Grid.Row="0" Text="Sanitize Export" FontSize="18" FontWeight="Bold" Foreground="White"/>

    <Border Grid.Row="2" Background="#1B1D21" BorderBrush="#2B2F36" BorderThickness="1" CornerRadius="10" Padding="12">
      <StackPanel>
        <RadioButton x:Name="rbStrict"
                     Content="Strict mode (remove all supported unreferenced globals and empty folders)"
                     Foreground="White"
                     IsChecked="True"
                     Margin="0,0,0,10"/>
        <RadioButton x:Name="rbCustom"
                     Content="Custom mode"
                     Foreground="White"/>
      </StackPanel>
    </Border>

    <Border Grid.Row="4" Background="#1B1D21" BorderBrush="#2B2F36" BorderThickness="1" CornerRadius="10" Padding="12">
      <StackPanel>
        <TextBlock Text="Custom options" FontWeight="SemiBold" Foreground="White"/>
        <CheckBox x:Name="cbVars"         Content="Remove unreferenced global variables"       Margin="0,10,0,0" Foreground="White" IsChecked="True"/>
        <CheckBox x:Name="cbConfigs"      Content="Remove unreferenced global configurations"  Margin="0,6,0,0"  Foreground="White" IsChecked="True"/>
        <CheckBox x:Name="cbSchedules"    Content="Remove unreferenced schedules"              Margin="0,6,0,0"  Foreground="White" IsChecked="True"/>
        <CheckBox x:Name="cbCounters"     Content="Remove unreferenced counters"               Margin="0,6,0,0"  Foreground="White" IsChecked="True"/>
        <CheckBox x:Name="cbGroups"       Content="Remove unreferenced computer groups"        Margin="0,6,0,0"  Foreground="White" IsChecked="True"/>
        <CheckBox x:Name="cbEmptyFolders" Content="Remove empty folders"                       Margin="0,6,0,0"  Foreground="White" IsChecked="True"/>
      </StackPanel>
    </Border>

    <StackPanel Grid.Row="6" Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="btnOk"     Content="OK"     Width="90" Margin="0,0,8,0"/>
      <Button x:Name="btnCancel" Content="Cancel" Width="90"/>
    </StackPanel>
  </Grid>
</Window>
'@

$script:GlobalCleanupXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Global Cleanup Options"
        Height="360"
        Width="440"
        WindowStartupLocation="CenterOwner"
        ResizeMode="NoResize"
        Background="#111315"
        Foreground="#F5F7FA">
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="12"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="16"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <TextBlock Grid.Row="0" Text="Choose global types to scan" FontSize="18" FontWeight="Bold" Foreground="White"/>

    <Border Grid.Row="2" Background="#1B1D21" BorderBrush="#2B2F36" BorderThickness="1" CornerRadius="10" Padding="12">
      <StackPanel>
        <CheckBox x:Name="cbGcVars"      Content="Variables"       Margin="0,0,0,6" Foreground="White" IsChecked="True"/>
        <CheckBox x:Name="cbGcConfigs"   Content="Configurations"  Margin="0,0,0,6" Foreground="White" IsChecked="True"/>
        <CheckBox x:Name="cbGcSchedules" Content="Schedules"       Margin="0,0,0,6" Foreground="White" IsChecked="True"/>
        <CheckBox x:Name="cbGcCounters"  Content="Counters"        Margin="0,0,0,6" Foreground="White" IsChecked="True"/>
        <CheckBox x:Name="cbGcGroups"    Content="Computer Groups" Margin="0,0,0,6" Foreground="White" IsChecked="True"/>
      </StackPanel>
    </Border>

    <StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="btnGcAll"    Content="All"    Width="80" Margin="0,0,8,0"/>
      <Button x:Name="btnGcNone"   Content="None"   Width="80" Margin="0,0,8,0"/>
      <Button x:Name="btnGcOk"     Content="OK"     Width="80" Margin="0,0,8,0"/>
      <Button x:Name="btnGcCancel" Content="Cancel" Width="80"/>
    </StackPanel>
  </Grid>
</Window>
'@

$script:HelpGuideXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="OIS Export Analyzer — User Guide"
        Height="700"
        Width="1100"
        MinHeight="500"
        MinWidth="800"
        WindowStartupLocation="CenterOwner"
        Background="#111315"
        Foreground="#F5F7FA">
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
    </Grid.RowDefinitions>

    <!-- Toolbar -->
    <Border Grid.Row="0"
            Background="#1B1D21"
            BorderBrush="#2B2F36"
            BorderThickness="0,0,0,1"
            Padding="10,8">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="200"/>
          <ColumnDefinition Width="20"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="180"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>

        <TextBlock Grid.Column="0"
                   Text="Jump:"
                   VerticalAlignment="Center"
                   Margin="0,0,8,0"
                   Foreground="#A9B1BC"/>

        <ComboBox x:Name="cmbSections"
                  Grid.Column="1"
                  Height="30"
                  VerticalContentAlignment="Center"/>

        <TextBlock Grid.Column="2"/>

        <TextBlock Grid.Column="3"
                   Text="Find:"
                   VerticalAlignment="Center"
                   Margin="0,0,8,0"
                   Foreground="#A9B1BC"/>

        <TextBox x:Name="txtFind"
                 Grid.Column="4"
                 Height="30"
                 Padding="8,4"
                 VerticalContentAlignment="Center"/>

        <Button x:Name="btnFindPrev"
                Grid.Column="5"
                Content="Prev"
                Width="60"
                Height="30"
                Margin="8,0,0,0"/>

        <Button x:Name="btnFindNext"
                Grid.Column="6"
                Content="Next"
                Width="60"
                Height="30"
                Margin="4,0,0,0"/>

        <Button x:Name="btnCopySection"
                Grid.Column="8"
                Content="Copy Section"
                Height="30"
                MinWidth="110"
                Margin="8,0,0,0"/>
      </Grid>
    </Border>

    <!-- Main content -->
    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="220" MinWidth="150"/>
        <ColumnDefinition Width="5"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>

      <GridSplitter Grid.Column="1"
                    Width="5"
                    HorizontalAlignment="Stretch"
                    Background="#2B2F36"/>

      <!-- Section list -->
      <Border Grid.Column="0"
              Background="#15171A"
              BorderBrush="#2B2F36"
              BorderThickness="0,0,1,0">
        <ListBox x:Name="lstSections"
                 Background="Transparent"
                 BorderThickness="0"
                 Foreground="#F5F7FA"
                 FontFamily="Segoe UI"
                 FontSize="13"
                 Padding="4"
                 ScrollViewer.HorizontalScrollBarVisibility="Disabled"/>
      </Border>

      <!-- Content -->
      <FlowDocumentScrollViewer x:Name="flowViewer"
                                Grid.Column="2"
                                Background="#111315"
                                BorderThickness="0"
                                VerticalScrollBarVisibility="Auto"
                                HorizontalScrollBarVisibility="Disabled"
                                IsSelectionEnabled="True"
                                Padding="20,16"/>
    </Grid>
  </Grid>
</Window>
'@

$script:SourcegraphXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Sourcegraph — Codebase Search"
        Height="680" Width="1100"
        MinHeight="440" MinWidth="750"
        WindowStartupLocation="CenterOwner"
        Background="#111315" Foreground="#F5F7FA">
  <Grid Margin="14">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="5"/>
      <RowDefinition Height="160"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header -->
    <StackPanel Grid.Row="0" Margin="0,0,0,10">
      <TextBlock Text="Sourcegraph Codebase Search"
                 FontSize="16" FontWeight="SemiBold"
                 Foreground="#60BDFF"
                 FontFamily="Segoe UI"/>
      <TextBlock Text="Search your Bitbucket repositories for references to policies, GUIDs, or any term."
                 Foreground="#A9B1BC" FontSize="12"
                 FontFamily="Segoe UI"
                 Margin="0,4,0,0"/>
    </StackPanel>

    <!-- Search bar -->
    <Grid Grid.Row="1" Margin="0,0,0,10">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <TextBox x:Name="txtSgQuery"
               Grid.Column="0"
               Padding="10,6"
               Height="34"
               FontFamily="Segoe UI"
               FontSize="13"
               VerticalContentAlignment="Center"
               ToolTip="Enter a policy name, GUID, file path, or any search term"/>
      <Button x:Name="btnSgSearch"
              Grid.Column="1"
              Content="Search"
              Height="34" MinWidth="90"
              Margin="8,0,0,0"/>
      <Button x:Name="btnSgSettings"
              Grid.Column="2"
              Content="Settings"
              Height="34" MinWidth="90"
              Margin="8,0,0,0"
              ToolTip="Configure Sourcegraph URL and API token"/>
    </Grid>

    <!-- Results grid -->
    <DataGrid x:Name="dgSgResults"
              Grid.Row="2"
              AutoGenerateColumns="False"
              IsReadOnly="True"
              CanUserAddRows="False"
              CanUserDeleteRows="False"
              CanUserResizeRows="False"
              CanUserSortColumns="True"
              CanUserResizeColumns="True"
              HeadersVisibility="Column"
              RowHeaderWidth="0"
              Background="#121417"
              Foreground="#F5F7FA"
              RowBackground="#15181C"
              AlternatingRowBackground="#111316"
              GridLinesVisibility="Horizontal"
              HorizontalGridLinesBrush="#2A2E35"
              BorderBrush="#2B2F36" BorderThickness="1"
              SelectionMode="Single" SelectionUnit="FullRow"
              ScrollViewer.HorizontalScrollBarVisibility="Auto"
              ScrollViewer.VerticalScrollBarVisibility="Auto"
              FontFamily="Segoe UI" FontSize="12">
      <DataGrid.ColumnHeaderStyle>
        <Style TargetType="DataGridColumnHeader">
          <Setter Property="Background"      Value="#1E2228"/>
          <Setter Property="Foreground"      Value="#F5F7FA"/>
          <Setter Property="FontWeight"      Value="SemiBold"/>
          <Setter Property="FontFamily"      Value="Segoe UI"/>
          <Setter Property="Padding"         Value="8,6"/>
          <Setter Property="BorderBrush"     Value="#2B2F36"/>
          <Setter Property="BorderThickness" Value="0,0,0,1"/>
        </Style>
      </DataGrid.ColumnHeaderStyle>
      <DataGrid.RowStyle>
        <Style TargetType="DataGridRow">
          <Setter Property="MaxHeight" Value="32"/>
        </Style>
      </DataGrid.RowStyle>
 <DataGrid.Columns>
  <DataGridTextColumn Header="Repository" Binding="{Binding Repository}" Width="Auto" MinWidth="120">
    <DataGridTextColumn.ElementStyle>
      <Style TargetType="TextBlock">
        <Setter Property="VerticalAlignment" Value="Center"/>
        <Setter Property="Margin"            Value="4,0"/>
        <Setter Property="Foreground"        Value="#60BDFF"/>
      </Style>
    </DataGridTextColumn.ElementStyle>
  </DataGridTextColumn>

  <DataGridTextColumn Header="File" Binding="{Binding FilePath}" Width="Auto" MinWidth="200">
    <DataGridTextColumn.ElementStyle>
      <Style TargetType="TextBlock">
        <Setter Property="VerticalAlignment" Value="Center"/>
        <Setter Property="Margin"            Value="4,0"/>
        <Setter Property="FontFamily"        Value="Consolas"/>
        <Setter Property="FontSize"          Value="11"/>
      </Style>
    </DataGridTextColumn.ElementStyle>
  </DataGridTextColumn>

  <DataGridTextColumn Header="Line" Binding="{Binding LineNumber}" Width="55" MinWidth="45">
    <DataGridTextColumn.ElementStyle>
      <Style TargetType="TextBlock">
        <Setter Property="HorizontalAlignment" Value="Right"/>
        <Setter Property="VerticalAlignment"   Value="Center"/>
        <Setter Property="Foreground"          Value="#A9B1BC"/>
        <Setter Property="Margin"              Value="0,0,8,0"/>
      </Style>
    </DataGridTextColumn.ElementStyle>
  </DataGridTextColumn>

<DataGridTextColumn Header="Match Preview" Binding="{Binding Preview}" Width="Auto" MinWidth="200" MaxWidth="600">
  <DataGridTextColumn.ElementStyle>
    <Style TargetType="TextBlock">
      <Setter Property="TextTrimming"      Value="CharacterEllipsis"/>
      <Setter Property="TextWrapping"      Value="NoWrap"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="FontFamily"        Value="Consolas"/>
      <Setter Property="FontSize"          Value="11"/>
      <Setter Property="Foreground"        Value="#A9B1BC"/>
      <Setter Property="Margin"            Value="4,0"/>
      <Setter Property="MaxWidth"          Value="600"/>
    </Style>
  </DataGridTextColumn.ElementStyle>
</DataGridTextColumn>
</DataGrid.Columns>
    </DataGrid>

    <!-- Splitter -->
    <GridSplitter Grid.Row="3" Height="5"
                  HorizontalAlignment="Stretch"
                  Background="#2B2F36" Cursor="SizeNS"/>

    <!-- Full match detail pane -->
    <Grid Grid.Row="4" Margin="0,4,0,0">
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="*"/>
      </Grid.RowDefinitions>
      <TextBlock x:Name="txtSgPreviewLabel"
                 Grid.Row="0"
                 Text="Full match content — select a result above"
                 Foreground="#A9B1BC"
                 FontFamily="Segoe UI"
                 FontSize="11"
                 Margin="0,0,0,4"/>
      <TextBox x:Name="txtSgPreview"
               Grid.Row="1"
               Background="#14161A"
               Foreground="#C8D0DA"
               BorderBrush="#2F343B" BorderThickness="1"
               FontFamily="Consolas" FontSize="12"
               IsReadOnly="True"
               AcceptsReturn="True"
               TextWrapping="Wrap"
               VerticalScrollBarVisibility="Auto"
               HorizontalScrollBarVisibility="Auto"
               Padding="10,8"/>
    </Grid>

    <!-- Footer -->
    <Grid Grid.Row="5" Margin="0,10,0,0">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <TextBlock x:Name="txtSgStatus"
                 Grid.Column="0"
                 VerticalAlignment="Center"
                 Foreground="#A9B1BC"
                 FontFamily="Segoe UI"
                 FontSize="12"
                 Text="Enter a search term and click Search."/>
      <Button x:Name="btnSgOpenInBrowser"
              Grid.Column="1"
              Content="Open in Browser"
              Height="32" MinWidth="130"
              Margin="0,0,8,0"
              IsEnabled="False"
              ToolTip="Open the selected file in Sourcegraph"/>
      <Button x:Name="btnSgClose"
              Grid.Column="2"
              Content="Close"
              Height="32" MinWidth="90"/>
    </Grid>
  </Grid>
</Window>
'@

#endregion XAML Strings

#region Load XAML & Bind Controls

if (-not $script:CliMode) {

  $xamlClean = ($script:MainXaml -replace "^\uFEFF","").TrimStart()
  $sr  = New-Object System.IO.StringReader $xamlClean
  $xr  = [System.Xml.XmlReader]::Create($sr)
  $win = [Windows.Markup.XamlReader]::Load($xr)
  if (-not $win) { throw "Failed to load WPF window from XAML." }

  $txtPath         = $win.FindName("txtPath")
  $btnBrowse       = $win.FindName("btnBrowse")
  $txtSearch       = $win.FindName("txtSearch")
  $btnClearSearch  = $win.FindName("btnClearSearch")
  $tvFolders       = $win.FindName("tvFolders")
  $txtTreeSummary  = $win.FindName("txtTreeSummary")
  $txtDropHint     = $win.FindName("txtDropHint")

  $txtUniqueId  = $win.FindName("txtUniqueId")
  $txtType      = $win.FindName("txtType")
  $txtName      = $win.FindName("txtName")
  $txtSourceXml = $win.FindName("txtSourceXml")

  $dgObjects      = $win.FindName("dgObjects")
  $tabInspector   = $win.FindName("tabInspector")
  $tabXml         = $win.FindName("tabXml")
  $miRecentFiles  = $win.FindName("miRecentFiles")
  $miToolsOpenXml = $win.FindName("miToolsOpenXml")

  $btnAnalyze  = $win.FindName("btnAnalyze")
  $btnParse    = $win.FindName("btnParse")
  $btnSanitize = $win.FindName("btnSanitize")

  $btnFindEmptyFolders   = $win.FindName("btnFindEmptyFolders")
  $btnRemoveEmptyFolders = $win.FindName("btnRemoveEmptyFolders")

  $btnFindUnreferencedGlobals   = $win.FindName("btnFindUnreferencedGlobals")
  $btnRemoveUnreferencedGlobals = $win.FindName("btnRemoveUnreferencedGlobals")

  $btnFindPolicyVars = $win.FindName("btnFindPolicyVars")

  $btnModifyName = $win.FindName("btnModifyName")
  $btnSetMaxPar  = $win.FindName("btnSetMaxPar")
  $btnApplyLBP   = $win.FindName("btnApplyLBP")
  $btnOnObjLog   = $win.FindName("btnOnObjLog")
  $btnOffObjLog  = $win.FindName("btnOffObjLog")
  $btnOnGenLog   = $win.FindName("btnOnGenLog")
  $btnOffGenLog  = $win.FindName("btnOffGenLog")

  $txtStatus  = $win.FindName("txtStatus")
  $txtCounts  = $win.FindName("txtCounts")

  $overlay    = $win.FindName("overlay")
  $txtOverlay = $win.FindName("txtOverlay")

  $btnCloseFile = $win.FindName("btnCloseFile")

  $txtMetricFolders  = $win.FindName("txtMetricFolders")
  $txtMetricRunbooks = $win.FindName("txtMetricRunbooks")
  $txtMetricPolicies = $win.FindName("txtMetricPolicies")
  $txtMetricObjects  = $win.FindName("txtMetricObjects")
  $txtMetricGlobals  = $win.FindName("txtMetricGlobals")

  $txtXmlPreview       = $win.FindName("txtXmlPreview")
  $txtSelectionSummary = $win.FindName("txtSelectionSummary")

  $btnExpandAll   = $win.FindName("btnExpandAll")
  $btnCollapseAll = $win.FindName("btnCollapseAll")

  $miFileOpen     = $win.FindName("miFileOpen")
  $miFileReload   = $win.FindName("miFileReload")
  $miFileSave     = $win.FindName("miFileSave")
  $miFileSaveAs   = $win.FindName("miFileSaveAs")
  $miFileSanitize = $win.FindName("miFileSanitize")
  $miFileExit     = $win.FindName("miFileExit")

  $miViewExpandAll   = $win.FindName("miViewExpandAll")
  $miViewCollapseAll = $win.FindName("miViewCollapseAll")
  $miViewOverview    = $win.FindName("miViewOverview")
  $miViewObjects     = $win.FindName("miViewObjects")
  $miViewXml         = $win.FindName("miViewXml")
  $miViewActions     = $win.FindName("miViewActions")

  $miToolsRename             = $win.FindName("miToolsRename")
  $miToolsMaxParallel        = $win.FindName("miToolsMaxParallel")
  $miToolsApplyLBP           = $win.FindName("miToolsApplyLBP")
  $miToolsFindUnrefGlobals   = $win.FindName("miToolsFindUnrefGlobals")
  $miToolsRemoveUnrefGlobals = $win.FindName("miToolsRemoveUnrefGlobals")
  $miToolsFindEmptyFolders   = $win.FindName("miToolsFindEmptyFolders")
  $miToolsRemoveEmptyFolders = $win.FindName("miToolsRemoveEmptyFolders")

  $miToolsFindPolicyVars = $win.FindName("miToolsFindPolicyVars")
  $miToolsFindPolicyVars.Add_Click({ Invoke-ButtonClick $btnFindPolicyVars })

  $miToolsCopyUniqueId = $win.FindName("miToolsCopyUniqueId")
  $miToolsCopyPath     = $win.FindName("miToolsCopyPath")
  $miToolsCopyXml      = $win.FindName("miToolsCopyXml")

  $miToolsCompare = $win.FindName("miToolsCompare")
  $btnBulkRename = $win.FindName("btnBulkRename")
  $miToolsExportReport = $win.FindName("miToolsExportReport")
  $btnFindDuplicatePolicies = $win.FindName("btnFindDuplicatePolicies")
  $btnCopySummary = $win.FindName("btnCopySummary")

  $miHelpAbout     = $win.FindName("miHelpAbout")
  $miHelpUsage     = $win.FindName("miHelpUsage")
  $miHelpRules     = $win.FindName("miHelpRules")
  $miHelpShortcuts = $win.FindName("miHelpShortcuts")

  $dgProperties            = $win.FindName("dgProperties")
  $btnApplyProperties      = $win.FindName("btnApplyProperties")
  if ($btnApplyProperties) { $btnApplyProperties.IsEnabled = $false }
  $txtPropertiesHint       = $win.FindName("txtPropertiesHint")
  $txtPropertyDetail       = $win.FindName("txtPropertyDetail")
  $txtPropertyDetailLabel  = $win.FindName("txtPropertyDetailLabel")
  $btnPopoutPropertyDetail = $win.FindName("btnPopoutPropertyDetail")
  $btnSearchCodebase       = $win.FindName("btnSearchCodebase")

  $miToolsSourcegraph         = $win.FindName("miToolsSourcegraph")
  $miToolsSourcegraphSettings = $win.FindName("miToolsSourcegraphSettings")

  $miHelpGuide = $win.FindName("miHelpGuide")


  # Buttons that require a loaded export — disabled until file is loaded
$btnCopySummary.IsEnabled           = $false
$btnSanitize.IsEnabled              = $false
$btnCloseFile.IsEnabled             = $false
$btnExpandAll.IsEnabled             = $false
$btnCollapseAll.IsEnabled           = $false
$btnModifyName.IsEnabled            = $false
$btnSetMaxPar.IsEnabled             = $false
$btnApplyLBP.IsEnabled              = $false
$btnParse.IsEnabled                 = $false
$btnOnObjLog.IsEnabled              = $false
$btnOffObjLog.IsEnabled             = $false
$btnOnGenLog.IsEnabled              = $false
$btnOffGenLog.IsEnabled             = $false
$btnBulkRename.IsEnabled            = $false
$btnFindUnreferencedGlobals.IsEnabled   = $false
$btnRemoveUnreferencedGlobals.IsEnabled = $false
$btnFindEmptyFolders.IsEnabled      = $false
$btnRemoveEmptyFolders.IsEnabled    = $false
$btnFindPolicyVars.IsEnabled        = $false
$btnFindDuplicatePolicies.IsEnabled = $false
$dgObjects.IsReadOnly      = $true
$dgObjects.SelectionMode   = 'Single'
$dgObjects.SelectionUnit   = 'FullRow'
$dgObjects.IsHitTestVisible = $true

  if ($script:IsElevated) {
    $tvFolders.AllowDrop = $false
  }

} # end GUI mode

#endregion Load XAML & Bind Controls

#region UI Helpers

function Update-WindowTitle {
  $base  = "OIS Export Analyzer v$script:AppVersion"
  $file  = if ($txtPath.Text.Trim()) { " — $([System.IO.Path]::GetFileName($txtPath.Text.Trim()))" } else { "" }
  $dirty = if ($script:HasUnsavedChanges) { " [Unsaved Changes]" } else { "" }
  $win.Title = "$base$file$dirty"
}

function Set-Status([string]$msg) {
  $txtStatus.Text    = $msg
  $txtStatus.ToolTip = $msg   # ← full text on hover
  [void]$win.Dispatcher.Invoke([action]{}, 'Background')
}

function Show-Overlay([string]$msg) {
  $txtOverlay.Text       = $msg
  $overlay.Visibility    = 'Visible'
  [void]$win.Dispatcher.Invoke([action]{}, 'Background')
}

function Hide-Overlay {
  $overlay.Visibility = 'Collapsed'
  [void]$win.Dispatcher.Invoke([action]{}, 'Background')
}

# Wraps any action block with consistent error reporting and overlay cleanup.
function Invoke-UiAction {
  param([scriptblock]$Action, [string]$Context = "Operation")
  try { & $Action }
  catch {
    Hide-Overlay
    $msg = "$($_.Exception.GetType().FullName)`n`n$($_.Exception.Message)"
    Set-Status "$Context failed: $msg"
    [void][System.Windows.MessageBox]::Show($msg, "$Context failed",
      [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
  }
}

function Show-WhyNoDrop {
  $msg = @"
Drag & drop is blocked when this app is running elevated (Administrator).

This is a Windows security restriction (UAC integrity levels) that prevents a non-elevated
process (like Explorer) from sending drag/drop messages to an elevated process.

Fix:
  Close this window
  Re-run the script WITHOUT admin rights
"@
  [void][System.Windows.MessageBox]::Show($msg, "Why drag & drop is blocked",
    [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
}


function Set-ExportLoadedState {
  param([bool]$Loaded)

  $state = $Loaded

  if ($btnCopySummary)              { $btnCopySummary.IsEnabled              = $state }
  if ($btnSanitize)                 { $btnSanitize.IsEnabled                 = $state }
  if ($btnCloseFile)                { $btnCloseFile.IsEnabled                = $state }
  if ($btnExpandAll)                { $btnExpandAll.IsEnabled                = $state }
  if ($btnCollapseAll)              { $btnCollapseAll.IsEnabled              = $state }
  if ($btnModifyName)               { $btnModifyName.IsEnabled               = $state }
  if ($btnSetMaxPar)                { $btnSetMaxPar.IsEnabled                = $state }
  if ($btnApplyLBP)                 { $btnApplyLBP.IsEnabled                 = $state }
  if ($btnParse)                    { $btnParse.IsEnabled                    = $state }
  if ($btnOnObjLog)                 { $btnOnObjLog.IsEnabled                 = $state }
  if ($btnOffObjLog)                { $btnOffObjLog.IsEnabled                = $state }
  if ($btnOnGenLog)                 { $btnOnGenLog.IsEnabled                 = $state }
  if ($btnOffGenLog)                { $btnOffGenLog.IsEnabled                = $state }
  if ($btnBulkRename)               { $btnBulkRename.IsEnabled               = $state }
  if ($btnFindUnreferencedGlobals)  { $btnFindUnreferencedGlobals.IsEnabled  = $state }
  if ($btnRemoveUnreferencedGlobals){ $btnRemoveUnreferencedGlobals.IsEnabled = $state }
  if ($btnFindEmptyFolders)         { $btnFindEmptyFolders.IsEnabled         = $state }
  if ($btnRemoveEmptyFolders)       { $btnRemoveEmptyFolders.IsEnabled       = $state }
  if ($btnFindPolicyVars)           { $btnFindPolicyVars.IsEnabled           = $state }
  if ($btnFindDuplicatePolicies)    { $btnFindDuplicatePolicies.IsEnabled    = $state }

  if ($miFileSave)     { $miFileSave.IsEnabled     = $state }
  if ($miFileSaveAs)   { $miFileSaveAs.IsEnabled   = $state }
  if ($miFileSanitize) { $miFileSanitize.IsEnabled = $state }
  if ($miFileReload)   { $miFileReload.IsEnabled   = $state }
}


function Invoke-ButtonClick {
  param([System.Windows.Controls.Primitives.ButtonBase]$Button)
  if (-not $Button) { return }
  $args = New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)
  $Button.RaiseEvent($args)
}

function Format-XmlPretty {
  param([Parameter(Mandatory)][string]$XmlText)
  if ([string]::IsNullOrWhiteSpace($XmlText)) { return "" }
  try {
    $doc = New-Object System.Xml.XmlDocument
    $doc.PreserveWhitespace = $false
    $doc.LoadXml($XmlText)
    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent             = $true
    $settings.IndentChars        = "  "
    $settings.NewLineChars       = [Environment]::NewLine
    $settings.NewLineHandling    = [System.Xml.NewLineHandling]::Replace
    $settings.OmitXmlDeclaration = $true
    $sw = New-Object System.IO.StringWriter
    $xw = [System.Xml.XmlWriter]::Create($sw, $settings)
    $doc.Save($xw)
    $xw.Flush()
    $xw.Close()
    return $sw.ToString().Trim()
  } catch {
    return $XmlText
  }
}

function Copy-TextToClipboard {
  param([string]$Text, [string]$SuccessMessage, [string]$EmptyMessage)
  if ([string]::IsNullOrWhiteSpace($Text)) {
    Set-Status $EmptyMessage
    [void][System.Windows.MessageBox]::Show($EmptyMessage, "Copy",
      [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    return
  }
  [System.Windows.Clipboard]::SetText($Text)
  Set-Status $SuccessMessage
}

function Clear-UI {
  Reset-StagedExportState
  $script:LastStagedAction = $null
  $txtPath.Text       = ""
  $txtSearch.Text     = ""
  $txtPath.IsReadOnly = $false
  $tvFolders.Items.Clear()
  $dgObjects.ItemsSource = $null
  $txtUniqueId.Text  = ""
  $txtType.Text      = ""
  $txtName.Text      = ""
  $txtSourceXml.Text = ""
  if ($txtXmlPreview)       { $txtXmlPreview.Text       = "" }
  if ($txtSelectionSummary) {
    $txtSelectionSummary.Text = "Select a folder, policy, or object group to inspect its details and related objects."
  }
  if ($dgProperties) { $dgProperties.ItemsSource = $null }
if ($btnApplyProperties) { $btnApplyProperties.IsEnabled = $false }
if ($txtPropertiesHint) { $txtPropertiesHint.Text = "Load an export to view properties." }
  $script:AllNodes = $null
  $script:Filtered = $null
  $script:NodeIndex.Clear()
  $txtCounts.Text = "Folders: 0   Runbooks: 0   Activities: 0   Variables: 0   Globals: 0"
  if ($txtMetricFolders)  { $txtMetricFolders.Text  = "0" }
  if ($txtMetricRunbooks) { $txtMetricRunbooks.Text  = "0" }
  if ($txtMetricObjects)  { $txtMetricObjects.Text   = "0" }
  if ($txtMetricPolicies) { $txtMetricPolicies.Text  = "0" }
  if ($txtMetricGlobals)  { $txtMetricGlobals.Text   = "0" }
  Set-ExportLoadedState -Loaded $false
  Set-Status "Ready. Browse or drag & drop a .ois_export file."
  Update-WindowTitle
}

function Reset-ObjectGridColumns {
  $dgObjects.Columns.Clear()
  $dgObjects.AutoGenerateColumns = $false

  $c1         = New-Object System.Windows.Controls.DataGridTextColumn
  $c1.Header  = "Name"
  $c1.Binding = New-Object System.Windows.Data.Binding("Name")
  $c1.Width   = 220

  $c2         = New-Object System.Windows.Controls.DataGridTextColumn
  $c2.Header  = "Type"
  $c2.Binding = New-Object System.Windows.Data.Binding("Type")
  $c2.Width   = 130

  $c3         = New-Object System.Windows.Controls.DataGridTextColumn
  $c3.Header  = "Unique ID"
  $c3.Binding = New-Object System.Windows.Data.Binding("UniqueId")
  $c3.Width   = 260

  $c4         = New-Object System.Windows.Controls.DataGridTextColumn
  $c4.Header  = "Path"
  $c4.Binding = New-Object System.Windows.Data.Binding("Path")
  $c4.Width   = 600

  foreach ($c in @($c1,$c2,$c3,$c4)) { [void]$dgObjects.Columns.Add($c) }
}


function Invoke-TaskbarFlash {
  if (-not $win) { return }
  try {
    if (-not $win.TaskbarItemInfo) {
      $win.TaskbarItemInfo = New-Object System.Windows.Shell.TaskbarItemInfo
    }
    $win.TaskbarItemInfo.ProgressState = [System.Windows.Shell.TaskbarItemProgressState]::Indeterminate

    $script:_TaskbarFlashTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:_TaskbarFlashTimer.Interval = [TimeSpan]::FromSeconds(3)
    $script:_TaskbarFlashTimer.Add_Tick({
      if ($win -and $win.TaskbarItemInfo) {
        $win.TaskbarItemInfo.ProgressState = [System.Windows.Shell.TaskbarItemProgressState]::None
      }
      $script:_TaskbarFlashTimer.Stop()
    })
    $script:_TaskbarFlashTimer.Start()
  } catch {}
}

#endregion UI Helpers

#region Icons & Tree View


function Get-NodeVisual([string]$type) {
    $t = if ([string]::IsNullOrWhiteSpace($type)) { '' } else { $type.Trim().ToLowerInvariant() }

    switch -Regex ($t) {
        '^folder$' {
            [pscustomobject]@{ Glyph = [char]0xE8B7; Brush = '#4FC3F7' }   # Folder
            break
        }
        '^runbook$' {
            [pscustomobject]@{ Glyph = [char]0xE8FC; Brush = '#81C784' }   # Flow / workflow
            break
        }
        '^policy$' {
            [pscustomobject]@{ Glyph = [char]0xEA18; Brush = '#FFB74D' }   # Shield / rule feel
            break
        }
        '^activity$' {
            [pscustomobject]@{ Glyph = [char]0xE9D5; Brush = '#F06292' }   # Task/activity
            break
        }
        '^object$' {
            [pscustomobject]@{ Glyph = [char]0xE8A5; Brush = '#B39DDB' }   # Generic object/document
            break
        }
        '^config$' {
            [pscustomobject]@{ Glyph = [char]0xE713; Brush = '#90A4AE' }   # Gear
            break
        }
        '^global$' {
            [pscustomobject]@{ Glyph = [char]0xE909; Brush = '#4DB6AC' }   # Globe
            break
        }
        '^schedule$' {
            [pscustomobject]@{ Glyph = [char]0xE823; Brush = '#FFD54F' }   # Clock
            break
        }
        '^variable$' {
            [pscustomobject]@{ Glyph = [char]0xE70F; Brush = '#BA68C8' }   # Pencil/editable value
            break
        }
        '^link$' {
            [pscustomobject]@{ Glyph = [char]0xE71B; Brush = '#7986CB' }   # Link
            break
        }
        '^group$' {
            [pscustomobject]@{ Glyph = [char]0xE716; Brush = '#64B5F6' }   # People/group
            break
        }
        '^counter$' {
            [pscustomobject]@{ Glyph = [char]0xE9D2; Brush = '#4DD0E1' }   # Chart/counter
            break
        }
        '^return$' {
            [pscustomobject]@{ Glyph = [char]0xE72B; Brush = '#AED581' }   # Return
            break
        }
        default {
            [pscustomobject]@{ Glyph = [char]0xE8A5; Brush = '#B0BEC5' }   # Generic fallback
            break
        }
    }
}


$FolderGlyphClosed = [char]0xE8B7
$FolderGlyphOpen   = [char]0xE8D5

function Get-FolderVisual([bool]$Expanded) {
    if ($Expanded) {
        return [pscustomobject]@{
            Glyph = $script:FolderGlyphOpen
            Brush = '#8DD6FF'
        }
    }
    else {
        return [pscustomobject]@{
            Glyph = $script:FolderGlyphClosed
            Brush = '#4FC3F7'
        }
    }
}


function ConvertTo-Brush([string]$Color) {
    return (New-Object System.Windows.Media.BrushConverter).ConvertFromString($Color)
}

function Get-SelectedTreeIconBrush([string]$Type) {
    $t = if ([string]::IsNullOrWhiteSpace($Type)) { '' } else { $Type.Trim().ToLowerInvariant() }

    switch -Regex ($t) {
        '^folder$'   { return '#D8F0FF' }
        '^runbook$'  { return '#DDF7DF' }
        '^policy$'   { return '#FFE7BF' }
        '^activity$' { return '#FFD7E5' }
        '^object$'   { return '#E8DDFF' }
        '^global$'   { return '#D8FFF5' }
        '^config$'   { return '#E6EDF2' }
        '^schedule$' { return '#FFF1B8' }
        '^variable$' { return '#EBD7F8' }
        '^link$'     { return '#DEE3FF' }
        '^group$'    { return '#D9EDFF' }
        '^counter$'  { return '#D9FAFF' }
        default      { return '#F5FAFF' }
    }
}

function Get-TreeHeaderParts {
    param(
        [Parameter(Mandatory)]
        [System.Windows.Controls.TreeViewItem]$Item
    )

    $result = [pscustomobject]@{
        Panel = $null
        Icon  = $null
        Label = $null
    }

    $header = $Item.Header
    if ($header -isnot [System.Windows.Controls.StackPanel]) { return $result }

    $result.Panel = $header

    if ($header.Children.Count -ge 1 -and $header.Children[0] -is [System.Windows.Controls.TextBlock]) {
        $result.Icon = $header.Children[0]
    }

    if ($header.Children.Count -ge 2 -and $header.Children[1] -is [System.Windows.Controls.TextBlock]) {
        $result.Label = $header.Children[1]
    }

    return $result
}

function New-TreeHeader([string]$type, [string]$text) {
    $isFolder = ($type -match '^folder$')

    if ($isFolder) {
        $visual = Get-FolderVisual -Expanded:$false
    }
    else {
        $visual = Get-NodeVisual $type
    }

    $panel = New-Object System.Windows.Controls.StackPanel
    $panel.Orientation = 'Horizontal'

    $icon = New-Object System.Windows.Controls.TextBlock
    $icon.Text = [string]$visual.Glyph
    $icon.FontFamily = 'Segoe Fluent Icons'
    $icon.FontSize = 14
    $icon.Foreground = ConvertTo-Brush $visual.Brush
    $icon.VerticalAlignment = 'Center'
    $icon.Margin = '0,0,6,0'
    $icon.Opacity = 0.96

    $label = New-Object System.Windows.Controls.TextBlock
    $label.Text = $text
    $label.FontFamily = 'Segoe UI'
    $label.FontSize = 13
    $label.VerticalAlignment = 'Center'
    $label.Foreground = [System.Windows.Media.Brushes]::White
    $label.Opacity = 0.96

    [void]$panel.Children.Add($icon)
    [void]$panel.Children.Add($label)

    return $panel
}


function Set-TreeItemHeaderVisual {
    param(
        [Parameter(Mandatory)]
        [System.Windows.Controls.TreeViewItem]$Item
    )

    if (-not $Item.Tag) { return }

    $type = [string]$Item.Tag.Type
    if ($type -match '^folder$') {
        $visual = Get-FolderVisual -Expanded:$Item.IsExpanded
    }
    else {
        $visual = Get-NodeVisual $type
    }

    $parts = Get-TreeHeaderParts -Item $Item
    if (-not $parts.Icon -or -not $parts.Label) { return }

    $parts.Icon.Text = [string]$visual.Glyph

    if ($Item.IsSelected) {
        $parts.Icon.Foreground = ConvertTo-Brush (Get-SelectedTreeIconBrush $type)
        $parts.Icon.FontWeight = [System.Windows.FontWeights]::SemiBold
        $parts.Icon.Opacity    = 1.0

        $parts.Label.Foreground = [System.Windows.Media.Brushes]::WhiteSmoke
        $parts.Label.FontWeight = [System.Windows.FontWeights]::SemiBold
        $parts.Label.Opacity    = 1.0
    }
    else {
        $parts.Icon.Foreground = ConvertTo-Brush $visual.Brush
        $parts.Icon.FontWeight = [System.Windows.FontWeights]::Normal
        $parts.Icon.Opacity    = 0.96

        $parts.Label.Foreground = [System.Windows.Media.Brushes]::White
        $parts.Label.FontWeight = [System.Windows.FontWeights]::Normal
        $parts.Label.Opacity    = 0.96
    }
}

function Add-TreeItem {
  param(
    [System.Windows.Controls.ItemsControl]$Parent,
    [object]$Node
  )

  $tvi        = New-Object System.Windows.Controls.TreeViewItem
  $tvi.Header = (New-TreeHeader -type $Node.Type -text $Node.Name)
  $tvi.Tag    = $Node

  $tvi.IsExpanded = ($Parent -eq $tvFolders)
  Set-TreeItemHeaderVisual -Item $tvi

  $tvi.Add_Expanded({
    param($sender, $e)
    if ($e.OriginalSource -ne $sender) { return }
    if ($sender -is [System.Windows.Controls.TreeViewItem]) {
      Set-TreeItemHeaderVisual -Item $sender
    }
  })

  $tvi.Add_Collapsed({
    param($sender, $e)
    if ($e.OriginalSource -ne $sender) { return }
    if ($sender -is [System.Windows.Controls.TreeViewItem]) {
      Set-TreeItemHeaderVisual -Item $sender
    }
  })

  $tvi.Add_Selected({
    param($sender, $e)
    if ($e.OriginalSource -ne $sender) { return }
    if ($sender -is [System.Windows.Controls.TreeViewItem]) {
      Set-TreeItemHeaderVisual -Item $sender
    }
  })

  $tvi.Add_Unselected({
    param($sender, $e)
    if ($e.OriginalSource -ne $sender) { return }
    if ($sender -is [System.Windows.Controls.TreeViewItem]) {
      Set-TreeItemHeaderVisual -Item $sender
    }
  })

  $cm       = New-Object Windows.Controls.ContextMenu
  $miCopy   = New-Object Windows.Controls.MenuItem
  $miSg     = New-Object Windows.Controls.MenuItem

  $miCopy.Header = "Copy Unique ID"
  $miSg.Header   = "Search Sourcegraph"

  # Use Tag on the ContextMenu to carry the node reference safely
  $cm.Tag = $Node

$miCopy.Add_Click({
    param($sender, $e)
    $n = $sender.Parent.Tag
    if ($n -and $n.UniqueId) {
      [Windows.Clipboard]::SetText($n.UniqueId)
      Set-Status "Copied: $($n.UniqueId)"
    }
  })

  $miSg.Add_Click({
    param($sender, $e)
    $n     = $sender.Parent.Tag
    $query = if ($n -and $n.Name) { $n.Name } else { '' }
    Show-SourcegraphDialog -Owner $win -InitialQuery $query
  })

  [void]$cm.Items.Add($miCopy)
  [void]$cm.Items.Add($miSg)
  $tvi.ContextMenu = $cm

  foreach ($child in $Node.Children) {
    Add-TreeItem -Parent $tvi -Node $child
  }

  [void]$Parent.Items.Add($tvi)
}


function Update-TreeView {
  param($Root)

  $tvFolders.Items.Clear()
  $script:NodeIndex.Clear()
  if ($null -eq $Root) { return }

  Add-TreeItem -Parent $tvFolders -Node $Root

  $first = $tvFolders.Items[0]
  if ($first -is [System.Windows.Controls.TreeViewItem]) {
    $first.IsSelected = $true
    if ($first.Tag) { Show-NodeDetails -Node $first.Tag }
  }

  Update-Counts -Root $Root
}

function Set-TreeExpansionState {
  param(
    [Parameter(Mandatory)][object]$ItemsControl,
    [Parameter(Mandatory)][bool]$Expand
  )
  foreach ($item in $ItemsControl.Items) {
    if ($item -is [System.Windows.Controls.TreeViewItem]) {
      $item.IsExpanded = $Expand
      if ($item.Items.Count -gt 0) {
        Set-TreeExpansionState -ItemsControl $item -Expand $Expand
      }
    }
  }
}

function Expand-AllTreeNodes {
  if (-not $tvFolders) { return }
  Set-TreeExpansionState -ItemsControl $tvFolders -Expand $true
  Set-Status "Expanded all nodes."
}

function Collapse-AllTreeNodes {
  if (-not $tvFolders) { return }
  Set-TreeExpansionState -ItemsControl $tvFolders -Expand $false
  Set-Status "Collapsed all nodes."
}

function Update-Counts {
  param($Root)

  $script:folders   = 0
  $script:runbooks  = 0
  $script:variables = 0
  $script:objs      = 0
  $script:globals   = 0

  function Walk($n) {
    if (-not $n) { return }
    switch -Regex ($n.Type) {
      '^folder$'                              { $script:folders++ }
      '^policy$'                              { $script:runbooks++ }
      '^variable$'                            { $script:variables++ }
      '^(schedule|counter|group|config)$'     { $script:globals++ }
    }
    if ($n.Objects) { $script:objs += $n.Objects.Count }
    foreach ($c in $n.Children) { Walk $c }
  }

  Walk $Root

  if ($txtCounts) {
    $txtCounts.Text = "Folders: $script:folders   Runbooks: $script:runbooks   Activities: $script:objs   Variables: $script:variables   Globals: $script:globals"
  }
  if ($txtMetricFolders)  { $txtMetricFolders.Text  = [string]$script:folders }
  if ($txtMetricRunbooks) { $txtMetricRunbooks.Text  = [string]$script:runbooks }
  if ($txtMetricObjects)  { $txtMetricObjects.Text   = [string]$script:objs }
  if ($txtMetricPolicies) { $txtMetricPolicies.Text  = [string]$script:variables }
  if ($txtMetricGlobals)  { $txtMetricGlobals.Text   = [string]$script:globals }
}


function Show-NodeDetails {
  param($Node)

  Reset-ObjectGridColumns

  $txtUniqueId.Text      = $Node.UniqueId
  $txtType.Text          = $Node.Type
  $txtName.Text          = $Node.Name
  $txtSourceXml.Text     = $Node.SourceXml
  $dgObjects.ItemsSource = $Node.Objects

  if ($txtXmlPreview) {
    $txtXmlPreview.Text = if ($Node.XmlPreview) {
      Format-XmlPretty -XmlText $Node.XmlPreview
    } else {
      "<No XML preview available for this item.>"
    }
  }

  if ($txtSelectionSummary) {
    $objCount   = @($Node.Objects).Count
    $childCount = @($Node.Children).Count
    $txtSelectionSummary.Text = "Type: $($Node.Type)  |  Child nodes: $childCount  |  Related objects: $objCount"
  }

  # Properties tab — load from live XML if node has a UniqueId
  if ($dgProperties) {
    $liveNode = $null
    if (-not [string]::IsNullOrWhiteSpace($Node.UniqueId)) {
      $p = Get-StagedExportSourcePath
      if (-not $p) { $p = Get-CurrentExportPath }
      if ($p -and (Test-Path -LiteralPath $p)) {
        try {
          $xml      = Get-OisXmlDocument -Path $p
          $liveNode = Find-XmlNodeByUniqueId -Xml $xml -UniqueId $Node.UniqueId
        } catch {}
      }
    }
    Load-PropertiesForNode -XmlNode $liveNode
  }
}


function Invoke-RestoreTreeSelection {
  param([string]$UniqueId)
  if ([string]::IsNullOrWhiteSpace($UniqueId)) { return }

  function Find-TreeViewItem {
    param([System.Windows.Controls.ItemsControl]$Parent, [string]$Id)
    foreach ($item in $Parent.Items) {
      if ($item -is [System.Windows.Controls.TreeViewItem]) {
        if ($item.Tag -and [string]$item.Tag.UniqueId -eq $Id) { return $item }
        $found = Find-TreeViewItem -Parent $item -Id $Id
        if ($found) { return $found }
      }
    }
    return $null
  }

  $match = Find-TreeViewItem -Parent $tvFolders -Id $UniqueId
  if ($match) {
    $match.IsSelected = $true
    $match.BringIntoView()
  }
}

#endregion Icons & Tree View

#region XML Helpers (shared utilities)

function Get-NodeId {
  param([System.Xml.XmlNode]$Node)
  foreach ($childName in @('UniqueID','UniqueId','ID','Id','Guid','GUID')) {
    $c = $Node.SelectSingleNode("./*[local-name()='$childName']")
    if ($c -and $c.InnerText) { return $c.InnerText.Trim() }
  }
  if ($Node.Attributes) {
    foreach ($attrName in @('UniqueID','UniqueId','ID','Id','Guid','GUID')) {
      $a = $Node.Attributes.GetNamedItem($attrName)
      if ($a -and $a.Value) { return $a.Value.Trim() }
    }
  }
  return $null
}

function Get-NodeDisplayName {
  param([System.Xml.XmlNode]$Node)
  foreach ($childName in @('Name','DisplayName')) {
    $c = $Node.SelectSingleNode("./*[local-name()='$childName']")
    if ($c -and $c.InnerText) { return $c.InnerText.Trim() }
  }
  return "($($Node.LocalName))"
}

function Get-InnerTextLocal {
  param([System.Xml.XmlNode]$Node, [string]$LocalName)
  if (-not $Node) { return "" }
  $c = $Node.SelectSingleNode("./*[local-name()='$LocalName']")
  if ($c -and $c.InnerText) { return $c.InnerText.Trim() }
  return ""
}

function Get-ChildNodesLocal {
  param([System.Xml.XmlNode]$Node, [string]$LocalName)
  if (-not $Node) { return @() }
  return @($Node.SelectNodes("./*[local-name()='$LocalName']"))
}

# Retrieves the first child element matching one of the provided local names.
function Get-XmlChild {
  param([System.Xml.XmlNode]$Node, [string[]]$Names)
  foreach ($n in $Names) {
    $c = $Node.SelectSingleNode("./*[local-name()='$n']")
    if ($c) { return $c }
  }
  return $null
}

function Get-XmlChildText {
  param([System.Xml.XmlNode]$Node, [string[]]$Names)
  $c = Get-XmlChild -Node $Node -Names $Names
  if ($c -and $c.InnerText) { return $c.InnerText.Trim() }
  return ''
}

# Creates a child element if it does not exist; returns it either way.
function Assert-XmlChild {
  param([System.Xml.XmlNode]$Node, [string]$Name, [string]$Datatype = $null)
  $c = $Node.SelectSingleNode("./*[local-name()='$Name']")
  if ($c) { return $c }
  $c = $Node.OwnerDocument.CreateElement($Name)
  if ($Datatype) {
    $a       = $Node.OwnerDocument.CreateAttribute("datatype")
    $a.Value = $Datatype
    [void]$c.Attributes.Append($a)
  }
  [void]$Node.AppendChild($c)
  return $c
}

function Set-XmlChildText {
  param([System.Xml.XmlNode]$Node, [string]$Name, [string]$Value, [string]$Datatype = $null)
  $c           = Assert-XmlChild -Node $Node -Name $Name -Datatype $Datatype
  $c.InnerText = $Value
}

# Returns $true when a string is null, empty, or one of the Orchestrator null tokens.
function Test-NullishString([string]$s) {
  if (-not $s) { return $true }
  $t = $s.Trim()
  return ($t -eq '' -or $t -eq 'null' -or $t -eq '(null)')
}

function ConvertTo-IntSafe([string]$s) {
  $n = 0
  if ($s) { [void][int]::TryParse($s.Trim(), [ref]$n) }
  return $n
}

function Set-OrCreateChildTextLocal {
  param(
    [System.Xml.XmlNode]$Node,
    [string]$LocalName,
    [string]$Value,
    [string]$Datatype = $null
  )
  $child = $Node.SelectSingleNode("./*[local-name()='$LocalName']")
  if (-not $child) {
    $child = $Node.OwnerDocument.CreateElement($LocalName)
    if ($Datatype) {
      $attr       = $Node.OwnerDocument.CreateAttribute("datatype")
      $attr.Value = $Datatype
      [void]$child.Attributes.Append($attr)
    }
    [void]$Node.AppendChild($child)
  }
  if ($Datatype -and -not $child.Attributes["datatype"]) {
    $attr       = $Node.OwnerDocument.CreateAttribute("datatype")
    $attr.Value = $Datatype
    [void]$child.Attributes.Append($attr)
  }
  $child.InnerText = $Value
  return $child
}

function Get-OisXmlDocument {
  param([Parameter(Mandatory)][string]$Path)

  $maxFileSizeMB = 512
$fileSizeMB    = (Get-Item -LiteralPath $Path).Length / 1MB
if ($fileSizeMB -gt $maxFileSizeMB) {
  throw "File is too large to parse safely ($([math]::Round($fileSizeMB,1)) MB). Maximum is $maxFileSizeMB MB."
}

  $xml = New-Object System.Xml.XmlDocument
  $xml.PreserveWhitespace = $true
  $xml.XmlResolver = $null
  $xml.Load($Path)
  return $xml
}

# Locates a node in the document by its UniqueID child value.
# Uses a targeted XPath for O(log n) vs a full //* linear scan.
function Find-XmlNodeByUniqueId {
  param([xml]$Xml, [string]$UniqueId)
  if ([string]::IsNullOrWhiteSpace($UniqueId)) { return $null }
  $safeId = $UniqueId.Trim().Replace("'", "''")
  return $Xml.SelectSingleNode("//*[*[local-name()='UniqueID' and normalize-space(.)='$safeId'] or *[local-name()='UniqueId' and normalize-space(.)='$safeId']]")
}

function Set-FirstMatchingChildValue {
  param(
    [System.Xml.XmlNode]$Node,
    [string[]]$CandidateNames,
    [string]$Value,
    [string]$Datatype = $null,
    [switch]$CreateIfMissing
  )
  foreach ($name in $CandidateNames) {
    $child = $Node.SelectSingleNode("./*[local-name()='$name']")
    if ($child) {
      if ($Datatype -and -not $child.Attributes["datatype"]) {
        $attr       = $Node.OwnerDocument.CreateAttribute("datatype")
        $attr.Value = $Datatype
        [void]$child.Attributes.Append($attr)
      }
      $child.InnerText = $Value
      return $child
    }
  }
  if ($CreateIfMissing -and $CandidateNames.Count -gt 0) {
    return Set-OrCreateChildTextLocal -Node $Node -LocalName $CandidateNames[0] -Value $Value -Datatype $Datatype
  }
  return $null
}

function Set-LoggingFieldsInPolicyObjects {
  param(
    [System.Xml.XmlNode]$PolicyNode,
    [string[]]$CandidateNames,
    [bool]$Enabled
  )
  $changed = 0
  $value   = if ($Enabled) { 'true' } else { 'false' }
  foreach ($obj in @($PolicyNode.SelectNodes("./*[local-name()='Object']"))) {
    foreach ($name in $CandidateNames) {
      $field = $obj.SelectSingleNode("./*[local-name()='$name']")
      if ($field) {
        if (-not $field.Attributes["datatype"]) {
          $attr       = $obj.OwnerDocument.CreateAttribute("datatype")
          $attr.Value = "bool"
          [void]$field.Attributes.Append($attr)
        }
        $field.InnerText = $value
        $changed++
      }
    }
  }
  return $changed
}

function Get-CleanExportLeafName {
  param([Parameter(Mandatory)][string]$Path)
  $leaf = Split-Path $Path -Leaf
  $name = [System.IO.Path]::GetFileNameWithoutExtension($leaf)
  $ext  = [System.IO.Path]::GetExtension($leaf)
  do {
    $old  = $name
    $name = $name -replace '^(Renamed_|MaxParallel_|LinkBestPractices_|ObjectLoggingOn_|ObjectLoggingOff_|GenericLoggingOn_|GenericLoggingOff_|NoEmptyFolders_|NoUnreferencedGlobals_|Sanitized_)+', ''
  } while ($name -ne $old)
  return "$name$ext"
}

function New-StampedExportFileName {
  param([Parameter(Mandatory)][string]$Prefix, [Parameter(Mandatory)][string]$SourcePath)
  $cleanLeaf = Get-CleanExportLeafName -Path $SourcePath
  $baseName  = [System.IO.Path]::GetFileNameWithoutExtension($cleanLeaf)
  $ext       = [System.IO.Path]::GetExtension($cleanLeaf)
  $stamp     = Get-Date -Format 'yyyyMMdd_HHmm'
  return "${Prefix}${baseName}_${stamp}${ext}"
}

# Extracts the first .ois_export found inside a zip and returns its temp path.
# Returns $null if no .ois_export entry is found.
function Expand-OisExportFromZip {
  param([Parameter(Mandatory)][string]$ZipPath)

  $zip = $null
  try {
    $zip   = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    $entry = $zip.Entries | Where-Object { $_.Name -like '*.ois_export' } | Select-Object -First 1

    if (-not $entry) { return $null }

    # Zip Slip protection — take only the filename, never trust the full entry path
    $safeName = [System.IO.Path]::GetFileName($entry.FullName)
    if ([string]::IsNullOrWhiteSpace($safeName) -or $safeName -notmatch '\.ois_export$') {
      return $null
    }

    $destPath     = Join-Path ([System.IO.Path]::GetTempPath()) $safeName
    $resolvedDest = [System.IO.Path]::GetFullPath($destPath)
    $resolvedTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())

    if (-not $resolvedDest.StartsWith($resolvedTemp, [System.StringComparison]::OrdinalIgnoreCase)) {
      throw "Zip entry path escapes temp directory — possible zip slip attack: $safeName"
    }

    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $resolvedDest, $true)
    return $resolvedDest

  } finally {
    if ($zip) { $zip.Dispose() }
  }
}

#endregion XML Helpers

#region Link Best Practices

function Apply-LinkBestPracticesToExportXml {
  [CmdletBinding()]
  param([Parameter(Mandatory)][xml]$Xml)

  # Find link nodes - primary via ObjectTypeName, fallback via SourceObject+TargetObject
  $links = @($Xml.SelectNodes("//*[local-name()='Object'][*[local-name()='ObjectTypeName' and normalize-space(text())='Link']]"))
  if (-not $links -or $links.Count -eq 0) {
    $links = @($Xml.SelectNodes("//*[local-name()='Object'][./*[local-name()='SourceObject'] and ./*[local-name()='TargetObject']]"))
  }

  $updated = 0
  $green   = 0
  $red     = 0
  $blue    = 0
  $orange  = 0

  foreach ($lnk in $links) {
    $waitDelay = ConvertTo-IntSafe (Get-XmlChildText $lnk @('WaitDelay'))
    $andField  = Get-XmlChildText $lnk @('And')
    $label     = Get-XmlChildText $lnk @('Label')
    $src       = Get-XmlChildText $lnk @('SourceObject')
    $tgt       = Get-XmlChildText $lnk @('TargetObject')

    if (-not $src -or -not $tgt) { continue }

    $category = if     ($waitDelay -gt 0)                  { 'Delay' }
                elseif ($label -match 'failure|failed|error') { 'Failure' }
                elseif (-not (Test-NullishString $andField))  { 'Custom' }
                else                                          { 'Success' }

    switch ($category) {
      'Success' {
        Set-XmlChildText $lnk 'Color' $script:ColorRefGreen 'int'
        if (Test-NullishString $label) { Set-XmlChildText $lnk 'Label' 'Success' 'string' }
        $green++
      }
      'Custom' {
        Set-XmlChildText $lnk 'Color' $script:ColorRefBlue 'int'
        if (Test-NullishString $label) { Set-XmlChildText $lnk 'Label' 'Condition' 'string' }
        $blue++
      }
      'Delay' {
        Set-XmlChildText $lnk 'Color' $script:ColorRefOrange 'int'
        if (Test-NullishString $label) {
          $d = if ($waitDelay -gt 0) { "$waitDelay sec" } else { "Delay" }
          Set-XmlChildText $lnk 'Label' "Wait: $d" 'string'
        }
        $orange++
      }
      'Failure' {
        Set-XmlChildText $lnk 'Color' $script:ColorRefRed 'int'
        if (Test-NullishString $label) { Set-XmlChildText $lnk 'Label' 'Failure' 'string' }
        $red++
      }
    }

    # Ensure SubPoints node exists (some tools choke if absent)
    $sp = Get-XmlChild $lnk @('SubPoints')
    if (-not $sp) { [void](Assert-XmlChild $lnk 'SubPoints' 'null') }

    $updated++
  }

  return [pscustomobject]@{
    LinksUpdated = $updated
    Green        = $green
    Red          = $red
    Blue         = $blue
    Orange       = $orange
    LinksFound   = $links.Count
  }
}

#endregion Link Best Practices

#region Data Model

function New-Node {
  param(
    [string]$Type,
    [string]$Name,
    [string]$UniqueId   = '',
    [string]$SourceXml  = '',
    [string]$XmlPreview = '',
    [object[]]$Objects  = @(),
    [object[]]$Children = @()
  )
  [pscustomobject]@{
    Type       = $Type
    Name       = $Name
    UniqueId   = $UniqueId
    SourceXml  = $SourceXml
    XmlPreview = $XmlPreview
    Objects    = $Objects
    Children   = $Children
  }
}

function New-ObjRow {
  param([string]$Name, [string]$Type, [string]$UniqueId, [string]$Path)
  [pscustomobject]@{ Name = $Name; Type = $Type; UniqueId = $UniqueId; Path = $Path }
}

function Get-ObjTypeFriendly([string]$objectTypeGuid, [string]$name) {
  switch ($objectTypeGuid) {
    '{7A65BD17-9532-4D07-A6DA-E0F89FA0203E}' { return 'link' }
    '{FA70125F-267E-4065-A4F6-D5493167D663}' { return 'return' }
    default {
      if ($name -eq 'Link') { return 'link' }
      return 'activity'
    }
  }
}

function Build-PolicyNode {
  param(
    [Parameter(Mandatory)][System.Xml.XmlNode]$PolicyXml,
    [Parameter(Mandatory)][string]$FolderPath,
    [Parameter(Mandatory)][string]$SourcePath
  )
  $pName    = Get-InnerTextLocal $PolicyXml 'Name'
  if (-not $pName) { $pName = "(unnamed policy)" }
  $PolicyId = Get-InnerTextLocal $PolicyXml 'UniqueID'

  $rows = @()
  foreach ($o in (Get-ChildNodesLocal $PolicyXml 'Object')) {
    $oName = Get-InnerTextLocal $o 'Name'
    if (-not $oName) { $oName = "(unnamed object)" }
    $oId   = Get-InnerTextLocal $o 'UniqueID'
    $oGuid = Get-InnerTextLocal $o 'ObjectType'
    $oType = Get-ObjTypeFriendly $oGuid $oName
    $rows += New-ObjRow -Name $oName -Type $oType -UniqueId $oId -Path ($FolderPath + "\" + $pName)
  }

  return New-Node -Type "policy" -Name $pName -UniqueId $PolicyId `
    -SourceXml $SourcePath -XmlPreview $PolicyXml.OuterXml `
    -Objects $rows -Children @()
}

function Build-FolderNode {
  param(
    [Parameter(Mandatory)][System.Xml.XmlNode]$FolderXml,
    [AllowNull()][AllowEmptyString()][string]$ParentPath = $null,
    [Parameter(Mandatory)][string]$SourcePath
  )
  $fName = Get-InnerTextLocal $FolderXml 'Name'
  if (-not $fName) { $fName = "(unnamed folder)" }
  $fId   = Get-InnerTextLocal $FolderXml 'UniqueID'
  $path  = if ([string]::IsNullOrWhiteSpace($ParentPath)) { $fName } else { "$ParentPath\$fName" }

  $fNode = New-Node -Type "folder" -Name $fName -UniqueId $fId `
    -SourceXml $SourcePath -XmlPreview $FolderXml.OuterXml `
    -Objects @() -Children @()

  foreach ($sub in (Get-ChildNodesLocal $FolderXml 'Folder')) {
    $fNode.Children += (Build-FolderNode -FolderXml $sub -ParentPath $path -SourcePath $SourcePath)
  }
  foreach ($pol in (Get-ChildNodesLocal $FolderXml 'Policy')) {
    $fNode.Children += (Build-PolicyNode -PolicyXml $pol -FolderPath $path -SourcePath $SourcePath)
  }

  $summary = @()
  foreach ($c in $fNode.Children) {
    $summary += New-ObjRow -Name $c.Name -Type $c.Type -UniqueId $c.UniqueId -Path $path
  }
  $fNode.Objects = $summary
  return $fNode
}

function Add-GlobalItems {
  param(
    [System.Xml.XmlNode]$XmlNode,
    [object]$ParentNode,
    [string]$ItemType,
    [string]$SrcPath
  )
  foreach ($child in $XmlNode.ChildNodes) {
    if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
    $local = $child.LocalName

    if ($local -eq 'Objects') {
      foreach ($obj in $child.ChildNodes) {
        if ($obj.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
        if ($obj.LocalName -ne 'Object') { continue }
        $name = (Get-InnerTextLocal $obj 'Name'); if (-not $name) { $name = "(unnamed)" }
        $id   = (Get-InnerTextLocal $obj 'UniqueID')
        $ParentNode.Children += New-Node -Type $ItemType -Name $name -UniqueId $id `
          -SourceXml $SrcPath -XmlPreview $obj.OuterXml -Objects @() -Children @()
      }
    } elseif ($local -eq 'Folder') {
      $folderName = (Get-InnerTextLocal $child 'Name')
      if (-not $folderName) { $folderName = "(unnamed folder)" }
      $folderId  = (Get-InnerTextLocal $child 'UniqueID')
      $subFolder = New-Node -Type "folder" -Name $folderName -UniqueId $folderId `
        -SourceXml $SrcPath -XmlPreview $child.OuterXml -Objects @() -Children @()
      Add-GlobalItems -XmlNode $child -ParentNode $subFolder -ItemType $ItemType -SrcPath $SrcPath
      $subFolder.Objects = @($subFolder.Children | ForEach-Object {
        New-ObjRow -Name $_.Name -Type $_.Type -UniqueId $_.UniqueId -Path "Global Settings\$folderName"
      })
      $ParentNode.Children += $subFolder
    }
  }
}

function Build-GlobalsFolder {
  param([Parameter(Mandatory)][xml]$Doc, [Parameter(Mandatory)][string]$SourcePath)

  $globalsRoot = New-Node -Type "folder" -Name "Global Settings" -UniqueId "" `
    -SourceXml $SourcePath -XmlPreview "" -Objects @() -Children @()

  $gs = $Doc.SelectSingleNode("/*[local-name()='ExportData']/*[local-name()='GlobalSettings']")
  if (-not $gs) { return $globalsRoot }
  $globalsRoot.XmlPreview = $gs.OuterXml

  foreach ($bucket in $gs.ChildNodes) {
    if ($bucket.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
    $bucketName = $bucket.LocalName
    $type = switch ($bucketName) {
      'Variables'      { 'variable' }
      'Schedules'      { 'schedule' }
      'Counters'       { 'counter'  }
      'ComputerGroups' { 'group'    }
      default          { 'config'   }
    }

    $bucketNode = New-Node -Type "folder" -Name $bucketName -UniqueId "" `
      -SourceXml $SourcePath -XmlPreview $bucket.OuterXml -Objects @() -Children @()

    Add-GlobalItems -XmlNode $bucket -ParentNode $bucketNode -ItemType $type -SrcPath $SourcePath

    $bucketNode.Objects = @($bucketNode.Children | ForEach-Object {
      New-ObjRow -Name $_.Name -Type $_.Type -UniqueId $_.UniqueId -Path "Global Settings\$bucketName"
    })
    $globalsRoot.Children += $bucketNode
  }

  $globalsRoot.Objects = @($globalsRoot.Children | ForEach-Object {
    New-ObjRow -Name $_.Name -Type "folder" -UniqueId "" -Path "Global Settings"
  })
  return $globalsRoot
}

function Build-GlobalConfigsFolder {
  param([Parameter(Mandatory)][xml]$Doc, [Parameter(Mandatory)][string]$SourcePath)

  $cfgRoot = New-Node -Type "folder" -Name "Global Configurations" -UniqueId "" `
    -SourceXml $SourcePath -XmlPreview "" -Objects @() -Children @()

  $gc = $Doc.SelectSingleNode("/*[local-name()='ExportData']/*[local-name()='GlobalConfigurations']")
  if (-not $gc) { return $cfgRoot }
  $cfgRoot.XmlPreview = $gc.OuterXml

  foreach ($entry in @($gc.SelectNodes(".//*[local-name()='Entry']"))) {
    $id   = (Get-InnerTextLocal $entry 'ID')
    $data = (Get-InnerTextLocal $entry 'Data')

    $name = $null
    if ($data) {
      $decoded = [System.Net.WebUtility]::HtmlDecode($data)
      if ($decoded -match '<Name>([^<]+)</Name>') { $name = $matches[1] }
      if (-not $name -and $decoded -match 'Name="([^"]+)"') { $name = $matches[1] }
    }
    if (-not $name) { $name = if ($id) { $id } else { "(unnamed)" } }

    $cfgRoot.Children += New-Node -Type "config" -Name $name -UniqueId $id `
      -SourceXml $SourcePath -XmlPreview ($entry.OuterXml) -Objects @() -Children @()
  }

  $cfgRoot.Objects = @($cfgRoot.Children | ForEach-Object {
    New-ObjRow -Name $_.Name -Type $_.Type -UniqueId $_.UniqueId -Path "Global Configurations"
  })
  return $cfgRoot
}

function Build-ModelFromOisExport {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path $Path)) { throw "File not found: $Path" }

  $maxFileSizeMB = 512
$fileSizeMB    = (Get-Item -LiteralPath $Path).Length / 1MB
if ($fileSizeMB -gt $maxFileSizeMB) {
  throw "File is too large to parse safely ($([math]::Round($fileSizeMB,1)) MB). Maximum is $maxFileSizeMB MB."
}

  [xml]$doc = Get-OisXmlDocument -Path $Path
  if (-not $doc.DocumentElement -or $doc.DocumentElement.LocalName -ne 'ExportData') {
    throw "This file does not look like an Orchestrator .ois_export (expected <ExportData> root)."
  }

  $root = New-Node -Type "folder" -Name "Root" -UniqueId "" `
    -SourceXml $Path -XmlPreview $doc.OuterXml -Objects @() -Children @()

  $policies = $doc.SelectSingleNode("/*[local-name()='ExportData']/*[local-name()='Policies']")
  if ($policies) {
    foreach ($f in @($policies.SelectNodes("./*[local-name()='Folder']"))) {
      $root.Children += Build-FolderNode -FolderXml $f -SourcePath $Path
    }
  }

  $root.Children += Build-GlobalsFolder      -Doc $doc -SourcePath $Path
  $root.Children += Build-GlobalConfigsFolder -Doc $doc -SourcePath $Path

  $root.Objects = @($root.Children | ForEach-Object {
    New-ObjRow -Name $_.Name -Type $_.Type -UniqueId $_.UniqueId -Path "Root"
  })
  return $root
}

function Import-OisExport {
  param([Parameter(Mandatory)][string]$Path)
  $model = Build-ModelFromOisExport -Path $Path
  return [pscustomobject]@{
    Model = $model
    Temp  = $null
    Docs  = @($Path)
  }
}


function New-PropertyRow {
  param(
    [string]$LocalName,
    [string]$Value,
    [string]$Datatype = '',
    [bool]$ReadOnly   = $false
  )
  $row = [pscustomobject]@{
    LocalName = $LocalName
    Value     = $Value
    Datatype  = $Datatype
    ReadOnly  = $ReadOnly
  }
  # Make Value a NoteProperty so TwoWay binding can update it
  return $row
}

# Fields that should never be edited directly
$script:ReadOnlyPropertyNames = @(
  'UniqueID','UniqueId','ObjectType','ObjectTypeName',
  'SourceObject','TargetObject','ParentID','ParentId'
)

#endregion Data Model

#region Search / Filter

function Test-NodeMatchesFilter {
  param($node, [string]$q)
  if (-not $q) { return $true }
  $q = $q.ToLowerInvariant()

  if ([string]$node.Name    -and $node.Name.ToLowerInvariant().Contains($q))    { return $true }
  if ([string]$node.Type    -and $node.Type.ToLowerInvariant().Contains($q))    { return $true }
  if ([string]$node.UniqueId -and $node.UniqueId.ToLowerInvariant().Contains($q)) { return $true }

  if ($node.Objects) {
    foreach ($o in $node.Objects) {
      if ([string]$o.Name     -and $o.Name.ToLowerInvariant().Contains($q))     { return $true }
      if ([string]$o.Type     -and $o.Type.ToLowerInvariant().Contains($q))     { return $true }
      if ([string]$o.UniqueId -and $o.UniqueId.ToLowerInvariant().Contains($q)) { return $true }
      if ([string]$o.Path     -and $o.Path.ToLowerInvariant().Contains($q))     { return $true }
    }
  }
  return $false
}

function Copy-FilteredTree {
  param($node, [string]$q)
  $keepChildren = @()
  foreach ($c in $node.Children) {
    $cc = Copy-FilteredTree -node $c -q $q
    if ($cc) { $keepChildren += $cc }
  }
  $keepSelf = Test-NodeMatchesFilter $node $q
  if (-not $keepSelf -and $keepChildren.Count -eq 0) { return $null }
  return New-Node -Type $node.Type -Name $node.Name -UniqueId $node.UniqueId `
    -SourceXml $node.SourceXml -XmlPreview $node.XmlPreview `
    -Objects $node.Objects -Children $keepChildren
}

#endregion Search / Filter

#region Recent Files

function Load-RecentFiles {
  $script:RecentFiles = @()
  if (-not (Test-Path -LiteralPath $script:RecentFilesPath)) { return }
  try {
    $raw = Get-Content -LiteralPath $script:RecentFilesPath -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return }
foreach ($item in @($raw | ConvertFrom-Json)) {
  $s = [string]$item
  # Only accept strings that look like absolute Windows paths to .ois_export or .zip files
  if (-not [string]::IsNullOrWhiteSpace($s) -and
      $s.Length -le 520 -and
      ($s -match '\.ois_export$' -or $s -match '\.zip$') -and
      [System.IO.Path]::IsPathRooted($s)) {
    $script:RecentFiles += $s
  }
}
  } catch {
    Set-Status "Could not load recent files list."
  }
}

function Save-RecentFiles {
  try {
    if (-not (Test-Path -LiteralPath $script:RecentFilesDir)) {
      [void](New-Item -ItemType Directory -Path $script:RecentFilesDir -Force)
    }
    @($script:RecentFiles | Select-Object -First $script:RecentFilesMax) |
      ConvertTo-Json -Depth 3 |
      Set-Content -LiteralPath $script:RecentFilesPath -Encoding UTF8
  } catch {
    Set-Status "Could not save recent files list."
  }
}

function Update-RecentFilesMenu {

  $script:RecentFiles = @($script:RecentFiles | Where-Object {
    Test-Path -LiteralPath $_ -ErrorAction SilentlyContinue
  })

  if (-not $miRecentFiles) { return }
  $miRecentFiles.Items.Clear()

  $items = @($script:RecentFiles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($items.Count -eq 0) {
    $miEmpty           = New-Object System.Windows.Controls.MenuItem
    $miEmpty.Header    = '(Empty)'
    $miEmpty.IsEnabled = $false
    [void]$miRecentFiles.Items.Add($miEmpty)
    return
  }

  $index = 1
  foreach ($path in $items) {
    $mi          = New-Object System.Windows.Controls.MenuItem
    $mi.Header   = "_$index $([System.IO.Path]::GetFileName($path))"
    $mi.Tag      = $path
    $mi.ToolTip  = $path
    $mi.Add_Click({
      param($sender, $e)
      Invoke-UiAction -Context "Open recent file" -Action {
        Open-RecentFile -Path ([string]$sender.Tag)
      }
    })
    [void]$miRecentFiles.Items.Add($mi)
    $index++
  }

  [void]$miRecentFiles.Items.Add((New-Object System.Windows.Controls.Separator))

  $miClear = New-Object System.Windows.Controls.MenuItem
  $miClear.Header = 'Clear Recent Files'
  $miClear.Add_Click({
    Invoke-UiAction -Context "Clear recent files" -Action { Clear-RecentFiles }
  })
  [void]$miRecentFiles.Items.Add($miClear)
}

function Add-RecentFile {
  param([Parameter(Mandatory)][string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  try   { $fullPath = [System.IO.Path]::GetFullPath($Path) }
  catch { $fullPath = $Path }

  $newList = @($fullPath)
  foreach ($existing in @($script:RecentFiles)) {
    if (-not [string]::Equals($existing, $fullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
      $newList += $existing
    }
  }
  $script:RecentFiles = @($newList | Select-Object -First $script:RecentFilesMax)
  Save-RecentFiles
  Update-RecentFilesMenu
}

function Clear-RecentFiles {
  $script:RecentFiles = @()
  try {
    if (Test-Path -LiteralPath $script:RecentFilesPath) {
      Remove-Item -LiteralPath $script:RecentFilesPath -Force
    }
  } catch {}
  Update-RecentFilesMenu
  Set-Status "Cleared recent files."
}

function Open-RecentFile {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    Set-Status ("Recent file not found: {0}" -f $Path)
    return
  }
  $txtPath.Text = $Path
  Import-ExportIntoUI -Path $Path
  Set-Status ("Opened recent file: {0}" -f ([System.IO.Path]::GetFileName($Path)))
}


function Save-WindowSettings {
  try {
    if (-not $win -or $win.WindowState -eq 'Minimized') { return }
    $settings = @{
      Top    = [int]$win.Top
      Left   = [int]$win.Left
      Width  = [int]$win.ActualWidth
      Height = [int]$win.ActualHeight
    } | ConvertTo-Json
    Set-Content -LiteralPath $script:WindowSettingsPath -Value $settings -Encoding UTF8
  } catch {}
}

function Restore-WindowSettings {
  try {
    if (-not (Test-Path -LiteralPath $script:WindowSettingsPath)) { return }
    $s = Get-Content -LiteralPath $script:WindowSettingsPath -Raw | ConvertFrom-Json
    if ($s.Width  -gt 400 -and $s.Width  -lt 3840) { $win.Width  = $s.Width  }
    if ($s.Height -gt 300 -and $s.Height -lt 2160) { $win.Height = $s.Height }
    # Validate position is on a visible monitor
    $screens = [System.Windows.Forms.Screen]::AllScreens
    $onScreen = $screens | Where-Object {
      $_.WorkingArea.Contains($s.Left, $s.Top)
    }
    if ($onScreen) {
      $win.Left = $s.Left
      $win.Top  = $s.Top
    }
  } catch {}
}

#endregion Recent Files

#region Copy / Selection Helpers

function Get-SelectedTreeViewItem {
  $selected = $tvFolders.SelectedItem
  if ($selected -is [System.Windows.Controls.TreeViewItem]) { return $selected }
  return $null
}

function Get-ParentTreeViewItem {
  param([System.Windows.DependencyObject]$Child)
  if (-not $Child) { return $null }
  $parent = [System.Windows.Media.VisualTreeHelper]::GetParent($Child)
  while ($parent) {
    if ($parent -is [System.Windows.Controls.TreeViewItem]) { return $parent }
    $parent = [System.Windows.Media.VisualTreeHelper]::GetParent($parent)
  }
  return $null
}

function Get-TreeViewItemPath {
  param([System.Windows.Controls.TreeViewItem]$Item)
  if (-not $Item) { return "" }
  $parts   = @()
  $current = $Item
  while ($current) {
    if ($current.Tag -and $current.Tag.Name) {
      $parts = ,([string]$current.Tag.Name) + $parts
    }
    $current = Get-ParentTreeViewItem -Child $current
  }
  return ($parts -join '\')
}

function Get-SelectedTreeNode {
  $selected = $tvFolders.SelectedItem
  if ($selected -is [System.Windows.Controls.TreeViewItem]) { return $selected.Tag }
  return $null
}

function Get-XmlTextByUniqueId {
  param([string]$UniqueId)
  $p = Get-StagedExportSourcePath
  if (-not $p) { $p = Get-CurrentExportPath }
  if (-not $p -or -not (Test-Path -LiteralPath $p)) { return $null }
  if ([string]::IsNullOrWhiteSpace($UniqueId)) { return $null }
  $xml    = Get-OisXmlDocument -Path $p
  $target = Find-XmlNodeByUniqueId -Xml $xml -UniqueId $UniqueId
  if ($target) { return $target.OuterXml }
  return $null
}

function Get-CurrentSelectionInfo {
  # Prefer selected object row when on Objects tab
  if ($tabInspector -and $tabInspector.SelectedIndex -eq 1 -and $dgObjects.SelectedItem) {
    $row     = $dgObjects.SelectedItem
    $xmlText = $null
    if ($row.UniqueId) { $xmlText = Get-XmlTextByUniqueId -UniqueId $row.UniqueId }
    return [pscustomobject]@{
      Name     = [string]$row.Name
      Type     = [string]$row.Type
      UniqueId = [string]$row.UniqueId
      Path     = [string]$row.Path
      XmlText  = $xmlText
      Source   = 'ObjectRow'
    }
  }

  # Fall back to selected tree node
  $treeItem = Get-SelectedTreeViewItem
  if ($treeItem -and $treeItem.Tag) {
    $node    = $treeItem.Tag
    $xmlText = $node.XmlPreview
    if (-not $xmlText -and $node.UniqueId) {
      $xmlText = Get-XmlTextByUniqueId -UniqueId $node.UniqueId
    }
    return [pscustomobject]@{
      Name     = [string]$node.Name
      Type     = [string]$node.Type
      UniqueId = [string]$node.UniqueId
      Path     = (Get-TreeViewItemPath -Item $treeItem)
      XmlText  = $xmlText
      Source   = 'Tree'
    }
  }
  return $null
}

function Open-SelectedObjectXml {
  $row = $dgObjects.SelectedItem
  if (-not $row) { Set-Status "No object row selected."; return }

  if ([string]::IsNullOrWhiteSpace([string]$row.UniqueId)) {
    Set-Status "Selected object does not have a Unique ID."
    [void][System.Windows.MessageBox]::Show("The selected row does not have a Unique ID.",
      "Open Object XML", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    return
  }

  $xmlText = Get-XmlTextByUniqueId -UniqueId $row.UniqueId
  if (-not $xmlText) {
    Set-Status "Could not locate XML for selected object."
    [void][System.Windows.MessageBox]::Show("Could not locate XML for the selected object.",
      "Open Object XML", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
    return
  }

  if ($txtXmlPreview) {
    $txtXmlPreview.Text = Format-XmlPretty -XmlText $xmlText
    try { $txtXmlPreview.CaretIndex = 0; $txtXmlPreview.ScrollToHome() } catch {}
  }
  if ($tabInspector) { $tabInspector.SelectedIndex = 2 }

  $displayName = if ([string]::IsNullOrWhiteSpace([string]$row.Name)) { [string]$row.UniqueId } else { [string]$row.Name }
  Set-Status ("Opened XML view for object: {0}." -f $displayName)
}


function Load-PropertiesForNode {
  param([System.Xml.XmlNode]$XmlNode)

  if (-not $dgProperties) { return }

  if (-not $XmlNode) {
    $dgProperties.ItemsSource = $null
    if ($btnApplyProperties) { $btnApplyProperties.IsEnabled = $false }
    if ($txtPropertiesHint) {
      $txtPropertiesHint.Text = "Select a folder, policy, or activity to view its properties."
    }
    return
  }

  # Element types that are containers, not scalar properties — skip these entirely
  $skipTypes = @('Folder','Policy','Object','Objects','GlobalSettings',
                 'GlobalConfigurations','GlobalVariable','GlobalConfiguration',
                 'Schedule','Counter','ComputerGroup','Policies')

  $rows = @()
  foreach ($child in @($XmlNode.ChildNodes)) {
    if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }

    # Skip container elements — they belong in the tree, not the property grid
    if ($skipTypes -contains $child.LocalName) { continue }

    # Skip elements that have element children (i.e. are themselves complex nodes)
    $hasElementChildren = @($child.ChildNodes | Where-Object {
      $_.NodeType -eq [System.Xml.XmlNodeType]::Element
    }).Count -gt 0
    if ($hasElementChildren) { continue }

    $localName = $child.LocalName
    $value     = $child.InnerText
    $datatype  = if ($child.Attributes -and $child.Attributes["datatype"]) {
      $child.Attributes["datatype"].Value
    } else { '' }

    $isReadOnly = $script:ReadOnlyPropertyNames -contains $localName

    $rows += New-PropertyRow -LocalName $localName -Value $value `
               -Datatype $datatype -ReadOnly $isReadOnly
  }

  $dgProperties.ItemsSource = $rows

  if ($btnApplyProperties) {
    $btnApplyProperties.IsEnabled = ($rows.Count -gt 0)
  }

  if ($txtPropertiesHint) {
    $txtPropertiesHint.Text = if ($rows.Count -gt 0) {
      "Edit a value and click Apply to stage the change."
    } else {
      "No scalar properties found for this node. Select a folder, policy, or activity."
    }
  }
}

function Apply-PropertyEdits {
  param([System.Xml.XmlNode]$XmlNode)

  if (-not $XmlNode -or -not $dgProperties.ItemsSource) { return 0 }

  # Commit any active edit cell first
  [void]$dgProperties.CommitEdit([System.Windows.Controls.DataGridEditingUnit]::Row, $true)

  $changed = 0
  foreach ($row in @($dgProperties.ItemsSource)) {
    if ($row.ReadOnly) { continue }

    $child = $XmlNode.SelectSingleNode("./*[local-name()='$($row.LocalName)']")
    if (-not $child) { continue }

    if ($child.InnerText -ne $row.Value) {
      $child.InnerText = $row.Value
      $changed++
    }
  }
  return $changed
}

#endregion Copy / Selection Helpers

#region Staged Export & Save

function Get-CurrentExportPath {
  $p = $txtPath.Text.Trim()
  if ([string]::IsNullOrWhiteSpace($p)) { return $null }
  try   { return [System.IO.Path]::GetFullPath($p) }
  catch { return $p }
}

function Get-StagedExportSourcePath {
  if ($script:HasUnsavedChanges -and
      -not [string]::IsNullOrWhiteSpace($script:StagedExportPath) -and
      (Test-Path -LiteralPath $script:StagedExportPath)) {
    try   { return [System.IO.Path]::GetFullPath($script:StagedExportPath) }
    catch { return $script:StagedExportPath }
  }
  return $null
}

# In Reset-StagedExportState — delete the old staged file when committing or discarding
function Reset-StagedExportState {
  if (-not [string]::IsNullOrWhiteSpace($script:StagedExportPath) -and
      (Test-Path -LiteralPath $script:StagedExportPath)) {
    try { Remove-Item -LiteralPath $script:StagedExportPath -Force -ErrorAction SilentlyContinue } catch {}
  }
  $script:StagedExportPath  = $null
  $script:HasUnsavedChanges = $false
  Update-WindowTitle
}

function Set-StagedExport {
  param([Parameter(Mandatory)][string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  $script:StagedExportPath  = $Path
  $script:HasUnsavedChanges = $true
  Update-WindowTitle
}

function Get-StagedExportTempPath {
  $baseName = "OisExport_Staged_{0}.ois_export" -f ([guid]::NewGuid().ToString("N"))
  return (Join-Path ([System.IO.Path]::GetTempPath()) $baseName)
}

function Load-StagedExportIntoUI {
  param(
    [Parameter(Mandatory)][string]$StagePath,
    [string]$StatusMessage = "Loaded staged export preview."
  )
  if (-not (Test-Path -LiteralPath $StagePath)) {
    throw "Staged export file not found: $StagePath"
  }
  Show-Overlay "Loading staged export preview..."
  Invoke-UiAction -Context "Load staged export preview" -Action {
    Set-Status "Parsing staged export preview..."
    $result                = Import-OisExport -Path $StagePath
    $script:AllNodes       = $result.Model
    $script:Filtered       = $script:AllNodes
    Update-TreeView -Root $script:AllNodes
    Set-StagedExport -Path $StagePath
    Set-Status $StatusMessage
  }
  Hide-Overlay
}

# Saves the modified XML to a temp path, then loads the preview.
# Returns the temp path so callers can report it to the user.
function Stage-EditedExport {
  param(
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)][string]$StatusMessage
  )
  $stagePath = Get-StagedExportTempPath
  $Xml.Save($stagePath)
  Load-StagedExportIntoUI -StagePath $stagePath -StatusMessage $StatusMessage
  return $stagePath
}

function Save-CurrentExport {
  Invoke-UiAction -Context "Save" -Action {
    $currentPath = Get-CurrentExportPath
    if (-not $currentPath -or -not (Test-Path -LiteralPath $currentPath)) {
      [void][System.Windows.MessageBox]::Show("Pick a valid .ois_export file first.", "Save",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
      return
    }
    $sourcePath = Get-StagedExportSourcePath
    if (-not $sourcePath) {
      Set-Status "No unsaved changes to save."
      [void][System.Windows.MessageBox]::Show("There are no unsaved staged changes to save.", "Save",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
      return
    }

    if ($script:BackupBeforeSave) {
      $backupPath = Backup-OisExportAsZip -SourcePath $currentPath
      if ($backupPath) { Set-Status "Backed up original to: $([System.IO.Path]::GetFileName($backupPath))" }
    }

    Copy-Item -LiteralPath $sourcePath -Destination $currentPath -Force

    # Write sanitize sidecar log next to the saved file
    $logPath = $null
    if ($script:LastStagedAction -eq 'Sanitize' -and @($script:LastSanitizeRemovedItems).Count -gt 0) {
      $logPath = Join-Path (Split-Path -Parent $currentPath) (
        [System.IO.Path]::GetFileNameWithoutExtension($currentPath) + ".sanitize-removals.log.txt")
      Write-OisCleanupLog -LogPath $logPath -ActionName "Sanitize Export" -Items @($script:LastSanitizeRemovedItems)
    }

    $script:LastStagedAction = $null
    Reset-StagedExportState
    Set-Status "Saved: $currentPath"

    # Save selected node id before reload
    $script:_PostStageSelectId = if (Get-SelectedTreeNode) { (Get-SelectedTreeNode).UniqueId } else { $null }

    # Feature 3 — offer handoff package
    $result = [System.Windows.MessageBox]::Show(
      "Saved:`n$currentPath`n`nCreate a handoff package (zip) for deployment?",
      "Save", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Information)

    if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
      $envChoice = [System.Windows.MessageBox]::Show(
        "Which environment is this package for?`n`nYes = BASELINE     No = PROD",
        "Handoff Package", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
      $env = if ($envChoice -eq [System.Windows.MessageBoxResult]::Yes) { "BASELINE" } else { "PRODUCTION" }

      # Use the sidecar log written above if it exists, otherwise check for one on disk
      if (-not $logPath) {
        $candidate = Join-Path (Split-Path $currentPath -Parent) (
          [System.IO.Path]::GetFileNameWithoutExtension($currentPath) + ".sanitize-removals.log.txt")
        $logPath = if (Test-Path -LiteralPath $candidate) { $candidate } else { $null }
      }

      $zipPath = New-OisHandoffPackage -ExportPath $currentPath -LogPath $logPath -Environment $env
      Set-Status "Handoff package created: $([System.IO.Path]::GetFileName($zipPath))"
$openFolder = [System.Windows.MessageBox]::Show(
        "Package created:`n$zipPath`n`nOpen containing folder?",
        "Handoff Package", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Information)
      if ($openFolder -eq [System.Windows.MessageBoxResult]::Yes) {
        Start-Process explorer.exe -ArgumentList "/select,`"$zipPath`""
      }
    }
    # Reload UI after all dialogs are done
    Import-ExportIntoUI -Path $currentPath -PreserveSelection

    # Restore selection
    if ($script:_PostStageSelectId) {
      Invoke-RestoreTreeSelection -UniqueId $script:_PostStageSelectId
      $script:_PostStageSelectId = $null
    }
  }
}

function Save-AsCurrentExportCopy {
  Invoke-UiAction -Context "Save As" -Action {
    $currentPath = Get-CurrentExportPath
    if (-not $currentPath -or -not (Test-Path -LiteralPath $currentPath)) {
      [void][System.Windows.MessageBox]::Show("Pick a valid .ois_export file first.", "Save As",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
      return
    }
    $sourcePath = Get-StagedExportSourcePath
    if (-not $sourcePath) { $sourcePath = $currentPath }

    $sfd = New-Object Microsoft.Win32.SaveFileDialog
    $sfd.Filter   = "Orchestrator Export (*.ois_export)|*.ois_export|All Files (*.*)|*.*"
    $sfd.FileName = [System.IO.Path]::GetFileName($currentPath)
    $sfd.InitialDirectory = Split-Path $currentPath -Parent
    if (-not $sfd.ShowDialog()) { return }

    $destPath = [System.IO.Path]::GetFullPath($sfd.FileName)
    if ([string]::Equals($sourcePath, $destPath, [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($currentPath, $destPath, [System.StringComparison]::OrdinalIgnoreCase)) {
      Set-Status "Save As cancelled: same file."
      [void][System.Windows.MessageBox]::Show(
        "The selected path is the same as the current file.`nChoose a different name or location.", "Save As",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
      return
    }

Copy-Item -LiteralPath $sourcePath -Destination $destPath -Force

    # Write sanitize sidecar log next to the saved file
    $logPath = $null
    if ($script:LastStagedAction -eq 'Sanitize' -and @($script:LastSanitizeRemovedItems).Count -gt 0) {
      $logPath = Join-Path (Split-Path -Parent $destPath) (
        [System.IO.Path]::GetFileNameWithoutExtension($destPath) + ".sanitize-removals.log.txt")
      Write-OisCleanupLog -LogPath $logPath -ActionName "Sanitize Export" -Items @($script:LastSanitizeRemovedItems)
    }

    $script:LastStagedAction = $null
    Reset-StagedExportState
    $txtPath.Text = $destPath
    $txtPath.IsReadOnly = $true
    Set-Status "Saved As: $destPath"

    # Save selected node id before reload
    $script:_PostStageSelectId = if (Get-SelectedTreeNode) { (Get-SelectedTreeNode).UniqueId } else { $null }

    # Feature 3 — offer handoff package
    $result = [System.Windows.MessageBox]::Show(
      "Created and opened:`n$destPath`n`nCreate a handoff package (zip) for deployment?",
      "Save As", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Information)

    if ($result -eq [System.Windows.MessageBoxResult]::Yes) {
      $envChoice = [System.Windows.MessageBox]::Show(
        "Which environment is this package for?`n`nYes = BASELINE     No = PROD",
        "Handoff Package", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
      $env = if ($envChoice -eq [System.Windows.MessageBoxResult]::Yes) { "BASELINE" } else { "PROD" }

      if (-not $logPath) {
        $candidate = Join-Path (Split-Path $destPath -Parent) (
          [System.IO.Path]::GetFileNameWithoutExtension($destPath) + ".sanitize-removals.log.txt")
        $logPath = if (Test-Path -LiteralPath $candidate) { $candidate } else { $null }
      }

      $zipPath = New-OisHandoffPackage -ExportPath $destPath -LogPath $logPath -Environment $env
      Set-Status "Handoff package created: $([System.IO.Path]::GetFileName($zipPath))"
$openFolder = [System.Windows.MessageBox]::Show(
        "Package created:`n$zipPath`n`nOpen containing folder?",
        "Handoff Package", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Information)
      if ($openFolder -eq [System.Windows.MessageBoxResult]::Yes) {
        Start-Process explorer.exe -ArgumentList "/select,`"$zipPath`""
      }
    }

    # Reload UI after all dialogs are done
    Import-ExportIntoUI -Path $destPath -PreserveSelection

    # Restore selection
    if ($script:_PostStageSelectId) {
      Invoke-RestoreTreeSelection -UniqueId $script:_PostStageSelectId
      $script:_PostStageSelectId = $null
      }
  }
}

function Show-SaveExportDialog {
  param([string]$DefaultFileName)
  $sfd = New-Object Microsoft.Win32.SaveFileDialog
  $sfd.Filter   = "Orchestrator Export (*.ois_export)|*.ois_export|All Files (*.*)|*.*"
  $sfd.FileName = $DefaultFileName
  if ($sfd.ShowDialog()) { return $sfd.FileName }
  return $null
}

function Backup-OisExportAsZip {
  param([Parameter(Mandatory)][string]$SourcePath)
  if (-not (Test-Path -LiteralPath $SourcePath)) { return $null }

  $dir     = Split-Path $SourcePath -Parent
  # Fall back to temp if source directory isn't writable
  if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
    $dir = [System.IO.Path]::GetTempPath()
  }

  $baseName = [System.IO.Path]::GetFileNameWithoutExtension($SourcePath)
  $stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
  $zipPath = Join-Path $dir "${baseName}_backup_${stamp}.zip"

  $zip = $null
  try {
    $zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
      $zip, $SourcePath, [System.IO.Path]::GetFileName($SourcePath))
  } finally {
    if ($zip) { $zip.Dispose() }
  }
  return $zipPath
}

#endregion Staged Export & Save

#region Import / Load

function Import-ExportIntoUI {
  param(
    [string]$Path,
    [switch]$PreserveSelection
  )
  Show-Overlay "Parsing export..."
  Invoke-UiAction -Context "Parse export" -Action {
    Set-Status "Parsing: $Path"
    $result          = Import-OisExport -Path $Path
    $script:AllNodes = $result.Model
    $script:Filtered = $script:AllNodes

    Update-TreeView -Root $script:AllNodes

    if ($txtPath)            { $txtPath.IsReadOnly = $true }
    if ($btnApplyProperties) { $btnApplyProperties.IsEnabled = $false }
    Set-ExportLoadedState -Loaded $true

    if (-not $PreserveSelection) {
      Reset-StagedExportState
      Add-RecentFile -Path $Path
    }

    # Health check
    try {
      $doc      = Get-OisXmlDocument -Path $Path
      $warnings = @(Get-OisExportHealthWarnings -Doc $doc)
      if ($warnings.Count -gt 0) {
        Set-Status ("Loaded: $Path  |  " + ($warnings -join "  |  "))
      } else {
        Set-Status "Loaded: $Path"
      }
    } catch {
      Set-Status "Loaded: $Path"
    }
  }
  Hide-Overlay
  Update-WindowTitle
}


function Invoke-CliMode {
  param()

  $inputPath = switch ($script:ActiveParameterSet) {
    'Sanitize'      { $Sanitize }
    'RemoveGlobals' { $RemoveGlobals }
    'RemoveFolders' { $RemoveFolders }
    'ApplyLBP'      { $ApplyLinkBestPractices }
    'SetParallel'   { $SetMaxParallel }
    'Logging'       { $SetLogging }
    'HealthCheck'   { $HealthCheck }
    'VarInventory'  { $PolicyVariableInventory }
    'Package'       { $CreateHandoffPackage }
    'Compare'       { $inputPath = $Compare }
    'BulkRename'    { $inputPath = $BulkRename }
    'ExportReport'  { $inputPath = $ExportReport }
    'SearchCodebase' { $inputPath = $SearchCodebase }
  }

if (-not (Test-Path -LiteralPath $inputPath)) {
  Write-Host "ERROR: Input file not found: $inputPath" -ForegroundColor Red
  exit 1
}

# Auto-generate output path only for operations that write a file
  $writesOutput = $script:ActiveParameterSet -in @('Sanitize','RemoveGlobals','RemoveFolders','ApplyLBP','SetParallel','Logging','Package','BulkRename','ExportReport')

  if ($writesOutput -and -not $OutputPath) {
    $prefix = switch ($script:ActiveParameterSet) {
      'Sanitize'      { 'Sanitized_' }
      'RemoveGlobals' { 'NoUnreferencedGlobals_' }
      'RemoveFolders' { 'NoEmptyFolders_' }
      'ApplyLBP'      { 'LinkBestPractices_' }
      'SetParallel'   { 'MaxParallel_' }
      'Logging'       { "$($LoggingAction)_$($LoggingType)Logging_" }
      'Package'       { "${Environment}_" }
      'ExportReport'  { 'ExportReport_' }
    }
    $OutputPath = Join-Path (Split-Path $inputPath -Parent) (
      New-StampedExportFileName -Prefix $prefix -SourcePath $inputPath)
  }

  switch ($script:ActiveParameterSet) {

    'HealthCheck' {
      Write-Host "OIS Export Analyzer v$script:AppVersion — Health Check" -ForegroundColor Cyan
      Write-Host "Input: $inputPath"
      [xml]$doc = Get-OisXmlDocument -Path $inputPath
      $warnings = @(Get-OisExportHealthWarnings -Doc $doc)
      if ($warnings.Count -eq 0) {
        Write-Host "No issues found." -ForegroundColor Green
      } else {
        foreach ($w in $warnings) { Write-Warning $w }
      }
      exit 0
    }

    'VarInventory' {
      Write-Host "OIS Export Analyzer v$script:AppVersion — Policy Variable Inventory" -ForegroundColor Cyan
      Write-Host "Input: $inputPath"
      [xml]$doc = Get-OisXmlDocument -Path $inputPath
      $inventory = @(Get-PolicyVariableInventory -Doc $doc)
      if ($inventory.Count -eq 0) {
        Write-Host "No policy variable references found." -ForegroundColor Yellow
      } else {
        $inventory | Format-Table PolicyName, FolderPath, ActivityName, VarName, IsLinkVar -AutoSize
        $linkCount = @($inventory | Where-Object { $_.IsLinkVar }).Count
        Write-Host "Total: $($inventory.Count) references  |  Possible link vars: $linkCount" -ForegroundColor Cyan
      }
      exit 0
    }

    'Sanitize' {
      Write-Host "OIS Export Analyzer v$script:AppVersion — Sanitize Export" -ForegroundColor Cyan
      Write-Host "Input:  $inputPath"

      $opts = if ($Strict) {
        @{ Strict=$true; Variables=$true; Configs=$true; Schedules=$true
           Counters=$true; Groups=$true; EmptyFolders=$true }
      } else {
        @{ Strict=$false; Variables=$true; Configs=$true; Schedules=$true
           Counters=$true; Groups=$true; EmptyFolders=$true }
      }

      if ($WhatIf) {
        # Preview only
        [xml]$doc = Get-OisXmlDocument -Path $inputPath
        $usagePoliciesOnly       = Get-UsageScopeText -Xml $doc -IncludePolicies
        $usagePoliciesAndConfigs = Get-UsageScopeText -Xml $doc -IncludePolicies -IncludeGlobalConfigurations
        $preview = @()
        if ($opts.Variables) { $preview += Get-UnreferencedNodesByUsageScope -Xml $doc -XPath "//*[local-name()='GlobalVariable']"    -UsageText $usagePoliciesAndConfigs -TypeLabel 'variable' }
        if ($opts.Configs)   { $preview += Get-UnreferencedNodesByUsageScope -Xml $doc -XPath "//*[local-name()='GlobalConfiguration']" -UsageText $usagePoliciesOnly       -TypeLabel 'config' }
        if ($opts.Schedules) { $preview += Get-UnreferencedNodesByUsageScope -Xml $doc -XPath "//*[local-name()='Schedule']"            -UsageText $usagePoliciesOnly       -TypeLabel 'schedule' }
        if ($opts.Counters)  { $preview += Get-UnreferencedNodesByUsageScope -Xml $doc -XPath "//*[local-name()='Counter']"             -UsageText $usagePoliciesOnly       -TypeLabel 'counter' }
        if ($opts.Groups)    { $preview += Get-UnreferencedNodesByUsageScope -Xml $doc -XPath "//*[local-name()='ComputerGroup']"       -UsageText $usagePoliciesOnly       -TypeLabel 'group' }
        if ($opts.EmptyFolders) { $preview += Get-OisEmptyFolders -Xml $doc }
        Write-Host "[WhatIf] Would remove $($preview.Count) item(s):" -ForegroundColor Yellow
        $preview | Format-Table Name, Type, UniqueId -AutoSize
        exit 0
      }

      $clean = Invoke-OisExportSanitize -Path $inputPath -Options $opts
      $clean.Save($OutputPath)
      $summary = Get-SanitizeRemovalSummary -Items @($script:LastSanitizeRemovedItems)
      Write-Host "Output: $OutputPath" -ForegroundColor Green
      Write-Host "Removed: $($summary.Total)  Variables: $($summary.Variables)  Configs: $($summary.Configs)  Schedules: $($summary.Schedules)  Counters: $($summary.Counters)  Groups: $($summary.Groups)  Empty Folders: $($summary.EmptyFolders)"

      if (-not $NoLog -and $summary.Total -gt 0) {
        $logPath = [System.IO.Path]::ChangeExtension($OutputPath, '') + "sanitize-removals.log.txt"
        Write-OisCleanupLog -LogPath $logPath -ActionName "Sanitize Export" -Items @($script:LastSanitizeRemovedItems)
        Write-Host "Log:    $logPath"
      }
      exit 0
    }

    'RemoveGlobals' {
      Write-Host "OIS Export Analyzer v$script:AppVersion — Remove Unreferenced Globals" -ForegroundColor Cyan
      Write-Host "Input:  $inputPath"
      [xml]$xml = Get-OisXmlDocument -Path $inputPath
      $xml.XmlResolver = $null
      $opts = @{ Variables=$true; Configs=$true; Schedules=$true; Counters=$true; Groups=$true }

      if ($WhatIf) {
        $preview = @(Get-UnreferencedGlobals -Xml $xml -Options $opts)
        Write-Host "[WhatIf] Would remove $($preview.Count) item(s):" -ForegroundColor Yellow
        $preview | Format-Table Name, Type, UniqueId -AutoSize
        exit 0
      }

      $removed = @(Remove-UnreferencedGlobalsFromXml -Xml $xml -Options $opts)
      $xml.Save($OutputPath)
      Write-Host "Output: $OutputPath" -ForegroundColor Green
      Write-Host "Removed: $($removed.Count)"
      if (-not $NoLog -and $removed.Count -gt 0) {
        $logPath = [System.IO.Path]::ChangeExtension($OutputPath, '') + "unreferenced-globals.log.txt"
        Write-OisCleanupLog -LogPath $logPath -ActionName "Remove Unreferenced Globals" -Items $removed
        Write-Host "Log:    $logPath"
      }
      exit 0
    }

    'RemoveFolders' {
      Write-Host "OIS Export Analyzer v$script:AppVersion — Remove Empty Folders" -ForegroundColor Cyan
      Write-Host "Input:  $inputPath"
      [xml]$xml = Get-OisXmlDocument -Path $inputPath
      $xml.XmlResolver = $null

      if ($WhatIf) {
        $preview = @(Get-OisEmptyFolders -Xml $xml)
        Write-Host "[WhatIf] Would remove $($preview.Count) empty folder(s):" -ForegroundColor Yellow
        $preview | Format-Table Name, Path -AutoSize
        exit 0
      }

      $removed = @(Remove-OisEmptyFoldersFromXml -Xml $xml)
      $xml.Save($OutputPath)
      Write-Host "Output: $OutputPath" -ForegroundColor Green
      Write-Host "Removed: $($removed.Count) empty folder(s)"
      if (-not $NoLog -and $removed.Count -gt 0) {
        $logPath = [System.IO.Path]::ChangeExtension($OutputPath, '') + "empty-folders.log.txt"
        Write-OisCleanupLog -LogPath $logPath -ActionName "Remove Empty Folders" -Items $removed
        Write-Host "Log:    $logPath"
      }
      exit 0
    }

    'ApplyLBP' {
      Write-Host "OIS Export Analyzer v$script:AppVersion — Apply Link Best Practices" -ForegroundColor Cyan
      Write-Host "Input:  $inputPath"
      [xml]$xml = Get-OisXmlDocument -Path $inputPath
      $xml.XmlResolver = $null
      $result = Apply-LinkBestPracticesToExportXml -Xml $xml

      if ($WhatIf) {
        Write-Host "[WhatIf] Would update $($result.LinksFound) link(s)." -ForegroundColor Yellow
        exit 0
      }

      $xml.Save($OutputPath)
      Write-Host "Output: $OutputPath" -ForegroundColor Green
      Write-Host "Links found: $($result.LinksFound)  Updated: $($result.LinksUpdated)  Green: $($result.Green)  Blue: $($result.Blue)  Orange: $($result.Orange)  Red: $($result.Red)"
      exit 0
    }

    'SetParallel' {
      Write-Host "OIS Export Analyzer v$script:AppVersion — Set Max Parallel" -ForegroundColor Cyan
      Write-Host "Input:  $inputPath  Value: $MaxParallelValue"
      [xml]$xml = Get-OisXmlDocument -Path $inputPath
      $xml.XmlResolver = $null
      $policies = @($xml.SelectNodes("//*[local-name()='Policy']"))
      if ($PolicyName) {
        $policies = @($policies | Where-Object { (Get-InnerTextLocal $_ 'Name') -eq $PolicyName })
      }
      $changed = 0
      foreach ($policy in $policies) {
        $result = Set-FirstMatchingChildValue -Node $policy `
          -CandidateNames $script:MaxParallelCandidateNames `
          -Value ([string]$MaxParallelValue) -Datatype 'int' -CreateIfMissing
        if ($result) { $changed++ }
      }
      if ($WhatIf) {
        Write-Host "[WhatIf] Would update $changed policy/policies." -ForegroundColor Yellow
        exit 0
      }
      $xml.Save($OutputPath)
      Write-Host "Output: $OutputPath" -ForegroundColor Green
      Write-Host "Updated: $changed policy/policies to MaxParallel=$MaxParallelValue"
      exit 0
    }

    'Logging' {
      Write-Host "OIS Export Analyzer v$script:AppVersion — Set Logging" -ForegroundColor Cyan
      Write-Host "Input:  $inputPath  Type: $LoggingType  Action: $LoggingAction"
      [xml]$xml = Get-OisXmlDocument -Path $inputPath
      $xml.XmlResolver = $null
      $policies = @($xml.SelectNodes("//*[local-name()='Policy']"))
      if ($PolicyName) {
        $policies = @($policies | Where-Object { (Get-InnerTextLocal $_ 'Name') -eq $PolicyName })
      }
      $enable   = ($LoggingAction -eq 'Enable')
      $totalChanged = 0
      foreach ($policy in $policies) {
        if ($LoggingType -in @('Object','Both')) {
          $totalChanged += Set-LoggingFieldsInPolicyObjects -PolicyNode $policy -CandidateNames $script:ObjectLoggingCandidateNames -Enabled $enable
        }
        if ($LoggingType -in @('Generic','Both')) {
          $totalChanged += Set-LoggingFieldsInPolicyObjects -PolicyNode $policy -CandidateNames $script:GenericLoggingCandidateNames -Enabled $enable
        }
      }
      if ($WhatIf) {
        Write-Host "[WhatIf] Would update $totalChanged field(s)." -ForegroundColor Yellow
        exit 0
      }
      $xml.Save($OutputPath)
      Write-Host "Output: $OutputPath" -ForegroundColor Green
      Write-Host "Updated: $totalChanged logging field(s)"
      exit 0
    }

    'Package' {
      Write-Host "OIS Export Analyzer v$script:AppVersion — Create Handoff Package" -ForegroundColor Cyan
      Write-Host "Input:  $inputPath  Environment: $Environment"
      $logCandidate = [System.IO.Path]::ChangeExtension($inputPath, '') + "sanitize-removals.log.txt"
      $logPath      = if (Test-Path -LiteralPath $logCandidate) { $logCandidate } else { $null }
      $zipPath      = New-OisHandoffPackage -ExportPath $inputPath -LogPath $logPath -Environment $Environment
      Write-Host "Package: $zipPath" -ForegroundColor Green
      exit 0
    }

    'Compare' {
      Write-Host "OIS Export Analyzer v$script:AppVersion — Export Diff" -ForegroundColor Cyan
      Write-Host "Base:     $Compare"
      Write-Host "Modified: $Against"

      if (-not (Test-Path -LiteralPath $Against)) {
        Write-Host "ERROR: Modified file not found: $Against" -ForegroundColor Red
        exit 1
      }

      $diff = Compare-OisExports -BasePath $Compare -ModifiedPath $Against
      Format-OisDiffReport -Diff $diff -UseColor
      exit 0
    }

    'BulkRename' {
      Write-Host "OIS Export Analyzer v$script:AppVersion — Bulk Rename" -ForegroundColor Cyan
      Write-Host "Input:   $inputPath"
      Write-Host "CSV:     $CsvPath"

      if (-not (Test-Path -LiteralPath $CsvPath)) {
        Write-Host "ERROR: CSV file not found: $CsvPath" -ForegroundColor Red
        exit 1
      }

      [xml]$xml = Get-OisXmlDocument -Path $inputPath
      $xml.XmlResolver = $null

      $results = Invoke-BulkRename -Xml $xml -CsvPath $CsvPath

      $results | Format-Table OldName, NewName, Type, Status -AutoSize

      $succeeded = @($results | Where-Object { $_.Status -eq 'Renamed' }).Count
      $notFound  = @($results | Where-Object { $_.Status -eq 'NotFound' }).Count

      if ($WhatIf) {
        Write-Host "[WhatIf] Would rename $succeeded item(s). $notFound not found." -ForegroundColor Yellow
        exit 0
      }

      if ($succeeded -gt 0) {
        $xml.Save($OutputPath)
        Write-Host "Output: $OutputPath" -ForegroundColor Green
        Write-Host "Renamed: $succeeded  Not found: $notFound"
      } else {
        Write-Host "No matching items found. No output written." -ForegroundColor Yellow
      }
      exit 0
    }

    'ExportReport' {
      Write-Host "OIS Export Analyzer v$script:AppVersion — Export Report" -ForegroundColor Cyan
      Write-Host "Input:  $inputPath"
      $reportLines = New-OisExportReport -Path $inputPath -OutputPath $OutputPath
      if (-not $OutputPath) {
        $reportLines | ForEach-Object { Write-Host $_ }
      } else {
        Write-Host "Report: $OutputPath" -ForegroundColor Green
        Write-Host "Lines:  $($reportLines.Count)"
      }
      exit 0
    }

    'SearchCodebase' {
      Write-Host "OIS Export Analyzer v$script:AppVersion — Sourcegraph Search" -ForegroundColor Cyan
      Write-Host "Input: $inputPath"

      [xml]$doc = Get-OisXmlDocument -Path $inputPath

      $policies = @($doc.SelectNodes("//*[local-name()='Policy']"))
      if ($policies.Count -eq 0) {
        Write-Host "No policies found in export." -ForegroundColor Yellow
        exit 0
      }

      # If PolicyName filter provided use it, otherwise search all
      if ($PolicyName) {
        $policies = @($policies | Where-Object { (Get-InnerTextLocal $_ 'Name') -eq $PolicyName })
        if ($policies.Count -eq 0) {
          Write-Host "No policy named '$PolicyName' found in export." -ForegroundColor Yellow
          exit 1
        }
      }

      $totalFound = 0
      foreach ($policy in $policies) {
        $pName = Get-InnerTextLocal $policy 'Name'
        $pId   = Get-InnerTextLocal $policy 'UniqueID'

        Write-Host ""
        Write-Host "Searching for: $pName" -ForegroundColor Yellow

        try {
          $results = @(Search-SourcegraphForPolicy `
            -PolicyName $pName `
            -UniqueId   $pId `
            -Url        $SourcegraphUrl `
            -Token      $SourcegraphToken)

          if ($results.Count -eq 0) {
            Write-Host "  No references found." -ForegroundColor Gray
          } else {
            $totalFound += $results.Count
            $results | Format-Table Repository, FilePath, LineNumber, Preview -AutoSize
          }
        } catch {
          Write-Warning "  Search failed: $_"
        }
      }

      Write-Host ""
      Write-Host "Total references found: $totalFound" -ForegroundColor Cyan
      exit 0
    }

  }
}


#endregion Import / Load

#region Cleanup Helpers

function Get-OisFolderName {
  param([Parameter(Mandatory)][System.Xml.XmlNode]$FolderNode)
  $nameNode = $FolderNode.SelectSingleNode("./*[local-name()='Name']")
  if ($nameNode -and $nameNode.InnerText) { return $nameNode.InnerText.Trim() }
  return "(unnamed folder)"
}

function Get-OisFolderPath {
  param([Parameter(Mandatory)][System.Xml.XmlNode]$FolderNode)
  $parts   = @()
  $current = $FolderNode
  while ($current -and $current.LocalName -eq 'Folder') {
    $parts = ,(Get-OisFolderName -FolderNode $current) + $parts
    $parent = $current.ParentNode
    while ($parent -and $parent.NodeType -ne [System.Xml.XmlNodeType]::Element) {
      $parent = $parent.ParentNode
    }
    if (-not $parent -or $parent.LocalName -ne 'Folder') { break }
    $current = $parent
  }
  return ($parts -join '\')
}


function Test-OisFolderIsEmpty {
  param([Parameter(Mandatory)][System.Xml.XmlNode]$FolderNode)

  # Check for child policy folders or runbooks (standard policy tree)
  $childFolders  = @($FolderNode.SelectNodes("./*[local-name()='Folder']")).Count
  $childPolicies = @($FolderNode.SelectNodes("./*[local-name()='Policy']")).Count

  # Check for Objects children (GlobalSettings Variables/Schedules/etc folders)
  $childObjects = @($FolderNode.SelectNodes(".//*[local-name()='Object']")).Count

  return ($childFolders -eq 0 -and $childPolicies -eq 0 -and $childObjects -eq 0)
}


function Get-OisEmptyFolders {
  param([Parameter(Mandatory)][System.Xml.XmlDocument]$Xml)
  $results = @()
  foreach ($folder in @($Xml.SelectNodes("//*[local-name()='Folder']"))) {
    if (-not (Test-OisFolderIsEmpty -FolderNode $folder)) { continue }
    $results += [pscustomobject]@{
      Name     = Get-OisFolderName -FolderNode $folder
      Type     = 'empty-folder'
      UniqueId = Get-NodeId -Node $folder
      Path     = Get-OisFolderPath -FolderNode $folder
    }
  }
  return $results
}

function Remove-OisEmptyFoldersFromXml {
  param([Parameter(Mandatory)][System.Xml.XmlDocument]$Xml)
  $removed = @()
  do {
    $removedThisPass = 0
    $folders = @($Xml.SelectNodes("//*[local-name()='Folder']")) |
      Sort-Object { $_.SelectNodes("ancestor::*[local-name()='Folder']").Count } -Descending
    foreach ($folder in $folders) {
      if (-not $folder.ParentNode) { continue }
      if (-not (Test-OisFolderIsEmpty -FolderNode $folder)) { continue }
      $removed += [pscustomobject]@{
        Name     = Get-OisFolderName -FolderNode $folder
        Type     = 'removed-empty-folder'
        UniqueId = Get-NodeId -Node $folder
        Path     = Get-OisFolderPath -FolderNode $folder
      }
      [void]$folder.ParentNode.RemoveChild($folder)
      $removedThisPass++
    }
  } while ($removedThisPass -gt 0)
  return $removed
}

function Get-OisExportHealthWarnings {
  param([Parameter(Mandatory)][xml]$Doc)

  $warnings = @()

  # Policies with no activities (excluding links and return objects)
  $policies = @($Doc.SelectNodes("//*[local-name()='Policy']"))
  $emptyPolicies = @($policies | Where-Object {
    $activities = @($_.SelectNodes(".//*[local-name()='Object']") | Where-Object {
      $typeName = $_.SelectSingleNode("*[local-name()='ObjectTypeName']")
      $typeName -and $typeName.InnerText.Trim() -notin @('Link','Return')
    })
    $activities.Count -eq 0
  })
  if ($emptyPolicies.Count -gt 0) {
    $warnings += "⚠ $($emptyPolicies.Count) policy/policies have no activities"
  }

  # Unreferenced global variables (quick indicator) — use correct XPath
  $policiesNode = $Doc.SelectSingleNode("/*[local-name()='ExportData']/*[local-name()='Policies']")
  $usageText    = if ($policiesNode) { $policiesNode.InnerXml } else { $null }
  if ($usageText) {
    $globalVars = @($Doc.SelectNodes("//*[local-name()='GlobalSettings']//*[local-name()='Variables']//*[local-name()='Object']"))
    $unrefCount = @($globalVars | Where-Object {
      $idNode = $_.SelectSingleNode("*[local-name()='UniqueID']")
      $id     = if ($idNode) { $idNode.InnerText.Trim() } else { $null }
      $id -and $usageText -notmatch [regex]::Escape($id)
    }).Count
    if ($unrefCount -gt 0) {
      $warnings += "⚠ $unrefCount unreferenced global variable(s) detected"
    }
  }

# Empty folders — only count policy-tree folders, not GlobalSettings bucket folders
  $emptyFolders = @($Doc.SelectNodes("//*[local-name()='Policies']//*[local-name()='Folder']") | Where-Object {
    @($_.SelectNodes("./*[local-name()='Folder']")).Count -eq 0 -and
    @($_.SelectNodes("./*[local-name()='Policy']")).Count -eq 0
  })
  if ($emptyFolders.Count -gt 0) {
    $warnings += "⚠ $($emptyFolders.Count) empty folder(s) found"
  }

  return $warnings
}

function Write-OisCleanupLog {
  param(
    [Parameter(Mandatory)][string]$LogPath,
    [Parameter(Mandatory)][string]$ActionName,
    [object[]]$Items = @()
  )
  if (-not $Items -or $Items.Count -eq 0) { return }

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("Action   : $ActionName")
  $lines.Add("Date     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
  $lines.Add("Count    : $($Items.Count)")
  $lines.Add("")
  foreach ($item in $Items) {
    $lines.Add("Name     : $($item.Name)")
    $lines.Add("Type     : $($item.Type)")
    $lines.Add("UniqueId : $($item.UniqueId)")
    $lines.Add("Path     : $($item.Path)")
    $lines.Add("")
  }
  Set-Content -LiteralPath $LogPath -Value $lines -Encoding UTF8
}

function Get-ReferencedGuids {
  param(
    [Parameter(Mandatory)][xml]$Xml,
    [switch]$IncludePolicies,
    [switch]$IncludeGlobalConfigurations
  )

  $guids      = [System.Collections.Generic.HashSet[string]]::new(
                  [System.StringComparer]::OrdinalIgnoreCase)
  $guidRegex  = [regex]'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'
  $includeAll = (-not $IncludePolicies.IsPresent -and -not $IncludeGlobalConfigurations.IsPresent)

  if ($IncludePolicies -or $includeAll) {
    $node = $Xml.SelectSingleNode("/*[local-name()='ExportData']/*[local-name()='Policies']")
    if ($node) {
      foreach ($m in $guidRegex.Matches($node.InnerXml)) { [void]$guids.Add($m.Value) }
    }
  }

  if ($IncludeGlobalConfigurations -or $includeAll) {
    $node = $Xml.SelectSingleNode("/*[local-name()='ExportData']/*[local-name()='GlobalConfigurations']")
    if ($node) {
      foreach ($m in $guidRegex.Matches($node.InnerXml)) { [void]$guids.Add($m.Value) }
    }
  }

  return $guids
}

# Keep for any callers that still need raw text (Compare-OisExports etc.)
function Get-UsageScopeText {
  param([xml]$Xml, [switch]$IncludePolicies, [switch]$IncludeGlobalConfigurations)
  $parts      = @()
  $includeAll = (-not $IncludePolicies.IsPresent -and -not $IncludeGlobalConfigurations.IsPresent)
  if ($IncludePolicies -or $includeAll) {
    $policies = $Xml.SelectSingleNode("/*[local-name()='ExportData']/*[local-name()='Policies']")
    if ($policies) { $parts += $policies.InnerXml }
  }
  if ($IncludeGlobalConfigurations -or $includeAll) {
    $globalConfigs = $Xml.SelectSingleNode("/*[local-name()='ExportData']/*[local-name()='GlobalConfigurations']")
    if ($globalConfigs) { $parts += $globalConfigs.InnerXml }
  }
  return ($parts -join "`n")
}

function Get-UnreferencedNodesByGuidSet {
  param(
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)][string]$XPath,
    [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$ReferencedGuids,
    [string]$TypeLabel
  )
  $results = @()
  foreach ($node in @($Xml.SelectNodes($XPath))) {
    $id = Get-NodeId -Node $node
    if (-not $id) { continue }
    if (-not $ReferencedGuids.Contains($id)) {
      $results += [pscustomobject]@{
        Name     = Get-NodeDisplayName -Node $node
        Type     = $TypeLabel
        UniqueId = $id
        Path     = $node.LocalName
      }
    }
  }
  return $results
}

function Remove-UnreferencedNodesByGuidSet {
  param(
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)][string]$XPath,
    [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$ReferencedGuids,
    [string]$TypeLabel
  )
  $removed = @()
  foreach ($node in @($Xml.SelectNodes($XPath))) {
    $id = Get-NodeId -Node $node
    if (-not $id) { continue }
    if (-not $ReferencedGuids.Contains($id)) {
      $removed += [pscustomobject]@{
        Name     = Get-NodeDisplayName -Node $node
        Type     = if ($TypeLabel) { $TypeLabel } else { $node.LocalName }
        UniqueId = $id
        Path     = $node.LocalName
      }
      if ($node.ParentNode) { [void]$node.ParentNode.RemoveChild($node) }
    }
  }
  return $removed
}

# Keep old text-based versions for any remaining callers
function Get-UnreferencedNodesByUsageScope {
  param([xml]$Xml, [string]$XPath, [string]$UsageText, [string]$TypeLabel)
  $results = @()
  foreach ($node in @($Xml.SelectNodes($XPath))) {
    $id = Get-NodeId -Node $node
    if (-not $id) { continue }
    if ($UsageText -notmatch [regex]::Escape($id)) {
      $results += [pscustomobject]@{
        Name     = Get-NodeDisplayName -Node $node
        Type     = $TypeLabel
        UniqueId = $id
        Path     = $node.LocalName
      }
    }
  }
  return $results
}

function Remove-UnreferencedNodesByUsageScope {
  param([xml]$Xml, [string]$XPath, [string]$UsageText, [string]$TypeLabel)
  $removed = @()
  foreach ($node in @($Xml.SelectNodes($XPath))) {
    $id = Get-NodeId -Node $node
    if (-not $id) { continue }
    if ($UsageText -notmatch [regex]::Escape($id)) {
      $removed += [pscustomobject]@{
        Name     = Get-NodeDisplayName -Node $node
        Type     = if ($TypeLabel) { $TypeLabel } else { $node.LocalName }
        UniqueId = $id
        Path     = $node.LocalName
      }
      if ($node.ParentNode) { [void]$node.ParentNode.RemoveChild($node) }
    }
  }
  return $removed
}

function Get-UnreferencedGlobals {
  param([xml]$Xml, [hashtable]$Options)
  $results   = @()
  $guidsPoly = Get-ReferencedGuids -Xml $Xml -IncludePolicies
  $guidsAll  = Get-ReferencedGuids -Xml $Xml -IncludePolicies -IncludeGlobalConfigurations

  if ($Options.Variables) { $results += @(Get-UnreferencedNodesByGuidSet -Xml $Xml `
    -XPath "//*[local-name()='GlobalSettings']//*[local-name()='Variables']//*[local-name()='Object']" `
    -ReferencedGuids $guidsAll -TypeLabel 'variable') }

  if ($Options.Configs)   { $results += @(Get-UnreferencedNodesByGuidSet -Xml $Xml `
    -XPath "//*[local-name()='GlobalConfigurations']/*[local-name()='Entry']" `
    -ReferencedGuids $guidsPoly -TypeLabel 'config') }

  if ($Options.Schedules) { $results += @(Get-UnreferencedNodesByGuidSet -Xml $Xml `
    -XPath "//*[local-name()='GlobalSettings']//*[local-name()='Schedules']//*[local-name()='Object']" `
    -ReferencedGuids $guidsPoly -TypeLabel 'schedule') }

  if ($Options.Counters)  { $results += @(Get-UnreferencedNodesByGuidSet -Xml $Xml `
    -XPath "//*[local-name()='GlobalSettings']//*[local-name()='Counters']//*[local-name()='Object']" `
    -ReferencedGuids $guidsPoly -TypeLabel 'counter') }

  if ($Options.Groups)    { $results += @(Get-UnreferencedNodesByGuidSet -Xml $Xml `
    -XPath "//*[local-name()='GlobalSettings']//*[local-name()='ComputerGroups']//*[local-name()='Object']" `
    -ReferencedGuids $guidsPoly -TypeLabel 'group') }

  return $results
}

function Remove-UnreferencedGlobalsFromXml {
  param([xml]$Xml, [hashtable]$Options)
  $removed   = @()
  $guidsPoly = Get-ReferencedGuids -Xml $Xml -IncludePolicies
  $guidsAll  = Get-ReferencedGuids -Xml $Xml -IncludePolicies -IncludeGlobalConfigurations

  if ($Options.Variables) { $removed += @(Remove-UnreferencedNodesByGuidSet -Xml $Xml `
    -XPath "//*[local-name()='GlobalSettings']//*[local-name()='Variables']//*[local-name()='Object']" `
    -ReferencedGuids $guidsAll -TypeLabel 'variable') }

  if ($Options.Configs)   { $removed += @(Remove-UnreferencedNodesByGuidSet -Xml $Xml `
    -XPath "//*[local-name()='GlobalConfigurations']/*[local-name()='Entry']" `
    -ReferencedGuids $guidsPoly -TypeLabel 'config') }

  if ($Options.Schedules) { $removed += @(Remove-UnreferencedNodesByGuidSet -Xml $Xml `
    -XPath "//*[local-name()='GlobalSettings']//*[local-name()='Schedules']//*[local-name()='Object']" `
    -ReferencedGuids $guidsPoly -TypeLabel 'schedule') }

  if ($Options.Counters)  { $removed += @(Remove-UnreferencedNodesByGuidSet -Xml $Xml `
    -XPath "//*[local-name()='GlobalSettings']//*[local-name()='Counters']//*[local-name()='Object']" `
    -ReferencedGuids $guidsPoly -TypeLabel 'counter') }

  if ($Options.Groups)    { $removed += @(Remove-UnreferencedNodesByGuidSet -Xml $Xml `
    -XPath "//*[local-name()='GlobalSettings']//*[local-name()='ComputerGroups']//*[local-name()='Object']" `
    -ReferencedGuids $guidsPoly -TypeLabel 'group') }

  return $removed
}

function Get-PolicyVariableInventory {
  param([Parameter(Mandatory)][xml]$Doc)

  $results  = @()
  # Matches Orchestrator's published data token: `d.T.~Vb/{GUID}`d.T.~Vb/
  $varPattern = [regex]'`d\.T\.~Vb/\{([0-9A-Fa-f\-]{36})\}`d\.T\.~Vb/'

  $policies = @($Doc.SelectNodes("//*[local-name()='Policy']"))

  foreach ($policy in $policies) {
    $policyName = Get-InnerTextLocal $policy 'Name'
    if (-not $policyName) { $policyName = "(unnamed policy)" }
    $policyId   = Get-InnerTextLocal $policy 'UniqueID'

    # Build folder path by walking ancestor Folder nodes
    $pathParts = @()
    $ancestor  = $policy.ParentNode
    while ($ancestor -and $ancestor.LocalName -eq 'Folder') {
      $folderNameNode = $ancestor.SelectSingleNode("*[local-name()='Name']")
      $folderLabel    = if ($folderNameNode) { $folderNameNode.InnerText.Trim() } else { "(unnamed)" }
      $pathParts      = ,$folderLabel + $pathParts
      $ancestor       = $ancestor.ParentNode
    }
    $folderPath = if ($pathParts.Count -gt 0) { $pathParts -join '\' } else { '\' }

    # Scan all text content inside this policy's objects for variable tokens
    $objects = @($policy.SelectNodes(".//*[local-name()='Object']"))
    foreach ($obj in $objects) {
      $objName = Get-InnerTextLocal $obj 'Name'
      if (-not $objName) { $objName = "(unnamed object)" }
      $objId   = Get-InnerTextLocal $obj 'UniqueID'

      # Search all child text nodes for the variable reference pattern
      $matches = $varPattern.Matches($obj.InnerXml)
      foreach ($match in $matches) {
        $referencedGuid = $match.Groups[1].Value

        # Try to resolve the GUID to a name from GlobalSettings
        $resolvedName = $null
$safeGuid = $referencedGuid.Replace("'", "''")
$varNode  = $Doc.SelectSingleNode(
  "//*[local-name()='UniqueID' and normalize-space(.)='$safeGuid']/..")
        if ($varNode) {
          $nameNode     = $varNode.SelectSingleNode("*[local-name()='Name']")
          $resolvedName = if ($nameNode) { $nameNode.InnerText.Trim() } else { $null }
        }

        $displayName = if ($resolvedName) { $resolvedName } else { "{$referencedGuid}" }
        $isLink      = $displayName -match 'link|lnk|conn|connection|\burl\b|\bhost\b|\bserver\b|\bpath\b|\bcred'

        $results += [pscustomobject]@{
          PolicyName    = $policyName
          PolicyId      = $policyId
          FolderPath    = $folderPath
          FullPath      = "$folderPath\$policyName"
          ActivityName  = $objName
          ActivityId    = $objId
          VarName       = $displayName
          VarUniqueId   = $referencedGuid
          IsLinkVar     = $isLink
        }
      }
    }
  }

  # Deduplicate — same variable referenced multiple times in same policy counts once
  $seen    = @{}
  $deduped = @()
  foreach ($r in $results) {
    $key = "$($r.PolicyId)|$($r.VarUniqueId)"
    if (-not $seen.ContainsKey($key)) {
      $seen[$key] = $true
      $deduped   += $r
    }
  }

  return $deduped
}

function Get-SanitizeRemovalSummary {
  param([object[]]$Items = @())
  $all = @($Items)
  return [pscustomobject]@{
    Total        = $all.Count
    Variables    = @($all | Where-Object { $_.Type -eq 'variable' }).Count
    Configs      = @($all | Where-Object { $_.Type -eq 'config' }).Count
    Schedules    = @($all | Where-Object { $_.Type -eq 'schedule' }).Count
    Counters     = @($all | Where-Object { $_.Type -eq 'counter' }).Count
    Groups       = @($all | Where-Object { $_.Type -eq 'group' }).Count
    EmptyFolders = @($all | Where-Object { $_.Type -eq 'removed-empty-folder' }).Count
  }
}

function Invoke-OisExportSanitize {
  param([string]$Path, [hashtable]$Options)

  $script:LastSanitizeRemovedItems = @()
  [xml]$xml = Get-OisXmlDocument -Path $Path

  if ($Options.Strict) {
    $Options = @{
      Variables    = $true
      Configs      = $true
      Schedules    = $true
      Counters     = $true
      Groups       = $true
      EmptyFolders = $true
    }
  }

  $guidsPoly = Get-ReferencedGuids -Xml $xml -IncludePolicies
  $guidsAll  = Get-ReferencedGuids -Xml $xml -IncludePolicies -IncludeGlobalConfigurations

  if ($Options.Variables) {
    $script:LastSanitizeRemovedItems += @(Remove-UnreferencedNodesByGuidSet -Xml $xml `
      -XPath "//*[local-name()='GlobalSettings']//*[local-name()='Variables']//*[local-name()='Object']" `
      -ReferencedGuids $guidsAll -TypeLabel 'variable')
  }
  if ($Options.Configs) {
    $script:LastSanitizeRemovedItems += @(Remove-UnreferencedNodesByGuidSet -Xml $xml `
      -XPath "//*[local-name()='GlobalConfigurations']/*[local-name()='Entry']" `
      -ReferencedGuids $guidsPoly -TypeLabel 'config')
  }
  if ($Options.Schedules) {
    $script:LastSanitizeRemovedItems += @(Remove-UnreferencedNodesByGuidSet -Xml $xml `
      -XPath "//*[local-name()='GlobalSettings']//*[local-name()='Schedules']//*[local-name()='Object']" `
      -ReferencedGuids $guidsPoly -TypeLabel 'schedule')
  }
  if ($Options.Counters) {
    $script:LastSanitizeRemovedItems += @(Remove-UnreferencedNodesByGuidSet -Xml $xml `
      -XPath "//*[local-name()='GlobalSettings']//*[local-name()='Counters']//*[local-name()='Object']" `
      -ReferencedGuids $guidsPoly -TypeLabel 'counter')
  }
  if ($Options.Groups) {
    $script:LastSanitizeRemovedItems += @(Remove-UnreferencedNodesByGuidSet -Xml $xml `
      -XPath "//*[local-name()='GlobalSettings']//*[local-name()='ComputerGroups']//*[local-name()='Object']" `
      -ReferencedGuids $guidsPoly -TypeLabel 'group')
  }
  if ($Options.EmptyFolders) {
    $script:LastSanitizeRemovedEmptyFolders = @(Remove-OisEmptyFoldersFromXml -Xml $xml)
    $script:LastSanitizeRemovedItems += $script:LastSanitizeRemovedEmptyFolders
  }

  return $xml
}

function New-OisHandoffPackage {
  param(
    [Parameter(Mandatory)][string]$ExportPath,
    [string]$LogPath     = $null,
    [string]$Environment = "BASELINE"
  )
  if (-not (Test-Path -LiteralPath $ExportPath)) {
    throw "Export file not found: $ExportPath"
  }

  $dir      = Split-Path $ExportPath -Parent
  $baseName = [System.IO.Path]::GetFileNameWithoutExtension($ExportPath)
  $stamp    = Get-Date -Format 'yyyyMMdd_HHmm'
  $zipPath  = Join-Path $dir "${Environment}_${baseName}_${stamp}.zip"

  $zip = $null
  try {
    $zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
      $zip, $ExportPath, [System.IO.Path]::GetFileName($ExportPath))
    if ($LogPath -and (Test-Path -LiteralPath $LogPath)) {
      [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
        $zip, $LogPath, [System.IO.Path]::GetFileName($LogPath))
    }
  } finally {
    if ($zip) { $zip.Dispose() }
  }
  return $zipPath
}


function Compare-OisExports {
  param(
    [Parameter(Mandatory)][string]$BasePath,
    [Parameter(Mandatory)][string]$ModifiedPath
  )

  [xml]$base = Get-OisXmlDocument -Path $BasePath
  [xml]$mod  = Get-OisXmlDocument -Path $ModifiedPath

  # Build lookup tables keyed by UniqueID
  function Get-NodeMap {
    param([xml]$Doc, [string]$XPath, [string]$TypeLabel)
    $map = @{}
    foreach ($node in @($Doc.SelectNodes($XPath))) {
      $id   = Get-NodeId -Node $node
      $name = Get-NodeDisplayName -Node $node
      if ($id) {
        $map[$id] = [pscustomobject]@{
          Id       = $id
          Name     = $name
          Type     = $TypeLabel
          OuterXml = $node.OuterXml
          Node     = $node
        }
      }
    }
    return $map
  }

  $xpaths = @{
    'policy'    = "//*[local-name()='Policy']"
    'folder'    = "//*[local-name()='Folder']"
    'variable'  = "//*[local-name()='GlobalVariable']"
    'config'    = "//*[local-name()='GlobalConfiguration']"
    'schedule'  = "//*[local-name()='Schedule']"
    'counter'   = "//*[local-name()='Counter']"
    'group'     = "//*[local-name()='ComputerGroup']"
    'object'    = "//*[local-name()='Object']"
  }

  $added    = @()
  $removed  = @()
  $modified = @()

  foreach ($type in $xpaths.Keys) {
    $baseMap = Get-NodeMap -Doc $base -XPath $xpaths[$type] -TypeLabel $type
    $modMap  = Get-NodeMap -Doc $mod  -XPath $xpaths[$type] -TypeLabel $type

    # Added in modified
    foreach ($id in $modMap.Keys) {
      if (-not $baseMap.ContainsKey($id)) {
        $added += [pscustomobject]@{
          Id   = $id
          Name = $modMap[$id].Name
          Type = $type
        }
      }
    }

    # Removed from base
    foreach ($id in $baseMap.Keys) {
      if (-not $modMap.ContainsKey($id)) {
        $removed += [pscustomobject]@{
          Id   = $id
          Name = $baseMap[$id].Name
          Type = $type
        }
      }
    }

    # Modified — same ID, different XML
    foreach ($id in $baseMap.Keys) {
      if (-not $modMap.ContainsKey($id)) { continue }

      $baseXml = $baseMap[$id].OuterXml
      $modXml  = $modMap[$id].OuterXml

      if ($baseXml -ne $modXml) {
        # Find which child elements changed
        $changes = @()
        $baseNode = $baseMap[$id].Node
        $modNode  = $modMap[$id].Node

        foreach ($child in @($modNode.ChildNodes)) {
          if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
          $hasElementChildren = @($child.ChildNodes | Where-Object {
            $_.NodeType -eq [System.Xml.XmlNodeType]::Element
          }).Count -gt 0
          if ($hasElementChildren) { continue }

          $baseChild = $baseNode.SelectSingleNode("./*[local-name()='$($child.LocalName)']")
$baseVal = if ($baseChild) { $baseChild.InnerText.Trim() } else { '' }
          $modVal  = $child.InnerText.Trim()

          # Skip if both are effectively empty — empty element vs missing element
          if ([string]::IsNullOrWhiteSpace($baseVal) -and [string]::IsNullOrWhiteSpace($modVal)) { continue }

          if ($baseVal -ne $modVal) {
$changes += [pscustomobject]@{
              Property = $child.LocalName
              OldValue = if ($baseChild) { $baseVal } else { '(not present)' }
              NewValue = $modVal
            }
          }
        }

        if ($changes.Count -gt 0) {
          $modified += [pscustomobject]@{
            Id      = $id
            Name    = $baseMap[$id].Name
            Type    = $type
            Changes = $changes
          }
        }
      }
    }
  }

  return [pscustomobject]@{
    Added    = $added
    Removed  = $removed
    Modified = $modified
    BasePath = $BasePath
    ModPath  = $ModifiedPath
  }
}

function Format-OisDiffReport {
  param(
    [Parameter(Mandatory)][object]$Diff,
    [switch]$UseColor
  )

  $totalChanges = $Diff.Added.Count + $Diff.Removed.Count + $Diff.Modified.Count

  if ($totalChanges -eq 0) {
    if ($UseColor) {
      Write-Host "No differences found — exports are identical." -ForegroundColor Green
    } else {
      Write-Output "No differences found — exports are identical."
    }
    return
  }

  Write-Host ""
  if ($Diff.Added.Count -gt 0) {
    if ($UseColor) { Write-Host "ADDED ($($Diff.Added.Count))" -ForegroundColor Green }
    else           { Write-Output "ADDED ($($Diff.Added.Count))" }
    $Diff.Added | Format-Table Type, Name, Id -AutoSize
  }

  if ($Diff.Removed.Count -gt 0) {
    if ($UseColor) { Write-Host "REMOVED ($($Diff.Removed.Count))" -ForegroundColor Red }
    else           { Write-Output "REMOVED ($($Diff.Removed.Count))" }
    $Diff.Removed | Format-Table Type, Name, Id -AutoSize
  }

  if ($Diff.Modified.Count -gt 0) {
    if ($UseColor) { Write-Host "MODIFIED ($($Diff.Modified.Count))" -ForegroundColor Yellow }
    else           { Write-Output "MODIFIED ($($Diff.Modified.Count))" }
    foreach ($item in $Diff.Modified) {
      Write-Host "  [$($item.Type)] $($item.Name)" -ForegroundColor Yellow
      foreach ($change in $item.Changes) {
        Write-Host "    $($change.Property):" -NoNewline
        Write-Host "  $($change.OldValue)" -ForegroundColor Red -NoNewline
        Write-Host "  →  " -NoNewline
        Write-Host "$($change.NewValue)" -ForegroundColor Green
      }
    }
  }

  Write-Host ""
  Write-Host "Summary: $($Diff.Added.Count) added  $($Diff.Removed.Count) removed  $($Diff.Modified.Count) modified" -ForegroundColor Cyan
}


function Invoke-BulkRename {
  param(
    [Parameter(Mandatory)][xml]$Xml,
    [Parameter(Mandatory)][string]$CsvPath,
    [switch]$WhatIf
  )

  $pairs = Import-Csv -LiteralPath $CsvPath

  # Validate CSV has required columns
  if (-not ($pairs | Get-Member -Name 'OldName' -ErrorAction SilentlyContinue) -or
      -not ($pairs | Get-Member -Name 'NewName' -ErrorAction SilentlyContinue)) {
    throw "CSV must have columns: OldName, NewName"
  }

  $results = @()

  foreach ($pair in $pairs) {
    $oldName = $pair.OldName.Trim()
    $newName = $pair.NewName.Trim()

    if ([string]::IsNullOrWhiteSpace($oldName) -or [string]::IsNullOrWhiteSpace($newName)) {
      continue
    }

    # Find all nodes whose Name child matches OldName
    $found = @($Xml.SelectNodes("//*[*[local-name()='Name' and normalize-space(.)='$($oldName.Replace("'","''"))']]"))

    if ($found.Count -eq 0) {
      $results += [pscustomobject]@{
        OldName = $oldName
        NewName = $newName
        Type    = ''
        Id      = ''
        Status  = 'NotFound'
      }
      continue
    }

    foreach ($node in $found) {
      $nameChild = $node.SelectSingleNode("*[local-name()='Name']")
      $type      = $node.LocalName
      $id        = Get-NodeId -Node $node

      if (-not $WhatIf -and $nameChild) {
        $nameChild.InnerText = $newName
      }

      $results += [pscustomobject]@{
        OldName = $oldName
        NewName = $newName
        Type    = $type
        Id      = $id
        Status  = 'Renamed'
      }
    }
  }

  return $results
}


function New-OisExportReport {
  param(
    [Parameter(Mandatory)][string]$Path,
    [string]$OutputPath
  )

  [xml]$doc = Get-OisXmlDocument -Path $Path

  $lines = [System.Collections.Generic.List[string]]::new()
  $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

  $lines.Add("OIS Export Report")
  $lines.Add("Generated : $stamp")
  $lines.Add("Source    : $Path")
  $lines.Add("Tool      : OIS Export Analyzer v$script:AppVersion")
  $lines.Add("")
  $lines.Add("=" * 70)
  $lines.Add("HEALTH WARNINGS")
  $lines.Add("=" * 70)
  $warnings = @(Get-OisExportHealthWarnings -Doc $doc)
  if ($warnings.Count -eq 0) {
    $lines.Add("  None")
  } else {
    foreach ($w in $warnings) { $lines.Add("  $w") }
  }

  $lines.Add("")
  $lines.Add("=" * 70)
  $lines.Add("SUMMARY METRICS")
  $lines.Add("=" * 70)

  $folders   = @($doc.SelectNodes("//*[local-name()='Folder']")).Count
  $policies  = @($doc.SelectNodes("//*[local-name()='Policy']")).Count
  $objects   = @($doc.SelectNodes("//*[local-name()='Object']")).Count
  $variables = @($doc.SelectNodes("//*[local-name()='GlobalVariable']")).Count
  $configs   = @($doc.SelectNodes("//*[local-name()='GlobalConfiguration']")).Count
  $schedules = @($doc.SelectNodes("//*[local-name()='Schedule']")).Count
  $counters  = @($doc.SelectNodes("//*[local-name()='Counter']")).Count
  $groups    = @($doc.SelectNodes("//*[local-name()='ComputerGroup']")).Count

  $lines.Add("  Folders              : $folders")
  $lines.Add("  Policies (Runbooks)  : $policies")
  $lines.Add("  Objects (Activities) : $objects")
  $lines.Add("  Global Variables     : $variables")
  $lines.Add("  Global Configurations: $configs")
  $lines.Add("  Schedules            : $schedules")
  $lines.Add("  Counters             : $counters")
  $lines.Add("  Computer Groups      : $groups")

  $lines.Add("")
  $lines.Add("=" * 70)
  $lines.Add("FOLDER TREE & POLICIES")
  $lines.Add("=" * 70)

  function Write-FolderTree {
    param([System.Xml.XmlNode]$Node, [int]$Depth = 0)
    $indent = "  " * $Depth
    $folderName = Get-InnerTextLocal $Node 'Name'
    $lines.Add("$indent[FOLDER] $folderName")

    foreach ($policy in @($Node.SelectNodes("./*[local-name()='Policy']"))) {
      $pName = Get-InnerTextLocal $policy 'Name'
      $pId   = Get-InnerTextLocal $policy 'UniqueID'
      $objCount = @($policy.SelectNodes(".//*[local-name()='Object']")).Count
      $lines.Add("$indent  [POLICY] $pName  ($objCount objects)  $pId")
    }

    foreach ($child in @($Node.SelectNodes("./*[local-name()='Folder']"))) {
      Write-FolderTree -Node $child -Depth ($Depth + 1)
    }
  }

  $rootFolders = @($doc.SelectNodes("/*[local-name()='ExportData']/*[local-name()='Policies']/*[local-name()='Folder']"))
  foreach ($f in $rootFolders) { Write-FolderTree -Node $f }

  $lines.Add("")
  $lines.Add("=" * 70)
  $lines.Add("GLOBAL VARIABLES")
  $lines.Add("=" * 70)
  $globalVars = @($doc.SelectNodes("//*[local-name()='GlobalVariable']"))
  if ($globalVars.Count -eq 0) {
    $lines.Add("  None included in this export.")
  } else {
    foreach ($v in $globalVars) {
      $vName = Get-InnerTextLocal $v 'Name'
      $vId   = Get-InnerTextLocal $v 'UniqueID'
      $lines.Add("  $vName  ($vId)")
    }
  }

  $lines.Add("")
  $lines.Add("=" * 70)
  $lines.Add("GLOBAL CONFIGURATIONS")
  $lines.Add("=" * 70)
  $globalCfgs = @($doc.SelectNodes("//*[local-name()='GlobalConfiguration']"))
  if ($globalCfgs.Count -eq 0) {
    $lines.Add("  None included in this export.")
  } else {
    foreach ($c in $globalCfgs) {
      $cName = Get-InnerTextLocal $c 'Name'
      $cId   = Get-InnerTextLocal $c 'UniqueID'
      $lines.Add("  $cName  ($cId)")
    }
  }

  $lines.Add("")
  $lines.Add("=" * 70)
  $lines.Add("DUPLICATE POLICY NAMES")
  $lines.Add("=" * 70)
  $dupes = Find-DuplicatePolicies -Doc $doc
  if ($dupes.Count -eq 0) {
    $lines.Add("  None detected.")
  } else {
    foreach ($d in $dupes) {
      $lines.Add("  '$($d.Name)' found in $($d.Count) locations:")
      foreach ($loc in $d.Locations) {
        $lines.Add("    - $loc")
      }
    }
  }

  $lines.Add("")
  $lines.Add("=" * 70)
  $lines.Add("END OF REPORT")
  $lines.Add("=" * 70)

  if ($OutputPath) {
    Set-Content -LiteralPath $OutputPath -Value $lines -Encoding UTF8
  }

  return $lines
}


function Find-DuplicatePolicies {
  param([Parameter(Mandatory)][xml]$Doc)

  $nameMap  = @{}
  $policies = @($Doc.SelectNodes("//*[local-name()='Policy']"))

  foreach ($policy in $policies) {
    $name = Get-InnerTextLocal $policy 'Name'
    if ([string]::IsNullOrWhiteSpace($name)) { continue }

    # Build folder path — no inline if
    $pathParts = @()
    $ancestor  = $policy.ParentNode
    while ($ancestor -and $ancestor.LocalName -eq 'Folder') {
      $folderNameNode = $ancestor.SelectSingleNode("*[local-name()='Name']")
      $folderLabel    = if ($folderNameNode) { $folderNameNode.InnerText.Trim() } else { "(unnamed)" }
      $pathParts      = ,$folderLabel + $pathParts
      $ancestor       = $ancestor.ParentNode
    }
    $folderPath = if ($pathParts.Count -gt 0) { $pathParts -join '\' } else { '\' }
    $fullPath   = "$folderPath\$name"

    if (-not $nameMap.ContainsKey($name)) { $nameMap[$name] = @() }
    $nameMap[$name] += $fullPath
  }

  $dupes = @()
  foreach ($name in $nameMap.Keys) {
    if ($nameMap[$name].Count -gt 1) {
      $dupes += [pscustomobject]@{
        Name      = $name
        Count     = $nameMap[$name].Count
        Locations = $nameMap[$name]
      }
    }
  }

  return $dupes
}


function Save-SourcegraphConfig {
  param(
    [Parameter(Mandatory)][string]$Url,
    [Parameter(Mandatory)][string]$Token
  )
  try {
    if (-not (Test-Path -LiteralPath $script:RecentFilesDir)) {
      [void](New-Item -ItemType Directory -Path $script:RecentFilesDir -Force)
    }

    # Encrypt token with DPAPI — only current user on this machine can decrypt
    $encryptedToken = $Token |
      ConvertTo-SecureString -AsPlainText -Force |
      ConvertFrom-SecureString

    @{ Url = $Url.TrimEnd('/'); Token = $encryptedToken } |
      ConvertTo-Json |
      Set-Content -LiteralPath $script:SourcegraphConfigPath -Encoding UTF8

    # Restrict file to current user only
    try {
      $acl  = Get-Acl -LiteralPath $script:SourcegraphConfigPath
      $acl.SetAccessRuleProtection($true, $false)
      $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
        'FullControl', 'Allow')
      $acl.SetAccessRule($rule)
      Set-Acl -LiteralPath $script:SourcegraphConfigPath -AclObject $acl
    } catch {}

    # Keep decrypted version in memory for this session
    $script:SourcegraphConfig = [pscustomobject]@{
      Url   = $Url.TrimEnd('/')
      Token = $Token
    }
  } catch {
    throw "Failed to save Sourcegraph config: $_"
  }
}

function Load-SourcegraphConfig {
  $script:SourcegraphConfig = $null
  if (-not (Test-Path -LiteralPath $script:SourcegraphConfigPath)) { return }
  try {
    $raw = Get-Content -LiteralPath $script:SourcegraphConfigPath -Raw |
      ConvertFrom-Json

    if (-not $raw.Url -or -not $raw.Token) { return }

    # Decrypt token with DPAPI
    $decryptedToken = $raw.Token |
      ConvertTo-SecureString |
      ForEach-Object {
        [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
          [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($_))
      }

    # One-time ACL migration for files saved before permission hardening
    try {
      $acl = Get-Acl -LiteralPath $script:SourcegraphConfigPath
      if ($acl.AreAccessRulesProtected -eq $false) {
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
          [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
          'FullControl', 'Allow')
        $acl.SetAccessRule($rule)
        Set-Acl -LiteralPath $script:SourcegraphConfigPath -AclObject $acl
      }
    } catch {}

    $script:SourcegraphConfig = [pscustomobject]@{
      Url   = $raw.Url
      Token = $decryptedToken
    }
  } catch {
    # Config may have been saved on a different machine or user — silently discard
    $script:SourcegraphConfig = $null
  }
}

function Get-SourcegraphConfig {
  if ($script:SourcegraphConfig) { return $script:SourcegraphConfig }
  Load-SourcegraphConfig
  return $script:SourcegraphConfig
}


function Invoke-SourcegraphSearch {
  param(
    [Parameter(Mandatory)][string]$Query,
    [string]$Url,
    [string]$Token,
    [int]$MaxResults = 100
  )

  if (-not $Url -or -not $Token) {
    $cfg = Get-SourcegraphConfig
    if (-not $cfg) { throw "No Sourcegraph config found. Configure via Tools > Sourcegraph Settings." }
    if (-not $Url)   { $Url   = $cfg.Url }
    if (-not $Token) { $Token = $cfg.Token }
  }

$gql = @{
  query     = 'query Search($query: String!) { search(query: $query, version: V3) { results { matchCount approximateResultCount results { __typename ... on FileMatch { repository { name } file { path url } lineMatches { preview lineNumber } chunkMatches { content contentStart { line } } } } } } }'
  variables = @{ query = $Query }
} | ConvertTo-Json -Depth 5

  try {
    $response = Invoke-RestMethod `
      -Uri         "$($Url.TrimEnd('/'))/.api/graphql" `
      -Method      POST `
      -Headers     @{ Authorization = "token $Token"; 'Content-Type' = 'application/json' } `
      -Body        $gql `
      -ErrorAction Stop

    $results = @()
    foreach ($match in @($response.data.search.results.results)) {

      # Skip non-file results (Repository matches, CommitSearchResults, etc.)
      if ($match.__typename -ne 'FileMatch') { continue }

      # Validate required properties exist
      if (-not $match.PSObject.Properties['repository'] -or
          -not $match.PSObject.Properties['file']) { continue }

      $repo     = $match.repository.name
      $filePath = $match.file.path
      $fileUrl  = $match.file.url

      # Try lineMatches first (older Sourcegraph), fall back to chunkMatches
      $hasLineMatches  = $match.PSObject.Properties['lineMatches']  -and $match.lineMatches  -and $match.lineMatches.Count  -gt 0
      $hasChunkMatches = $match.PSObject.Properties['chunkMatches'] -and $match.chunkMatches -and $match.chunkMatches.Count -gt 0

      if ($hasLineMatches) {
        foreach ($line in @($match.lineMatches)) {
          $results += [pscustomobject]@{
            Repository = $repo
            FilePath   = $filePath
            FileUrl    = $fileUrl
            LineNumber = $line.lineNumber + 1
            Preview    = $line.preview.Trim()
            SearchType = ''
          }
        }
      } elseif ($hasChunkMatches) {
        foreach ($chunk in @($match.chunkMatches)) {
          $lineNum = if ($chunk.PSObject.Properties['contentStart'] -and $chunk.contentStart) {
            $chunk.contentStart.line + 1
          } else { 0 }
          $preview = if ($chunk.PSObject.Properties['content'] -and $chunk.content) {
            ($chunk.content -split "`n")[0].Trim()
          } else { '' }
          $results += [pscustomobject]@{
            Repository = $repo
            FilePath   = $filePath
            FileUrl    = $fileUrl
            LineNumber = $lineNum
            Preview    = $preview
            SearchType = ''
          }
        }
      } else {
        $results += [pscustomobject]@{
          Repository = $repo
          FilePath   = $filePath
          FileUrl    = $fileUrl
          LineNumber = 0
          Preview    = '(file match — no line detail)'
          SearchType = ''
        }
      }
    }

    return [pscustomobject]@{
      Results     = $results
      MatchCount  = $response.data.search.results.matchCount
      Approximate = $response.data.search.results.approximateResultCount
      Query       = $Query
    }
  } catch {
    throw "Sourcegraph search failed: $($_.Exception.Message)"
  }
}


function Search-SourcegraphForPolicy {
  param(
    [string]$PolicyName,
    [string]$UniqueId,
    [string]$Url,
    [string]$Token,
    [int]$MaxResults = 50
  )

  $queries = @()

  if ($PolicyName) {
    $safeName = $PolicyName.Replace('"','\"')
    $queries += [pscustomobject]@{
      Label = "Policy name: $PolicyName"
      Query = "`"$safeName`" count:$MaxResults"
    }
  }

  if ($UniqueId) {
    $safeId = $UniqueId.Trim('{}')
    $queries += [pscustomobject]@{
      Label = "Unique ID: $UniqueId"
      Query = "$safeId count:$MaxResults"
    }
  }

  $allResults = @()
  foreach ($q in $queries) {
    try {
      $r = Invoke-SourcegraphSearch -Query $q.Query -Url $Url -Token $Token -MaxResults $MaxResults
      foreach ($result in $r.Results) {
        $result | Add-Member -NotePropertyName 'SearchType' -NotePropertyValue $q.Label -Force
        $allResults += $result
      }
    } catch {
      Write-Warning "Search failed for '$($q.Label)': $_"
    }
  }

  # Deduplicate by file+line
  $seen    = @{}
  $deduped = @()
  foreach ($r in $allResults) {
    $key = "$($r.Repository)|$($r.FilePath)|$($r.LineNumber)"
    if (-not $seen.ContainsKey($key)) {
      $seen[$key] = $true
      $deduped   += $r
    }
  }

  return $deduped
}

#endregion Cleanup Helpers

#region Dialog Helpers

function Show-SanitizeOptionsDialog {
  param([System.Windows.Window]$Owner)
  if (-not $script:SanitizeXaml) {
    throw "Sanitize dialog XAML was not defined."
  }
  $sr  = New-Object System.IO.StringReader (($script:SanitizeXaml -replace "^\uFEFF","").TrimStart())
  $xr  = [System.Xml.XmlReader]::Create($sr)
  $dlg = [Windows.Markup.XamlReader]::Load($xr)
  $dlg.Owner = $Owner

  $rbStrict       = $dlg.FindName("rbStrict")
  $rbCustom       = $dlg.FindName("rbCustom")
  $cbVars         = $dlg.FindName("cbVars")
  $cbConfigs      = $dlg.FindName("cbConfigs")
  $cbSchedules    = $dlg.FindName("cbSchedules")
  $cbCounters     = $dlg.FindName("cbCounters")
  $cbGroups       = $dlg.FindName("cbGroups")
  $cbEmptyFolders = $dlg.FindName("cbEmptyFolders")
  $btnOk          = $dlg.FindName("btnOk")
  $btnCancel      = $dlg.FindName("btnCancel")

  $toggleCustom = {
    $enable = [bool]$rbCustom.IsChecked
    foreach ($b in @($cbVars,$cbConfigs,$cbSchedules,$cbCounters,$cbGroups,$cbEmptyFolders)) {
      if ($b) { $b.IsEnabled = $enable }
    }
  }
  $rbStrict.Add_Checked($toggleCustom)
  $rbCustom.Add_Checked($toggleCustom)
  & $toggleCustom

  $script:_SanitizeResult = $null

  $btnOk.Add_Click({
    $script:_SanitizeResult = @{
      Strict       = [bool]$rbStrict.IsChecked
      Variables    = [bool]$cbVars.IsChecked
      Configs      = [bool]$cbConfigs.IsChecked
      Schedules    = [bool]$cbSchedules.IsChecked
      Counters     = [bool]$cbCounters.IsChecked
      Groups       = [bool]$cbGroups.IsChecked
      EmptyFolders = [bool]$cbEmptyFolders.IsChecked
    }
    $dlg.DialogResult = $true
    $dlg.Close()
  })
  if ($btnCancel) {
    $btnCancel.Add_Click({ $dlg.DialogResult = $false; $dlg.Close() })
  }

  [void]$dlg.ShowDialog()
  return $script:_SanitizeResult
}

function Show-GlobalCleanupOptionsDialog {
  param([System.Windows.Window]$Owner)
  if (-not $script:GlobalCleanupXaml) { throw "Global cleanup dialog XAML was not defined." }

  $sr  = New-Object System.IO.StringReader (($script:GlobalCleanupXaml -replace "^\uFEFF","").TrimStart())
  $xr  = [System.Xml.XmlReader]::Create($sr)
  $dlg = [Windows.Markup.XamlReader]::Load($xr)
  $dlg.Owner = $Owner

  $cbGcVars      = $dlg.FindName("cbGcVars")
  $cbGcConfigs   = $dlg.FindName("cbGcConfigs")
  $cbGcSchedules = $dlg.FindName("cbGcSchedules")
  $cbGcCounters  = $dlg.FindName("cbGcCounters")
  $cbGcGroups    = $dlg.FindName("cbGcGroups")
  $btnGcAll      = $dlg.FindName("btnGcAll")
  $btnGcNone     = $dlg.FindName("btnGcNone")
  $btnGcOk       = $dlg.FindName("btnGcOk")
  $btnGcCancel   = $dlg.FindName("btnGcCancel")

  $setChecks = {
    param([bool]$Value)
    foreach ($cb in @($cbGcVars,$cbGcConfigs,$cbGcSchedules,$cbGcCounters,$cbGcGroups)) {
      if ($cb) { $cb.IsChecked = $Value }
    }
  }

  $script:_GlobalCleanupResult = $null

  $btnGcAll.Add_Click({  & $setChecks $true })
  $btnGcNone.Add_Click({ & $setChecks $false })

  $btnGcOk.Add_Click({
    $script:_GlobalCleanupResult = @{
      Variables = [bool]$cbGcVars.IsChecked
      Configs   = [bool]$cbGcConfigs.IsChecked
      Schedules = [bool]$cbGcSchedules.IsChecked
      Counters  = [bool]$cbGcCounters.IsChecked
      Groups    = [bool]$cbGcGroups.IsChecked
    }
    if (-not ($script:_GlobalCleanupResult.Values -contains $true)) {
      [void][System.Windows.MessageBox]::Show("Select at least one global type.", "Global Cleanup Options",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
      return
    }
    $dlg.DialogResult = $true
    $dlg.Close()
  })
  if ($btnGcCancel) {
    $btnGcCancel.Add_Click({ $dlg.DialogResult = $false; $dlg.Close() })
  }

  [void]$dlg.ShowDialog()
  return $script:_GlobalCleanupResult
}

function Show-TextInputDialog {
  param([string]$Title, [string]$Prompt, [string]$DefaultText = "")
  $safeTitle   = [System.Security.SecurityElement]::Escape($Title)
  $safePrompt  = [System.Security.SecurityElement]::Escape($Prompt)
  $safeDefault = [System.Security.SecurityElement]::Escape($DefaultText)
  $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$safeTitle"
        Height="190"
        Width="460"
        WindowStartupLocation="CenterOwner"
        ResizeMode="NoResize"
        Background="#111315"
        Foreground="#F5F7FA">
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="12"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="16"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <TextBlock Grid.Row="0" Text="$safePrompt" TextWrapping="Wrap" Foreground="White"/>
    <TextBox   x:Name="txtValue" Grid.Row="2" Height="32" Text="$safeDefault"/>
    <StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="btnOk"     Content="OK"     Width="90" Margin="0,0,8,0"/>
      <Button x:Name="btnCancel" Content="Cancel" Width="90"/>
    </StackPanel>
  </Grid>
</Window>
"@
  $sr  = New-Object System.IO.StringReader $xaml
  $xr  = [System.Xml.XmlReader]::Create($sr)
  $dlg = [Windows.Markup.XamlReader]::Load($xr)
  $dlg.Owner = $win

  $txtValue  = $dlg.FindName("txtValue")
  $btnOk     = $dlg.FindName("btnOk")
  $btnCancel = $dlg.FindName("btnCancel")

  $script:_TextInputResult = $null
  $btnOk.Add_Click({
    $script:_TextInputResult = $txtValue.Text
    $dlg.DialogResult = $true
    $dlg.Close()
  })
  $btnCancel.Add_Click({ $dlg.DialogResult = $false; $dlg.Close() })

  [void]$dlg.ShowDialog()
  return $script:_TextInputResult
}

function ConvertFrom-MarkdownToFlowDocument {
  param([Parameter(Mandatory)][string]$Markdown)

  $doc              = New-Object System.Windows.Documents.FlowDocument
  $doc.FontFamily   = New-Object System.Windows.Media.FontFamily("Segoe UI")
  $doc.FontSize     = 13
  $doc.Foreground   = [System.Windows.Media.Brushes]::White
  $doc.Background   = [System.Windows.Media.SolidColorBrush][System.Windows.Media.Color]::FromRgb(0x11,0x13,0x15)
  $doc.LineHeight   = 22
  $doc.PagePadding  = [System.Windows.Thickness]::new(0)

  foreach ($line in $Markdown -split "`n") {
    $line = $line.TrimEnd()

    # H2
    if ($line -match '^## (.+)') {
      $p            = New-Object System.Windows.Documents.Paragraph
      $p.Margin     = [System.Windows.Thickness]::new(0,16,0,6)
      $r            = New-Object System.Windows.Documents.Run($Matches[1])
      $r.FontSize   = 20
      $r.FontWeight = [System.Windows.FontWeights]::SemiBold
      $r.Foreground = [System.Windows.Media.SolidColorBrush][System.Windows.Media.Color]::FromRgb(0x60,0xBD,0xFF)
      $p.Inlines.Add($r)
      $doc.Blocks.Add($p)
      continue
    }

    # H3
    if ($line -match '^### (.+)') {
      $p            = New-Object System.Windows.Documents.Paragraph
      $p.Margin     = [System.Windows.Thickness]::new(0,12,0,4)
      $r            = New-Object System.Windows.Documents.Run($Matches[1])
      $r.FontSize   = 15
      $r.FontWeight = [System.Windows.FontWeights]::SemiBold
      $r.Foreground = [System.Windows.Media.SolidColorBrush][System.Windows.Media.Color]::FromRgb(0xF5,0xF7,0xFA)
      $p.Inlines.Add($r)
      $doc.Blocks.Add($p)
      continue
    }

    # HR
    if ($line -match '^---') {
      $p            = New-Object System.Windows.Documents.Paragraph
      $p.Margin     = [System.Windows.Thickness]::new(0,8,0,8)
      $p.BorderBrush = [System.Windows.Media.SolidColorBrush][System.Windows.Media.Color]::FromRgb(0x2B,0x2F,0x36)
      $p.BorderThickness = [System.Windows.Thickness]::new(0,0,0,1)
      $doc.Blocks.Add($p)
      continue
    }

    # Bullet
    if ($line -match '^\s*[-\*] (.+)') {
      $p            = New-Object System.Windows.Documents.Paragraph
      $p.Margin     = [System.Windows.Thickness]::new(16,2,0,2)
      $content      = $Matches[1]
      $p.Inlines.Add((New-Object System.Windows.Documents.Run("• ")))
      Add-InlineRuns -Paragraph $p -Text $content
      $doc.Blocks.Add($p)
      continue
    }

    # Table row (simple | col | col |)
    if ($line -match '^\s*\|(.+)\|') {
      $cells = $line -split '\|' | Where-Object { $_ -ne '' } | ForEach-Object { $_.Trim() }
      $p     = New-Object System.Windows.Documents.Paragraph
      $p.Margin = [System.Windows.Thickness]::new(0,2,0,2)
      if ($cells.Count -ge 2) {
        $r1            = New-Object System.Windows.Documents.Run("$($cells[0])")
        $r1.FontWeight = [System.Windows.FontWeights]::SemiBold
        $r1.Foreground = [System.Windows.Media.SolidColorBrush][System.Windows.Media.Color]::FromRgb(0x60,0xBD,0xFF)
        $r2            = New-Object System.Windows.Documents.Run("   $($cells[1])")
        $p.Inlines.Add($r1)
        $p.Inlines.Add($r2)
      }
      $doc.Blocks.Add($p)
      continue
    }

    # Indented code block
    if ($line -match '^    (.+)') {
      $p              = New-Object System.Windows.Documents.Paragraph
      $p.Margin       = [System.Windows.Thickness]::new(16,2,0,2)
      $r              = New-Object System.Windows.Documents.Run($Matches[1])
      $r.FontFamily   = New-Object System.Windows.Media.FontFamily("Consolas")
      $r.FontSize     = 12
      $r.Foreground   = [System.Windows.Media.SolidColorBrush][System.Windows.Media.Color]::FromRgb(0xA9,0xB1,0xBC)
      $p.Inlines.Add($r)
      $doc.Blocks.Add($p)
      continue
    }

    # Empty line
    if ([string]::IsNullOrWhiteSpace($line)) {
      $p        = New-Object System.Windows.Documents.Paragraph
      $p.Margin = [System.Windows.Thickness]::new(0,3,0,3)
      $doc.Blocks.Add($p)
      continue
    }

    # Normal paragraph with inline bold
    $p        = New-Object System.Windows.Documents.Paragraph
    $p.Margin = [System.Windows.Thickness]::new(0,2,0,2)
    Add-InlineRuns -Paragraph $p -Text $line
    $doc.Blocks.Add($p)
  }

  return $doc
}

function Add-InlineRuns {
  param(
    [Parameter(Mandatory)][System.Windows.Documents.Paragraph]$Paragraph,
    [Parameter(Mandatory)][string]$Text
  )
  $parts = $Text -split '(\*\*[^*]+\*\*)'
  foreach ($part in $parts) {
    if ($part -match '^\*\*(.+)\*\*$') {
      $r            = New-Object System.Windows.Documents.Run($Matches[1])
      $r.FontWeight = [System.Windows.FontWeights]::SemiBold
      $r.Foreground = [System.Windows.Media.SolidColorBrush][System.Windows.Media.Color]::FromRgb(0xF5,0xF7,0xFA)
      $Paragraph.Inlines.Add($r)
    } else {
      $r            = New-Object System.Windows.Documents.Run($part)
      $r.Foreground = [System.Windows.Media.SolidColorBrush][System.Windows.Media.Color]::FromRgb(0xA9,0xB1,0xBC)
      $Paragraph.Inlines.Add($r)
    }
  }
}

function Show-UserGuide {
  param([System.Windows.Window]$Owner)

  $sr  = New-Object System.IO.StringReader (($script:HelpGuideXaml -replace "^\uFEFF","").TrimStart())
  $xr  = [System.Xml.XmlReader]::Create($sr)
  $dlg = [Windows.Markup.XamlReader]::Load($xr)
  if ($Owner) { $dlg.Owner = $Owner }

  $lstSections  = $dlg.FindName("lstSections")
  $cmbSections  = $dlg.FindName("cmbSections")
  $flowViewer   = $dlg.FindName("flowViewer")
  $txtFind      = $dlg.FindName("txtFind")
  $btnFindPrev  = $dlg.FindName("btnFindPrev")
  $btnFindNext  = $dlg.FindName("btnFindNext")
  $btnCopySection = $dlg.FindName("btnCopySection")

  $sectionNames = @($script:HelpSections.Keys)
  $script:_GuideCurrentSection = 0

  function Load-Section {
    param([int]$Index)
    if ($Index -lt 0 -or $Index -ge $sectionNames.Count) { return }
    $script:_GuideCurrentSection = $Index
    $name    = $sectionNames[$Index]
    $content = $script:HelpSections[$name]
    $doc     = ConvertFrom-MarkdownToFlowDocument -Markdown $content
    $flowViewer.Document = $doc
    $lstSections.SelectedIndex  = $Index
    $cmbSections.SelectedIndex  = $Index
  }

  # Populate section list and combo
  foreach ($name in $sectionNames) {
    [void]$lstSections.Items.Add($name)
    [void]$cmbSections.Items.Add($name)
  }

  Load-Section 0

  $lstSections.Add_SelectionChanged({
    $i = $lstSections.SelectedIndex
    if ($i -ge 0 -and $i -ne $script:_GuideCurrentSection) {
      Load-Section $i
    }
  })

  $cmbSections.Add_SelectionChanged({
    $i = $cmbSections.SelectedIndex
    if ($i -ge 0 -and $i -ne $script:_GuideCurrentSection) {
      Load-Section $i
    }
  })

  $btnFindPrev.Add_Click({
    $i = $script:_GuideCurrentSection - 1
    if ($i -lt 0) { $i = $sectionNames.Count - 1 }
    Load-Section $i
  })

  $btnFindNext.Add_Click({
    $i = $script:_GuideCurrentSection + 1
    if ($i -ge $sectionNames.Count) { $i = 0 }
    Load-Section $i
  })

  $txtFind.Add_KeyDown({
    param($sender, $e)
    if ($e.Key -eq [System.Windows.Input.Key]::Return) {
      $q = $txtFind.Text.Trim().ToLowerInvariant()
      if (-not $q) { return }
      # Search forward from current section
      $start = $script:_GuideCurrentSection + 1
      for ($offset = 0; $offset -lt $sectionNames.Count; $offset++) {
        $idx  = ($start + $offset) % $sectionNames.Count
        $name = $sectionNames[$idx]
        if ($name.ToLowerInvariant().Contains($q) -or
            $script:HelpSections[$name].ToLowerInvariant().Contains($q)) {
          Load-Section $idx
          return
        }
      }
    }
  })

  $btnCopySection.Add_Click({
    $name    = $sectionNames[$script:_GuideCurrentSection]
    $content = $script:HelpSections[$name]
    [System.Windows.Clipboard]::SetText($content)
  })

  [void]$dlg.ShowDialog()
}


function Show-DiffResultDialog {
  param(
    [Parameter(Mandatory)][object]$Diff,
    [System.Windows.Window]$Owner
  )

$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Export Diff Results"
        Height="620" Width="900"
        MinHeight="400" MinWidth="600"
        WindowStartupLocation="CenterOwner"
        Background="#111315" Foreground="#F5F7FA">

  <Window.Resources>
    <Style x:Key="DiffHeaderStyle" TargetType="DataGridColumnHeader">
      <Setter Property="Background"      Value="#1E2228"/>
      <Setter Property="Foreground"      Value="#F5F7FA"/>
      <Setter Property="FontWeight"      Value="SemiBold"/>
      <Setter Property="Padding"         Value="8,6"/>
      <Setter Property="BorderBrush"     Value="#2B2F36"/>
      <Setter Property="BorderThickness" Value="0,0,0,1"/>
    </Style>
  </Window.Resources>

  <Grid Margin="12">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <StackPanel Grid.Row="0" Margin="0,0,0,10">
      <TextBlock x:Name="txtDiffSummary"
                 FontSize="14" FontWeight="SemiBold"
                 Foreground="#60BDFF"/>
      <TextBlock x:Name="txtDiffPaths"
                 FontSize="11" Foreground="#6B7280"
                 Margin="0,4,0,0" TextWrapping="Wrap"/>
    </StackPanel>

    <TabControl Grid.Row="1" Background="Transparent" BorderThickness="0">

      <TabItem Header="Added">
        <DataGrid x:Name="dgAdded"
                  ColumnHeaderStyle="{StaticResource DiffHeaderStyle}"
                  AutoGenerateColumns="False" IsReadOnly="True"
                  CanUserAddRows="False" CanUserDeleteRows="False"
                  Background="#121417" Foreground="#F5F7FA"
                  RowBackground="#15181C" AlternatingRowBackground="#111316"
                  GridLinesVisibility="Horizontal"
                  HorizontalGridLinesBrush="#2A2E35"
                  BorderBrush="#2B2F36" BorderThickness="1"
                  HeadersVisibility="Column" RowHeaderWidth="0">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Type"      Binding="{Binding Type}" Width="100"/>
            <DataGridTextColumn Header="Name"      Binding="{Binding Name}" Width="280"/>
            <DataGridTextColumn Header="Unique ID" Binding="{Binding Id}"   Width="*"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>

      <TabItem Header="Removed">
        <DataGrid x:Name="dgRemoved"
                  ColumnHeaderStyle="{StaticResource DiffHeaderStyle}"
                  AutoGenerateColumns="False" IsReadOnly="True"
                  CanUserAddRows="False" CanUserDeleteRows="False"
                  Background="#121417" Foreground="#F5F7FA"
                  RowBackground="#15181C" AlternatingRowBackground="#111316"
                  GridLinesVisibility="Horizontal"
                  HorizontalGridLinesBrush="#2A2E35"
                  BorderBrush="#2B2F36" BorderThickness="1"
                  HeadersVisibility="Column" RowHeaderWidth="0">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Type"      Binding="{Binding Type}" Width="100"/>
            <DataGridTextColumn Header="Name"      Binding="{Binding Name}" Width="280"/>
            <DataGridTextColumn Header="Unique ID" Binding="{Binding Id}"   Width="*"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>

<TabItem Header="Modified">
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="*"/>
      <RowDefinition Height="5"/>
      <RowDefinition Height="180"/>
      <RowDefinition Height="5"/>
      <RowDefinition Height="140"/>
    </Grid.RowDefinitions>

    <DataGrid x:Name="dgModified"
              Grid.Row="0"
              ColumnHeaderStyle="{StaticResource DiffHeaderStyle}"
              AutoGenerateColumns="False" IsReadOnly="True"
              CanUserAddRows="False" CanUserDeleteRows="False"
              Background="#121417" Foreground="#F5F7FA"
              RowBackground="#15181C" AlternatingRowBackground="#111316"
              GridLinesVisibility="Horizontal"
              HorizontalGridLinesBrush="#2A2E35"
              BorderBrush="#2B2F36" BorderThickness="1"
              HeadersVisibility="Column" RowHeaderWidth="0"
              SelectionMode="Single" SelectionUnit="FullRow">
      <DataGrid.Columns>
        <DataGridTextColumn Header="Type"      Binding="{Binding Type}"        Width="100"/>
        <DataGridTextColumn Header="Name"      Binding="{Binding Name}"        Width="280"/>
        <DataGridTextColumn Header="Changes"   Binding="{Binding ChangeCount}" Width="80"/>
        <DataGridTextColumn Header="Unique ID" Binding="{Binding Id}"          Width="*"/>
      </DataGrid.Columns>
    </DataGrid>

    <GridSplitter Grid.Row="1" Height="5"
                  HorizontalAlignment="Stretch"
                  Background="#2B2F36" Cursor="SizeNS"/>

    <!-- Changes grid — capped row height, truncated values -->
    <DataGrid x:Name="dgChanges"
              Grid.Row="2"
              ColumnHeaderStyle="{StaticResource DiffHeaderStyle}"
              AutoGenerateColumns="False" IsReadOnly="True"
              CanUserAddRows="False" CanUserDeleteRows="False"
              Background="#121417" Foreground="#F5F7FA"
              RowBackground="#15181C" AlternatingRowBackground="#111316"
              GridLinesVisibility="Horizontal"
              HorizontalGridLinesBrush="#2A2E35"
              BorderBrush="#2B2F36" BorderThickness="1"
              HeadersVisibility="Column" RowHeaderWidth="0"
              SelectionMode="Single" SelectionUnit="FullRow">
      <DataGrid.RowStyle>
        <Style TargetType="DataGridRow">
          <Setter Property="MaxHeight" Value="48"/>
        </Style>
      </DataGrid.RowStyle>
      <DataGrid.Columns>
        <DataGridTextColumn Header="Property"  Binding="{Binding Property}" Width="160">
          <DataGridTextColumn.ElementStyle>
            <Style TargetType="TextBlock">
              <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
              <Setter Property="VerticalAlignment" Value="Center"/>
            </Style>
          </DataGridTextColumn.ElementStyle>
        </DataGridTextColumn>
        <DataGridTextColumn Header="Old Value" Binding="{Binding OldValue}" Width="*">
          <DataGridTextColumn.ElementStyle>
            <Style TargetType="TextBlock">
              <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
              <Setter Property="TextWrapping" Value="NoWrap"/>
            </Style>
          </DataGridTextColumn.ElementStyle>
        </DataGridTextColumn>
        <DataGridTextColumn Header="New Value" Binding="{Binding NewValue}" Width="*">
          <DataGridTextColumn.ElementStyle>
            <Style TargetType="TextBlock">
              <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
              <Setter Property="TextWrapping" Value="NoWrap"/>
            </Style>
          </DataGridTextColumn.ElementStyle>
        </DataGridTextColumn>
      </DataGrid.Columns>
    </DataGrid>

    <GridSplitter Grid.Row="3" Height="5"
                  HorizontalAlignment="Stretch"
                  Background="#2B2F36" Cursor="SizeNS"/>

    <!-- Full value detail pane -->
    <Grid Grid.Row="4">
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="*"/>
      </Grid.RowDefinitions>
      <Grid Grid.Row="0" Margin="0,4,0,4">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <TextBlock x:Name="txtDiffOldLabel"
                   Grid.Column="0"
                   Text="Old Value:"
                   Foreground="#6B7280" FontSize="11"
                   Margin="0,0,4,0"/>
        <TextBlock x:Name="txtDiffNewLabel"
                   Grid.Column="1"
                   Text="New Value:"
                   Foreground="#6B7280" FontSize="11"
                   Margin="4,0,0,0"/>
      </Grid>
      <Grid Grid.Row="1">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="4"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <TextBox x:Name="txtDiffOldValue"
                 Grid.Column="0"
                 Background="#14161A" Foreground="#FF6B6B"
                 BorderBrush="#2F343B" BorderThickness="1"
                 FontFamily="Consolas" FontSize="11"
                 IsReadOnly="True" AcceptsReturn="True"
                 TextWrapping="Wrap"
                 VerticalScrollBarVisibility="Auto"
                 HorizontalScrollBarVisibility="Auto"
                 Padding="6,4"/>
        <GridSplitter Grid.Column="1" Width="4"
                      HorizontalAlignment="Stretch"
                      Background="#2B2F36" Cursor="SizeWE"/>
        <TextBox x:Name="txtDiffNewValue"
                 Grid.Column="2"
                 Background="#14161A" Foreground="#6BFF8A"
                 BorderBrush="#2F343B" BorderThickness="1"
                 FontFamily="Consolas" FontSize="11"
                 IsReadOnly="True" AcceptsReturn="True"
                 TextWrapping="Wrap"
                 VerticalScrollBarVisibility="Auto"
                 HorizontalScrollBarVisibility="Auto"
                 Padding="6,4"/>
      </Grid>
    </Grid>

  </Grid>
</TabItem>

    </TabControl>

    <StackPanel Grid.Row="2" Orientation="Horizontal"
                HorizontalAlignment="Right" Margin="0,10,0,0">
      <Button x:Name="btnDiffExport" Content="Export Report"
              Width="120" Margin="0,0,8,0"/>
      <Button x:Name="btnDiffClose" Content="Close" Width="90"/>
    </StackPanel>
  </Grid>
</Window>
'@

  $sr  = New-Object System.IO.StringReader $xaml
  $xr  = [System.Xml.XmlReader]::Create($sr)
  $dlg = [Windows.Markup.XamlReader]::Load($xr)
  if ($Owner) { $dlg.Owner = $Owner }

  $txtDiffSummary = $dlg.FindName("txtDiffSummary")
  $txtDiffPaths   = $dlg.FindName("txtDiffPaths")
  $dgAdded        = $dlg.FindName("dgAdded")
  $dgRemoved      = $dlg.FindName("dgRemoved")
  $dgModified     = $dlg.FindName("dgModified")
  $dgChanges      = $dlg.FindName("dgChanges")
  $btnDiffExport  = $dlg.FindName("btnDiffExport")
  $btnDiffClose   = $dlg.FindName("btnDiffClose")
  $txtDiffOldValue  = $dlg.FindName("txtDiffOldValue")
  $txtDiffNewValue  = $dlg.FindName("txtDiffNewValue")
  $txtDiffOldLabel  = $dlg.FindName("txtDiffOldLabel")
  $txtDiffNewLabel  = $dlg.FindName("txtDiffNewLabel")

  $totalChanges = $Diff.Added.Count + $Diff.Removed.Count + $Diff.Modified.Count

  $txtDiffSummary.Text = if ($totalChanges -eq 0) {
    "No differences found — exports are identical."
  } else {
    "Found $totalChanges change(s): $($Diff.Added.Count) added  $($Diff.Removed.Count) removed  $($Diff.Modified.Count) modified"
  }
  $txtDiffPaths.Text = "Base: $($Diff.BasePath)`nModified: $($Diff.ModPath)"

  $dgAdded.ItemsSource   = $Diff.Added
  $dgRemoved.ItemsSource = $Diff.Removed

  # Modified grid needs a ChangeCount property for display
  $modifiedRows = @($Diff.Modified | ForEach-Object {
    [pscustomobject]@{
      Id          = $_.Id
      Name        = $_.Name
      Type        = $_.Type
      ChangeCount = $_.Changes.Count
      Changes     = $_.Changes
    }
  })
  $dgModified.ItemsSource = $modifiedRows

  $dgModified.Add_SelectionChanged({
    $row = $dgModified.SelectedItem
    if ($row -and $row.Changes) {
      $dgChanges.ItemsSource = $row.Changes
    } else {
      $dgChanges.ItemsSource = $null
    }
  })



  $btnDiffExport.Add_Click({
    $sfd = New-Object Microsoft.Win32.SaveFileDialog
    $sfd.Filter   = "Text Report (*.txt)|*.txt|CSV (*.csv)|*.csv|All Files (*.*)|*.*"
    $sfd.FileName = "ExportDiff_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"
    $sfd.InitialDirectory = Split-Path $Diff.BasePath -Parent
    if (-not $sfd.ShowDialog()) { return }

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("OIS Export Diff Report")
    $lines.Add("Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $lines.Add("Base      : $($Diff.BasePath)")
    $lines.Add("Modified  : $($Diff.ModPath)")
    $lines.Add("")
    $lines.Add("ADDED ($($Diff.Added.Count))")
    foreach ($i in $Diff.Added) { $lines.Add("  [$($i.Type)] $($i.Name)  $($i.Id)") }
    $lines.Add("")
    $lines.Add("REMOVED ($($Diff.Removed.Count))")
    foreach ($i in $Diff.Removed) { $lines.Add("  [$($i.Type)] $($i.Name)  $($i.Id)") }
    $lines.Add("")
    $lines.Add("MODIFIED ($($Diff.Modified.Count))")
    foreach ($i in $Diff.Modified) {
      $lines.Add("  [$($i.Type)] $($i.Name)")
      foreach ($c in $i.Changes) {
        $lines.Add("    $($c.Property): '$($c.OldValue)'  ->  '$($c.NewValue)'")
      }
    }
    Set-Content -LiteralPath $sfd.FileName -Value $lines -Encoding UTF8
    Set-Status "Diff report saved: $($sfd.FileName)"
  })

  $btnDiffClose.Add_Click({ $dlg.Close() })

  [void]$dlg.ShowDialog()
}


$btnFindDuplicatePolicies.Add_Click({
  Invoke-UiAction -Context "Find Duplicate Policies" -Action {
    $p = Get-CurrentExportPath
    if (-not $p -or -not (Test-Path -LiteralPath $p)) {
      [void][System.Windows.MessageBox]::Show("Load an export first.", "Find Duplicate Policies")
      return
    }

    Show-Overlay "Scanning for duplicate policy names..."
    try {
      [xml]$doc = Get-OisXmlDocument -Path $p
      $dupes = @(Find-DuplicatePolicies -Doc $doc)
    } finally { Hide-Overlay }
    Invoke-TaskbarFlash

    if ($dupes.Count -eq 0) {
      Set-Status "No duplicate policy names found."
      [void][System.Windows.MessageBox]::Show(
        "No duplicate policy names detected.",
        "Find Duplicate Policies", [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information)
      return
    }

    # Flatten for the Objects grid
    $rows = @()
    foreach ($d in $dupes) {
      foreach ($loc in $d.Locations) {
        $rows += [pscustomobject]@{
          Name     = $d.Name
          Count    = $d.Count
          FullPath = $loc
        }
      }
    }

    Reset-ObjectGridColumns
    $dgObjects.Columns.Clear()
    $c1 = New-Object System.Windows.Controls.DataGridTextColumn
    $c1.Header  = "Policy Name"
    $c1.Binding = New-Object System.Windows.Data.Binding("Name")
    $c1.Width   = 260
    $c2 = New-Object System.Windows.Controls.DataGridTextColumn
    $c2.Header  = "Occurrences"
    $c2.Binding = New-Object System.Windows.Data.Binding("Count")
    $c2.Width   = 100
    $c3 = New-Object System.Windows.Controls.DataGridTextColumn
    $c3.Header  = "Full Path"
    $c3.Binding = New-Object System.Windows.Data.Binding("FullPath")
    $c3.Width   = 500
    foreach ($c in @($c1,$c2,$c3)) { [void]$dgObjects.Columns.Add($c) }

    $dgObjects.ItemsSource      = $rows
    $tabInspector.SelectedIndex = 1

    Set-Status "Found $($dupes.Count) duplicate policy name(s) across $($rows.Count) total occurrence(s)."
    [void][System.Windows.MessageBox]::Show(
      "Found $($dupes.Count) policy name(s) used in multiple folders.`n`n" +
      "Results listed on the Objects tab.",
      "Find Duplicate Policies", [System.Windows.MessageBoxButton]::OK,
      [System.Windows.MessageBoxImage]::Warning)
  }
})


$btnCopySummary.Add_Click({
  $folders   = if ($txtMetricFolders)  { $txtMetricFolders.Text  } else { "0" }
  $runbooks  = if ($txtMetricRunbooks) { $txtMetricRunbooks.Text } else { "0" }
  $objects   = if ($txtMetricObjects)  { $txtMetricObjects.Text  } else { "0" }
  $globals   = if ($txtMetricGlobals)  { $txtMetricGlobals.Text  } else { "0" }
  $file      = if ($txtPath)           { $txtPath.Text           } else { "" }
  $status    = if ($txtStatus)         { $txtStatus.Text         } else { "" }

$text  = "OIS Export Summary`n"
  $text += "File      : $file`n"
  $text += "Folders   : $folders`n"
  $text += "Runbooks  : $runbooks`n"
  $text += "Activities: $objects`n"
  $text += "Variables : $($txtMetricPolicies.Text)`n"
  $text += "Globals   : $globals`n"
  if ($status) { $text += "Status    : $status`n" }
  $text += "Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm')"

  [System.Windows.Clipboard]::SetText($text)
  Set-Status "Summary copied to clipboard."
})


function Show-SourcegraphDialog {
  param(
    [System.Windows.Window]$Owner,
    [string]$InitialQuery = ''
  )

  $sr  = New-Object System.IO.StringReader (($script:SourcegraphXaml -replace "^\uFEFF","").TrimStart())
  $xr  = [System.Xml.XmlReader]::Create($sr)
  $dlg = [Windows.Markup.XamlReader]::Load($xr)
  if ($Owner) { $dlg.Owner = $Owner }

  $txtSgQuery        = $dlg.FindName("txtSgQuery")
  $btnSgSearch       = $dlg.FindName("btnSgSearch")
  $btnSgSettings     = $dlg.FindName("btnSgSettings")
  $dgSgResults       = $dlg.FindName("dgSgResults")
  $txtSgPreview      = $dlg.FindName("txtSgPreview")
  $txtSgPreviewLabel = $dlg.FindName("txtSgPreviewLabel")
  $txtSgStatus       = $dlg.FindName("txtSgStatus")
  $btnSgOpenInBrowser = $dlg.FindName("btnSgOpenInBrowser")
  $btnSgClose        = $dlg.FindName("btnSgClose")

  if ($InitialQuery) { $txtSgQuery.Text = $InitialQuery }

$btnSgSearch.Add_Click({
    $q = $txtSgQuery.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($q)) { return }

    $cfg = Get-SourcegraphConfig
    if (-not $cfg) {
      [void][System.Windows.MessageBox]::Show(
        "Sourcegraph is not configured.`nClick Settings to enter your URL and API token.",
        "Not Configured", [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Warning)
      return
    }

    $txtSgStatus.Text             = "Searching..."
    $dgSgResults.ItemsSource      = $null
    $txtSgPreview.Text            = ''
    $btnSgOpenInBrowser.IsEnabled = $false

    try {
      $searchResult = Invoke-SourcegraphSearch -Query "$q count:50" -Url $cfg.Url -Token $cfg.Token
      $results      = @($searchResult.Results)
      $dgSgResults.ItemsSource = $results

      $txtSgStatus.Text = if ($results.Count -gt 0) {
        "Found $($results.Count) result(s) for: $q  —  click a row to see the full match"
      } else {
        "No results found for: $q"
      }
    } catch {
      $txtSgStatus.Text = "Error: $($_.Exception.Message)"
    }
  })

$dgSgResults.Add_SelectionChanged({
    $row = $dgSgResults.SelectedItem
    if ($row) {
      $txtSgPreview.Text      = [string]$row.Preview
      $txtSgPreviewLabel.Text = "Line $($row.LineNumber)  —  $($row.Repository)  /  $($row.FilePath)"
      $btnSgOpenInBrowser.IsEnabled = (-not [string]::IsNullOrWhiteSpace([string]$row.FileUrl))
    } else {
      $txtSgPreview.Text      = ''
      $txtSgPreviewLabel.Text = "Full match content — select a result above"
      $btnSgOpenInBrowser.IsEnabled = $false
    }
  })

  $btnSgOpenInBrowser.Add_Click({
    $row = $dgSgResults.SelectedItem
    if ($row -and $row.FileUrl) {
      $cfg = Get-SourcegraphConfig
      $url = "$($cfg.Url)$($row.FileUrl)?L$($row.LineNumber)"
      try { [System.Diagnostics.Process]::Start($url) } catch {}
    }
  })

  $btnSgSettings.Add_Click({
    Show-SourcegraphSettingsDialog -Owner $dlg
  })

  $txtSgQuery.Add_KeyDown({
    param($sender, $e)
    if ($e.Key -eq [System.Windows.Input.Key]::Return) {
      $btnSgSearch.RaiseEvent(
        (New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
    }
  })

  $btnSgClose.Add_Click({ $dlg.Close() })

  [void]$dlg.ShowDialog()
}

function Show-SourcegraphSettingsDialog {
  param([System.Windows.Window]$Owner)

$settingsXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Sourcegraph Settings"
        Height="240" Width="520"
        WindowStartupLocation="CenterOwner"
        ResizeMode="NoResize"
        Background="#111315" Foreground="#F5F7FA">
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="120"/>
      <ColumnDefinition Width="*"/>
    </Grid.ColumnDefinitions>

    <TextBlock Grid.Row="0" Grid.ColumnSpan="2"
               Text="Configure your Sourcegraph connection. The token is stored locally in AppData."
               Foreground="#6B7280" FontSize="11" TextWrapping="Wrap"
               Margin="0,0,0,14"/>

    <TextBlock Grid.Row="1" Grid.Column="0" Text="Instance URL:"
               VerticalAlignment="Center" Margin="0,0,8,8"/>
    <TextBox x:Name="txtSgUrl" Grid.Row="1" Grid.Column="1"
             Padding="8,4" Height="32" Margin="0,0,0,8"
             ToolTip="e.g. https://sourcegraph.yourcompany.com"/>

    <TextBlock Grid.Row="2" Grid.Column="0" Text="API Token:"
               VerticalAlignment="Center" Margin="0,0,8,8"/>
    <PasswordBox x:Name="txtSgToken" Grid.Row="2" Grid.Column="1"
                 Padding="8,4" Height="32" Margin="0,0,0,8"/>

    <TextBlock Grid.Row="3" Grid.ColumnSpan="2"
               Text="Generate a token at: Your Sourcegraph profile → Access tokens → Generate new token"
               Foreground="#6B7280" FontSize="10" TextWrapping="Wrap"
               Margin="0,0,0,14"/>

    <StackPanel Grid.Row="4" Grid.ColumnSpan="2"
                Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="btnSgSave"   Content="Save"   Width="90" Margin="0,0,8,0"/>
      <Button x:Name="btnSgCancel" Content="Cancel" Width="90"/>
    </StackPanel>
  </Grid>
</Window>
'@

  $sr2  = New-Object System.IO.StringReader $settingsXaml
  $xr2  = [System.Xml.XmlReader]::Create($sr2)
  $dlg2 = [Windows.Markup.XamlReader]::Load($xr2)
  if ($Owner) { $dlg2.Owner = $Owner }

  $txtSgUrl    = $dlg2.FindName("txtSgUrl")
  $txtSgToken  = $dlg2.FindName("txtSgToken")
  $btnSgSave   = $dlg2.FindName("btnSgSave")
  $btnSgCancel = $dlg2.FindName("btnSgCancel")

  $cfg = Get-SourcegraphConfig
  if ($cfg) {
    $txtSgUrl.Text   = $cfg.Url
    $txtSgToken.Password = $cfg.Token
  }

$btnSgSave.Add_Click({
    $url   = $txtSgUrl.Text.Trim()
    $token = $txtSgToken.Password.Trim()

    if ([string]::IsNullOrWhiteSpace($url) -or [string]::IsNullOrWhiteSpace($token)) {
      [void][System.Windows.MessageBox]::Show("Both URL and token are required.",
        "Validation", [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Warning)
      return
    }

    try {
      Save-SourcegraphConfig -Url $url -Token $token
      [void][System.Windows.MessageBox]::Show(
        "Sourcegraph settings saved successfully.",
        "Saved", [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information)
      $dlg2.DialogResult = $true
      $dlg2.Close()
    } catch {
      [void][System.Windows.MessageBox]::Show("Failed to save: $_",
        "Error", [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Error)
    }
  })

  $btnSgCancel.Add_Click({ $dlg2.DialogResult = $false; $dlg2.Close() })
  [void]$dlg2.ShowDialog()
}

#endregion Dialog Helpers


# ---- CLI early exit — Invoke-CliMode is now defined, dispatch and exit before any GUI code ----
if ($script:CliMode) {
  Invoke-CliMode
  exit 0
}

#region Event Handlers — File / Browse / Tree

$tvFolders.Add_SelectedItemChanged({
  Invoke-UiAction -Context "Select item" -Action {
    $selected = $_.NewValue
    if ($selected -is [System.Windows.Controls.TreeViewItem] -and $selected.Tag) {
      Show-NodeDetails -Node $selected.Tag
    }
  }
})

$dgObjects.Add_MouseDoubleClick({
  param($sender, $e)
  Invoke-UiAction -Context "Open object XML" -Action {
    $source = $e.OriginalSource
    while ($source -and -not ($source -is [System.Windows.Controls.DataGridRow])) {
      try   { $source = [System.Windows.Media.VisualTreeHelper]::GetParent($source) }
      catch { $source = $null }
    }
    if ($source -is [System.Windows.Controls.DataGridRow] -and $dgObjects.SelectedItem) {
      Open-SelectedObjectXml
    }
  }
})


$dgObjects.Add_SelectionChanged({
  $row = $dgObjects.SelectedItem
  if (-not $row -or -not $dgProperties) { return }

  $uid = if ($row.PSObject.Properties['UniqueId']) { [string]$row.UniqueId } else { $null }
  if ([string]::IsNullOrWhiteSpace($uid)) {
    Load-PropertiesForNode -XmlNode $null
    return
  }

  $p = Get-StagedExportSourcePath
  if (-not $p) { $p = Get-CurrentExportPath }
  if (-not $p -or -not (Test-Path -LiteralPath $p)) { return }

  try {
    $xml      = Get-OisXmlDocument -Path $p
    $liveNode = Find-XmlNodeByUniqueId -Xml $xml -UniqueId $uid
    if ($liveNode) {
      Load-PropertiesForNode -XmlNode $liveNode
      if ($tabInspector) { $tabInspector.SelectedIndex = 3 }
    }
  } catch {}
})

$dgObjects.Add_PreviewMouseLeftButtonDown({
  param($sender, $e)
  $dep = $e.OriginalSource -as [System.Windows.DependencyObject]
  while ($dep) {
    if ($dep -is [System.Windows.Controls.DataGridRow]) {
      $dep.IsSelected = $true
      break
    }
    try   { $dep = [System.Windows.Media.VisualTreeHelper]::GetParent($dep) }
    catch { break }
  }
})


# Drag & drop helpers
function Invoke-DragOver($sender, $e) {
  if ($e.Data.GetDataPresent([Windows.DataFormats]::FileDrop)) {
    $files = $e.Data.GetData([Windows.DataFormats]::FileDrop)
    $p     = if ($files -and $files.Count -ge 1) { [string]$files[0] } else { $null }
$e.Effects = if ($p -and (Test-Path $p) -and
  ($p.ToLower().EndsWith('.ois_export') -or $p.ToLower().EndsWith('.zip'))) {
  [Windows.DragDropEffects]::Copy
} else {
  [Windows.DragDropEffects]::None
}
  } else {
    $e.Effects = [Windows.DragDropEffects]::None
  }
  $e.Handled = $true
}

function Invoke-FileDrop($sender, $e) {
  if (-not $e.Data.GetDataPresent([Windows.DataFormats]::FileDrop)) { $e.Handled = $true; return }
  $files = $e.Data.GetData([Windows.DataFormats]::FileDrop)
  $p     = if ($files -and $files.Count -ge 1) { [string]$files[0] } else { $null }

  if ($p -and (Test-Path $p)) {
    if ($p.ToLower().EndsWith('.zip')) {
      Set-Status "Extracting .ois_export from zip..."
      $extracted = Expand-OisExportFromZip -ZipPath $p
      if ($extracted) {
        $txtPath.Text = $extracted
        Set-Status "Extracted and loaded from zip: $([System.IO.Path]::GetFileName($p))"
      } else {
        Set-Status "No .ois_export found inside zip."
        [void][System.Windows.MessageBox]::Show(
          "No .ois_export file was found inside the dropped zip.",
          "Extract Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
      }
    } elseif ($p.ToLower().EndsWith('.ois_export')) {
      $txtPath.Text = $p
      Set-Status "Dropped: $p"
    } else {
      Set-Status "Drop rejected: pick a .ois_export or .zip file."
    }
  }
  $e.Handled = $true
}

$win.Add_DragOver({    Invoke-DragOver $this $_ })
$win.Add_DragEnter({   Invoke-DragOver $this $_ })
$win.Add_Drop({        Invoke-FileDrop $this $_ })
$tvFolders.Add_DragOver({  Invoke-DragOver $this $_ })
$tvFolders.Add_DragEnter({ Invoke-DragOver $this $_ })
$tvFolders.Add_Drop({      Invoke-FileDrop $this $_ })

$btnBrowse.Add_Click({
  Invoke-UiAction -Context "Browse" -Action {
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Filter = "Orchestrator Export (*.ois_export)|*.ois_export|Zip Archive (*.zip)|*.zip|All Files (*.*)|*.*"
    if ($dlg.ShowDialog()) {
      if ($dlg.FileName.ToLower().EndsWith('.zip')) {
        Set-Status "Extracting .ois_export from zip..."
        $extracted = Expand-OisExportFromZip -ZipPath $dlg.FileName
        if ($extracted) {
          $txtPath.Text = $extracted
          Set-Status "Extracted from zip: $([System.IO.Path]::GetFileName($dlg.FileName))"
        } else {
          [void][System.Windows.MessageBox]::Show(
            "No .ois_export file was found inside the selected zip.",
            "Extract Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        }
      } else {
        $txtPath.Text = $dlg.FileName
        Set-Status "Selected: $($dlg.FileName)"
      }
    }
  }
})

$btnCloseFile.Add_Click({
  Invoke-UiAction -Context "Close file" -Action {
    if ($script:HasUnsavedChanges) {
      $choice = [System.Windows.MessageBox]::Show(
        "You have staged changes that have not been saved.`n`nClose the export and discard them?",
        "Close Export",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning)
      if ($choice -ne [System.Windows.MessageBoxResult]::Yes) { return }
    }
    $script:LastTemp = $null
    $script:LastDocs = $null
    Clear-UI
  }
})

$txtSearch.Add_TextChanged({
  Invoke-UiAction -Context "Filter" -Action {
    if (-not $script:AllNodes) { return }
    $q = $txtSearch.Text.Trim()
    $script:Filtered = if ($q) { Copy-FilteredTree -node $script:AllNodes -q $q } else { $script:AllNodes }
    Update-TreeView -Root $script:Filtered

    if ($txtTreeSummary) {
      if ($q -and $tvFolders.Items.Count -eq 0) {
        $txtTreeSummary.Text       = "No results found for: $q"
        $txtTreeSummary.Foreground = [System.Windows.Media.Brushes]::OrangeRed
      } elseif ($q) {
        $txtTreeSummary.Text       = "Showing filtered results for: $q"
        $txtTreeSummary.Foreground = ConvertTo-Brush '#A9B1BC'
      } else {
        $txtTreeSummary.Text       = "Search folders, policies, IDs, and object names."
        $txtTreeSummary.Foreground = ConvertTo-Brush '#A9B1BC'
      }
    }

    Set-Status ("Filter: " + ($(if ($q) { $q } else { "(none)" })))
  }
})

# Show/hide the X button based on whether there is text
$txtSearch.Add_TextChanged({
  if ($btnClearSearch) {
    $btnClearSearch.Visibility = if ($txtSearch.Text.Length -gt 0) { 'Visible' } else { 'Collapsed' }
  }
})

$btnClearSearch.Add_Click({
  $txtSearch.Text  = ""
  $txtSearch.Focus() | Out-Null
})

# Load & Analyze: initial parse of an export
$btnAnalyze.Add_Click({
  Invoke-UiAction -Context "Analyze" -Action {
    $p = Get-CurrentExportPath
    if (-not $p -or -not (Test-Path $p)) {
      [void][System.Windows.MessageBox]::Show("Pick a valid .ois_export file first.", "Missing File",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
      return
    }
    Import-ExportIntoUI -Path $p
  }
})

# Reload Current Export: re-parse without changing path
$btnParse.Add_Click({
  Invoke-UiAction -Context "Reload" -Action {
    $p = Get-CurrentExportPath
    if (-not $p -or -not (Test-Path $p)) {
      [void][System.Windows.MessageBox]::Show("Pick a valid .ois_export file first.", "Missing File",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
      return
    }
    Import-ExportIntoUI -Path $p
  }
})

$btnExpandAll.Add_Click({
  Invoke-UiAction -Context "Expand all" -Action { Expand-AllTreeNodes }
})

$btnCollapseAll.Add_Click({
  Invoke-UiAction -Context "Collapse all" -Action { Collapse-AllTreeNodes }
})


$dgProperties.Add_SelectionChanged({
  $row = $dgProperties.SelectedItem
  if (-not $row -or -not $txtPropertyDetail) { return }

  $txtPropertyDetail.Text       = [string]$row.Value
  $txtPropertyDetail.IsReadOnly = [bool]$row.ReadOnly
  $txtPropertyDetail.Foreground = if ($row.ReadOnly) {
    [System.Windows.Media.SolidColorBrush][System.Windows.Media.Color]::FromRgb(0x4A,0x52,0x60)
  } else {
    [System.Windows.Media.SolidColorBrush][System.Windows.Media.Color]::FromRgb(0xF5,0xF7,0xFA)
  }

  if ($txtPropertyDetailLabel) {
    $label = if ($row.ReadOnly) { "Selected (read-only): $($row.LocalName)" } else { "Selected: $($row.LocalName)" }
    $txtPropertyDetailLabel.Text = $label
  }

# Enable Search Codebase button for any non-empty property value
  if ($btnSearchCodebase) {
    $hasValue  = -not [string]::IsNullOrWhiteSpace([string]$row.Value)
    $hasCfg    = (Get-SourcegraphConfig) -ne $null
    $btnSearchCodebase.IsEnabled = ($hasValue -and $hasCfg)
    $btnSearchCodebase.ToolTip   = if ($hasCfg) {
      "Search Sourcegraph for references to this value"
    } else {
      "Configure Sourcegraph in Tools > Sourcegraph Settings to enable"
    }
  }

})
$dgProperties.Add_BeginningEdit({
  param($sender, $e)
  $row = $e.Row.Item
  if ($row -and $row.ReadOnly) {
    $e.Cancel = $true
  }
})


$txtStatus.Cursor = [System.Windows.Input.Cursors]::Hand
$txtStatus.ToolTip = "Click to copy"

$txtStatus.Add_MouseLeftButtonUp({
  if (-not [string]::IsNullOrWhiteSpace($txtStatus.Text)) {
    [System.Windows.Clipboard]::SetText($txtStatus.Text)
    $script:_StatusOrig = $txtStatus.Text
    $txtStatus.Text = "✓ Copied"

    $script:_StatusTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:_StatusTimer.Interval = [TimeSpan]::FromSeconds(1.5)
    $script:_StatusTimer.Add_Tick({
      $txtStatus.Text = $script:_StatusOrig
      $script:_StatusTimer.Stop()
    })
    $script:_StatusTimer.Start()
  }
})

#endregion Event Handlers — File / Browse / Tree

#region Event Handlers — Edit Actions

$btnModifyName.Add_Click({
  Invoke-UiAction -Context "Rename Selected" -Action {
    $node = Get-SelectedTreeNode
    if (-not $node) {
      [void][System.Windows.MessageBox]::Show("Select a folder, policy, or item in the tree first.", "Rename Selected")
      return
    }
    if ([string]::IsNullOrWhiteSpace($node.UniqueId)) {
      [void][System.Windows.MessageBox]::Show("The selected item does not have a Unique ID and cannot be renamed safely.", "Rename Selected")
      return
    }
    $newName = Show-TextInputDialog -Title "Rename Selected" -Prompt "Enter the new name:" -DefaultText $node.Name
    if ([string]::IsNullOrWhiteSpace($newName)) { return }

    $xml    = Get-OisXmlDocument -Path (Get-CurrentExportPath)
    $target = Find-XmlNodeByUniqueId -Xml $xml -UniqueId $node.UniqueId
    if (-not $target) { throw "Could not locate the selected item in the export XML." }

    [void](Set-OrCreateChildTextLocal -Node $target -LocalName 'Name' -Value $newName -Datatype 'string')
    $out = Stage-EditedExport -Xml $xml -StatusMessage "Renamed item and saved: $newName"

    if ($out) {
      [void][System.Windows.MessageBox]::Show(
        "Changes staged for preview.`n`nUse Save to overwrite the current file, or Save As to create a new file.",
        "Rename Selected")
    }
  }
})

$btnSetMaxPar.Add_Click({
  Invoke-UiAction -Context "Set Max Parallel" -Action {
    $node = Get-SelectedTreeNode
    if (-not $node -or $node.Type -ne 'policy') {
      [void][System.Windows.MessageBox]::Show("Select a policy/runbook node first.", "Set Max Parallel")
      return
    }
    $value = Show-TextInputDialog -Title "Set Max Parallel" -Prompt "Enter the max parallel value:" -DefaultText "1"
    if ([string]::IsNullOrWhiteSpace($value)) { return }
    $n = 0
    if (-not [int]::TryParse($value, [ref]$n)) {
      [void][System.Windows.MessageBox]::Show("Enter a valid integer.", "Set Max Parallel")
      return
    }
    $xml    = Get-OisXmlDocument -Path (Get-CurrentExportPath)
    $target = Find-XmlNodeByUniqueId -Xml $xml -UniqueId $node.UniqueId
    if (-not $target) { throw "Could not locate the selected policy in the export XML." }

    [void](Set-FirstMatchingChildValue -Node $target -CandidateNames $script:MaxParallelCandidateNames `
      -Value ([string]$n) -Datatype 'int' -CreateIfMissing)

    $out = Stage-EditedExport -Xml $xml -StatusMessage "Updated max parallel value to $n"

    if ($out) {
      [void][System.Windows.MessageBox]::Show(
        "Staged:`n$out`n`nNote: candidate field names: $($script:MaxParallelCandidateNames -join ', ').",
        "Set Max Parallel")
    }
  }
})

$btnApplyLBP.Add_Click({
  Invoke-UiAction -Context "Apply Link Best Practices" -Action {
    $xml    = Get-OisXmlDocument -Path (Get-CurrentExportPath)
    $result = Apply-LinkBestPracticesToExportXml -Xml $xml
    $out    = Stage-EditedExport -Xml $xml -StatusMessage "Applied link best practices."

    if ($out) {
      [void][System.Windows.MessageBox]::Show(
        "Staged:`n$out`n`nLinks found: $($result.LinksFound)`nLinks updated: $($result.LinksUpdated)`nGreen: $($result.Green)`nBlue: $($result.Blue)`nOrange: $($result.Orange)`nRed: $($result.Red)",
        "Apply Link Best Practices")
    }
  }
})


$btnApplyProperties.Add_Click({
  Invoke-UiAction -Context "Apply Properties" -Action {
    $node = Get-SelectedTreeNode
    if (-not $node -or [string]::IsNullOrWhiteSpace($node.UniqueId)) {
      [void][System.Windows.MessageBox]::Show(
        "Select a tree node with a Unique ID to apply property edits.",
        "Apply Properties")
      return
    }

    $p = Get-CurrentExportPath
    if (-not $p -or -not (Test-Path -LiteralPath $p)) {
      [void][System.Windows.MessageBox]::Show("No export file is loaded.", "Apply Properties")
      return
    }

    $xml    = Get-OisXmlDocument -Path $p
    $target = Find-XmlNodeByUniqueId -Xml $xml -UniqueId $node.UniqueId
    if (-not $target) { throw "Could not locate the selected node in the export XML." }

    $changed = Apply-PropertyEdits -XmlNode $target
    if ($changed -eq 0) {
      Set-Status "No property values were changed."
      return
    }

    # Save the UniqueId so we can re-select after reload
    $script:_PostStageSelectId = $node.UniqueId

    $out = Stage-EditedExport -Xml $xml `
             -StatusMessage "Applied $changed property edit(s) to $($node.Name)."

    # Re-select the same node in the reloaded tree
    if ($script:_PostStageSelectId) {
      Invoke-RestoreTreeSelection -UniqueId $script:_PostStageSelectId
      $script:_PostStageSelectId = $null
    }
  }
})

# Consolidated handler for all four logging toggle buttons.
function Invoke-LoggingToggle {
param([string]$FieldLabel, [string[]]$CandidateNames, [bool]$Enable)

  Invoke-UiAction -Context "$FieldLabel Logging" -Action {
    $node = Get-SelectedTreeNode
    if (-not $node -or $node.Type -ne 'policy') {
      [void][System.Windows.MessageBox]::Show("Select a policy/runbook node first.", "$FieldLabel Logging")
      return
    }
    $xml    = Get-OisXmlDocument -Path (Get-CurrentExportPath)
    $policy = Find-XmlNodeByUniqueId -Xml $xml -UniqueId $node.UniqueId
    if (-not $policy) { throw "Could not locate the selected policy in the export XML." }

    $changed = Set-LoggingFieldsInPolicyObjects -PolicyNode $policy -CandidateNames $CandidateNames -Enabled $Enable
    if ($changed -eq 0) {
      [void][System.Windows.MessageBox]::Show(
        "No existing $($FieldLabel.ToLower()) logging fields found.`n`nCandidates:`n$($CandidateNames -join "`n")`n`nInspect an activity XML and update the candidate array if needed.",
        "$FieldLabel Logging")
      return
    }
    $action = if ($Enable) { "Enabled" } else { "Disabled" }
    $out = Stage-EditedExport -Xml $xml -StatusMessage "$action $($FieldLabel.ToLower()) logging on $changed field(s)."
    if ($out) {
      [void][System.Windows.MessageBox]::Show("Staged:`n$out`n`nUpdated fields: $changed", "$FieldLabel Logging")
    }
  }
}

$btnOnObjLog.Add_Click({  Invoke-LoggingToggle 'Object'  $script:ObjectLoggingCandidateNames  $true })
$btnOffObjLog.Add_Click({ Invoke-LoggingToggle 'Object'  $script:ObjectLoggingCandidateNames  $false })
$btnOnGenLog.Add_Click({  Invoke-LoggingToggle 'Generic' $script:GenericLoggingCandidateNames $true })
$btnOffGenLog.Add_Click({ Invoke-LoggingToggle 'Generic' $script:GenericLoggingCandidateNames $false })

$btnPopoutPropertyDetail.Add_Click({
  Invoke-UiAction -Context "Pop out property value" -Action {
    $row = $dgProperties.SelectedItem
    if (-not $row) {
      [void][System.Windows.MessageBox]::Show(
        "Select a property row first.", "Pop Out",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information)
      return
    }

    $script:_PopLabel   = [string]$row.LocalName
    $script:_PopContent = [string]$row.Value
    $script:_PopReadOnly = [bool]$row.ReadOnly

    $popXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Property — $($script:_PopLabel)"
        Height="500"
        Width="720"
        MinHeight="200"
        MinWidth="400"
        WindowStartupLocation="CenterOwner"
        Background="#111315"
        Foreground="#F5F7FA">
  <Grid Margin="12">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <TextBlock Grid.Row="0"
               Text="$($script:_PopLabel)"
               FontSize="15"
               FontWeight="SemiBold"
               Margin="0,0,0,8"
               Foreground="#60BDFF"/>

    <TextBox x:Name="txtPopContent"
             Grid.Row="1"
             Background="#14161A"
             Foreground="#F5F7FA"
             BorderBrush="#2F343B"
             BorderThickness="1"
             FontFamily="Consolas"
             FontSize="12"
             AcceptsReturn="True"
             TextWrapping="Wrap"
             VerticalScrollBarVisibility="Auto"
             HorizontalScrollBarVisibility="Auto"
             IsReadOnly="False"
             Padding="10,8"/>

<StackPanel Grid.Row="2"
                Orientation="Horizontal"
                HorizontalAlignment="Right"
                Margin="0,10,0,0">
      <Button x:Name="btnPopApplyClose"
              Content="Apply &amp; Close"
              Width="130"
              Margin="0,0,8,0"/>
      <Button x:Name="btnPopCopy"
              Content="Copy to Clipboard"
              Width="150"
              Margin="0,0,8,0"/>
      <Button x:Name="btnPopClose"
              Content="Cancel"
              Width="90"/>
    </StackPanel>
  </Grid>
</Window>
"@

    $sr     = New-Object System.IO.StringReader $popXaml
    $xr     = [System.Xml.XmlReader]::Create($sr)
    $script:_PopWin = [Windows.Markup.XamlReader]::Load($xr)
    $script:_PopWin.Owner = $win

    $script:_TxtPopContent = $script:_PopWin.FindName("txtPopContent")
    $script:_BtnPopApplyClose = $script:_PopWin.FindName("btnPopApplyClose")
    $script:_BtnPopCopy       = $script:_PopWin.FindName("btnPopCopy")
    $script:_BtnPopClose      = $script:_PopWin.FindName("btnPopClose")

    $script:_TxtPopContent.Text      = $script:_PopContent
    $script:_TxtPopContent.IsReadOnly = $script:_PopReadOnly

    $script:_BtnPopApplyClose.IsEnabled = (-not $script:_PopReadOnly)

    $script:_BtnPopApplyClose.Add_Click({
      $selectedRow = $dgProperties.SelectedItem
      if ($selectedRow -and -not $selectedRow.ReadOnly) {
        $selectedRow.Value = $script:_TxtPopContent.Text
        if ($txtPropertyDetail) { $txtPropertyDetail.Text = $script:_TxtPopContent.Text }
      }
      $script:_PopWin.Close()
    })

    $script:_BtnPopCopy.Add_Click({
      [System.Windows.Clipboard]::SetText($script:_TxtPopContent.Text)
      $script:_BtnPopCopy.Content = "Copied!"
    })

    $script:_BtnPopClose.Add_Click({
      $script:_PopWin.Close()
    })

    [void]$script:_PopWin.ShowDialog()
  }
})


if ($btnSearchCodebase) {
  $btnSearchCodebase.Add_Click({
    Invoke-UiAction -Context "Search Codebase" -Action {
      $row = $dgProperties.SelectedItem
      if (-not $row) { return }

      $value = [string]$row.Value
      if ([string]::IsNullOrWhiteSpace($value)) {
        Set-Status "No value to search."
        return
      }

      # Build a useful search query from the value
      $query = if ($value -match '^\{[0-9A-Fa-f\-]{36}\}$') {
        # GUID — search without braces
        $value.Trim('{}')
      } elseif ($value.Length -gt 200) {
        # Long value (script) — extract first non-empty non-comment line
        $firstLine = ($value -split "`n" |
          Where-Object { $_.Trim() -ne '' -and $_.Trim() -notmatch '^#' -and $_.Trim() -notmatch '^param\(' } |
          Select-Object -First 1)
        if ($firstLine) {
          $firstLine.Trim().Substring(0, [Math]::Min(80, $firstLine.Trim().Length))
        } else {
          $value.Substring(0, 80)
        }
      } else {
        $value.Trim()
      }

      $label = [string]$row.LocalName
      Set-Status "Searching Sourcegraph for $label : $query"
      Show-SourcegraphDialog -Owner $win -InitialQuery $query
    }
  })
}


$txtPropertyDetail.Add_TextChanged({
  $row = $dgProperties.SelectedItem
  if (-not $row -or $row.ReadOnly) { return }
  $row.Value = $txtPropertyDetail.Text
})

#endregion Event Handlers — Edit Actions

#region Event Handlers — Cleanup

$btnFindEmptyFolders.Add_Click({
  Reset-ObjectGridColumns
  Invoke-UiAction -Context "Find Empty Folders" -Action {
    $p = Get-CurrentExportPath
    if (-not $p -or -not (Test-Path -LiteralPath $p)) {
      [void][System.Windows.MessageBox]::Show("Pick a valid .ois_export file first.", "Find Empty Folders",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
      return
    }
    Show-Overlay "Scanning export for empty folders..."
    try {
      $xml        = Get-OisXmlDocument -Path $p
      $candidates = @(Get-OisEmptyFolders -Xml $xml)
    } finally { Hide-Overlay }

    $dgObjects.ItemsSource    = $null
    $dgObjects.ItemsSource    = $candidates
    $tabInspector.SelectedIndex = 1

    if ($candidates.Count -eq 0) {
      Set-Status "No empty folders found."
      [void][System.Windows.MessageBox]::Show("No empty folders were found in the export.", "Find Empty Folders",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
      return
    }
    Set-Status "Found $($candidates.Count) empty folder candidate(s)."
    [void][System.Windows.MessageBox]::Show(
      "Found $($candidates.Count) empty folder candidate(s). Listed on the Objects tab.",
      "Find Empty Folders", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
  }
})

$btnFindPolicyVars.Add_Click({
  Invoke-UiAction -Context "Find Policy Variables" -Action {
    $p = Get-CurrentExportPath
    if (-not $p -or -not (Test-Path -LiteralPath $p)) {
      [void][System.Windows.MessageBox]::Show("Pick a valid .ois_export file first.",
        "Find Policy Variables", [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Warning)
      return
    }

    Show-Overlay "Scanning for policy-level variables..."
    try {
      [xml]$doc     = Get-OisXmlDocument -Path $p
      $inventory    = @(Get-PolicyVariableInventory -Doc $doc)
      $linkVarCount = @($inventory | Where-Object { $_.IsLinkVar }).Count
    } finally { Hide-Overlay }
    Invoke-TaskbarFlash

    if ($inventory.Count -eq 0) {
      Set-Status "No policy-level variables found."
      [void][System.Windows.MessageBox]::Show(
        "No policy-level variables (Initialize Data objects) were found in the export.",
        "Find Policy Variables", [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Information)
      return
    }

# Rebuild columns for inventory view
    $dgObjects.Columns.Clear()
    $dgObjects.AutoGenerateColumns = $false

    $colDefs = @(
      @{ Header = 'Policy';       Binding = 'PolicyName';   Width = 180 }
      @{ Header = 'Folder Path';  Binding = 'FolderPath';   Width = 200 }
      @{ Header = 'Activity';     Binding = 'ActivityName'; Width = 160 }
      @{ Header = 'Variable';     Binding = 'VarName';      Width = 200 }
      @{ Header = 'Unique ID';    Binding = 'VarUniqueId';  Width = 280 }
      @{ Header = 'Link Var?';    Binding = 'IsLinkVar';    Width = 80  }
    )

    foreach ($col in $colDefs) {
      $c = New-Object System.Windows.Controls.DataGridTextColumn
      $c.Header  = $col.Header
      $c.Binding = New-Object System.Windows.Data.Binding($col.Binding)
      $c.Width   = $col.Width
      [void]$dgObjects.Columns.Add($c)
    }

    $dgObjects.ItemsSource      = $null
    $dgObjects.ItemsSource      = $inventory
    $tabInspector.SelectedIndex = 1

$uniquePolicies    = @($inventory | Select-Object -ExpandProperty PolicyName -Unique).Count
    $linkWarning       = if ($linkVarCount -gt 0) { "  |  ⚠ $linkVarCount possible link variable(s)" } else { "" }
    $unresolvedCount   = @($inventory | Where-Object { $_.VarName -match '^\{[0-9A-Fa-f\-]{36}\}$' }).Count
    $unresolvedWarning = if ($unresolvedCount -gt 0) { "  |  ⚠ $unresolvedCount unresolved GUID(s) — re-export with globals included" } else { "" }

    Set-Status "Found $($inventory.Count) policy variable(s) across $uniquePolicies policy/policies$linkWarning$unresolvedWarning"

    [void][System.Windows.MessageBox]::Show(
      "Found $($inventory.Count) policy-level variable reference(s).`n`n" +
      "Policies with variables: $uniquePolicies`n" +
      "Possible link variables: $linkVarCount`n`n" +
      "Results are listed on the Objects tab.`n`n" +
      "Note: Variable names only resolve if Global Variables were included`n" +
      "in the export. Raw GUIDs indicate unresolved references.",
      "Find Policy Variables", [System.Windows.MessageBoxButton]::OK,
      [System.Windows.MessageBoxImage]::Information)
  }
})

$btnRemoveEmptyFolders.Add_Click({
  Reset-ObjectGridColumns
  Invoke-UiAction -Context "Remove Empty Folders" -Action {
    $p = Get-CurrentExportPath
    if (-not $p -or -not (Test-Path -LiteralPath $p)) {
      [void][System.Windows.MessageBox]::Show("Pick a valid .ois_export file first.", "Remove Empty Folders",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
      return
    }
    Show-Overlay "Scanning export for empty folders..."
    try {
      $xml        = Get-OisXmlDocument -Path $p
      $candidates = @(Get-OisEmptyFolders -Xml $xml)
    } finally { Hide-Overlay }

    if ($candidates.Count -eq 0) {
      $dgObjects.ItemsSource = $null
      Set-Status "No empty folders found."
      [void][System.Windows.MessageBox]::Show("No empty folders were found in the export.", "Remove Empty Folders",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
      return
    }
    $choice = [System.Windows.MessageBox]::Show(
      "Found $($candidates.Count) empty folder candidate(s).`n`nSave a cleaned copy with those folders removed?",
      "Remove Empty Folders", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
    if ($choice -ne [System.Windows.MessageBoxResult]::Yes) { return }

    $sfd = New-Object Microsoft.Win32.SaveFileDialog
    $sfd.Filter   = "Orchestrator Export (*.ois_export)|*.ois_export|All Files (*.*)|*.*"
    $sfd.FileName = New-StampedExportFileName -Prefix 'NoEmptyFolders_' -SourcePath $p
    $sfd.InitialDirectory = Split-Path $p -Parent
    if (-not $sfd.ShowDialog()) { return }

    Show-Overlay "Removing empty folders..."
    try {
      $removed = @(Remove-OisEmptyFoldersFromXml -Xml $xml)
      $xml.Save($sfd.FileName)
      $logPath = Join-Path (Split-Path -Parent $sfd.FileName) (
        [System.IO.Path]::GetFileNameWithoutExtension($sfd.FileName) + ".empty-folders.log.txt")
      Write-OisCleanupLog -LogPath $logPath -ActionName "Remove Empty Folders" -Items $removed
    } finally { Hide-Overlay }
    Invoke-TaskbarFlash

    $dgObjects.ItemsSource    = $null
    $dgObjects.ItemsSource    = $removed
    $tabInspector.SelectedIndex = 1

    Set-Status "Removed $($removed.Count) empty folder(s). Saved: $($sfd.FileName)"
    [void][System.Windows.MessageBox]::Show(
      "Created:`n$($sfd.FileName)`n`nLog:`n$logPath`n`nRemoved empty folders: $($removed.Count)",
      "Remove Empty Folders", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
  }
})

$btnFindUnreferencedGlobals.Add_Click({
  Reset-ObjectGridColumns
  Invoke-UiAction -Context "Find Unreferenced Globals" -Action {
    $p = Get-CurrentExportPath
    if (-not $p -or -not (Test-Path -LiteralPath $p)) {
      [void][System.Windows.MessageBox]::Show("Pick a valid .ois_export file first.", "Find Unreferenced Globals",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
      return
    }
    $options = Show-GlobalCleanupOptionsDialog -Owner $win
    if (-not $options) { return }

    Show-Overlay "Scanning export for unreferenced globals..."
    try {
      $xml        = Get-OisXmlDocument -Path $p
      $candidates = @(Get-UnreferencedGlobals -Xml $xml -Options $options)
    } finally { Hide-Overlay }

    $dgObjects.ItemsSource    = $null
    $dgObjects.ItemsSource    = $candidates
    $tabInspector.SelectedIndex = 1

    if ($candidates.Count -eq 0) {
      Set-Status "No unreferenced globals found."
      [void][System.Windows.MessageBox]::Show("No unreferenced globals found for the selected types.", "Find Unreferenced Globals",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
      return
    }

    $counts = @{
      variable = @($candidates | Where-Object { $_.Type -eq 'variable' }).Count
      config   = @($candidates | Where-Object { $_.Type -eq 'config' }).Count
      schedule = @($candidates | Where-Object { $_.Type -eq 'schedule' }).Count
      counter  = @($candidates | Where-Object { $_.Type -eq 'counter' }).Count
      group    = @($candidates | Where-Object { $_.Type -eq 'group' }).Count
    }
    Set-Status "Found $($candidates.Count) unreferenced global candidate(s)."
    [void][System.Windows.MessageBox]::Show(
      "Found $($candidates.Count) unreferenced global candidate(s).`n`n" +
      "Variables: $($counts.variable)`nGlobal Configurations: $($counts.config)`n" +
      "Schedules: $($counts.schedule)`nCounters: $($counts.counter)`nComputer Groups: $($counts.group)`n`n" +
      "Listed on the Objects tab.",
      "Find Unreferenced Globals", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
  }
})

$btnRemoveUnreferencedGlobals.Add_Click({
  Reset-ObjectGridColumns
  Invoke-UiAction -Context "Remove Unreferenced Globals" -Action {
    $p = Get-CurrentExportPath
    if (-not $p -or -not (Test-Path -LiteralPath $p)) {
      [void][System.Windows.MessageBox]::Show("Pick a valid .ois_export file first.", "Remove Unreferenced Globals",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
      return
    }
    $options = Show-GlobalCleanupOptionsDialog -Owner $win
    if (-not $options) { return }

    Show-Overlay "Scanning export for unreferenced globals..."
    try {
      $xml        = Get-OisXmlDocument -Path $p
      $candidates = @(Get-UnreferencedGlobals -Xml $xml -Options $options)
    } finally { Hide-Overlay }

    if ($candidates.Count -eq 0) {
      $dgObjects.ItemsSource = $null
      Set-Status "No unreferenced globals found."
      [void][System.Windows.MessageBox]::Show("No unreferenced globals found for the selected types.", "Remove Unreferenced Globals",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
      return
    }

    $choice = [System.Windows.MessageBox]::Show(
      "Found $($candidates.Count) unreferenced global candidate(s).`n`nSave a cleaned copy with those globals removed?",
      "Remove Unreferenced Globals", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
    if ($choice -ne [System.Windows.MessageBoxResult]::Yes) { return }

    $sfd = New-Object Microsoft.Win32.SaveFileDialog
    $sfd.Filter   = "Orchestrator Export (*.ois_export)|*.ois_export|All Files (*.*)|*.*"
    $sfd.FileName = New-StampedExportFileName -Prefix 'NoUnreferencedGlobals_' -SourcePath $p
    $sfd.InitialDirectory = Split-Path $p -Parent
    if (-not $sfd.ShowDialog()) { return }

    Show-Overlay "Removing unreferenced globals..."
    try {
      $removed = @(Remove-UnreferencedGlobalsFromXml -Xml $xml -Options $options)
      $xml.Save($sfd.FileName)
      $logPath = Join-Path (Split-Path -Parent $sfd.FileName) (
        [System.IO.Path]::GetFileNameWithoutExtension($sfd.FileName) + ".unreferenced-globals.log.txt")
      Write-OisCleanupLog -LogPath $logPath -ActionName "Remove Unreferenced Globals" -Items $removed
    } finally { Hide-Overlay }
    Invoke-TaskbarFlash

    $dgObjects.ItemsSource    = $null
    $dgObjects.ItemsSource    = $removed
    $tabInspector.SelectedIndex = 1

    $counts = @{
      variable = @($removed | Where-Object { $_.Type -eq 'variable' }).Count
      config   = @($removed | Where-Object { $_.Type -eq 'config' }).Count
      schedule = @($removed | Where-Object { $_.Type -eq 'schedule' }).Count
      counter  = @($removed | Where-Object { $_.Type -eq 'counter' }).Count
      group    = @($removed | Where-Object { $_.Type -eq 'group' }).Count
    }
    Set-Status "Removed $($removed.Count) unreferenced global item(s). Saved: $($sfd.FileName)"
    [void][System.Windows.MessageBox]::Show(
      "Created:`n$($sfd.FileName)`n`nLog:`n$logPath`n`n" +
      "Removed total: $($removed.Count)`nVariables: $($counts.variable)`n" +
      "Global Configurations: $($counts.config)`nSchedules: $($counts.schedule)`n" +
      "Counters: $($counts.counter)`nComputer Groups: $($counts.group)",
      "Remove Unreferenced Globals", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
  }
})

$btnSanitize.Add_Click({
  Invoke-UiAction -Context "Sanitize Export" -Action {
    $p = Get-CurrentExportPath
    if (-not $p -or -not (Test-Path -LiteralPath $p)) {
      [void][System.Windows.MessageBox]::Show("Pick a valid .ois_export file first.",
        "Sanitize Export", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
      return
    }

    $opts = Show-SanitizeOptionsDialog -Owner $win
    if (-not $opts) { return }

    Show-Overlay "Sanitizing export (staging preview)..."
    try {
      $clean   = Invoke-OisExportSanitize -Path $p -Options $opts
      $summary = Get-SanitizeRemovalSummary -Items @($script:LastSanitizeRemovedItems)

$out     = Stage-EditedExport -Xml $clean `
                   -StatusMessage ("Sanitize staged. Removed: {0}" -f $summary.Total)
      $script:LastStagedAction = 'Sanitize'   # <-- here
      Hide-Overlay
      Invoke-TaskbarFlash

      [void][System.Windows.MessageBox]::Show(
        "Sanitize changes staged for preview.`n`n" +
        "Use Save to overwrite the current file, or Save As to create a new file.`n`n" +
        "Removed total: $($summary.Total)`n" +
        "Variables: $($summary.Variables)`n" +
        "Global Configurations: $($summary.Configs)`n" +
        "Schedules: $($summary.Schedules)`n" +
        "Counters: $($summary.Counters)`n" +
        "Computer Groups: $($summary.Groups)`n" +
        "Empty Folders: $($summary.EmptyFolders)",
        "Sanitize Export", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    }
    catch {
      Hide-Overlay
      throw
    }
  }
})


$btnBulkRename.Add_Click({
  Invoke-UiAction -Context "Bulk Rename" -Action {
    $p = Get-CurrentExportPath
    if (-not $p -or -not (Test-Path -LiteralPath $p)) {
      [void][System.Windows.MessageBox]::Show("Pick a valid .ois_export file first.", "Bulk Rename")
      return
    }

    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Title  = "Select Rename CSV (OldName,NewName)"
    $dlg.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    if (-not $dlg.ShowDialog()) { return }

    $csvPath = $dlg.FileName

    $xml = Get-OisXmlDocument -Path $p
    $results = Invoke-BulkRename -Xml $xml -CsvPath $csvPath

    $succeeded = @($results | Where-Object { $_.Status -eq 'Renamed' }).Count
    $notFound  = @($results | Where-Object { $_.Status -eq 'NotFound' }).Count

    if ($succeeded -eq 0) {
      Reset-ObjectGridColumns
      $dgObjects.ItemsSource    = $results
      $tabInspector.SelectedIndex = 1
      Set-Status "Bulk rename: no matching items found."
      [void][System.Windows.MessageBox]::Show(
        "No items matched the names in the CSV.`n`nCheck that OldName values exactly match the Name field in the export.",
        "Bulk Rename", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
      return
    }

    $choice = [System.Windows.MessageBox]::Show(
      "Found $succeeded item(s) to rename. $notFound not found.`n`nStage these renames as a preview?",
      "Bulk Rename", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
    if ($choice -ne [System.Windows.MessageBoxResult]::Yes) { return }

    $out = Stage-EditedExport -Xml $xml `
             -StatusMessage "Bulk rename staged: $succeeded item(s) renamed."

    Reset-ObjectGridColumns
    $dgObjects.ItemsSource    = $results
    $tabInspector.SelectedIndex = 1

    [void][System.Windows.MessageBox]::Show(
      "Staged $succeeded rename(s). $notFound item(s) not found.`n`n" +
      "Results listed on the Objects tab.`n" +
      "Use Save or Save As to commit.",
      "Bulk Rename", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
  }
})


#endregion Event Handlers — Cleanup

#region Event Handlers — Tools / Copy

$miToolsOpenXml.Add_Click({
  Invoke-UiAction -Context "Open object XML" -Action { Open-SelectedObjectXml }
})

$miToolsCopyUniqueId.Add_Click({
  Invoke-UiAction -Context "Copy Unique ID" -Action {
    $info = Get-CurrentSelectionInfo
    if (-not $info) {
      [void][System.Windows.MessageBox]::Show("Select a tree item or object row first.", "Copy Unique ID",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
      return
    }
    Copy-TextToClipboard -Text $info.UniqueId `
      -SuccessMessage "Copied Unique ID to clipboard." `
      -EmptyMessage "No Unique ID is available for the current selection."
  }
})

$miToolsCopyPath.Add_Click({
  Invoke-UiAction -Context "Copy Path" -Action {
    $info = Get-CurrentSelectionInfo
    if (-not $info) {
      [void][System.Windows.MessageBox]::Show("Select a tree item or object row first.", "Copy Path",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
      return
    }
    Copy-TextToClipboard -Text $info.Path `
      -SuccessMessage "Copied path to clipboard." `
      -EmptyMessage "No path is available for the current selection."
  }
})

$miToolsCopyXml.Add_Click({
  Invoke-UiAction -Context "Copy XML" -Action {
    $info = Get-CurrentSelectionInfo
    if (-not $info) {
      [void][System.Windows.MessageBox]::Show("Select a tree item or object row first.", "Copy XML",
        [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
      return
    }
    $xmlText = if ($info.XmlText) { Format-XmlPretty -XmlText $info.XmlText } else { $null }
    Copy-TextToClipboard -Text $xmlText `
      -SuccessMessage "Copied XML to clipboard." `
      -EmptyMessage "No XML is available for the current selection."
  }
})


$miToolsCompare.Add_Click({
  Invoke-UiAction -Context "Compare Exports" -Action {

    $dlgBase = New-Object Microsoft.Win32.OpenFileDialog
    $dlgBase.Title  = "Select Base (Original) Export"
    $dlgBase.Filter = "Orchestrator Export (*.ois_export)|*.ois_export|All Files (*.*)|*.*"
    if (-not $dlgBase.ShowDialog()) { return }
    $basePath = $dlgBase.FileName

    $dlgMod = New-Object Microsoft.Win32.OpenFileDialog
    $dlgMod.Title  = "Select Modified Export"
    $dlgMod.Filter = "Orchestrator Export (*.ois_export)|*.ois_export|All Files (*.*)|*.*"
    $dlgMod.InitialDirectory = Split-Path $basePath -Parent
    if (-not $dlgMod.ShowDialog()) { return }
    $modPath = $dlgMod.FileName

    Show-Overlay "Comparing exports..."
    try {
      $diff = Compare-OisExports -BasePath $basePath -ModifiedPath $modPath
    } finally { Hide-Overlay }

    Show-DiffResultDialog -Diff $diff -Owner $win
  }
})


$miToolsExportReport.Add_Click({
  Invoke-UiAction -Context "Export Report" -Action {
    $p = Get-CurrentExportPath
    if (-not $p -or -not (Test-Path -LiteralPath $p)) {
      [void][System.Windows.MessageBox]::Show("Load an export first.", "Export Report")
      return
    }

    $sfd = New-Object Microsoft.Win32.SaveFileDialog
    $sfd.Filter   = "Text Report (*.txt)|*.txt|All Files (*.*)|*.*"
    $sfd.FileName = "ExportReport_$([System.IO.Path]::GetFileNameWithoutExtension($p))_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"
    $sfd.InitialDirectory = Split-Path $p -Parent
    if (-not $sfd.ShowDialog()) { return }

    Show-Overlay "Generating export report..."
    try {
      $lines = New-OisExportReport -Path $p -OutputPath $sfd.FileName
    } finally { Hide-Overlay }

    Set-Status "Report saved: $($sfd.FileName)"
    [void][System.Windows.MessageBox]::Show(
      "Report saved:`n$($sfd.FileName)`n`n$($lines.Count) lines written.",
      "Export Report", [System.Windows.MessageBoxButton]::OK,
      [System.Windows.MessageBoxImage]::Information)
  }
})


$miToolsSourcegraph.Add_Click({
  $node  = Get-SelectedTreeNode
  $query = if ($node -and $node.Name) { $node.Name } else { '' }
  Show-SourcegraphDialog -Owner $win -InitialQuery $query
})

$miToolsSourcegraphSettings.Add_Click({
  Show-SourcegraphSettingsDialog -Owner $win
})

#endregion Event Handlers — Tools / Copy

#region Event Handlers — Menu

$miFileOpen.Add_Click({    Invoke-ButtonClick $btnBrowse })
$miFileReload.Add_Click({  Invoke-ButtonClick $btnParse })
$miFileSave.Add_Click({    Save-CurrentExport })
$miFileSaveAs.Add_Click({  Save-AsCurrentExportCopy })
$miFileSanitize.Add_Click({ Invoke-ButtonClick $btnSanitize })
$miFileExit.Add_Click({    $win.Close() })

$miViewExpandAll.Add_Click({   Invoke-ButtonClick $btnExpandAll })
$miViewCollapseAll.Add_Click({ Invoke-ButtonClick $btnCollapseAll })
$miViewOverview.Add_Click({    if ($tabInspector) { $tabInspector.SelectedIndex = 0 } })
$miViewObjects.Add_Click({     if ($tabInspector) { $tabInspector.SelectedIndex = 1 } })
$miViewXml.Add_Click({         if ($tabInspector) { $tabInspector.SelectedIndex = 2 } })
$miViewActions.Add_Click({     if ($tabInspector) { $tabInspector.SelectedIndex = 4 } })

$miToolsRename.Add_Click({             Invoke-ButtonClick $btnModifyName })
$miToolsMaxParallel.Add_Click({        Invoke-ButtonClick $btnSetMaxPar })
$miToolsApplyLBP.Add_Click({           Invoke-ButtonClick $btnApplyLBP })
$miToolsFindUnrefGlobals.Add_Click({   Invoke-ButtonClick $btnFindUnreferencedGlobals })
$miToolsRemoveUnrefGlobals.Add_Click({ Invoke-ButtonClick $btnRemoveUnreferencedGlobals })
$miToolsFindEmptyFolders.Add_Click({   Invoke-ButtonClick $btnFindEmptyFolders })
$miToolsRemoveEmptyFolders.Add_Click({ Invoke-ButtonClick $btnRemoveEmptyFolders })

#endregion Event Handlers — Menu

#region Event Handlers — Help

$miHelpAbout.Add_Click({
  [void][System.Windows.MessageBox]::Show(
    "OIS Export Analyzer v$script:AppVersion`n`nInspect, sanitize, and modify SCORCH .ois_export files.`n`n" +
    "Current focus:`n  Tree navigation`n  Object inspection`n  XML viewing`n  Cleanup and export actions",
    "About OIS Export Analyzer",
    [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
})

$miHelpUsage.Add_Click({
  [void][System.Windows.MessageBox]::Show(
    "Suggested workflow:`n`n" +
    "1. Open Export (Ctrl+O)`n" +
    "2. Load & Analyze`n" +
    "3. Browse folders/policies on the left`n" +
    "4. Review Overview / Objects / XML`n" +
    "5. Apply edits or Sanitize — changes are staged as a preview`n" +
    "6. Use Save (Ctrl+S) or Save As (Ctrl+Shift+S) to commit`n" +
    "7. Re-open the saved export and validate changes",
    "Usage Notes",
    [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
})

$miHelpRules.Add_Click({
  [void][System.Windows.MessageBox]::Show(
    "Naming / Cleanup Rules:`n`n" +
    "  All edits stage a preview first — nothing is written until you Save or Save As.`n" +
    "  Sanitize can remove unreferenced globals and empty folders.`n" +
    "  Empty folder cleanup is safer than trying to guess 'unused runbooks'.`n" +
    "  Link best-practice coloring depends on what can be inferred from link XML.",
    "Naming / Cleanup Rules",
    [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
})


$miHelpGuide.Add_Click({
  Show-UserGuide -Owner $win
})

$miHelpShortcuts.Add_Click({
  [void][System.Windows.MessageBox]::Show(
    "Keyboard Shortcuts:`n`n" +
    "  Ctrl+O          Open Export`n" +
    "  Ctrl+R / F5     Reload Current Export`n" +
    "  Ctrl+S          Save`n" +
    "  Ctrl+Shift+S    Save As`n" +
    "  Ctrl+Alt+S      Sanitize Export`n" +
    "  Ctrl+1          Go to Overview tab`n" +
    "  Ctrl+2          Go to Objects tab`n" +
    "  Ctrl+3          Go to XML tab`n" +
    "  Ctrl+4          Go to Actions tab`n" +
    "  Ctrl+Shift+I    Copy Unique ID`n" +
    "  Ctrl+Shift+P    Copy Path`n" +
    "  Ctrl+Shift+X    Copy XML" +
    "  F1              User Guide`n",
    "Keyboard Shortcuts",
    [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
})

#endregion Event Handlers — Help

#region Keyboard Shortcuts

$win.Add_PreviewKeyDown({
  param($sender, $e)
  $ctrl  = ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control) -ne 0
  $shift = ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Shift) -ne 0
  $alt   = ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Alt) -ne 0

  switch ($true) {
    # Escape = clear search if it has text
    { -not $ctrl -and -not $shift -and -not $alt -and $e.Key -eq [System.Windows.Input.Key]::Escape } {
      if ($txtSearch -and $txtSearch.Text.Length -gt 0) {
        $txtSearch.Text = ""
        $e.Handled = $true
        return
      }
    }
    # Ctrl+O = Open
    { $ctrl -and -not $shift -and -not $alt -and $e.Key -eq [System.Windows.Input.Key]::O } {
      if ($miFileOpen) { $miFileOpen.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.MenuItem]::ClickEvent))) }
      $e.Handled = $true; return
    }
    # Ctrl+R = Reload
    { $ctrl -and -not $shift -and -not $alt -and $e.Key -eq [System.Windows.Input.Key]::R } {
      if ($miFileReload) { $miFileReload.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.MenuItem]::ClickEvent))) }
      $e.Handled = $true; return
    }
    # F5 = Reload
    { -not $ctrl -and -not $shift -and -not $alt -and $e.Key -eq [System.Windows.Input.Key]::F5 } {
      if ($miFileReload) { $miFileReload.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.MenuItem]::ClickEvent))) }
      $e.Handled = $true; return
    }
    # Ctrl+S = Save
    { $ctrl -and -not $shift -and -not $alt -and $e.Key -eq [System.Windows.Input.Key]::S } {
      if ($miFileSave) { $miFileSave.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.MenuItem]::ClickEvent))) }
      $e.Handled = $true; return
    }
    # Ctrl+Shift+S = Save As
    { $ctrl -and $shift -and -not $alt -and $e.Key -eq [System.Windows.Input.Key]::S } {
      if ($miFileSaveAs) { $miFileSaveAs.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.MenuItem]::ClickEvent))) }
      $e.Handled = $true; return
    }
    # Ctrl+Alt+S = Sanitize
    { $ctrl -and $alt -and -not $shift -and $e.Key -eq [System.Windows.Input.Key]::S } {
      if ($miFileSanitize) { $miFileSanitize.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.MenuItem]::ClickEvent))) }
      $e.Handled = $true; return
    }
    # Ctrl+1..4 = Tab navigation
    { $ctrl -and -not $shift -and $e.Key -eq [System.Windows.Input.Key]::D1 } {
      if ($tabInspector) { $tabInspector.SelectedIndex = 0 }; $e.Handled = $true; return
    }
    { $ctrl -and -not $shift -and $e.Key -eq [System.Windows.Input.Key]::D2 } {
      if ($tabInspector) { $tabInspector.SelectedIndex = 1 }; $e.Handled = $true; return
    }
    { $ctrl -and -not $shift -and $e.Key -eq [System.Windows.Input.Key]::D3 } {
      if ($tabInspector) { $tabInspector.SelectedIndex = 2 }; $e.Handled = $true; return
    }
    { $ctrl -and -not $shift -and $e.Key -eq [System.Windows.Input.Key]::D4 } {
      if ($tabInspector) { $tabInspector.SelectedIndex = 3 }; $e.Handled = $true; return
    }
    # Ctrl+Shift+I = Copy Unique ID
    { $ctrl -and $shift -and $e.Key -eq [System.Windows.Input.Key]::I } {
      if ($miToolsCopyUniqueId) { $miToolsCopyUniqueId.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.MenuItem]::ClickEvent))) }
      $e.Handled = $true; return
    }
    # Ctrl+Shift+P = Copy Path
    { $ctrl -and $shift -and $e.Key -eq [System.Windows.Input.Key]::P } {
      if ($miToolsCopyPath) { $miToolsCopyPath.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.MenuItem]::ClickEvent))) }
      $e.Handled = $true; return
    }
    # Ctrl+Shift+X = Copy XML
    { $ctrl -and $shift -and $e.Key -eq [System.Windows.Input.Key]::X } {
      if ($miToolsCopyXml) { $miToolsCopyXml.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.MenuItem]::ClickEvent))) }
      $e.Handled = $true; return
    }
    { -not $ctrl -and -not $shift -and -not $alt -and $e.Key -eq [System.Windows.Input.Key]::F1 } {
  Show-UserGuide -Owner $win
  $e.Handled = $true; return
}
  }
})

#endregion Keyboard Shortcuts

#region Startup
$win.Add_Closing({
  param($sender, $e)
  if ($script:HasUnsavedChanges) {
    $choice = [System.Windows.MessageBox]::Show(
      "You have staged changes that have not been saved.`n`nClose anyway and discard them?",
      "Unsaved Changes",
      [System.Windows.MessageBoxButton]::YesNo,
      [System.Windows.MessageBoxImage]::Warning)
    if ($choice -ne [System.Windows.MessageBoxResult]::Yes) {
      $e.Cancel = $true
      return
    }
  }
  if ($script:StagedExportPath -and (Test-Path -LiteralPath $script:StagedExportPath)) {
    try { Remove-Item -LiteralPath $script:StagedExportPath -Force -ErrorAction SilentlyContinue } catch {}
  }
  Save-WindowSettings
})

# Apply elevation UI state
if ($script:IsElevated) {
  if ($txtDropHint) {
    $txtDropHint.Text       = "⚠ Drag & drop disabled when running elevated.`nRestart PowerShell without admin rights."
    $txtDropHint.Foreground = '#B00020'
    $txtDropHint.FontStyle  = 'Normal'
    $txtDropHint.FontWeight = 'SemiBold'
  }
  Set-Status "⚠ Drag & drop disabled when elevated. Restart PowerShell without admin rights."
  [void][System.Windows.MessageBox]::Show(
    "This tool is running as Administrator.`n`n" +
    "Drag & drop is commonly blocked when elevated due to UAC.`n`n" +
    "To enable drag & drop:`n" +
    "  Close this window`n" +
    "  Start PowerShell normally (not 'Run as administrator')`n" +
    "  Run the script again",
    "Drag & Drop Disabled (Elevated)",
    [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
} else {
  Set-Status "Ready. Browse or drag & drop a .ois_export file."
}

Load-RecentFiles
Update-RecentFilesMenu
Load-SourcegraphConfig
# Load-AiConfig
Update-WindowTitle
Restore-WindowSettings

# Clean up stale staged export files from previous sessions that were force-killed
try {
  Get-ChildItem -Path $env:TEMP -Filter 'OisExport_Staged_*.ois_export' -ErrorAction SilentlyContinue |
    Where-Object { (Get-Date) - $_.LastWriteTime -gt [TimeSpan]::FromHours(1) } |
    ForEach-Object {
      Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
    }
} catch {}

# Clean up staged temp file if PowerShell is force-killed
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
  if ($script:StagedExportPath -and (Test-Path -LiteralPath $script:StagedExportPath)) {
    try { Remove-Item -LiteralPath $script:StagedExportPath -Force -ErrorAction SilentlyContinue } catch {}
  }
}

[void]$win.ShowDialog()
#endregion Startup