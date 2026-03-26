<#
.SYNOPSIS
    Identifies devices targeted by a hotpatch-enabled Windows quality update policy 
    that are NOT also targeted by a VBS (Virtualization-Based Security) configuration policy.

.DESCRIPTION
    This script uses the Microsoft Graph Beta API to:
    1. Find all Windows quality update policies with hotpatch enabled.
    2. Get the group assignments for those hotpatch policies.
    3. Find all device configuration policies that enable VBS (DeviceGuard).
    4. Compare the group assignments to identify gaps.

.NOTES
    Requires: Microsoft.Graph.Beta PowerShell modules
    Permissions: DeviceManagementConfiguration.Read.All
    API: Beta (subject to change)
#>

# -----------------------------------------------
# 1. Connect to Microsoft Graph
# -----------------------------------------------
Install-Module Microsoft.Graph.Beta -Force -AllowClobber      
Import-Module Microsoft.Graph.Beta
#Import-Module Microsoft.Graph.Beta.WindowsUpdates

Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All"

Write-Host "=== Hotpatch + VBS Policy Gap Analysis ===" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------------
# 2. Get all Windows Quality Update Policies with Hotpatch enabled
# -----------------------------------------------
Write-Host "Step 1: Retrieving Windows Quality Update Policies..." -ForegroundColor Yellow

$qualityUpdatePolicies = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdatePolicies" `
    -OutputType PSObject

$hotpatchPolicies = $qualityUpdatePolicies.value | Where-Object { $_.hotpatchEnabled -eq $true }

if (-not $hotpatchPolicies) {
    Write-Host "No hotpatch-enabled quality update policies found. Exiting." -ForegroundColor Green
    Disconnect-MgGraph
    return
}

Write-Host "Found $($hotpatchPolicies.Count) hotpatch-enabled policy(ies):" -ForegroundColor Green
$hotpatchPolicies | ForEach-Object {
    Write-Host "  - [$($_.id)] $($_.displayName)" -ForegroundColor White
}
Write-Host ""

# -----------------------------------------------
# 3. Get group assignments for each hotpatch policy
# -----------------------------------------------
Write-Host "Step 2: Retrieving hotpatch policy assignments..." -ForegroundColor Yellow

$hotpatchGroupIds = @()

foreach ($policy in $hotpatchPolicies) {
    $assignments = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdatePolicies/$($policy.id)/assignments" `
        -OutputType PSObject

    foreach ($assignment in $assignments.value) {
        $target = $assignment.target
        if ($target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
            $hotpatchGroupIds += [PSCustomObject]@{
                PolicyName = $policy.displayName
                PolicyId   = $policy.id
                GroupId    = $target.groupId
            }
        }
    }
}

if (-not $hotpatchGroupIds) {
    Write-Host "No group assignments found for hotpatch policies. Exiting." -ForegroundColor Green
    Disconnect-MgGraph
    return
}

Write-Host "Hotpatch policies target the following groups:" -ForegroundColor Green
$hotpatchGroupIds | ForEach-Object {
    Write-Host "  - Policy: $($_.PolicyName) -> Group: $($_.GroupId)" -ForegroundColor White
}
Write-Host ""

# -----------------------------------------------
# 4. Get all configuration policies and find VBS-related ones
# -----------------------------------------------
Write-Host "Step 3: Searching for VBS/DeviceGuard configuration policies..." -ForegroundColor Yellow

# Search in Settings Catalog policies (configurationPolicies)
$configPolicies = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$top=100" `
    -OutputType PSObject

$vbsPolicyIds = @()

foreach ($cp in $configPolicies.value) {
    # Get settings for each policy to check for VBS/DeviceGuard settings
    $settings = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($cp.id)/settings" `
        -OutputType PSObject

    foreach ($setting in $settings.value) {
        $settingDef = $setting.settingInstance.settingDefinitionId
        if ($settingDef -match "deviceguard" -or $settingDef -match "virtualizationbasedtechnology") {
            $vbsPolicyIds += $cp.id
            Write-Host "  Found VBS policy: [$($cp.id)] $($cp.name)" -ForegroundColor Green
            break
        }
    }
}

# Also check Endpoint Protection profiles (deviceConfigurations)
$deviceConfigs = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$top=100" `
    -OutputType PSObject

foreach ($dc in $deviceConfigs.value) {
    $odataType = $dc.'@odata.type'
    # Check for Endpoint Protection profiles that may contain VBS settings
    if ($odataType -eq '#microsoft.graph.windows10EndpointProtectionConfiguration') {
        # These profiles can contain DeviceGuard/VBS settings
        if ($dc.dmaGuardDeviceEnumerationPolicy -or $dc.userRightsAccessCredentialManagerAsTrustedCaller) {
            $vbsPolicyIds += $dc.id
            Write-Host "  Found VBS-related Endpoint Protection profile: [$($dc.id)] $($dc.displayName)" -ForegroundColor Green
        }
    }
}

Write-Host ""

# -----------------------------------------------
# 5. Get group assignments for VBS policies
# -----------------------------------------------
Write-Host "Step 4: Retrieving VBS policy assignments..." -ForegroundColor Yellow

$vbsGroupIds = @()

foreach ($vbsPolicyId in ($vbsPolicyIds | Select-Object -Unique)) {
    # Try Settings Catalog assignments
    try {
        $vbsAssignments = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$vbsPolicyId/assignments" `
            -OutputType PSObject

        foreach ($assignment in $vbsAssignments.value) {
            $target = $assignment.target
            if ($target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                $vbsGroupIds += $target.groupId
            }
        }
    } catch {
        # Try deviceConfigurations assignments
        try {
            $vbsAssignments = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$vbsPolicyId/assignments" `
                -OutputType PSObject

            foreach ($assignment in $vbsAssignments.value) {
                $target = $assignment.target
                if ($target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                    $vbsGroupIds += $target.groupId
                }
            }
        } catch {
            Write-Host "  Could not retrieve assignments for policy $vbsPolicyId" -ForegroundColor DarkYellow
        }
    }
}

$vbsGroupIds = $vbsGroupIds | Select-Object -Unique

Write-Host "VBS policies target the following groups:" -ForegroundColor Green
$vbsGroupIds | ForEach-Object { Write-Host "  - Group: $_" -ForegroundColor White }
Write-Host ""

# -----------------------------------------------
# 6. Compare and report gaps
# -----------------------------------------------
Write-Host "Step 5: Identifying gaps..." -ForegroundColor Yellow
Write-Host "==========================================" -ForegroundColor Cyan

$gapsFound = $false

foreach ($hotpatchAssignment in $hotpatchGroupIds) {
    if ($hotpatchAssignment.GroupId -notin $vbsGroupIds) {
        $gapsFound = $true
        Write-Host "[GAP DETECTED]" -ForegroundColor Red -NoNewline
        Write-Host " Policy: '$($hotpatchAssignment.PolicyName)'" -ForegroundColor White
        Write-Host "  Group ID '$($hotpatchAssignment.GroupId)' is targeted by hotpatch but has NO VBS policy assigned." -ForegroundColor Red
        Write-Host ""
    }
}

if (-not $gapsFound) {
    Write-Host "[OK] All hotpatch-targeted groups also have a VBS configuration policy assigned." -ForegroundColor Green
} else {
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "RECOMMENDATION: Deploy a VBS enablement policy (DeviceGuard/EnableVirtualizationBasedSecurity)" -ForegroundColor Yellow
    Write-Host "to the identified groups to ensure hotpatch updates can be applied successfully." -ForegroundColor Yellow
}

Write-Host ""

# -----------------------------------------------
# 7. Disconnect
# -----------------------------------------------
Disconnect-MgGraph
Write-Host "Script completed." -ForegroundColor Cyan
