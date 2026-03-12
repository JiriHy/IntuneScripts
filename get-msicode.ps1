param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

if (-not (Test-Path $FilePath)) {
    Write-Error "File not found: $FilePath"
    exit 1
}

$msi = New-Object -ComObject WindowsInstaller.Installer
$database = $msi.OpenDatabase($FilePath, 0)
$view = $database.OpenView("SELECT Value FROM Property WHERE Property='ProductCode'")
$view.Execute()
$record = $view.Fetch()

if ($record) {
    $productCode = $record.StringData(1)
    Write-Output $productCode
} else {
    Write-Error "Could not retrieve MSI product code"
}

$view.Close()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($database) | Out-Null
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($msi) | Out-Null