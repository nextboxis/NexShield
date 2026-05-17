try {
    attrib -r 'data\nexshield_db.json' -ErrorAction SilentlyContinue
    New-Item -Path 'data\backups' -ItemType Directory -Force | Out-Null
    $t = Get-Date -Format 'yyyyMMdd_HHmmss'
    $dest = "data/backups/nexshield_db_moved_$t.json"
    Copy-Item -Path 'data\nexshield_db.json' -Destination $dest -Force -ErrorAction Stop
    Remove-Item -LiteralPath 'data\nexshield_db.json' -Force -ErrorAction SilentlyContinue
    Write-Host 'Backup success:' $dest
} catch {
    Write-Host 'Backup/move failed:' $_.Exception.Message
    exit 1
}