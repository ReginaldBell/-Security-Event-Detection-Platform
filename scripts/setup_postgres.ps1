param(
    [string]$PgBin = "C:\Program Files\PostgreSQL\18\bin",
    [string]$HostName = "localhost",
    [int]$Port = 5432,
    [string]$AdminUser = "postgres",
    [string]$AppUser = "securewatch",
    [string]$AppPassword = "securewatch",
    [string]$AppDatabase = "securewatch"
)

$ErrorActionPreference = "Stop"

$psql = Join-Path $PgBin "psql.exe"
$createdb = Join-Path $PgBin "createdb.exe"
$envPath = Join-Path (Get-Location) ".env"

if (!(Test-Path $psql)) {
    throw "psql.exe not found at $psql"
}
if (!(Test-Path $createdb)) {
    throw "createdb.exe not found at $createdb"
}

$adminPasswordPlain = $env:POSTGRES_ADMIN_PASSWORD
if (!$adminPasswordPlain -and (Test-Path $envPath)) {
    $adminPasswordPlain = Get-Content $envPath |
        Where-Object { $_ -match "^\s*POSTGRES_ADMIN_PASSWORD\s*=" } |
        Select-Object -First 1 |
        ForEach-Object { ($_ -split "=", 2)[1].Trim().Trim('"').Trim("'") }
}

$bstr = [IntPtr]::Zero
try {
    if ($adminPasswordPlain) {
        $env:PGPASSWORD = $adminPasswordPlain
    } else {
        $adminPassword = Read-Host "Postgres password for user '$AdminUser'" -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminPassword)
        $env:PGPASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }

    & $psql -h $HostName -p $Port -U $AdminUser -d postgres -v ON_ERROR_STOP=1 -c "DO `$`$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$AppUser') THEN CREATE ROLE $AppUser LOGIN PASSWORD '$AppPassword'; ELSE ALTER ROLE $AppUser WITH LOGIN PASSWORD '$AppPassword'; END IF; END `$`$;"

    $exists = & $psql -h $HostName -p $Port -U $AdminUser -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = '$AppDatabase';"
    $existsText = if ($null -eq $exists) { "" } else { ($exists -join "").Trim() }
    if ($existsText -ne "1") {
        & $createdb -h $HostName -p $Port -U $AdminUser -O $AppUser $AppDatabase
        Write-Host "Created database '$AppDatabase' owned by '$AppUser'."
    } else {
        Write-Host "Database '$AppDatabase' already exists."
    }

    Write-Host "SecureWatch database is ready."
    Write-Host "DATABASE_URL=postgresql+psycopg://$AppUser`:$AppPassword@$HostName`:$Port/$AppDatabase"
}
finally {
    $env:PGPASSWORD = $null
    if ($bstr -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    $adminPasswordPlain = $null
}
