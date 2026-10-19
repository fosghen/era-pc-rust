$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$version = ((Get-Content Cargo.toml | Select-String '^version = "([^"]+)"$').Matches.Groups[1].Value)
$name = "era-pc-rust-$version-windows-x64"
$dist = Join-Path $root 'dist'
$stage = Join-Path $dist $name
if (Test-Path $stage) { throw "Package staging directory already exists: $stage" }
New-Item -ItemType Directory -Path $stage | Out-Null
New-Item -ItemType Directory -Path "$stage/examples", "$stage/docs", "$stage/THIRD-PARTY" | Out-Null
Copy-Item target/x86_64-pc-windows-msvc/release/era-engine.exe $stage
Copy-Item examples/dispersion.json "$stage/examples"
Copy-Item examples/dispersion-search.json, examples/dispersion-reference.json "$stage/examples"
Copy-Item docs/DISPERSION.md "$stage/docs"
Copy-Item docs/VALIDATION.md "$stage/docs"
Copy-Item packaging/run-dispersion.cmd, packaging/README-WINDOWS.txt $stage
$sha = git rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'git rev-parse failed' }
"version=$version`ncommit=$sha`ntarget=x86_64-pc-windows-msvc`nrust=1.90.0`nstatus=experimental" |
    Set-Content -Encoding utf8 "$stage/BUILD.txt"

# Include upstream license notices for every pinned dependency (including build-time).
$metadataText = cargo +1.90.0 metadata --locked --format-version 1
if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
$metadata = $metadataText | ConvertFrom-Json
foreach ($package in $metadata.packages | Where-Object { $_.source }) {
    $source = Split-Path -Parent $package.manifest_path
    $destination = Join-Path "$stage/THIRD-PARTY" "$($package.name)-$($package.version)"
    $licenses = Get-ChildItem $source -File | Where-Object { $_.Name -match '^(LICENSE|COPYING|NOTICE)' }
    if (-not $licenses) { throw "Missing license notice for $($package.name)" }
    New-Item -ItemType Directory $destination | Out-Null
    $licenses | Copy-Item -Destination $destination
}

# Smoke-test the exact EXE included in the archive, without a vendor database.
$env:ERA_DATA = 'nonexistent-packaging-test-data'
$output = & "$stage/era-engine.exe" dispersion "$stage/examples/dispersion.json"
if ($LASTEXITCODE -ne 0) { throw 'Packaged EXE failed' }
$result = $output | ConvertFrom-Json
if ($result.receptors.Count -ne 5) { throw 'Wrong receptor count' }
if ([Math]::Abs($result.source_parameters[0].cm_mg_m3 - 0.02137663748860852) -gt 1e-12) {
    throw 'Windows numerical smoke test failed'
}
$archive = Join-Path $dist "$name.zip"
if (Test-Path $archive) { throw "Archive already exists: $archive" }
Compress-Archive -Path $stage -DestinationPath $archive
$hash = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $name.zip" | Set-Content -Encoding ascii "$archive.sha256"
Write-Output "Built and verified $archive"
