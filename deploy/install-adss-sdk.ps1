<#
.SYNOPSIS
  Installs the licensed ADSS Client SDK jar into the local Maven repository.

.DESCRIPTION
  The ADSS Client SDK is not published to Maven Central, so it must be installed
  once before the orchestrator can be built. This is the Windows counterpart of
  deploy/install-adss-sdk.sh.

.PARAMETER SdkDir
  The JAVAsdk directory containing API\lib\adss_client_api.jar.
  Defaults to the parent of this project.

.EXAMPLE
  .\deploy\install-adss-sdk.ps1
#>
[CmdletBinding()]
param(
    [string]$SdkDir
)

$ErrorActionPreference = 'Stop'

$projectDir = Split-Path -Parent $PSScriptRoot
if (-not $SdkDir) { $SdkDir = Split-Path -Parent $projectDir }

$groupId = 'com.ascertia'
$artifactId = 'adss-client-api'

if (-not (Get-Command mvn -ErrorAction SilentlyContinue)) {
    throw "Maven 3.9+ is required but 'mvn' is not on PATH."
}

$jar = Join-Path $SdkDir 'API\lib\adss_client_api.jar'
if (-not (Test-Path $jar)) {
    throw "Cannot find $jar. Pass -SdkDir with the JAVAsdk directory."
}

# Derive the version from the SDK's own version file so the pom and the jar
# never drift apart.
$versionFile = Join-Path $SdkDir 'adss-clientsdk.version'
if (Test-Path $versionFile) {
    $props = @{}
    Get-Content $versionFile | ForEach-Object {
        if ($_ -match '^\s*([A-Z_]+)=(.*)$') { $props[$Matches[1]] = $Matches[2].Trim() }
    }
    $version = '{0}.{1}.{2}' -f $props['ADSS_CLIENTSDK_MAJOR_VERSION'],
                                $props['ADSS_CLIENTSDK_MINOR_VERSION'],
                                $props['ADSS_CLIENTSDK_PATCH_LEVEL']
} else {
    $version = '8.3.7'
}

$pom = Get-Content (Join-Path $projectDir 'pom.xml') -Raw
if ($pom -match '<adss\.sdk\.version>([^<]+)</adss\.sdk\.version>') {
    $pomVersion = $Matches[1]
    if ($pomVersion -ne $version) {
        throw "SDK version mismatch: the jar is $version but pom.xml expects $pomVersion. Update <adss.sdk.version> in pom.xml."
    }
}

# Verify the shipped checksum when the SDK provides one.
$checksumFile = "$jar.SHA-256"
if (Test-Path $checksumFile) {
    $expected = (Get-Content $checksumFile -Raw).Trim()
    $actual = (Get-FileHash $jar -Algorithm SHA256).Hash
    if ($expected -and ($expected.ToLower() -ne $actual.ToLower())) {
        throw "Checksum mismatch for $jar. Do not install this jar."
    }
    Write-Host "[ok] Checksum verified" -ForegroundColor Green
}

& mvn -B org.apache.maven.plugins:maven-install-plugin:3.1.2:install-file `
    "-Dfile=$jar" `
    "-DgroupId=$groupId" `
    "-DartifactId=$artifactId" `
    "-Dversion=$version" `
    "-Dpackaging=jar"

if ($LASTEXITCODE -ne 0) { throw "mvn install-file failed with exit code $LASTEXITCODE" }

Write-Host "[ok] Installed ${groupId}:${artifactId}:${version} into the local Maven repository" -ForegroundColor Green
Write-Host "[ok] Now run:  cd `"$projectDir`"; mvn -B clean package" -ForegroundColor Green
