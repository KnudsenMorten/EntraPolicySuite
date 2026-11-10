# EntraPolicySuite 2.0 -- ONE image for everything (DESIGN §2): the tick job and every work job run
# tools/eps-engine/job-entry.ps1 and differ only by EPS_JOB; the web app is EPS_JOB = Web (tools/eps-web, behind the
# shared sign-in front, which is its own pinned image in the same revision).
# Built in the customer's own registry (ACR Basic; az acr build / the registry's build task - nothing is built on a workstation).
#
# Build context = repo root:
#   docker build -f SOLUTIONS/EntraPolicySuite/tools/eps-engine/Dockerfile -t <acr>/eps-engine:<version> .
#
# PIM's image rules, copied (tools/pim-manager/Dockerfile):
#   * REST only, NO PowerShell module and no az CLI (framework NO-AZ). The SQL data plane has no REST API, so the TDS
#     driver is a pinned .NET ASSEMBLY (Microsoft.Data.SqlClient), not a module - EPS-SqlStore Add-Types it from
#     $env:EPS_SQLCLIENT_DLL. The gallery tooling is removed, so a module cannot even be installed at runtime.
#   * base images PINNED BY DIGEST (a tag is a mutable pointer); the same digests PIM vetted 2026-09-18. To refresh:
#     read the registry's digest for the tag (docker buildx imagetools inspect <image>:<tag>), replace it here.
#   * the solution tree is PRUNED in a build stage (tests, fixtures, internal, output, docs never reach a layer).
#   * the image runs as a NON-ROOT user (uid/gid 10001). It writes only to the temp directory.
# tests/Test-EpsContainerImage.ps1 checks every one of these rules.

# ---- stage 1: the pinned SQL driver assembly (no PS module) ----
FROM mcr.microsoft.com/dotnet/sdk:8.0@sha256:5ef85cc12cb25be6ec319a7392d1e9efd53c3bc8abb971c53d8058a473f09053 AS sqldriver
WORKDIR /drv
RUN dotnet new classlib -n shim -o shim \
 && cd shim \
 && dotnet add package Microsoft.Data.SqlClient --version 5.2.2 \
 && dotnet publish -c Release -o /drv/out \
 && test -f /usr/share/zoneinfo/Europe/Copenhagen

# ---- stage 2: the solution tree, pruned to what runs in a container ----
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04@sha256:62300a213a9293916333df2b014cd3a8f22fb0b0b65f2bb446aaf436bcf8c868 AS src
COPY SOLUTIONS/EntraPolicySuite /src/EntraPolicySuite
WORKDIR /src/EntraPolicySuite
RUN rm -rf tests internal output docs CLAUDE.md \
 && test -f VERSION \
 && test -f tools/eps-engine/job-entry.ps1 \
 && test -f tools/eps-web/Start-EpsWeb.ps1 \
 && test -f tools/eps-web/www/index.html \
 && test -f sql/eps-schema.sql \
 && test -f engine/conditions/catalog.json \
 && test -f engine/settings/catalog.json \
 && test -f engine/ca/templates.json \
 && test -f engine/ca/graph-enums.json \
 && test -f engine/onboarding/defaults.json \
 && for f in EPS-Conditions EPS-TagEngine EPS-FastEval EPS-V1Import EPS-SqlStore EPS-Guard EPS-Graph EPS-Exchange EPS-TagJob EPS-Scheduler EPS-TamperMonitor EPS-HybridWorker EPS-WorkerPage EPS-Mail EPS-WebAuth EPS-Audit EPS-Settings EPS-Rules EPS-CaAnalyzer EPS-CaManage EPS-CaWrite EPS-CaOptions EPS-Backup EPS-Onboarding EPS-GroupManage EPS-GroupWrite EPS-OnboardManage EPS-OnboardWrite EPS-IdentityReport EPS-SignInMethods EPS-LogAnalytics EPS-WebApi EPS-ConfigEngine EPS-Uplink EPS-Updater EPS-UpdateApply EPS-SupportAccess EPS-Arm EPS-DbInit EPS-Install EPS-InstallWeb EPS-InstallNetwork EPS-JobRename InvardiaUpdate.verify EPS-Licence EPS-SupportRead; do test -f engine/_shared/$f.ps1; done

# ---- stage 3: runtime ----
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04@sha256:62300a213a9293916333df2b014cd3a8f22fb0b0b65f2bb446aaf436bcf8c868

# NO gallery / SDK module and NO az CLI in the image (framework NO-AZ, PIM §100.52): the gallery tooling and PSReadLine
# are removed; the build FAILS if any banned module or an az binary is still there.
RUN pwsh -NoLogo -NoProfile -NonInteractive -Command '$ErrorActionPreference = "Stop"; \
    $drop = @("PowerShellGet", "PackageManagement", "Microsoft.PowerShell.PSResourceGet", "PSReadLine"); \
    $isBanned = { param($n) ($drop -contains $n) -or ($n -like "Az") -or ($n -like "Az.*") -or ($n -like "Microsoft.Graph*") -or ($n -like "ExchangeOnline*") -or ($n -like "SqlServer*") -or ($n -like "ActiveDirectory*") }; \
    foreach ($p in @($env:PSModulePath -split ":" | Where-Object { $_ -and (Test-Path -LiteralPath $_) })) { \
        Get-ChildItem -LiteralPath $p -Directory | Where-Object { & $isBanned $_.Name } | Remove-Item -Recurse -Force }; \
    $left = @(Get-Module -ListAvailable | Where-Object { & $isBanned $_.Name } | ForEach-Object { $_.Name } | Sort-Object -Unique); \
    if ($left.Count) { throw ("modules still in the image: " + ($left -join ", ")) }; \
    if (Get-Command az -CommandType Application -ErrorAction SilentlyContinue) { throw "the az CLI is in the image" }; \
    Write-Host "module strip ok"'

RUN groupadd --system --gid 10001 eps \
 && useradd --system --uid 10001 --gid 10001 --create-home --home-dir /home/eps --shell /usr/sbin/nologin eps \
 && mkdir -p /app && chown -R 10001:10001 /app

COPY --from=sqldriver /drv/out/*.dll /opt/sqlclient/
ENV EPS_SQLCLIENT_DLL=/opt/sqlclient/Microsoft.Data.SqlClient.dll

# the time-zone database: the PowerShell base image has none, so a 'daily 01:00' schedule in Platform.TimeZone
# (e.g. Europe/Copenhagen) could not be computed (found live 2026-10-31: "schedule error ... not found"). Copied from
# the pinned SDK stage - no package install, the build stays pinned.
COPY --from=sqldriver /usr/share/zoneinfo /usr/share/zoneinfo

WORKDIR /app
COPY --from=src --chown=10001:10001 /src/EntraPolicySuite /app/EntraPolicySuite
ENV HOME=/home/eps

# the version the image was built from, so the updater can tell whether a rebuild is needed
ARG EPS_CONTENT_HASH=""
ENV EPS_CONTENT_HASH=$EPS_CONTENT_HASH

USER 10001:10001
ENTRYPOINT ["pwsh","-NoProfile","-NonInteractive","-File","/app/EntraPolicySuite/tools/eps-engine/job-entry.ps1"]
