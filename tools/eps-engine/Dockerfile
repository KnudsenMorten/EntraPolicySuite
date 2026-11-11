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
#   * base images PINNED BY DIGEST (a tag is a mutable pointer). To refresh: read the registry's digest for the tag
#     (HEAD https://mcr.microsoft.com/v2/<repo>/manifests/<tag> -> Docker-Content-Digest), replace it here.
#     IMAGE-PATCH-1 (framework, owner 2026-11-10: "we need to include this in the framework so we immediately patch images
#     when this happens"): every pin is refreshed weekly and at once on a fixable High / Critical finding, and the runtime
#     stage takes the OS security updates at build (apt-get upgrade only - no package is ever added), so an image built today
#     carries today's fixed packages even when the base tag has not moved. Refreshed 2026-11-10.
#   * IMAGE-PATCH-1 point 0 (owner 2026-11-10: "this is very critical and approved. each solution must move to .net 10 +
#     latest ps you mentioned"; "i dont understand why we download ps from ms if it is included in image"): .NET 8 and
#     PowerShell 7.4 reached end of support on 2026-11-10. Every stage is mcr.microsoft.com/dotnet/sdk:10.0-noble by
#     digest - it SHIPS PowerShell 7.6 LTS and the .NET team rebuilds it on every security update. No package is
#     installed; the build FAILS unless pwsh reports 7.6.x.
#   * the solution tree is PRUNED in a build stage (tests, fixtures, internal, output, docs never reach a layer).
#   * the image runs as a NON-ROOT user (uid/gid 10001). It writes only to the temp directory.
# tests/Test-EpsContainerImage.ps1 checks every one of these rules.

# ---- stage 1: the pinned SQL driver assembly (no PS module) ----
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e AS sqldriver
WORKDIR /drv
RUN dotnet new classlib -n shim -o shim \
 && cd shim \
 && dotnet add package Microsoft.Data.SqlClient --version 5.2.2 \
 && dotnet publish -c Release -o /drv/out \
 && test -f /usr/share/zoneinfo/Europe/Copenhagen

# ---- stage 2: the solution tree, pruned to what runs in a container ----
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e AS src
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
 && for f in EPS-Conditions EPS-TagEngine EPS-FastEval EPS-V1Import EPS-SqlStore EPS-Guard EPS-Graph EPS-Exchange EPS-TagJob EPS-Scheduler EPS-TamperMonitor EPS-HybridWorker EPS-WorkerPage EPS-Mail EPS-WebAuth EPS-Audit EPS-Settings EPS-Rules EPS-CaAnalyzer EPS-CaManage EPS-CaWrite EPS-CaOptions EPS-Backup EPS-Onboarding EPS-GroupManage EPS-GroupWrite EPS-OnboardManage EPS-OnboardWrite EPS-IdentityReport EPS-SignInMethods EPS-LogAnalytics EPS-WebApi EPS-ConfigEngine EPS-Uplink EPS-Updater EPS-UpdateApply EPS-SupportAccess EPS-Arm EPS-DbInit EPS-Install EPS-InstallWeb EPS-InstallNetwork EPS-JobRename InvardiaUpdate.verify EPS-Licence EPS-SupportRead EPS-Watchdog; do test -f engine/_shared/$f.ps1; done

# ---- stage 3: runtime ----
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e

# IMAGE-PATCH-1: the OS security updates at build (the base tag has not moved since it was pinned, its packages have).
# Upgrade only - no package is added; the package lists are removed so no apt state ships in the layer.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && pwsh -NoLogo -NoProfile -NonInteractive -Command '$v = $PSVersionTable.PSVersion; if ($v.Major -ne 7 -or $v.Minor -ne 6) { throw "PowerShell $v, not 7.6 LTS" }; if ([Environment]::Version.Major -ne 10) { throw ".NET $([Environment]::Version), not 10" }; Write-Host "PowerShell $v on .NET $([Environment]::Version)"'

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
