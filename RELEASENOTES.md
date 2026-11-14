# Entra Policy Suite 2.0 - release notes

v1 (the scripts) stays on the `v1` branch with its releases v1.0.1 and v1.0.2.

## 2.1.31 - Security updates from Microsoft install faster
Builds on the owner's decision: "we need to fix images in fast lane" (2026-11-14, relayed by Invardia, framework SEC-LANE-1)
- New: a security update that only moves your installation onto Microsoft's newest images (the same code) installs at once:
  it does not wait for running jobs and has no database step. A job that is running keeps going and the next run uses the
  new image.
- New: once a job has succeeded on the new image, the previous images are removed from your registry.
- New: your installation reports which image each job and the web app run (with its .NET version) to Invardia support, so
  support can see that every installation is patched.
- Fix: the image build no longer fails when the version file ends with a line break.
## 2.1.30 - A stopped update is reported to Invardia support at once
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "stability + data quality is prio 1" (2026-11-12, relayed by Invardia)
- Fix: when an update stops while preparing the new version, your installation now tells Invardia support right away.
  Before, it waited for its next scheduled report, up to four hours later.
- Fix: a security update numbered with a fourth part (for example 2.1.28.2) is recognised by the update check the same way in every Invardia product.
## 2.1.28.2 - Security update for the sign-in page
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "Approve 2.1.28.1 for rings 2/3" (2026-11-14, relayed by Invardia, framework SEC-LANE-1)
- Security update: the web app's sign-in front moves to 2.1.2 - its ASP.NET Core packages are on Microsoft's security release 10.0.15. The same engine code as 2.1.28.
- Fix: 2.1.28.1 could not be installed - the update stopped while preparing the new version and the installation kept running 2.1.28. This version installs.
## 2.1.28.1 - Security update: Microsoft's newest base image (IMAGE-PATCH)
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "Approve 2.1.28.1 for rings 2/3" (2026-11-14, relayed by Invardia, framework SEC-LANE-1)
- Security update: the web app's sign-in front moves to 2.1.2 - its ASP.NET Core packages are on Microsoft's security release 10.0.15. The same engine code as 2.1.28.
- Nothing else changes: no feature, setting, permission or database change. Your installation updates by itself.

## 2.1.28 - A group-scoped test run never quietly covers fewer people
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "stability + data quality is prio 1" (2026-11-12, relayed by Invardia)
- Fix: a tagging run limited to the members of an Entra group now stops with the reason when that group name matches
  more than one group (or its remembered group was deleted) - nothing is evaluated or written - instead of running on
  fewer people than asked and saying the group is not in the tenant.
- Fix: a rule's list of matched people from an earlier run no longer disappears when a later run failed or matched
  nobody.
- Fix: an update that sends a change to Azure again after no answer sends it at most once more in all, also when Azure
  asks it to slow down in between.
## 2.1.27 - An update that cannot prepare the new version is reported at once
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "stability + data quality is prio 1" (2026-11-12, relayed by Invardia)
- Fix: when an update stops while preparing the new version, your installation keeps running its current version and
  Invardia support is now told at once, instead of only after the same problem repeated several times.
## 2.1.26 - Pro installations update to the newest version again
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "stability + data quality is prio 1" (2026-11-12, relayed by Invardia)
- Fix: a Pro installation could not install 2.1.24 or 2.1.25 - its update stopped while preparing the new version and
  the installation kept running the version before. Pro installations now update again, straight to this version.
  Community installations were not affected.
- Fix: the release notes describe each fix by what you see, in plain words.
## 2.1.25 - An update that could not check its release again says so, and tries again
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "stability + data quality is prio 1" (2026-11-12, relayed by Invardia)
- Fix: just before it installs, an update checks its release once more. When Invardia does not answer that check, it
  now asks again once, a few seconds later, instead of stopping at once.
- Fix: when the update still cannot confirm its release, its run now says exactly that and it tries again within the
  hour. Before, it said it had waited for running jobs, even when none were running.
## 2.1.24 - What's new in the app
Builds on the owner's decision: "all solutions have a whats new which is human friendly info from release notes. structure in fix and new features must be in gui" / "include all releases. newest first" (2026-11-13, relayed by Invardia, framework WHATS-NEW-1)
- New: Help > What's new shows every release of Entra Policy Suite, newest first, in plain words: what is new and what was
  fixed, with anything you need to do shown first. A "New" badge on the menu shows after an update until you open the page.
- New: the same text is on GitHub (WHATSNEW.md) and on invardia.com.
## 2.1.23 - The hybrid worker catches up with an update sooner
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "stability + data quality is prio 1" (2026-11-12, relayed by Invardia)
- Fix: when the hybrid worker checks for its update while your installation is still updating, it now checks again 10
  minutes later instead of an hour later. It still only takes the version your installation runs.
## 2.1.22 - The admin views say when the admin list may be incomplete
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "stability + data quality is prio 1" (2026-11-12, relayed by Invardia)
- Fix: when the identity report could not read some role groups, the admin views and the Admin column now say "May be
  incomplete" with how many groups could not be read, instead of looking complete.
## 2.1.21 - AD tag changes are never left waiting without work for the hybrid worker
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "stability + data quality is prio 1" (2026-11-12, relayed by Invardia)
- Fix: when recording the outcome of a large tagging run stopped part way, the AD changes already marked as waiting for
  the hybrid worker could be left without the work the worker takes, so they were never written. They now always get it,
  and a change is never queued twice.
- Fix: when that work cannot be queued, the tagging run, the undo and the tamper restore now end as failed with the
  reason, instead of reporting success with changes nobody writes.
- Fix: an undo that cannot record its outcome now ends as failed with the reason at once, and the undo's answer on the
  page says why.
## 2.1.20 - The hybrid worker never leaves an older tag value in AD
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "stability + data quality is prio 1" (2026-11-12, relayed by Invardia)
- Fix: the hybrid worker now writes tag changes to on-premises AD in the order they were queued. When a newer value for
  the same user and attribute is already written or waiting, the older one is skipped and never written, so an older
  value can no longer end up in AD after a newer one. The worker page shows why it was skipped.
- Fix: "Try again" on a failed AD tag change is refused when a newer value for that user and attribute is already
  written or waiting, and a tamper restore waits until a newer queued tag value is written.
- Fix: two hybrid workers taking work at the same time no longer risk blocking each other.
## 2.1.19 - A dropped connection no longer fails a report, and a tag restore goes through the right directory
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "stability + data quality is prio 1" (2026-11-12, relayed by Invardia)
- Fix: when a read from Microsoft Graph or Exchange Online gets no answer at all (for example a connection that could
  not be set up), it is sent once more after a few seconds instead of failing the whole run. Only reads are sent again,
  never a change.
- Fix: a job run that fails now always says why in its run record, not only in its log.
- Fix: restoring a tampered tag on a user that is synced from on-premises AD is now written by the hybrid worker in AD,
  as tagging does. The tamper event stays open until the restored value is read back; if the worker cannot write it,
  the event says so.
- Fix: restoring a tampered tag on a mail-enabled cloud user now uses the Exchange Online path when Entra refuses the
  change, as tagging does.
## 2.1.18 - Finishing an interrupted update no longer rebuilds it
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "stability + data quality is prio 1" (2026-11-12, relayed by Invardia)
- Fix: when an update that stopped part way is finished, it only moves the parts left behind. The image is not built
  again and the database step is not repeated, because both were already done.
- Fix: when Azure is still busy with a request that was sent once more, the update waits for it (at most 5 minutes)
  instead of stopping.
- Fix: a request that Azure did not answer and that was sent once more is now shown in the update's run log and run
  summary.
## 2.1.17 - An update that is interrupted by Azure finishes within minutes
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "stability + data quality is prio 1" (2026-11-12, relayed by Invardia)
- Fix: when Azure does not answer a request during an update, the update sends that request once more instead of
  stopping. Starting a job is never sent twice.
- Fix: when an update still stops part way, the next check (within minutes) finishes it, instead of leaving some parts
  on the new version and some on the old one until the next update. While that lasts, the update's run says which
  parts are on which version, and which part it stopped at.
## 2.1.16 - Undo and restore are recorded before they change anything, and a repeating analyzer problem is reported once
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "only send in data for the latest collection that completed" / "it should be possible to include new rules and it must never break the pipeline" (2026-11-12, relayed by Invardia, framework TRUST-1)
- Fix: undoing a tagging run and restoring a tampered tag now record each change before it is made, then its outcome -
  as tagging itself does since 2.1.15 - so a change is never made without a record of it.
- Fix: when the CA Policy Analyzer cannot evaluate some users, the run says how many, and when that repeats run after run
  it is reported to Invardia support as one item, not once per run.
- Fix: whether a partial CA Policy Analyzer run is only partial because of its sign-in limit is now recorded as such,
  instead of being read from the wording of its log.
## 2.1.15 - Reports never show partial results as complete, and tagging changes are recorded before they are made
Builds on the owner's decision: "only send in data for the latest collection that completed" / "it should be possible to include new rules and it must never break the pipeline" (2026-11-12, relayed by Invardia, framework TRUST-1)
- Fix: a CA Policy Analyzer run that could not evaluate every user, or that reached its sign-in limit, is now marked as
  partial. Its results are kept, but each policy page keeps showing the last complete analysis with its date. Its alert
  mail still goes out and says in its first line that the run is partial and how many sign-ins were read - the number of
  impacted users is then "at least" that many.
- Fix: when the review of a Conditional Access policy fails, the policy keeps its last review (with the date it was made)
  as long as the policy itself has not changed.
- Fix: when a group that holds an Entra role cannot be read, the identity report says that its members' admin role is
  unknown, instead of showing them as having no role.
- Fix: when the Intune devices cannot be read although the right for it is one Entra Policy Suite uses, the identity
  report run is partial: nothing from it is shown and the report keeps its last complete run. Grant the right again and
  the next run is complete.
- Fix: when a break-glass account cannot be found, the Conditional Access monitor says the check cannot run and names
  the account. A policy that leaves out an account that IS found is still reported as a lock-out risk.
- Fix: when two Entra groups share the name a tagging rule uses, or the group the rule was linked to is gone, the tags
  that depend on it are left as they are instead of falling back to the default value.
- Fix: a v1 rule that uses a condition type that does not exist is no longer imported; the import plan names it. A rule
  like that which is already stored stays as it is.
- Fix: user and device tagging now records each change before it is made and then marks its outcome, so a change is never
  made without a record of it. The engine gets one new database right for this.
- Fix: every request Entra Policy Suite sends to Microsoft Graph and Azure now carries its text as UTF-8 and says so.
  Microsoft has started to refuse mails whose text has characters such as æ, ø or å when they were not sent that way.
## 2.1.14 - A source that cannot be read never changes a tag, and a check that cannot run never clears a finding
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "only send in data for the latest collection that completed" / "it should be possible to include new rules and it must never break the pipeline" (2026-11-12, relayed by Invardia, framework TRUST-1)
- Fix: when user or device tagging could not read a source a rule needs (for example AD group membership from the
  hybrid worker, Entra group membership, Exchange recipients or the licence list), the rule was treated as "no match"
  and the next rule or the fallback value was written. Now such a tag is left exactly as it is - no new value and no
  fallback - and each one is named on the run's changes page as "Unknown". Every other tag is applied as usual and the
  run still ends OK. If the source itself fails to read, only the rules that need it are affected.
- Fix: a rule whose condition fails (an invalid pattern, a condition that errors or a condition type that does not
  exist) no longer stops the whole run: that rule's tags are left as they are and named, the rest of the run goes on.
- Fix: an open Conditional Access finding stays open until a run confirms it again. Until then it is marked "awaiting
  a re-check since" with the date.
- These cases are reported with a stable warning code in the run's report to Invardia support, so they are followed up.
## 2.1.13 - The image clean-up keeps the scan results and signatures of the images it keeps
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "prune images must be part of the framework" / "we cannot loose a single row of data. stability + data quality is prio 1" (2026-11-12, relayed by Invardia, framework IMAGE-PRUNE CONTRACT)
- Fix: Microsoft Defender for Cloud attaches its scan results (and a signature on them) to each image in your registry.
  The clean-up now keeps these for every image it keeps, instead of treating them as old leftovers. Images that are
  removed take their own scan results with them.
## 2.1.12 - The image clean-up keeps everything your installation runs or needs, and says what it does as it does it
Builds on the owner's decision: "prune images must be part of the framework" / "we cannot loose a single row of data. stability + data quality is prio 1" (2026-11-12, relayed by Invardia, framework IMAGE-PRUNE CONTRACT)
- What is kept is now decided from what your installation records, not from version numbers: every image a job, the
  web app or an active revision ran before the update and runs after it, the images named in the last update's
  release record, every part of a multi-platform image and every image another kept image is built on. If any of this
  cannot be read, nothing is deleted in that repository and the next update tries again.
- Before the first image is deleted, the update writes a release record (what the new version runs and what the
  previous one ran) to the database and reads it back; if it cannot, nothing is deleted.
- The run log says, per repository and as it happens, how many images there are, how many are kept and why, how many
  will be deleted, and afterwards how many were deleted and how many are left. These lines are kept at every log level.
  The totals also go to the audit trail and to the update's report to Invardia.
- At most 100 images per repository are deleted in one update; a larger backlog continues at the next update.
- Invardia support can switch the clean-up off for an installation (`EPS_Updater_ImagePrune = off` on the update job);
  an installation run keeps that setting.
- Note: the clean-up runs in the update job that installs the next version, so this behaviour starts with the update
  after 2.1.12.
## 2.1.11 - Old images are removed from your registry after each update
Builds on the owner's decision: "why woud we need to keep old images" - "agreed" (2026-11-12, relayed by Invardia, framework IMAGE-PATCH-1 IMAGE-PRUNE)
- After an update has installed and every job and the web app read back healthy on the new version, the update job
  deletes the older Entra Policy Suite images from your installation's own container registry. It keeps the image you
  run now and the one before it (for a rollback one version down); an older version is rebuilt from its release when
  needed. Microsoft Defender for Cloud scans every image stored in a registry, so old images kept showing
  vulnerabilities that the running version no longer has.
- Only the installation's own images (the engine and the sign-in front) in its own registry are touched; nothing is
  deleted before the new version reads back healthy. The run and the audit trail say how many were deleted and kept.
## 2.1.10 - Mails name the environment by its handle
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "What eng is this" (2026-11-12, relayed by Invardia, framework MAIL-ENV 12.11a)
- Fix: 2.1.9 named the environment by its display name, which can be just "PROD". Every mail now names it by its handle,
  as Invardia holds it - for example "[PROD] contoso-prod - Warning: ..." - and adds the display name only when it says
  more than the handle.
## 2.1.9 - Every mail says which environment sent it
Builds on the owner's decision: "What eng is this" (2026-11-12, relayed by Invardia, framework MAIL-ENV 12.11a)
- Every mail Entra Policy Suite sends (tamper alerts, CA monitor and CA Policy Analyzer alerts, the identity report, the
  passkey rollout, the test mail) now starts with its environment: the subject reads for example
  "[PROD] internal - Warning: ..." and the first line of the mail names the environment and the tenant (name and id).
  The name is the one Invardia holds for your environment; an installation not connected to Invardia uses its own name.
- When the tenant name is not set in Settings, the mail uses your directory's own display name.
- The Invardia support link now also reports how healthy the database statistics are (whether they refresh in the
  background, the share that is out of date, and when they were last refreshed), so a slow page is caught early.
## 2.1.8 - Connect a Community installation to Invardia, only if you say yes
Builds on the owner's decision: "Ask at install (opt-in)" (2026-11-11, relayed by Invardia)
- The install asks once: "Connect this install to Invardia: health reports + updates on request?" The answer is no
  unless you type y. Answer it ahead with `-ConnectToInvardia yes` or `-ConnectToInvardia no`; a re-run keeps a yes,
  and `-ConnectToInvardia no` takes it back.
- Yes: at its next update run the installation gets its own key from Invardia (no licence needed). It then sends the
  support link's health reports (numbers and states only - never a user, device, tag value or name) and can be asked
  by Invardia to update now.
- No (the default): nothing changes - the installation stays anonymous.
## 2.1.7 - A Community installation sends Invardia nothing unless you say yes
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "Ask at install (opt-in)" (2026-11-11, relayed by Invardia)
- Fix: 2.1.6 let a Community installation check its edition with Invardia once a day (tenant id, install id and
  version) without asking you. A Community installation now sends nothing for it - it simply runs the free features -
  unless you said yes at install to connect it to Invardia. Pro installations are unchanged.
- Everything else in 2.1.6 stays: the real edition on the resource group, the support link prepared at install, and the
  update job run right after the install.

## 2.1.6 - Pro and Community installations are set up the same way
Builds on the owner's decision: "it must be same pro community, dont get it" (2026-11-11, relayed by Invardia, framework PRO-COMMUNITY-SAME)
- Fix: every installation's resource group was tagged edition=community, Pro included. It now carries the real edition.
- Fix: a Community installation prepares the Invardia support link the same way as Pro (the place for its key and the
  engine's right to read it are made at install), so the link works without running the install again.
- Fix: every installation runs its update job right after the install, not only Pro - it is current at once.
- Every installation checks its edition with Invardia the same way, once a day: a Community installation is told it is
  Community (the free features) - no request and no mail on Invardia's side; a licence or trial for your tenant still
  arrives by itself.
- Only the licensed features and where the package comes from differ between Pro and Community.

## 2.1.5 - Ready for same-day security patches of Microsoft's base images
Builds on the owner's decision: "make sure it is consistent cross all solutions" (2026-11-11, relayed by Invardia, framework IMAGE-PATCH-1)
- Your installation, its update and its hybrid worker now accept a security patch numbered with four parts (for
  example 2.1.5.1). When Microsoft publishes a new base image with security fixes, Invardia releases it as such a patch
  - the same code on the new image - and it reaches your installation within a day, without waiting for the next release.
- The update check is the same one PIM Manager uses (3.1.8), so every Invardia product reads these versions alike.

## 2.1.4 - Security fix: the engine and the sign-in front run on .NET 10.0.15
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "this is very critical and approved. each solution must move to .net 10 + latest ps you mentioned" (2026-11-10, relayed by Invardia, framework IMAGE-PATCH-1 point 0)
- Security fix: the engine's container image moves to .NET 10.0.15 (Microsoft's image of 10 November 2026). It carries
  Microsoft's latest security fixes for the .NET runtime.
- Security fix: the web app's sign-in front moves to 2.1.1 - the same fix, on .NET 10.0.15, the front every Invardia product
  runs. Signing in works as before.
- Nothing else changes: no feature, setting, permission or database change. Your installation updates by itself.

## 2.1.3 - An update held back by running jobs is tried again within the hour
FIX-ONLY: defects only - no feature, right, setting or schema change
Builds on the owner's decision: "alignment is crucial" (2026-11-10)
- Fix: when the nightly update had to wait for running jobs and gave up, it waited a whole day for the next night.
  Now the installation tries again every hour until the update is installed, for at most 24 hours. If it has to give up
  3 times in a row, Invardia support is told at once. Nothing changes while a job runs - the update still installs only
  between runs.
- The update's message says what happens next ("tries again within the hour") instead of "retries next night".
- Fix: the hybrid worker's check that it may write the tag attributes in Active Directory failed as a whole when a rule
  writes an attribute your AD schema does not have (an AD without the Exchange schema has no extensionAttribute1-15
  unless added). Get started now shows that attribute as missing, with what to do, and checks the others.

## 2.1.2 - Key Vault and updater checks in Get started
Builds on the owner's decision: "alignment is crucial" (2026-11-10)
- New in Get started: two checks of your installation's Key Vault, read by the update job every night - purge protection
  is on, and every secret Entra Policy Suite uses is in Key Vault (none in app settings or job definitions). The check
  names a count, never a secret.
- Invardia support now sees when your updater last ran and whether it installed a release, found nothing to do, or
  failed - so an installation that stopped updating is noticed.

## 2.1.1 - The hybrid worker keeps up with your installation
Builds on the owner's decision: "alignment is crucial" (2026-11-10)
- Fix: the hybrid worker could stay on an old version. Its update followed the version your installation ran BEFORE its
  last nightly update, so after every update night it waited another day. The installation now keeps its running
  version current for the worker every 5 minutes.
- The worker checks for its update every hour instead of once a day at 05:30. A worker installed earlier switches its own
  task to every hour after its next update; nothing to do on the server.
- With the worker current, its check that it may write the tag attributes in Active Directory is answered again, and the
  Get started step shows ok or missing instead of unknown.

## 2.1.0 - Entra Policy Suite 2.1
Builds on the owner's decision: "maybe it is time to move version, we had it in the framework. we did large upd today" (2026-11-10)
Entra Policy Suite 2.1 is a minor release: nothing breaks and there is nothing to do. Your installation updates from
2.0 by itself, on its ring, like every update.
- New since 2.0.120: the engine runs on .NET 10 and PowerShell 7.6 on Microsoft's own container image, and the web
  app's sign-in front on .NET 10.
- New since 2.0.123: a job that hangs is caught, stopped and started once more, and Invardia support is told at once
  (error code eps-run-0101).
- New since 2.0.124: the job that reports to Invardia is the Invardia support link; one report that could not be
  delivered no longer turns it amber, and you are never mailed about it.
- What 2.0 brought, and 2.1 carries on: Conditional Access management (the template library, adopting your policies,
  the stage lifecycle, monitors and the CA Policy Analyzer), user and device tagging with the Rules grid, test runs, the
  commit queue and undo, the identity report, the tamper monitor and alert mail, named locations from Azure service tags,
  nightly backups, the hybrid worker for Active Directory, the private network install, and updates that install
  themselves on your ring.

## 2.0.125 - The Invardia support link name in the run log and the on/off setting
Builds on the owner's decision: "must go into all solutions" (2026-11-10, the Invardia support link rule)
- The run log of the Invardia support link now names it that way ("Invardia support link: ..."), not "uplink".
- Its on/off setting is labelled Invardia support link and says what turning it off means: it stops all reports to
  Invardia support.

## 2.0.124 - The Invardia support link: its own name, and no alarm for one missed report
Builds on the owner's decision: "must go into all solutions" (2026-11-10, the Invardia support link rule)
- The job that reports to Invardia is now called the Invardia support link on the Jobs page, the overview, the settings
  and in the documentation. It sends Entra Policy Suite's health and run results to Invardia support, so support can see
  problems and updates can roll out. It is not a link to another tenant.
- A report that could not be delivered no longer turns the job amber at once: the run stays green with the line "1 report
  could not be delivered; it is retried next cycle". Only 3 undelivered cycles in a row turn it amber. A delivered cycle
  clears the count.
- You are never mailed when a report cannot be delivered; Invardia sees a missing report itself.

## 2.0.123 - A job that hangs is caught, stopped and started again
Builds on the owner's decision: "build the stall watchdog now" (2026-11-10)
- New: every job now reports its progress while it runs. A run that makes no progress for 60 minutes, or runs more
  than twice its usual length (at least 30 minutes) without progress, is stopped and started once more. Before, a
  hanging job ran until its time limit.
- A run that hangs again within 24 hours stays stopped and shows on Jobs & runs with the reason. A run a person asked
  for is not repeated without them: ask for it again. An update is never stopped half-way.
- Invardia support is told at once about a job that hung (error code eps-run-0101) and looks at it; it closes by
  itself after the next good run of the job.

## 2.0.121 - The update brings the web app's sign-in front to .NET 10
Builds on the owner's decision: "this is very critical and approved. each solution must move to .net 10 + latest ps you mentioned" (2026-11-10, relayed by Invardia, framework IMAGE-PATCH-1 point 0)
- Fix: an install that was already up to date did not move its web app's sign-in front to the version the release
  pins (the update stopped with "Cannot bind argument to parameter 'Path'"). It now does, on its next update run.
- Security fix: the sign-in front is version 2.1.0 on .NET 10 LTS - the same front every Invardia product runs.
- Signing in works as before: the same Microsoft Entra sign-in, the same roles, nothing to change in your tenant.

## 2.0.120 - .NET 10 for the web app's sign-in front too
Builds on the owner's decision: "this is very critical and approved. each solution must move to .net 10 + latest ps you mentioned" (2026-11-10, relayed by Invardia, framework IMAGE-PATCH-1 point 0)
- Security fix: the web app's sign-in front moves to version 2.0.0 on .NET 10 LTS (a small Ubuntu chiseled runtime, no
  shell or package manager) with its libraries on their current patched versions. With 2.0.119 every part of Entra
  Policy Suite now runs on .NET 10 LTS and PowerShell 7.6 LTS.
- Signing in works as before: the same Microsoft Entra sign-in, the same roles, nothing to change in your tenant.

## 2.0.119 - .NET 10 and PowerShell 7.6: the product moves off the versions whose support ended
Builds on the owner's decision: "this is very critical and approved. each solution must move to .net 10 + latest ps you mentioned" (2026-11-10, relayed by Invardia, framework IMAGE-PATCH-1 point 0)
- Security fix: .NET 8 and PowerShell 7.4 reached the end of Microsoft's support on 10 November 2026 and receive no
  more security fixes. Every job and the web app's pages now run on .NET 10 LTS and PowerShell 7.6 LTS (both supported
  to November 2028), from Microsoft's .NET 10 image, which the .NET team rebuilds on every security update.
- The image also takes the operating system's security updates when it is built; the build stops if it does not run
  PowerShell 7.6 on .NET 10.
- Security fix: the web app's sign-in front moves to version 1.4.6, on a smaller patched runtime image (Ubuntu
  chiseled, no shell or package manager). It moves to .NET 10 in a following version.
- Nothing in your directory, the database, the rights or the settings changes. The update installs like any other.

## 2.0.118 - Security patch: the container images on today's patched base images
Builds on the owner's decision: "we need to include this in the framework so we immediately patch images when this happens" (2026-11-10, relayed by Invardia, framework IMAGE-PATCH-1)
- Security fix: the engine image (every job and the web app's pages) is built on the current .NET SDK base and takes
  the operating system's security updates when it is built, with the latest security fixes. Nothing else in the
  product changes.
- A private network install: the image build now also reaches archive.ubuntu.com and security.ubuntu.com for the
  security updates; they are on the network hand-off list. A subnet the install made needs no change; if your firewall allows only listed
  hosts, add these two before the update installs.
- The pages on invardia.com now match the code: the Conditional Access changes a SuperAdmin can make, what is on after
  the install, every identity and its rights, all jobs and settings, every install parameter and script.

## 2.0.117 - Optional components, rights are never taken away by themselves, the AD step finishes itself
Builds on the owner's decision: "i have not approved any removal of graph rights" (2026-11-09, direct; optional components per the rights rule relayed by Invardia 2026-11-09)
- Turning a feature off no longer takes its rights away: the install reports the right as not needed and keeps it.
  Nothing is removed by itself; you can take a right away with Grant-EpsEnginePermissions.ps1 -Remove.
- New page Administration > Optional components: each optional part (writing to users, writing to devices, Exchange,
  alert mails, Log Analytics, the hybrid worker and its AD writes, support access) with whether it is on, which of its
  rights are missing and the script that adds exactly those rights. The page only reads.
- Three new scripts add the rights of one component each: Enable-EpsUserTagging, Enable-EpsDeviceTagging and
  Enable-EpsExchangeAccess. Run with -WhatIf, each one shows what it would add and changes nothing; the grant is
  read back.
- The Active Directory step of the hybrid worker finishes by itself: the worker reads the delegation back, and the step
  clears once the rights are there. Nobody has to come back and mark it done.
- The tamper monitor no longer reports Entra Policy Suite's own tag changes as tampering.
- The architecture and security pages list every identity by its role and the rights it holds, the optional
  components, how updates arrive and the newer jobs.

## 2.0.116 - Requests start at once, identity views say what they assume, a clearer GUI
- A change you commit, a Run now or an analysis you ask for now starts within seconds: the web app wakes the engine
  check right after it writes the request, instead of waiting for the next 5-minute check. The wake-up runs one normal
  engine check with all its guards. The web app gets one narrow new right for it. If the wake-up cannot be sent, the 5-minute check starts the request as before.
- Each identity report view lists what it assumes: where each fact comes from (the MFA registration report, Entra and
  AD sign-ins, the tags, Intune, the hybrid worker's AD read) and who is left out. The list is worked out from the
  fields the view actually checks, so it cannot drift from it.
- The audit log says what a request did ("Adopt CA policy 62f1960c…", "Commit the queue") instead of the raw request;
  the full target is on the hover.
- The rules page: New rule and Test run are the actions; Test runs, Deleted rules and Condition types sit in one More
  menu. A rule imported from v1 shows a "from v1" badge, with the v1 rows on its hover.
- Tamper events and tag changes show the tag (Classification) instead of the attribute it is stored in.
- Settings: the alert mail choices are in words (Off, from a mailbox of yours, through your SMTP relay).
- Get started: the v1 import steps are folded until opened.
- One spelling across the app and the docs: "Analyze".

## 2.0.115 - Per-user sign-in methods, corrected identity report views, red markers for what waits for you
- A new background job reads each user's sign-in methods one by one (every method, and the device behind Windows Hello
  for Business and Microsoft Authenticator) and keeps them per user. A user is read again only when the MFA registration
  report shows a change, or after 90 days; admins are read first; nobody is skipped. Until a user is read, the report
  says unknown, never 'no MFA'. Off by default (Settings > Per-user sign-in methods).
- The release flow follows the rule that nothing is public before the rings 2/3 approval: test rings get a pre-release.
- "Active without MFA" and "No MFA, but a company smartphone" now list the right users: enabled users who are not
  registered for MFA.
- An admin is now anyone who can reach a directory role: active or eligible, directly or through a role group, and
  through PIM for Groups when the engine may read it (the run says so when it may not).
- The inactivity and guest views count non-interactive sign-ins too, and the guest view finds every guest account.
- "SSPR on, not registered" leaves out guests, and "MFA users - not compliant" lists enabled users only.
- The AD OU views stay empty until an OU pattern is set (before, every AD user counted as in the wrong OU).
- The licence check knows the Microsoft 365 E5 and E3 bundles without Teams (EEA), so users who hold them are no longer
  listed as missing a licence.
- The engine is granted three more read-only rights at its next install run: PIM for Groups eligibility and assignments
  (so admins through PIM for Groups are seen) and the users' authentication methods (for the per-user sign-in methods
  that follow). Nothing is removed.
- The menu shows a red count on an item, and the total on its menu group, when something waits for you or did not
  complete: changes waiting in the commit queue (or that failed there), jobs whose last run failed, partly failed, was
  held or is stuck, open tamper events, and a late hybrid worker or a failed AD write. The Overview lists each with a
  link. Work that runs within its normal time is not counted.
- The Identity report colours a view's name by its severity only when the view finds something; a check that finds
  nothing is shown plain.
- The Actions menu of a row is as wide as its longest action, so no action wraps over two lines.
- The Conditional Access policy list shows what is happening to each policy right after its stage: the analysis it
  waits for (requested or running) or had last (impacted of in scope, with a link), and the monitors that cover it.
  The template comparison follows. A requested analysis shows on its row at once.
- A monitor name may now hold spaces (for example "int users"); the field says which characters it takes and drops any
  other as you type, instead of refusing the name on Save.
- In a Pro install the menu no longer marks its Pro pages "(Pro)"; the mark stays only where a Pro feature is not on.
- In the rule editor, picking the value for AD-synced users proposes the value for cloud users: its cloud counterpart
  when the tag type has one (for example Internal_User_AD_Synced_MFA gives Internal_User_Cloud_MFA), else the same value.
  "Same as AD-synced" and "Use the cloud peer" set it in one click; a value you pick yourself is kept.

## 2.0.112 - Committing without a reason works again
- Committing changes in the commit queue without a reason failed with "internal error". A reason is optional, and a
  commit without one is written again.
- A run page showed a placeholder word instead of "-" in its number cards when a number was not known; it shows "-"
  again.

## 2.0.111 - Easier to read: larger text, clearer buttons
- The text in the web app is larger (body 14 px, nothing under 12 px) and the buttons are bigger.
- The main action on a page is the filled button. Actions that write or remove something are red: Discard all in the
  commit queue, Disable on a policy page, and Apply on a scheduled job. In the commit queue, Commit all is the main
  button and testing first is the second one.
- A Conditional Access policy page shows its current stage as a marker, and its stage moves are no longer loud buttons.
- The panel of the selected rule stays in view while you scroll down the rules.
- The commit queue names the fields in words (for example "Value for AD-synced users") and a new item no longer looks
  like a deletion.
- The tag type list says what its mode means, for example "the first matching rule wins".
- Conditional Access groups say "not read yet" instead of 0 before the groups were read, and Create shows only on a
  missing group.
- Settings: Save stands out once a field is changed; the internal name moved into a tooltip.
- Long page explanations show two lines and open with "Read more".
- Smaller wording fixes: "Written to" instead of "Dir", "not reported yet" instead of "?", "open tamper events" on the
  overview, and the CSV import's delete option says DELETE in red.

## 2.0.110 - Tag values are picked from a list, and the Tag types page loads again
- The Tag types page showed "Could not load" as soon as one value was set by two or more rules. It loads again.
- In the rule editor, a tag type with a list of values now gives a dropdown of exactly those values for AD-synced and
  cloud users, instead of a text field that refused any value not on the list. A tag type without a list keeps a text
  field. A pattern value (for generated values) adds "Other value matching ...", and a value an older rule holds that is
  no longer on the list stays visible and marked.
- Editing a value cell in the rules grid uses the same dropdown.

## 2.0.109 - An install run finds the update job by its real name
- An install run now finds the update job under the name it has in your install. Before, on an install made with 2.0.55
  or later, or after -RenameJobs, a re-run with the Community launcher did not see that the install is Pro, and a new
  Pro install did not start its first licence request at once (the nightly run still asked).
- The install guide's naming table no longer lists the old job names; it says how an older install moves to the names
  shown.
- The rights list describes the hybrid worker's AD rights as they are now set up: one permission group at the domain
  root.
## 2.0.108 - Standard job names, and the hybrid worker's AD rights at the domain root
- An install made before 2.0.55 can move its schedule check job and its update job to the standard job names with one
  install run with -RenameJobs. Each new job is made from the old one's settings and proven with one run before the old
  one is removed. The identities, their rights and the web address do not change. Without the switch the install only
  shows the plan.
- The database role of the schedule check gets its standard name in place; its members and permissions stay.
- The AD script of the hybrid worker gives its rights to a permission group with the worker's gMSA as its only member,
  at the domain root, for the tag attributes you list (users, and computers with -ObjectClasses computer). It reads every
  change back. You now list your attributes; there is no default.
- The install guide has one table with the names you will see in Azure and Entra ID; the rest of the documentation
  names each part by its role.
- Each identity's rights are listed in one file the install and the tests check against.

## 2.0.107 - An install run never removes a Graph permission
- An install run no longer removes a Graph permission the engine or the updater holds outside its list (2.0.106 would
  have). It adds what is missing and only names an extra permission; nothing is taken away.
- The setup step "Engine Graph permissions beyond its list" is now a report only: it stays green and names any extra
  permission as kept.
- The write permissions are still granted only while a feature that writes is on, as before (unchanged since 2.0.99).

## 2.0.106 - The engine and the updater keep exactly the Graph permissions they need
- A Graph permission the engine or the updater no longer needs is now removed by the next install run, and read back.
  Before, a permission that was granted once and later dropped from the list stayed for good.
- Getting started and the setup steps now show a step "Engine holds no Graph permission beyond its list". It names any
  extra permission, and the install run that removes it.
- The security pack and the install help no longer describe a separate scheduler identity: the engine identity runs the
  schedule check (as it has since 2.0.56).
- The hybrid worker guide names Entra Policy Suite's own worker identity for a server that also runs another product's
  worker.

## 2.0.105 - Every job reports its runs, and a failing job retries with smaller batches
- Backups are saved under file names that are valid on every system. A policy name with a character such as ':' or '?'
  no longer gives a backup file that Windows cannot open.
- The identity report reads the on-premises security identifier (objectSid) of AD users correctly in the Linux
  container, without a Windows-only component.
- Every job now records its runs: the database setup, the support access check, the support reads and the configuration
  changes appear under Jobs & runs and are reported to Invardia like every other job.
- A job whose last runs did not complete runs with smaller batches and pages: half the size after each failed run, at
  most eight times smaller. A size that keeps timing out is no longer retried unchanged.
- Two new alerts to Invardia: a job that has not completed its last three runs, and records Invardia had to skip. Both
  close by themselves when the cause is gone.
- The engine may read the web app (and nothing else in Azure) to report which version of the sign-in front it runs. A new
  install gets this right; an existing install gets it on its next install run.

## 2.0.104 - A failure that repeats is reported as one, never retried forever
- A job that does not complete three runs in a row is now reported to Invardia as a repeated failure, with how many runs
  and the last kind of error. Invardia opens a fix request for it. This covers every job that records its runs. It also
  covers the update job when it has to give up for the night three nights in a row, and the tamper monitor when its
  alert mail cannot be sent while mail is set up. A missing permission stays a step for you, never a product fault.
- The report to Invardia no longer gets stuck on one record. A run record that Invardia refuses for its content no
  longer holds back the records of other jobs, and after three refusals in a row it is skipped. A refused alert no longer
  stops the run records either.

## 2.0.103 - Every change to this repository is scanned for secrets
- 2.0.103 contains everything in 2.0.102 (the hybrid worker updates itself) plus only this: the public repository's
  secret scan. There is no product change.
- This GitHub repository now checks every push and pull request for secrets (keys, tokens, passwords) with gitleaks,
  in addition to GitHub's own secret scanning. A finding fails the check. The scanner is a pinned version whose
  download is verified before it runs, and it never prints a found value.
- Nothing changes in the product itself: an installation updated to 2.0.103 runs the same code as 2.0.102.

## 2.0.102 - The hybrid worker updates itself
- The hybrid worker now updates itself once a day. A new scheduled task on the worker server runs as SYSTEM and moves
  the worker to the version your Entra Policy Suite installation runs. It never runs ahead of it, and never goes back.
- It takes only a release Invardia signed. It checks every release before anything changes. A release that fails a
  check is refused and the worker keeps running.
- The new version is unpacked next to the running one, then the worker switches over. The previous version is kept.
  The new version then tests itself, and if that test fails the worker switches back by itself.
- The worker runs only the Community files, also for a Pro installation. A release with Pro code among the worker's
  files is refused.
- The Hybrid worker page shows each worker's last daily update.
- To add the daily update to a worker installed before 2.0.102, run `Install-EpsHybridWorker.ps1` on it once more. The
  worker server needs outbound HTTPS to invardia.com and to the release download.
- An install run done through Invardia's Support app now reads which features are switched on before it changes the
  engine's write permissions.

## 2.0.101 - Support can read a private installation, safely
- A private installation can now be read by Invardia support without opening anything: a new job inside your network
  runs ONE read from a short list this release ships (recent runs, job schedules, settings, the licence state without
  the licence itself, the hybrid workers, the update runs) when Invardia support asks for it. It never runs a query or
  script sent to it, refuses an old request, writes the result only to its own log, and every request is recorded in
  the audit.
- The job has its own identity that can only read those tables and write the audit. Invardia's Support app can only ask
  for one of those reads, and only if you allowed it.
- An install run adds the job, its queue and its identity. The update alone does not.

## 2.0.100 - The Entra Policy Suite logo
- The web app's header shows the Invardia Entra Policy Suite logo - the Community or Pro logo, depending on your
  licence - and the browser tab shows the Entra Policy Suite app icon.
- Alert mails carry the logo in their header. A mail client that blocks images shows the product name instead.
- The README carries the logo too, and the product's texts say "tag" where they said "label".

## 2.0.99 - Fewer standing rights, and the install checks you first
- The engine now reads users and devices with read-only permissions (`User.Read.All`, `Device.Read.All`). It holds the
  write permissions only while a feature that writes is switched on: `User.ReadWrite.All` while user tagging, the
  tamper monitor or (Pro) the stale identity clean-up's disable action is on, `Device.ReadWrite.All` while device
  tagging is on. The install grants a write permission when a feature needs it and removes it when none does. The
  setup checks show which one is needed and the command that grants it.
- Pro: the stale identity clean-up disables approved accounts only while the new SuperAdmin setting "Allow the clean-up
  to disable approved accounts" is on (off by default). Reviewing and marking the list works as before.
- Creating a break-glass account without the write permission now stops with the permission named and the command that
  grants it.
- Before it creates anything, the install now checks that you hold Owner on the subscription (or Contributor and User
  Access Administrator) and an active Global Administrator or Privileged Role Administrator role, and that the region
  has room for a Container Apps environment and a SQL server. It lists everything missing at once.
- New script Grant-EpsUpdaterPermissions.ps1: gives the update identity a Microsoft Graph permission it is missing (only
  the ones Entra Policy Suite declares for it), read back.

## 2.0.98 - "Update now" for Pro installations
- Fixed: on a Pro installation the 15-minute "update now" check from 2.0.97 was refused by Invardia, because it did
  not send the installation's licence. It now sends it, so "update now" works for Pro as it does for Community.

## 2.0.97 - "Update now" works within minutes
- When Invardia marks a release "update now" for your ring, Entra Policy Suite now starts its update within about 15
  minutes instead of waiting for the nightly update. It starts once per version, only when updates are switched on, and
  it waits for the usual reasons (for example while another update is running). The nightly update stays as before.
- The Pro install script now says that it downloads the signed Pro package from Invardia.
- The setup scripts on invardia.com now run the Entra Policy Suite version they were published for by default, instead
  of the newest release (-EpsVersion still picks another).

## 2.0.96 - A smaller Pro package
- The Pro package now carries only what an installation runs and updates from (the engine, the database files, the
  setup and worker scripts, the sign-in front and the Pro features), plus the readme and these release notes. Our own
  development notes are no longer included. Nothing changes in how Entra Policy Suite works.

## 2.0.95 - The ownership handover completes
- Fixed: when Invardia's Support app ran the install, it is now always removed as owner of the sign-in registration
  (after the update identity is in place, as before).
- The install now waits a little for Entra to show a new owner before it judges the change, instead of reporting a
  warning for an owner that was in fact added.

## 2.0.94 - The web app's sign-in registration is owned by the installation itself
- The web app's sign-in registration in Entra is now owned by the installation's own update identity, not by whoever
  ran the install. When Invardia's Support app ran the install, it removes itself as owner at the end of the run (after
  the update identity is in place, so the registration always has an owner). A person who installs stays owner.
- The update identity gets one new permission for this, which reaches only the registration it owns: it keeps that
  registration's own settings as they should be on every update. The tenant-wide consent and who is assigned to the app are still set by the install.
- An install run that is not allowed to change the registration no longer stops there: it says so, and the update
  identity applies the change on its next run.

## 2.0.93 - Clearer run reports to Invardia
- When the scheduler could not start a job, its run now says which job and why. A start that only timed out on the
  job's queue (a short storage hiccup - the next check a few minutes later starts the job) is reported as that, so it
  is not mistaken for a real failure.
- The scheduler's runs are reported to Invardia as "eps-engine", the same name as its role everywhere else. Nothing
  changes in your installation's Azure resources.
- Coming from 2.0.90, this version also brings 2.0.91 and 2.0.92 (below): updates that re-read the release after a
  wait, the tamper check's settings kept current by the update, and the updater stopping a job execution that has
  been stuck for hours. That last rule is built and tested, and has not yet been needed at an installation.

## 2.0.92 - The tamper check's settings reach every installation
- The update now also keeps the tamper check's settings current on every installation, so an installation gets them
  with its next update. Nothing else in a job's settings is changed.

## 2.0.91 - Updates that do not get stuck
- An update that had to wait for a running job now reads the release again before it downloads. Before, a long wait
  could leave it with an expired download link, and the update stopped (nothing was changed) until the next night.
- A job execution that has been running for hours without starting its run is now stopped by the updater (it is
  logged and reported), instead of holding the update back. A stuck tamper check is now stopped quickly, so the next
  checks always run.
- Every job prints a first line when it starts, and the tamper check prints each stage, so a job that stops is easy
  to place in its log.
- Adding the hybrid worker's database user no longer has to wait for the jobs to finish: it changes only users and
  roles, never a table. Anything else the database setup does still waits until no job runs.
- Pro: the MCP server's tool names are now lower-case with underscores (for example get_rules_object_type_id), the
  form MCP clients and invardia.com expect, and each tool says whether it only reads.

## 2.0.90 - Pro: the API for your scripts and an MCP server for AI assistants
- Pro: your own scripts reach Entra Policy Suite through its API, and AI assistants through its MCP server - always as
  the signed-in person, with that person's own role (Reader, Admin or SuperAdmin). There is no key to hand out and no
  app identity: you take your own token with the Azure CLI, and only people assigned to the app get one. A change goes
  through the same checks as on the pages (the commit queue, the engine's signed request) and the audit trail shows it as
  yours. Settings, the access list, restores and deletes stay in the app.
- Administration > API and MCP (Pro) shows the addresses of your installation, the line that gives you your token, an
  example for a script, the line to add the MCP server to Claude Code, and the tools your role gets.
- The install now pre-authorises the Azure CLI for the app's own sign-in scope, so taking your token asks for no extra
  consent. It grants nothing by itself. Existing installations get it on their next install run.
- The API reference handed to invardia.com now includes the MCP server's tools (mcp.json).

## 2.0.89 - The first Pro release, with the License page fixed
- The first Pro release: Entra Policy Suite Pro and the 60-day trial are ordered at invardia.com. The license and the
  signed Pro update channel were proven end to end at Invardia's own installation (2.0.88), and this version was walked
  through page by page as an administrator with a Pro license: Passkey rollout, Stale identities, License optimization
  and Policy as code.
- Administration > License works again: it showed only "Could not load" in every edition. It now lists the edition, the
  state, the dates and the Pro features by the names of their pages; API access, the MCP server and several tenants
  (MSP) say "licensed - comes in a later release" instead of "yes".
- The header names the edition the license gives (Pro Enterprise, Pro Business, Pro (trial)); it said "Community" always.
- A page opened while the Pro pages were still loading could be drawn twice, one copy under the other. Each page now
  draws once.
- Stale identities: "Mark disable" and "Mark keep" ask for the reason in the app's own dialog, not the browser's prompt.
- License optimization and Policy as code link to their own settings section, by the name the Settings page uses.
- The texts that said Pro and the trial open later now say they are ordered at invardia.com.

## 2.0.88 - License request messages and the policy as code Key Vault right
- The first Pro release: the license and the signed Pro update channel were proven end to end at Invardia's own
  installation - the license was requested, signed by Invardia, checked and kept in the installation's Key Vault, and
  this version was then taken from the signed Pro channel and installed by the product's own update job.
- When Invardia refuses a license request, the update run's log now shows Invardia's reason, not only the HTTP code.
- Policy as code: Git push and read need a Key Vault right that Entra Policy Suite never grants itself. Until your Key
  Vault administrator grants it, push and read refuse and name the right. The zip download of the policy files works
  without it.

## 2.0.87 - Pro: the license path, the trial, the License page and the first Pro features
- (2.0.86 was published on GitHub but never released to an install: its documentation pack failed a spelling check. 2.0.87 is the same release with that text fixed.)
- New: Entra Policy Suite Pro and the trial, the same way as PIM Manager and SecurityInsight. Pro and the trial open
  when Invardia announces them. Everything Entra Policy Suite does today stays in Community - no install loses anything.
- New: the Pro install line - the same two lines, line 1 from invardia.com/support/eps/. The Pro launcher signs you in
  to the tenant you install into and takes the Pro package from Invardia (signed by Invardia and checked before
  anything runs), never from GitHub. The Community line from GitHub is unchanged.
- New: the license comes by itself. A Pro install asks Invardia for its license from the update job (right after the
  install, then every night), checks it - Invardia's signature, this product, this tenant, the dates - and keeps it in
  the install's own Key Vault. It renews by itself before it ends, and takes a re-issued license by itself. Nobody
  pastes or uploads a license. A Community install never asks.
- New: Administration > License - the edition (Community, Pro Enterprise, Pro Business or the trial), who it is for,
  how long it is valid (and the 30 days of grace after), users against the license, the license request, the install
  key, which Pro features it switches on, and a link to buy or renew. "Claim again" (SuperAdmin) asks Invardia once
  more after a refusal.
- New: Pro Business covers up to 1,000 users in scope in one tenant. At 90 % and at or over the limit the Overview,
  the License page and the user tagging run say so. Nothing stops: tagging and collection go on.
- New: a Pro install takes its updates from Invardia's signed Pro channel on its update ring; a Community install
  keeps the Community channel.
- The heartbeat to Invardia carries the edition from the verified license, the license's state and its id.
- Pro - available when Pro launches: **Passkey rollout** (Identity report): per persona, how many people can sign in
  with a passkey, a security key or Windows Hello for Business, a target date and owner per persona, the daily progress
  and whether the target is on track, the list of who is not ready (CSV), and an optional daily mail to the persona's
  owner (off by default). Nothing in the tenant changes.
- Pro - available when Pro launches: **Stale identities** (Identity report): users and guests with no sign-in for 90
  days (a setting), never signed in, or disabled but still licensed. An Admin marks each keep or disable with a reason,
  a SuperAdmin approves, and only then are the approved accounts disabled - each read back, recorded and audited, and
  enabled again from the same page. Break-glass and service accounts are never listed; accounts synced from AD are
  disabled in AD.
- Pro - available when Pro launches: **License optimization** (Identity report). The licenses to review from the
  newest identity report - on disabled accounts, on accounts with no sign-in for a while (90 days, a setting), and
  licenses a suite of the same person already holds - plus the service plans switched off for everyone who has a
  license. Each is priced with your own price table (EUR per user per month; it starts with list prices you can change),
  with the saving per month and per year, per license and per persona, and an Excel download. Read only: Entra Policy
  Suite never removes or changes a license.
- Pro - available when Pro launches: **Policy as code** (Conditional Access). Your managed policies as JSON - one file
  per policy and an index - as a zip, or pushed to your GitHub or Azure DevOps repository as one commit. Review changes
  there with a pull request, then read the merged commit back: per policy new, changed or the same, and the policies Git
  does not have. You pick what to apply, and it goes through the same restore as the Backups page (the plan, the
  break-glass check, a backup first, a new policy created off, never a delete). The Git access key stays in your Key
  Vault; Entra Policy Suite reads it when it pushes or reads and never stores it.
- The identity report keeps each user's licenses as part numbers and the service plans switched off per license.

## 2.0.85 - the product pages for Invardia's shop
- Invardia's product page for Entra Policy Suite: the edition table (Community, Pro, Pro Business - every feature in
  plain words; Pro Business up to 1,000 users in one tenant), the description, fresh screenshots of the current version,
  the install lines, support and what comes next. Pro and the trial open when Invardia announces them.
- Fixed: the architecture page said Community sends nothing to Invardia - it sends counts and states once Invardia has
  issued its key, and a SuperAdmin can switch that off.
## 2.0.84 - the update job keeps the database setup identity in the SQL admin group
- New: the update job keeps the database setup identity a member of the SQL admin group on every run, and renews a
  time-limited Privileged Identity Management for Groups assignment before it ends - the install no longer has to be
  run again for that. An update checks the membership again right before it updates the database, and does not touch
  the database when the membership cannot be made. A SQL admin group that is not role-assignable is reported, never
  changed.
- The update job's identity needs a few more Microsoft Graph permissions for this (listed in the security pack). Run
  the install again once to grant them; the update job reports any it lacks.
- New: -ReplaceSqlAdminGroup (an install switch, never done without it) replaces a SQL admin group that is not
  role-assignable: the old group is renamed '<name>-old' and kept, a new role-assignable group gets its members, and
  the server's admin moves to it on a run at least 24 hours later - then the database setup job runs at once, and if
  it cannot sign in the admin is moved back. Plan it first with -WhatIf.

## 2.0.83 - tagging test runs, the identity report in Log Analytics, v1's report mail and SMTP relay, analyzer options, log levels, and the policy Edit form picks instead of typing

- Fixed: a tag type's fallback value (the value every object no rule decides gets) is no longer offered for removal on
  Tag types, and is refused if asked: change the fallback first.
- Fixed: Jobs shows each next start in the same time zone as the schedule - the install's time zone, named in both
  column headers - and the time is picked on a 24-hour clock.
- Changed: a Test run started while changes wait in the commit queue tests those waiting changes unless you choose
  otherwise; the commit queue shows a change field by field (what changes, before and after) instead of two raw texts,
  and with a second approver your own staged changes are left for another admin to commit.
- Changed: in the rules grid on a laptop screen the rule panel folds away (one click opens it), a rule with a change
  waiting is marked on its row, and "In the selected rules, set ... to ..." says what the bulk set does.
- Changed: people are picked from the directory, not typed, in a Test run, a saved scope and "Never tag these users".
- Changed: the Audit page shows readable actions and the changes by default (reads - views, exports, checks, sign-ins -
  one choice away), each change field by field; Tamper puts Accept / Restore first; a tag change links its run; the
  Overview's last runs open their run; the identity report shows readable labels and method names, offers a column's
  values in its filter, and opens the tag changes of the person you look at; the undo of a tagging run and of a commit
  of the rules each say what the other one is for.
- Changed: the install puts the database setup job's identity into the SQL admin group itself - directly, or, where
  that is not allowed, as an active Privileged Identity Management member of the group (permanent, or for the longest
  time the group's policy allows, with the end date shown so the install is run again before it). When neither is
  allowed, the install stops and names both reasons and the right that is missing; it no longer runs the database
  steps as you instead.
- Changed: a new install creates the SQL admin group as a role-assignable group, so only a Privileged Role
  Administrator or a Global Administrator can change who administers the database. An existing group that is not
  role-assignable is reported by the install and left as it is.
- New: test the changes waiting in the commit queue BEFORE you commit them - "Test these staged changes" on the commit
  queue and the Rules page, or "Which rules" in the Test run dialog. The test uses the rules as the commit would make
  them and writes nothing; commit them afterwards and Go live runs exactly those rules on everyone. A test run that
  was started before this version has to be run again once before it can go live.
- Changed: a commit says what it starts - for example "User tagging APPLY - it writes the tags on 92 users (the last
  run on everyone)". The commit queue lists what waits (tick to commit or discard) apart from what was committed, with
  before and after side by side. "Test this rule" in a rule's side panel tests it on the people you pick.
- Changed: Jobs offers what each job does - Preview / Apply and a scope only for tagging; "Back up now", "Run the report
  now", "Check for an update now" and Run now for the others; internal jobs are no longer listed. The schedule is
  picked (every day / week / month / every few minutes or hours, and the time), not typed, with On / Off and a Next
  run column. Runs can be filtered on every job, and every job has a readable name.
- Changed: the Overview's numbers are links to what they count, and an install that is not set up yet says so with a
  link to Get started.
- Changed: tagging rules - the persona is picked from the ones the rules use (or typed new), a group condition picks
  its group from the tenant, a tag value shows the rules that set it (and can only be removed when none does), the
  grid's conditions wrap and its filter pane can be folded away, and leaving the grid with edits that are not staged
  asks first.
- Changed: the identity report shows its columns by readable names, its filter starts on the name, and a click on a
  person or device opens every value they have with "Test run on this user".
- Fixed: tables no longer show a filter box over a column of buttons; the tag changes of an object are one click from
  the Tamper page.
- New: the identity report in Log Analytics, as v1 did it. After each report run, every user's row goes to the table
  EntraUsersMetadata_CL in your workspace in v1's columns, and v1's exposure lists are read back with the Entra sign-in
  logs: service accounts and shared device users signing in from a trusted or a non-trusted location, their sign-ins,
  and those with no sign-in in 90 days. They are on the Identity page under Exposure (Log Analytics) and export to Excel
  as v1's workbook. An account with a capital letter in its user principal name is now found too (v1 missed it).
- Set it up once with the new script Initialize-EpsLogAnalytics.ps1: it makes the table (or adds what a table v1 made
  lacks, keeping its columns), a data collection endpoint and rule, and gives the engine two rights only - Monitoring
  Metrics Publisher on that one rule and Log Analytics Reader on that one workspace. No new Microsoft Graph permission.
  Then a SuperAdmin switches on Settings > Identity report > Send the report to Log Analytics (off by default).
- New: test runs for tagging. The Test run button on the Rules page tries the rules on the people you pick - a list,
  a group, an OU, a filter or a saved scope - for all tag types or the ones you choose: Test writes nothing, Apply
  writes only their tags. Tagging > Test runs shows each run: the counts per tag value and per rule, and per person
  every tag as it is now and as the rules want it, with the rule that decided it; open a person for the whole decision,
  rule by rule. It replaces "Try on a user".
- New: Go live on a test of all tag types runs the same rules once on everyone (a SuperAdmin, with a reason). It is
  refused when the rules changed after the test - test again first - and the mass-change guard still holds it. The
  scheduled tagging runs go on as before; Go live does not change them.
- New: the Matched count on the Rules page explains itself. "who?" next to it (and "Who it matched" in the side panel)
  lists who the rule decided in the last run - each with the value the rule set and the value it had - searchable, as
  CSV, and from any recent run; open a tested person's whole decision, or start a test run on anyone in the list. A rule
  that decided nobody says why (switched off, never wins because an earlier rule takes every match, changed after the
  run, or nobody met all its conditions) and shows the closest misses from the latest test run.
- New: Administration > Settings can export the whole configuration as one file - the tagging rules, tag types and
  values, condition types, saved scopes, the settings and the CA Policy Analyzer's personas and monitors - and import
  such a file. An import shows every change first (new, changed, the same, refused); you untick what you want to keep,
  and each change goes through the same checks as on its own page. Secrets, approvals and records are never in the file
  and never imported. SuperAdmin only.
- New: Remove policies on the Conditional Access page deletes policies that are off - the ones you select, or every
  policy whose name matches a pattern such as *-Initial-*, as v1 could. Only policies that are off are removed; you see
  the exact list, type the count to confirm, and a backup of each is taken first. SuperAdmin only.
- New: a backup's named locations and authentication strengths can be put back - made again when they are gone, their
  definition back when they changed. Nothing is ever deleted.
- Changed: promoting a new version of a template now also sets the template's shared dynamic pilot group as v1 did (Prod
  pauses its rule), before either policy changes; if the group cannot be set, nothing is changed.
- New: the identity report workbook can go to its own recipients (Settings > Identity report > Who gets the workbook),
  as v1 mailed it to its own list; empty sends it to the alert recipients as before.
- New: alert mail and the report can go through your own SMTP relay, as v1 sent its mail (Settings > Alert mail = smtp,
  with the server, port, TLS and from address). When the relay needs a password, it stays in your Key Vault: you name
  the secret and give the engine read on it; Entra Policy Suite reads it when it sends and never stores or shows it.
  Without a secret the mail is sent anonymously. Send a test mail works for both kinds.
- New in the CA Policy Analyzer (More options), as v1's evaluator had them: policy numbers and ranges such as 6,200-249,
  only the policies that are on, report-only or off, a fixed window from - to instead of the last hours (for one
  analysis; a monitor keeps reading the last hours), and at most a number of sign-ins. An analysis exports to Excel and
  HTML as well as CSV.
- New: the log level per feature, as v1's verbose switches (Settings > Logging): Off keeps only warnings and errors,
  Normal (the default) the information lines, Verbose also one line per planned tag change. Run logs are kept 90 days
  by default (Keep run logs), the runs themselves and the audit trail always.
- New: Import v1 also reads v1's Automation-DefaultVariables.psm1 (from v1's FUNCTIONS folder) for the identity
  report's mail and OUs, the mail relay and the tag attributes - only those values; a password is never imported. Get
  started shows each break-glass account's v1 tag values next to it.
- Conditional Access > Groups: every row has its actions first - Check (read that group now), Create, Edit rule, Set rule,
  Members, force update and Copy id (the group's object id for the Microsoft Entra admin center) - also before the groups were read.
  A page not read yet says so, with a button to read the groups; the page updates itself when the engine is done.
- Edit rule: the rule in your tenant and v1's rule side by side, and an editor. Validate asks Microsoft Entra to check
  the rule before anything is saved, and whether a test user would be a member. A SuperAdmin saves it with a reason; it
  is kept as your rule for that group, so Set rule, the force update and the stage moves keep it. Back to v1's rule
  puts v1's rule back.
- A pilot group's own rule is its Pilot1 base: each stage widens its _pilot1 part as v1 does, and Prod pauses it.
- New: in the Conditional Access Edit and Clone form every list of users, groups, roles, applications and named locations
  shows its entries as names with an Add button: search by name among what Entra Policy Suite already knows, add All /
  None / guests and the other special values with one click, and an Admin can search the whole tenant for the rest.
  Break-glass accounts and groups are marked, and removing one warns you that an enabled policy without them is refused.
- New: every setting with a fixed set of choices is a check box or a dropdown - Block access or Grant access with the
  controls, client apps, platforms, risk levels, user actions, authentication flows, sign-in frequency, persistent
  browser, Conditional Access App Control - and the authentication strength is picked from your tenant's strengths by
  name. Typing is only needed in Advanced (JSON).
- New: the choices come from Microsoft Graph. A new monthly job reads which values each policy setting allows and your
  tenant's authentication strengths, named locations and directory roles; a value Microsoft adds later is offered too,
  marked "new from Graph", and listed on the job's run. It only reads; Run now reads at once (Jobs). Run the install
  again once to add the job; until it has run, the form uses the list that ships with this release.
- Get started: every step says how to fix what it found - a link to the page that does it, or the command to run with
  a Copy button. A step that needs an earlier one waits until that one is ready, and says which.
- A policy's page shows who it hits: Analyse this policy (the last 7 days, read only) and the last analysis's count of
  impacted users - also in the dialog before you move a policy to Pilot2, Pilot3 or Prod. "Pick more in the Analyzer"
  opens the Analyzer with the policy ticked.
- Conditional Access > Policies: each row starts with its Actions (open, edit, clone, analyse, move to a stage, adopt or
  release); the cards at the top filter the list; the state reads On, Report-only or Off; Deploy a new policy from a
  template is one click away.
- Templates show what a template does in words (the JSON is still there behind a toggle), link the policy deployed from
  it, and deploy a selection at the stage you pick (off or Pilot1). Template updates offer "Test the new version next to
  it" per policy.
- People are picked, not typed: the members of a group and the people on the Access page; a person's role changes in
  place.
- Settings: a search box and an index of the groups; a link to a setting from another page lands on its group. The group
  targeting method is a choice of v1's three; the authentication strength and location names and the region are picked
  from lists; a setting a script sets shows the command to run.
- Hybrid worker: the connection test shows the worker's answer when it comes; failed AD changes can be tried again
  several at once.
- Faster pages after a big run: the database now refreshes its statistics in the background, and after a tagging run,
  the identity report, a backup, the CA Policy Analyzer, the service-tag job or an import the engine refreshes only the
  statistics that run made out of date. No data changes, and a refresh that cannot run never stops the job.
- Changed: "Analyse this policy" reads the sign-ins since the policy's last change (its stage move or its adoption) and
  says whose sign-ins those are - at Pilot1 the pilot group's report-only sign-ins. Before Prod the dialog says plainly
  that users outside the pilot group were not in that analysis. The line shows the new answer by itself when it is in.
- Changed: Get started's "Fix it" commands are ready to run with your tenant and subscription filled in; an Admin is
  told what to ask a SuperAdmin for; a step that waits for an earlier one has its buttons switched off until then; the
  three group targeting methods are explained. The Overview counts a step that only informs as ready.
- Changed: the policy list's actions are one menu button; the open-findings card filters the list; the documentation
  shows readable columns and On / Report-only / Off (all columns on a switch); templates name their strengths and
  controls in words; the last SuperAdmin is not offered Remove.
## 2.0.82 - deploy templates, the hybrid worker page, Get started creates what is missing, backup and undo
- New: Conditional Access > Templates shows which templates are in your tenant already, and a SuperAdmin deploys a
  template as a NEW policy - off, or report-only for the pilot group - one at a time or the selected ones. What it
  creates is shown first: the policy, every group it uses and whether the group is there. The groups it needs that are
  missing are created first, as v1's setup did; the policy is then created and managed from here at once.
- New: when a newer version of a template comes with a release, the policy's page offers to test it NEXT TO your
  policy: a second policy, named with its version, report-only for the pilot group; your policy is not touched. When it
  is ready, Promote turns the new version on and your old one off (kept); Roll back puts the old one back as it was.
  After a promote, the old version can be removed - you type its name to confirm.
- Every one of these is a SuperAdmin's own action with a reason: the policies are read again first, a change is refused
  when a policy changed since you looked or when the result would no longer exclude the break-glass accounts, and every
  change is read back and recorded in the policy's history and the audit trail. Nothing deploys, promotes or removes a
  policy by itself.
- New page Administration > Hybrid worker: every worker with its scheduled task (running, disabled, last result, next
  run), the AD domain and domain controller it uses, the account it runs as, its version against this release and when
  it last reported (late after a time you set). Below: the AD changes waiting for it and the ones that failed with why,
  the numbers per day, and the three steps to add a worker with this install's values filled in, ready to copy.
- New: Test connection (Admin) asks a worker, on its next cycle, what it is connected to and whether it can read AD
  users; it reads AD only. Try again (Admin) queues a failed AD tag change once more as a new change, the failed one
  stays in the history.
- New: several AD forests or domains, as v1's environments (Internal_Prod, DMZ_Prod, ...): list them in Settings >
  Hybrid worker by user principal name suffix, install one worker per environment with -Environment, and each AD change
  goes to the worker of its user's environment. The Overview shows one line about the workers, with a link to the page.
- New: Get started creates what v1's setup created, each after you saw the change and gave a reason (SuperAdmin), applied
  by the engine and read back:
  - the two authentication strengths the templates name - FIDO2 + Temporary Access Pass (limited to v1's 11 key models)
    and Windows Hello for Business + Temporary Access Pass - when they are missing; an existing strength is never changed
  - the denied-countries named location with v1's countries and unknown countries; when it is there, the countries of
    v1's list it lacks are added and none is taken out
  - a trusted location (your office or NAT IP ranges), or new ranges for one you named before
  - the break-glass accounts of your list that are not in the tenant, as cloud accounts that must change their password
    at the first sign-in. Entra Policy Suite never shows or keeps the password: set it, or a Temporary Access Pass, in
    Entra, register the FIDO2 key and give the role yourself, as with v1
- New: the named-locations job from v1 - each day it keeps the named locations 'Azure.Network.ServiceTag.<tag>' up to date
  with the IP prefixes of your Azure service tags (the tag list from v1's file, imported on the Import v1 page), and
  changes a location only when its prefixes changed or it is missing. It changes no other named location and no policy.
  Switch it on with the setting NamedLocations.Enabled (off by default); the region is the setting NamedLocations.Region.
  Switch v1's own job off when you switch this one on.
- The engine needs one more Microsoft Graph permission for the strengths, Policy.ReadWrite.AuthenticationMethod: run the
  install again once (Get started, step 1, shows when it is granted).
- New: Administration > Backups / Undo. Every night every Conditional Access policy (adopted or not), named location and
  authentication strength is backed up, together with the tagging configuration (rules, tag types and values, condition
  types, saved scopes and the settings - never a secret); the newest 30 are kept, and "Back up now" takes one at any time.
  A backup can be downloaded as JSON files, one per policy, as v1 exported them.
- New: a backup is also taken just BEFORE every change Entra Policy Suite makes to a policy, and before every commit of
  the tagging rules. If that backup cannot be written, the change is not made.
- New: put policies back from a backup - pick them, see what changes for each, approve. A policy that is no longer in
  your tenant is created again, off. A tagging configuration backup is restored as the same changes the pages make
  (each checked; with the commit queue on, staged for a commit).
- New: Undo. Every change made to a policy from here can be undone from its page (a copy or a deployed policy is turned
  off, never deleted); a tagging run can be undone (each tag goes back to its old value - a tag changed since is left as
  it is, and the mass-change guard applies); a commit of the tagging rules can be undone. An undo is a new change: shown
  first, approved with a reason, checked like any change (for a policy: SuperAdmin, read again first, refused when the
  result would no longer exclude the break-glass accounts). Nothing is restored by itself.

## 2.0.81 - edit and clone a Conditional Access policy, and the groups your policies use
- New: Edit on an adopted policy's page changes any part of it - its name, state, the users, groups and roles it
  includes or excludes, applications, user actions, client apps, platforms, locations, sign-in and user risk, the
  grant controls and authentication strength, and the session controls - in a form, with an Advanced (JSON) box for
  anything the form does not show. Groups, users, roles and named locations can be typed by name.
- New: Clone creates a new policy from an adopted one with your changes. The copy is always created off and is
  adopted at once; move it through the stages when it is ready.
- Both are SuperAdmin only and always your own action: Check shows what changes before anything is sent, you approve
  it with a reason, and the engine reads the policy again first. It refuses when the policy changed since you looked,
  or when the result would no longer exclude the break-glass accounts. Every change is read back, recorded in the
  policy's history and the audit trail. Nothing edits or copies a policy by itself.
- Fixed: the Settings page lines every setting up in three columns (name, value, buttons), so Save and More info stay
  on screen on a wide window.
- Fixed: an install with a private registry makes its build pool the way Azure accepts it, and a pool being replaced
  is finished by the next run instead of being left out.
- New page Conditional Access > Groups: every group the policies use - the target groups, the break-glass group, the
  registration group, and each adopted policy's exclude and pilot groups - with whether it is in your tenant, its
  members, whether a dynamic group's rule is as it should be, and its administrative unit.
- A SuperAdmin can create a missing group exactly as v1 did, set a dynamic group's rule back, change the members of a
  pilot or exclude group, run v1's group force update for one policy, and create the three administrative units and
  place the groups in them. Each change is shown first and needs a reason; the engine applies it and reads it back.
  Nothing changes a group by itself.
- Get started: a missing group can be created from its step.
- A stage move now also sets the policy's dynamic pilot group for the stage, as v1 did (Pilot1 to Pilot3 widen it, Prod
  pauses its rule). If the group cannot be set, the policy is not changed.
- The engine needs two more Microsoft Graph permissions for this, Group.ReadWrite.All and
  AdministrativeUnit.ReadWrite.All: run the install again once (Get started, step 1, shows when they are granted).

## 2.0.80 - the report backlog in the heartbeat
- The 4-hourly heartbeat tells Invardia how many run reports are still waiting to be sent and how old the oldest
  is (0 when it has caught up), so a backlog shows up at once.

## 2.0.79 - run reports catch up with Invardia (fix)
- Fixed: an install with many runs could fall behind in reporting them to Invardia (at one install about two days),
  because each 4-hour report sent at most 20 records. A report now sends up to 100, in rounds of 20 with a pause
  between rounds to stay within the allowed request rate, so a backlog is cleared within a few reports.
- A job with a failed run or an update run is reported first. Each job's runs are still sent oldest first, so
  nothing is skipped.

## 2.0.78 - a saved monitor you can follow (fix)
- Fixed: "Add to monitor..." seemed to do nothing. Its answer appeared at the top of the page, out of sight when the
  page was scrolled. Notices now float at the bottom right, visible wherever you are on the page.
- Fixed: a new or changed monitor was not shown after a reload, with nothing to say why. The engine applies a saved
  monitor at its next check (within 5 minutes). The Monitors list now shows what is still waiting, and after a
  reload the page goes on following your waiting changes until they are applied.
- "Add to monitor..." names a monitor that is saved but not applied yet, and does not change a monitor while a change
  to it is still waiting, so one change never overwrites the other.

## 2.0.77 - the build pool in the heartbeat
- A private-network install tells Invardia the state of its registry build pool (size, instances running, when it
  was checked), as the update job read it. An install without a pool sends nothing for it.
- A heartbeat value with an entry named "count" that is 0 is no longer dropped as empty.

## 2.0.76 - the update waits for running jobs (fix)
- In 2.0.74 and 2.0.75 the update stopped before it could check which jobs were running, so it installed nothing. It
  changed nothing, and nothing else was affected. Now it checks, waits for running jobs and installs. An install on
  2.0.74 or 2.0.75 needs one install run to get this release; later updates install by themselves again.
- Only Entra Policy Suite's own jobs are waited for, never another product's job in the same resource group.

## 2.0.75 - a private install's build pool runs only while it builds
- **Superseded by 2.0.76 - do not install** (the update in this release stops safely before it installs anything; see
  2.0.76). Its GitHub release is marked pre-release.
- On a private-network install, the registry's build pool has no running instances between builds. Installing or
  updating starts two instances for the image build and stops them again afterwards, also when the build fails, and
  checks that they stopped. A build on the pool may take up to 90 minutes. A pool made by an earlier release is made
  again in the new size, with no instances running.

## 2.0.74 - updates install only between runs
- **Superseded by 2.0.76 - do not install** (the update in this release stops safely before it installs anything; see
  2.0.76). Its GitHub release is marked pre-release.
- An update never changes the database while another job runs. When a new release is due, no new job starts (a "Run
  now" waits); the update waits until the running jobs have finished - at most 45 minutes - and only then installs.
  If they are still running after 45 minutes, nothing is changed and the update tries again the next night; Invardia
  is told. Nothing that runs is ever stopped.

## 2.0.73 - support access in the heartbeat
- The heartbeat to Invardia reports the support access the install applied: the support level in effect and that its
  read access is in place - as the support-access job read it back, never a guessed value.

## 2.0.72 - sign-in front 1.4.5
- The web app's sign-in front is version 1.4.5 (wording only; it behaves as 1.4.4). An install run builds it in your
  registry; the updater keeps the front an install run deployed.

## 2.0.71 - the shared update verifier, current wording
- The update verifier that Entra Policy Suite shares with Invardia's other products is taken at its newest version
  (wording only; it checks the same things).

## 2.0.70 - a fuller audit trail, and a stricter launcher
- The audit trail now also records: each person's sign-in to the web app (at most once per 8 hours), who looked at
  the identity report and at a CA analysis's sign-in rows (once per person per view per hour), the download of the
  alarm inputs, every run of the database setup job with its result, and every release the updater installed.
- The install launcher checks every release before it runs anything.
- Wording in shipped files describes what the product does.

## 2.0.69 - importing v1 data without a database right
- New page Overview > Import v1 (SuperAdmin): upload the files from v1's DATA folder (and v1's user tagging script for
  the attribute per tag type). Reading them saves nothing: the page shows, area by area, what would be added, what would
  change (old and new value) and what is already so, with the hints on the rules. Import, and Entra Policy Suite writes
  it within 5 minutes - the rules, tag types and values, settings, break-glass accounts, administrative units, target
  groups and service tags. The change history and the audit trail record who imported what. A new import replaces the
  rules an earlier v1 import made; rules made in the app are never touched.
- Nobody needs a database right to import v1 any more. Import-EpsV1Data.ps1 still shows the plan from the v1 folder, but
  it writes nothing: with -Apply it lists the files to upload on the Import v1 page. -ConnectionString is no longer used.
- The install takes -SupportAppId (with -SupportAccess) and -Resume, with the same names and meaning as Invardia's other
  products: -SupportAppId names your Invardia Support app by its id and gives it a starting support level (default:
  troubleshoot - read, plus admin only during an open support session) until your organization's level from the
  Invardia portal arrives; -Resume continues an interrupted install with the same values and is refused when there is
  none.
- The install lines are the same everywhere: two lines, Community from GitHub, Pro from invardia.com.

## 2.0.68 - the external alarm without a database right
- The Tamper page has a new button for Admins and SuperAdmins: Download the alarm inputs. It gives one file with the
  break-glass accounts, the watched tag attributes and the known writers.
- Deploy-EpsAzureMonitorAlerts.ps1 builds the external Azure Monitor alarm from that file (-InputFile) and no longer
  reads the database. Run it again with a fresh file after any of those change.

## 2.0.67 - adding a hybrid worker without a database right
- Grant-EpsHybridWorkerAccess.ps1 gives (or with -Remove takes away) the hybrid worker's database access through the
  install's database setup job, which reads the result back: you need the right to start a job in the install's resource
  group, no database right. An install made before 2.0.59 is changed as before.

## 2.0.66 - mail settings without a database right
- Initialize-EpsMailSender.ps1 stores the mail settings (mode, sender, recipients, environment name) through the
  install's database setup job: you need the right to start a job in the install's resource group, no database right.
  The job takes only these settings, checks every value and writes the change to the audit trail. An install made
  before 2.0.59 is changed as before.

## 2.0.65 - the updater keeps a private install's Key Vault private
- On every run, the update job of a private network install checks that the install's Key Vault is still private (public
  access off, deny by default, trusted Azure services allowed, no IP or network rules). A vault that lost those settings -
  for example after it was recovered - is set private again and read back. A public install is not changed.

## 2.0.64 - support access audited; naming a SuperAdmin without a database right
- Fixed: every change to the Support app's database access is now in the audit trail, and so is a support session that
  was refused.
- Set-EpsWebAccess.ps1 names a SuperAdmin through the install's database setup job when there is none: you need the
  right to start a job in the install's resource group, no database right. Admin and Reader are given in the web app's
  Access page. An install made before 2.0.59 is changed as before.

## 2.0.63 - support access follows the level set in the Invardia portal
- A new job, run every 5 minutes as the database setup identity, asks Invardia for the support access level your
  organization set for this install in the Invardia customer portal and applies it to the database:
  - none: the Invardia Support app has no database user;
  - read: the Support app can read the product's tables, nothing more;
  - troubleshoot / setup: read, plus database admin only while Invardia has an open support session for this install,
    at most 8 hours, removed again when the session closes or its time has passed.
- If Invardia cannot be reached, the last level keeps applying, and an admin window still ends at its time. Every
  change is read back and written to the audit trail. No part of the product (engine, web app, worker) can raise or
  lower it.
- An install run adds the job.

## 2.0.62 - support consent from the Invardia portal
- The install keeps the support access level your organization sets for it in the Invardia customer portal (none, read,
  or troubleshoot / setup), as Invardia sends it with the answer to the install's own heartbeat. The web app can only
  read it.
- A support session that goes beyond that level, or that arrives before any level was received, is not taken: it is
  recorded as closed and the refusal is written to the audit trail.
- Fixed: the install now reads its environment name from Invardia.

## 2.0.61 - setup steps for the database job and the updater
- The heartbeat to Invardia reports two more setup steps: whether the database setup job has set up the database, and
  whether the update job has its own identity to install releases. Each comes from a real record (the job's own record
  in the database, and the last update run), never from a remembered value.
- When the database setup job is in use, the version of the sign-in front the web app runs is recorded through that job,
  so the person who installs needs no database right for it either.

## 2.0.60 - the updater installs approved releases
- The nightly update job now installs a release Invardia approved for your update ring: it downloads the release and
  checks it against the signed size and SHA-256, builds the new image in your own container registry (on the build pool
  of a private install), updates the database with the database setup job, then moves every job and the web app to the
  new image and reads each one back. A stage that fails stops the update before anything moves; the next night tries
  again. When a job is running, the update waits for the next night.
- The update job does this as its own identity, with rights on the install's resource group only.
  The engine identity still holds no Azure right. An install run with this release adds the identity; until then the
  update job only checks, as before.
- Each stage of an update is reported to Invardia as it happens.
- Fixed: 2.0.59 read the SQL admin group's members back from the group, which leaves the setup job's identity out for
  an installer without directory read rights - the install then ran the database steps the old way. The membership is
  now read from the identity's side.

## 2.0.59 - nobody needs database admin rights to install
- The database is now set up by a one-time job inside your install, with its own identity: the schema, one
  least-privilege role per identity, their database users, the sign-in front's state and you as the first SuperAdmin.
  Every user is read back before the install goes on.
- The Azure SQL server's admin is a security group (or your own with -SqlAdminGroupId) that holds the job's identity.
  The person who installs needs no SQL right. A private install needs no machine inside the network for its database
  steps.
- An existing install keeps its SQL admin. A group admin gets the job's identity added; a server whose admin is a person
  goes on as before, and the installer says so.
- The install's final check now reads the scheduler run's result from Azure instead of from the database.

## 2.0.58 - long runs reported to Invardia in the agreed shape
- While a job runs, the heartbeat reports it the way Invardia reads it: running, which job, since when, and how its
  length compares with its usual one.
- When Invardia refuses a field of the heartbeat and names it, the heartbeat is sent again without only that field;
  the rest of the report still arrives.
- Fixed: 2.0.57 did not raise an existing S0 database to S1 (Azure reports an S0 database's size in another form than
  the install compared). An install run now raises it.

## 2.0.57 - the database starts larger, and the sign-in version in the heartbeat
- A new install's database starts at Standard S1 with 250 GB (was S0). An install run raises an existing S0 or Basic
  database to S1; a database you sized yourself is left as it is.
- The heartbeat to Invardia now reports the version of the sign-in front the web app runs. The install records it at
  every deploy, so no extra Azure right is needed.

## 2.0.56 - the scheduler runs as the engine identity in every install
- An install made before 2.0.55 moves its scheduler job to the engine identity, as new installs do. Its job names and
  other Azure names stay as they are.
- After the install has run the scheduler that way, it removes the old scheduler identity: its role assignments, its database user and the identity itself, each read back. Nothing is removed before that.

## 2.0.55 - standard names for new installs, and the return route for a private install
- A new install uses the standard names: resource group rg-eps; the scheduler job and the update job get the standard
  job names (see the install guide's naming table); registry, SQL server, Key Vault and storage end in six characters
  derived from the install. The scheduler now runs as the engine identity, so a new install has two managed identities
  (the engine identity and the web identity).
- An existing install keeps every Azure name it has. Run without -ResourceGroup, the installer and the setup scripts
  find an install in rg-entrapolicysuite and stay there.
- Private install behind a hub firewall: new optional -InternalRanges and -FirewallIp. On a network the install makes,
  it creates the route table rt-eps on the apps subnet (your ranges back through the firewall, BGP route propagation
  off) and reads it back. Without it, replies to your network time out. On your own network the route is on the
  network hand-off list.

## 2.0.54 - the install waits instead of failing, and reads back what it links
- When the install needs something from you first, it now says it is WAITING instead of failing: missing DNS records,
  or no proof yet from inside your network. The step shows "waiting" with the reason, and the installer ends with exit
  code 4. Run the same command again when it is done; it resumes at that step.
- Private install: every private DNS zone link the install makes is read back before the install goes on.
- Private install: when your sign-in may not read your hub network or your central DNS zones, or write records in
  them, the install warns you and puts it on the network hand-off list as a task for your network team. It no longer
  stops.
- A build pool or Key Vault left in a failed state by an earlier run is created again when the install resumes.
- Two stop messages no longer suggest removing something that may be in use elsewhere.

## 2.0.53 - private install: the build pool's way out
- Azure now creates new subnets without internet access. In a private install, the registry's build pool runs in the
  endpoints subnet and needs a way out: the subnet the install makes now has default outbound access on, and one it made
  in an earlier run is set the same way.
- Before the build pool is created, the install checks the subnet's way out (a NAT gateway, a 0.0.0.0/0 route, or
  default outbound access). When you bring your own subnet and it has none, the install says so before it creates
  anything, and tells you what to add. Your subnet is never changed.

## 2.0.52 - Exchange rights only where they are used
- The engine holds the Exchange Online permission and the Exchange Recipient Administrator role only while user tagging,
  the identity report or a rule with a mailbox condition is on. A new install grants neither. An install run removes them
  when none of these is on any more, and grants them again when one is switched on. Alert mail does not need them.
- The setup step for the Exchange role now says whether it is needed, and the command that grants or removes it.

## 2.0.51 - security findings to Invardia by default
- Send security findings to Invardia (Uplink.Alerts.Enabled) is on by default: Invardia now takes all six kinds (tag
  changes made outside Entra Policy Suite, high-severity tag changes, Conditional Access drift, a deleted policy, a
  missing break-glass exclusion, a silent hybrid worker). A SuperAdmin can switch it off. An install that switched it off
  keeps it off.

## 2.0.50 - standard identity names, the read-back
- Fixed: right after a rename, Microsoft Graph can return the old name for a while; the install stopped instead of
  waiting. It now waits up to two minutes for the new name.

## 2.0.49 - standard identity names
- The web app's app registration and enterprise application are named Entra Policy Suite (with the resource group in
  brackets only when several installs share one tenant). An install made before is renamed in place by its next install
  run: same object, same app id, nobody loses access.
- A SQL admin group still named after the old product name gets its standard name in place, and the SQL
  server's admin entry follows it. A group you named yourself keeps its name.
- The install lists what it renamed at the end.

## 2.0.48 - the update check reads the install key
- Fixed: the update check did not read the per-install key from the Key Vault, so it never asked Invardia whether an
  update is wanted now and never reported a new version.

## 2.0.47 - the update check says more
- The update check's run log always says what happened with the "update now" question to Invardia, including why
  it was not asked.

## 2.0.46 - the update check
- New job: every night at 03:00 the update job asks Invardia which Entra Policy Suite version is approved for this
  install's update ring, checks that the answer is genuine and complete, and records what it would install in its run.
  In this release it only checks: it downloads and installs nothing. With the per-install key it also reports a new
  version to Invardia once. New setting Update.Enabled (on by default) switches it off.

## 2.0.45 - the product name, the rest
- The installer's closing line, two messages and the generated security review pack and API reference also say
  Entra Policy Suite.

## 2.0.44 - the product name
- The product is called Entra Policy Suite everywhere you read it: the web app's title, the mails (the header and the
  subject, e.g. `[Entra Policy Suite]`), the Azure Monitor alert names, the script help and the documentation. The
  GitHub repository, the installer, the support path and the Azure resource names stay EntraPolicySuite, so an existing
  install updates in place and nothing is renamed.

## 2.0.43 - wording
- The product page text of the CA Policy Analyzer uses US spelling, like the rest of the documentation.

## 2.0.42 - mails with a button, the update ring, a script for the engine's permissions
- Every mail EntraPolicySuite sends has the product's header, one blue button that opens the page the mail is about
  (the Tamper page, Conditional Access, the CA Policy Analyzer, the identity report, the mail settings) and a link to
  the web app. The test mail and the identity report mail now use the same subject format as every other mail.
- New script Grant-EpsEnginePermissions.ps1: gives the engine a permission it is missing after the install, or takes
  one away (-Remove). Only the permissions EntraPolicySuite declares for its engine can be asked for; -WhatIf shows the
  plan; every change is read back.
- The install's resource group gets the standard tags (product, ring, edition, hosting, tenant, owner, purpose); a
  re-run keeps the tags you set yourself.
- New install parameter -Ring: the update ring this install belongs to, reported to Invardia.
## 2.0.41 - private network install: re-installs and resumes
- Fixed: re-installing a private install into the same resource group stopped at the Key Vault key when the vault was
  recovered from an earlier install. The install now sets the vault's network rules every time before it makes the key.
- Fixed: an install resumed from before the jobs step could stop at the web app ("applications/ -> 405").
## 2.0.40 - private network install: the Key Vault key, a stricter region check
- Fixed: a private network install stopped at the Key Vault key. The private Key Vault still has public access off and
  no IP or network rules, and now lets trusted Azure services through, so the install can create its key.
- The region check now also catches a refused region on a fresh install (no resource group yet), and its test storage
  account uses the same settings as the real one, so a policy your install passes does not stop the check.
- The web sign-in step waits for Microsoft Entra to show the new app before it gives consent, instead of failing once.
## 2.0.39 - the region check explains an Azure Policy
- When an Azure Policy in your subscription refuses the region check's test resources, the install now says so in plain
  words and names the policy, then goes on. Before, it showed only Azure's generic message.
## 2.0.38 - private network install fixed, the region is checked first
- Fixed: a private network install stopped at its first private endpoint ("the private endpoint ... gives no address").
  The install now reads each endpoint's addresses from its network interface.
- Before anything is created, the install checks that Azure accepts new resources in the chosen region for your
  subscription. If it does not, it stops, creates nothing, and names regions that do.
## 2.0.37 - the security pack, Conditional Access docs corrected
- The security pack for reviewers is now delivered with each release: architecture, identities, every permission and
  why, data, vendor access, supply chain, change control, hardening, compliance, uninstall and scripts. It is generated
  from the code, so it always matches the version you run.
- Fixed: the documentation still said EntraPolicySuite cannot change a Conditional Access policy. It can make one
  change, on approval: a SuperAdmin moves an adopted policy to another stage after seeing what changes. The install
  documentation now lists the permission for it.
- The install's script description no longer mentions a custom role that installs since 2.0.10 no longer create.
## 2.0.36 - move a policy to any stage, the stage preview shows names
- Conditional Access: a SuperAdmin can move an adopted policy to any stage - Pilot1, Pilot2, Pilot3 or Prod, up or
  down - or disable it. A move that skips stages says which. The Move stage column has one "Move to ..." list per policy.
- Fixed: the move dialog showed "System.Object[]" instead of the users and groups the policy has now, and listed them
  as a change even when they stayed the same.
- The environment name in the page header, in alert mails and in the report to Invardia is now the name Invardia keeps
  for the install, when it reports to Invardia. The Environment name setting is the fallback.
## 2.0.35 - a private install checks everything first, a shorter install line
- A private network install now checks everything it needs before it creates anything: your network and its two
  subnets, the hub network, and every private DNS zone EntraPolicySuite uses in your central DNS zones resource group.
  Anything missing is listed at once, in plain words, and nothing is created. Fix the list and run the same command
  again, or leave out -PrivateDnsZonesResourceGroupId and the install makes its own zones.
- The install line names only what you must give: `-TenantId <tenant id> -SubscriptionId <subscription id>`. The region
  is West Europe unless you add `-Location <region>`.
- The support scripts at invardia.com/support/eps/ come with a full README: the install lines and every script with
  its documentation page and SHA-256.
## 2.0.34 - what an install tells Invardia, sign-in on a second run
- For installs that report to Invardia: the heartbeat now gives the install's addresses (the web app and its API) and,
  while a job runs, how long it has been running against its usual length.
- The setup scripts for mail, web access and alerts now always sign in again on a second run in the same PowerShell
  window, instead of reusing an earlier sign-in that has expired or belongs to another tenant.
- The install line names the region: `-TenantId <tenant id> -SubscriptionId <subscription id> -Location <region>`.
- Every script a person runs is now handed over to Invardia for invardia.com/support/eps/, each as one self-contained
  file. It downloads the release, checks it against the release's SHA-256, and runs the script from it.
## 2.0.33 - every policy has its persona, template library 2.0-v1.1
- A Conditional Access policy shows its persona even when none of your managed personas takes it: its template's
  persona, or, for a policy without a template, the persona its name says. CA000-CA0xx are Global, CA095-CA099
  BreakGlassAccounts. Your managed personas still come first.
- **Template library 2.0-v1.1:** each template's persona now comes from the template's name, which fixes v1's spelling
  slips (Users-Internals, Users-Internal-Developerss, Users-Externals) and CA262. The 29 corrected templates are version
  v1.1. Conditional Access > Template updates shows each change, old against new, for you to adopt.
- Personas you don't manage yet are marked as coming from the template in Manage personas. Editing one makes it yours.
- CA Policy Analyzer: the "read a large log in parts" field is gone. EPS decides: a window longer than a day is read a
  day at a time.
- Get started opens with how to bring v1 over: the tagging rules in the browser (Tagging Rules > Import CSV), or
  everything with the import script, step by step.
- Tagging Rules grid: one number column, # (the run order). The rule's id shows when you point at the number.
## 2.0.32 - the menus open
- The six menus opened in 2.0.31 but stayed hidden under the menu bar. They now fold out, on a click and when you point
  at them.
## 2.0.31 - six menus instead of sixteen tabs
- The menu has six groups: **Overview**, **Tagging**, **Conditional Access**, **Identity report**, **Jobs & runs** and
  **Administration**. Each group opens a list of its pages, every page with one line on what it is for. The group
  you are in is highlighted.
- The full name "Entra Policy Suite" next to EPS in the header is now light and easy to read.
## 2.0.30 - an action per user in the identity report
- Every user in the identity report has four follow-up fields: **Action** (Disable, Delete, Investigate, Remove from
  cloud sync), **Status** (Not started, In progress, Closed), **Who** (who is responsible) and **Notes**.
- Tick users, or take every user a view and its filters show (up to 5,000), and set the fields on all of them at once.
  For example: filter to the service accounts that are synced to the cloud, then set "Remove from cloud sync", the team,
  and a note.
- A field you leave as it is stays unchanged; "clear" empties it.
- The fields are kept per user across report runs. They show in every user view and can be filtered, sorted, pivoted and
  exported like any other column.
- Setting them needs Admin and is journaled and audited. It is a record for follow-up: nothing in the tenant or AD
  changes.
## 2.0.29 - alerts to Invardia accepted, EPS in the header, rules collapsed
- Alerts sent to Invardia (for installs that report) carry only the fields Invardia's alert contract takes.
- The header says **EPS**, with "Entra Policy Suite" in smaller letters.
- Tagging Rules: the groups start collapsed (Expand all opens them; a search shows what it finds). The value column says
  **Tag Value**, and Matched explains itself when you point at it: how many accounts the rule matched in the last run.
- Get started: the mail-sender step's text no longer reads like a command.
## 2.0.28 - Get started
- A new page, **Get started**, lists what EntraPolicySuite needs before the templates, tagging and reports work: what
  v1's scripts set up first. **Check now** reads the tenant and changes nothing. Each item shows as ready, missing or
  to check, with what was found. There are 13 steps:
  1. The engine's Graph permissions and Exchange role, and the licences the templates need.
  2. The break-glass accounts: cloud-only, password never expires, Global Administrator, their group, excluded from
     every policy.
  3. The FIDO2 and Windows Hello authentication strengths (compared with v1's: the allowed methods and the 11 key
     models), and the authentication methods switched on.
  4. The group targeting method, now a choice of v1's three, and the group names that follow from it.
  5. The target groups: in the tenant, with members, the dynamic rule as stored.
  6. The pilot and exclude groups of your adopted policies.
  7. The administrative units.
  8. Named locations: denied countries and a trusted location for your offices.
  9. The tag attributes, the rules, and the AD Connect sync account left out.
  10. The alert mail.
  11. The hybrid worker.
  12. The report's AD OU patterns.
  13. The templates that need an input.
- The break-glass accounts can now be added and changed on the page (SuperAdmin), where until now only the v1 import
  filled the list. This changes EntraPolicySuite's list only, never the tenant. Never write a password there.
- The heartbeat to Invardia (for installs that report) now says, from a real check each time, whether every one-time
  setup step is in place, such as each of the engine's Graph permissions.
- Creating what is missing, as v1 did, comes in the next releases, one step at a time, each after you see the plan.
## 2.0.27 - stage buttons for Conditional Access policies
- On the Conditional Access page, a SuperAdmin moves an adopted policy one stage at a time: Initial (off), Pilot1
  (report-only for the pilot group), Pilot2 / Pilot3 (on for the pilot group), Prod (on for its targets), one stage
  back, or off (Disable). The policy page shows the stages, a button for each move, and the moves made.
- Each move first shows what changes: the name, the state and who the policy includes, now and after the move. A move
  that enforces the policy (Pilot2, Pilot3, Prod) needs a tick that you checked who it enforces for.
- What a move changes is what the v1 scripts' stage modes did, for the group-targeting method you set. EntraPolicySuite
  never changes a group: with dynamic pilot groups, the move says which pilot values the group's rule must take, and
  you change the rule yourself.
- The engine applies the move within 5 minutes. It reads the policy again first, and refuses (changing nothing) when:
  - the policy changed since you looked at it
  - a group the stage needs is not in the tenant
  - the break-glass accounts would not stay excluded
  Turning a policy off is always allowed.
- It then makes the one change and reads the policy back. The move is journaled, audited and kept in the policy's
  history, and the monitor does not report your own move as a drift.
- **Run the install again after the update:** the engine needs the Microsoft Graph permission
  Policy.ReadWrite.ConditionalAccess for the stage buttons. To leave it out, use
  `-ExcludeGraphRole Policy.ReadWrite.ConditionalAccess`; the buttons then say the tenant refused the move.
- Nothing changes a Conditional Access policy by itself: no schedule, job, monitor or template update writes one.
## 2.0.26 - template updates you control
- Conditional Access has a new tab, **Template updates**. When a release brings a newer template library, nothing
  changes by itself. The tab lists what is new, changed or removed since the library your install took. For each
  changed template it shows the settings side by side (before and after), and how each of your policies with that
  CA number differs from the new template. Each template can be exported as JSON, as it is now and as you took it.
- Persona changes in the library (a CA number added to a persona, or taken out) are listed per persona. **Apply** adds
  or removes the numbers as name rules in your persona, and creates the persona if you do not have it. **Skip** leaves
  your persona as it is. Either way the change is not offered again.
- A template change is only **marked as seen**. The next update then compares from that version. Your policies are never
  changed: if you want what a new template does, make the change yourself in the tenant.
- Every take needs Admin, has a reason, and is applied by the engine, journaled and audited.
- This release has the same library as before (2.0-v1), so the tab says "Nothing new". The engine records the library
  your install took at its next read of the policy list.
## 2.0.25 - personas and monitors: leave out any policy
- A persona can leave out a policy its name rules take: in Manage personas, untick it and it stays out; tick it again
  to take it back.
- "Remove from monitor..." on the Conditional Access page now removes any policy. A policy you picked one by one is
  unpicked; a policy that comes in through a persona or an older series rule is left out of that monitor. The
  confirmation says per policy what happens. "Add to monitor..." takes a left-out policy back.
- The CA Policy Analyzer form shows a monitor's left-out policies as "left out of this monitor", each with "take back".
  Unticking a policy that a ticked persona takes leaves it out of that monitor.
- The Persona column on the Conditional Access page shows the personas you manage: every persona that takes the policy
  ("no persona" when none). Filtering on a persona finds a policy that is in several.
- Personas and monitors work on your real policies. The built-in personas are a starting list, made once from your
  policies when the analyzer first runs; after that it is yours. You can delete the last persona: an empty list stays
  empty. Policies in no persona are listed under "No persona".
- The analyzer still only reads: nothing changes a Conditional Access policy.
## 2.0.24 - one CA Policy Analyzer form, personas you manage
- The CA Policy Analyzer has ONE form: pick a new monitor or an existing one at the top, then 1. which policies,
  2. which sign-ins (the last 24 hours, 3, 7, 14 or 30 days) and 3. Analyse now or Save as monitor. Analyse first and
  save the same choice as a monitor, or save it straight away. Edit on a monitor loads it into the same form.
- The less common options (non-interactive sign-ins, guests, disabled accounts, reading a large log in parts) are under
  a closed "More options". "Read the policy list" is now a small "Refresh the list" link beside the policy count.
- Personas are a list you manage (Manage personas): create one, rename it, add or remove policies and name rules
  (CA2 = every CA2xx, CA006 = the CA006 policies, CA6* = a wildcard), delete it. The template personas are the starting
  list. A policy can be in several personas, or none. A monitor that names a persona follows a rename, and takes a
  change at its next run. A persona a monitor uses is deleted only after the page names those monitors and you confirm.
- The Series box is gone. A monitor saved with series keeps running them; the form shows them and lets you remove them.
- Each policy in the list shows the monitors it is in. On the Conditional Access page, select policies and choose
  "Add to monitor..." or "Remove from monitor...".
- The persona groups sort as intended: Global first, the personas A-Z, policies without a persona last.
- The analyzer still only reads: nothing changes a Conditional Access policy.

## 2.0.23 - bulk changes in one engine check, full-width pages
- A bulk change (for example adopting many Conditional Access policies at once) is applied in ONE engine check:
  the engine takes every waiting configuration change together instead of one per check.
- The bar at the top says what really happens: the engine picks changes up at its next check (every 5 minutes), and it
  counts how many are applied and how many are waiting. A second click while a selection is still being sent sends
  nothing twice.
- Pages use the full width of the window on a laptop and a desktop alike: the explanations, info boxes, settings
  fields, table cells and the search box are no longer capped.

## 2.0.22 - a readable rule editor
- Tagging Rules: new, edit, duplicate and restore open the rule in a wide dialog. Each field (persona, tag type, the
  value, notes) has its own full-width line, so long tag types, values and notes are readable, and each condition is a
  row of type, target and Remove, with its explanation under it. The dialog closes after a save; the bar at the top
  follows the change.

## 2.0.21 - private network install
- Private network install: add `-PrivateNetwork` to install EntraPolicySuite inside your own virtual network. The web app
  then has no public address (reachable from your network, still behind the Entra sign-in), and the database, Key Vault,
  job queues and container registry are created with public access off and reached through private endpoints and
  private DNS zones. Bring your own network (`-VnetId`) or let the install make one (`-VnetAddressPrefix`, default
  10.230.0.0/24); use your central DNS zones (`-PrivateDnsZonesResourceGroupId`); optionally peer with your hub
  (`-HubVnetId -PeerToHub`) and link the zones to it (`-LinkZonesToHub`). The parameter names are the same as in
  SecurityInsight.
- The install checks DNS from the machine it runs on before it touches any data, prints the exact DNS records your
  network needs when a name does not resolve, and continues where it stopped when you run it again. At the end a check
  from inside the network proves the web app and every job before the install reports success.
- The network hand-off: the peering, DNS zones and records, outbound addresses and the check to run are printed and
  saved next to the install journal, with a ready-to-run script for the owner of your hub network.
- An existing public install moves to the private network with the same command and `-PrivateNetwork`; `-WhatIf`
  shows the plan first.
- The two-line install passes every install parameter on (the private network ones included);
  `tools/setup/install-parameters.json` lists them all with their defaults.
- The scripts print the README on GitHub as their documentation link.

## 2.0.20 - the first public release of 2.0
EntraPolicySuite moves from scripts to your own Azure: Container Apps jobs, Azure SQL and a web app your admins sign in
to with Microsoft Entra ID.
- **Install in two lines** (PowerShell 7 or Azure Cloud Shell, browser sign-in, no modules): `Start-EpsInstall.ps1`
  downloads the release, checks it against GitHub's SHA-256 digest and runs the installer. `-WhatIf` shows the plan;
  a stopped install resumes.
- **User and device tagging** with rules as cards (persona, tag type, value, conditions), a preview of every run before
  it applies, rule guards, scopes, and an import of your v1 rule files.
- **Tagging Rules page** with grouping, Expand all / Collapse all, multi-select filters and bulk actions.
- **Tag tamper monitor**: a change to a watched tag that EntraPolicySuite did not make is alerted; accept or restore it.
- **Conditional Access**: the template library, a review of your policies against it with a Persona column, adopt /
  release (also several at once), and a documentation export. EntraPolicySuite never writes a Conditional Access policy.
- **CA Policy Analyzer**: policies grouped by persona (Global first); pick a persona, a series (CA2 = the whole CA2xx
  series, shown as you type) or single policies; monitors per persona, each with its own alert recipients.
- **Identity report** with gap views and a workbook download.
- **Hybrid worker** for AD-synced users.
- **Access and audit**: SuperAdmin / Admin / Reader roles and an append-only audit trail; a note on a change is optional.
- Every feature is off after the install.
