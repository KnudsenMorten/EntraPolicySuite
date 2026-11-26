# What's new in Entra Policy Suite

## 2.1.74 · 2026-11-26 · Fix-only

Mail through an SMTP relay keeps the From address the relay accepts.

### New features

None in this version.

### Fixes

- **SMTP mail keeps its accepted From** - With an SMTP relay, the From address the relay already accepts stays the From. A different saved sender becomes the From only when its test mail passes.

## 2.1.73 · 2026-11-26 · Security

Break-glass accounts can always sign in, and a mail sender change is proven before it switches.

### New features

None in this version.

### Fixes

- **Break-glass accounts can always sign in** - A Conditional Access change that would stop a break-glass account from signing in is refused. Only the break-glass templates may include them, with a control they can meet: MFA or the FIDO strength. CA095 is unchanged.
- **Queued changes checked again** - Changes the web app hands to the engine are checked again by the engine - who may make them and what they change - before they run.
- **A sender change proven first** - The mail setup switches the sender only after Entra Policy Suite itself may send as the new mailbox. If anything fails, the old rights are put back.

## 2.1.72 · 2026-11-25 · Security

Every mail comes from one sender, changing the sender works, and the send right is checked every day.

### New features

None in this version.

### Fixes

- **One sender for every mail** - Every mail now comes from the one sender mailbox, also through an SMTP relay. The separate SMTP from address is gone; an existing one is moved into the sender once, so no mail stops.
- **Changing the sender works** - The mail setup checks that the right for a new mailbox works before it switches (Exchange can take up to 2 hours), then removes the right for the old one. If it does not work, the old sender stays.
- **The send right checked every day** - Once a day Entra Policy Suite checks that it may send as the sender mailbox and as no other one - without sending anything - and reports the result.

## 2.1.71 · 2026-11-25 · Fix-only

A quieter change notice, and admins through PIM for Groups are counted again.

### New features

None in this version.

### Fixes

- **A quieter change notice** - After a change the bar shows one plain line - "Sent - the engine applies it within 5 minutes". Once you close it, it stays closed until your next change; the result is shown in the status line.
- **Admins through PIM for Groups** - The Identity report reads Privileged Identity Management for Groups per role group, as Microsoft Graph requires, so people who reach an admin role only through PIM for Groups are counted as admins again.

## 2.1.70 · 2026-11-25 · Fix-only

Copying, deploying and removing a Conditional Access policy no longer reports a false error.

### New features

None in this version.

### Fixes

- **No false error after a copy or deploy** - A new policy can take Microsoft a few seconds to show. Entra Policy Suite now waits for it (up to a minute) instead of reporting an error while the policy was in fact created.
- **Remove checks again before it reports** - After removing a policy, Entra Policy Suite waits up to a minute for Microsoft to confirm it is gone, so a removed policy is no longer reported as still there.
- **Edit and stage moves wait too** - Edit and moving a policy between stages also wait for Microsoft before they report.

## 2.1.68 · 2026-11-24 · Security

The support access check completes again.

### New features

None in this version.

### Fixes

- **Support access check completes** - Since 2.1.66 the support access check could not record the level Setup, so each check ended as failed, although the access was applied as you chose. It now completes.

## 2.1.67 · 2026-11-24 · Security

A first install is checked against Invardia's signature, and every page states the same security facts.

### New features

None in this version.

### Fixes

- **Signed first install, one set of facts** - The first install of the Community edition now takes only the release signed for your ring and checks it like every update. The security pages, the security pack and the product pages state the same rights and limits.

## 2.1.66 · 2026-11-24 · Fix-only

Invardia support uses the shared levels: Troubleshoot reads only, Setup adds a time-boxed admin session.

### New features

None in this version.

### Fixes

- **Support levels: Troubleshoot reads only** - Invardia support now uses the levels of the other Invardia products. Troubleshoot reads only. Setup also allows database admin, only during a support session you open, for at most 8 hours.

## 2.1.65 · 2026-11-24 · Fix-only

The architecture page lists the highly privileged rights and says where each claim stops.

### New features

None in this version.

### Fixes

- **Architecture page: privileged rights and limits** - The architecture page lists the rights that can change access in your tenant, what each could do and its limit, and how far the audit trail and the managed-identity sign-in reach.

## 2.1.64 · 2026-11-24 · Fix-only

Security updates install within 15 minutes, not at night.

### New features

None in this version.

### Fixes

- **Security updates install at once** - When a security update (a new base image on the version your installation runs) is released to its ring, the engine finds it within 15 minutes and starts the update at once, not at the nightly update at 03:00.

## 2.1.63 · 2026-11-23 · Fix-only

The install guide shows each part's standard and earlier name.

### New features

None in this version.

### Fixes

- **Names table shows earlier names** - The install guide's table of names now shows the standard name, the earlier name an install made before 2.0.55 may still use, and the identity of each part. The 2.1.59 notes now say what that version fixed.

## 2.1.62.2 · 2026-11-23 · Fix-only

A security update from Microsoft.

### New features

None in this version.

### Fixes

- **Security update from Microsoft** - Your installation runs on Microsoft's newest security update (.NET 10.0.15). Nothing else changes.

## 2.1.62.1 · 2026-11-23 · Fix-only

A security update from Microsoft.

### New features

None in this version.

### Fixes

- **Security update from Microsoft** - Your installation runs on Microsoft's newest security update (.NET 10.0.15). Nothing else changes.

## 2.1.62 · 2026-11-23 · Fix-only

The security pack lists only the product's own identities.

### New features

None in this version.

### Fixes

- **Security pack lists only its own identities** - The identities table in the security pack lists only the identities Entra Policy Suite creates and uses. The person who runs the install is named as a requirement of the install, not as an identity.

## 2.1.61 · 2026-11-23 · Fix-only

The Jobs docs say when an update stops a job run.

### New features

None in this version.

### Fixes

- **Jobs docs explain stopped job runs** - The Update job's description says that a job run which has stopped working is stopped so the update can go on, and that a run which still writes to its log is never stopped.

## 2.1.60.1 · 2026-11-23 · Fix-only

A security update from Microsoft.

### New features

None in this version.

### Fixes

- **Security update from Microsoft** - Your installation runs on Microsoft's newest security update (.NET 10.0.15). Nothing else changes.

## 2.1.60 · 2026-11-21 · Fix-only

A job run that stopped working no longer holds an update back.

### New features

None in this version.

### Fixes

- **Updates go on past a stopped job run** - When a job run is far past its usual length and has logged nothing since it started, the update stops that run, reports it to Invardia and goes on. A run that still logs is never stopped.

## 2.1.59 · 2026-11-20 · Fix-only

Completes the 2.1.58 fix for the 4-hour reports to Invardia.

### New features

None in this version.

### Fixes

- **4-hour reports stay on schedule** - Completes the 2.1.58 fix: when the report right after an update came while a regular report was also due, the 4-hour schedule still moved. Now only a regular report sets it.

## 2.1.58 · 2026-11-20 · Fix-only

The connection to Invardia reports every 4 hours, also after an update.

### New features

None in this version.

### Fixes

- **Regular reports to Invardia after an update** - After an update your installation reports its new version to Invardia at once and then keeps its 4-hour schedule. Before, Invardia could hear nothing for up to 8 hours.

## 2.1.57 · 2026-11-20 · Fix-only

The security pack names each part by its role.

### New features

None in this version.

### Fixes

- **One table of names in the security pack** - The security pack lists the Azure names of your installation in one table, with the earlier names an older install may still use. The rest of the pack names each part by its role.

## 2.1.56 · 2026-11-20 · Security

The earlier sign-in's unused code is removed, and every failed run carries a support code.

### New features

None in this version.

### Fixes

- **Unused sign-in code removed** - The code of the earlier sign-in, unused since Microsoft's built-in sign-in took over, is gone from the install and the update. Your installation is not changed.
- **A support code on every failed run** - A job run that does not end OK now names a stable code, so Invardia support can tell you the cause and the next step without reading logs.
- **Corrected help pages** - The install and security pages describe Microsoft's built-in sign-in, and the tamper monitor page says when an accepted change closes.

## 2.1.55.1 · 2026-11-19 · Fix-only

A security update from Microsoft.

### New features

None in this version.

### Fixes

- **Security update from Microsoft** - Your installation runs on Microsoft's newest security update (.NET 10.0.15). Nothing else changes.

## 2.1.55 · 2026-11-16 · Security

The API for scripts and the MCP server are switched off on every install until they are opened again on purpose.

### New features

None in this version.

### Fixes

- **Script API and MCP server switched off** - Both addresses and their sign-in information answer as if they did not exist, whatever the license. The API and MCP page says so. Sign-in to the web app and the connection to Invardia are unchanged.

## 2.1.53 · 2026-11-16 · Security

The API for applications is switched off on every install until it is opened again on purpose.

### New features

None in this version.

### Fixes

- **The API for applications is off** - Settings by code and Support fixes are switched off: the address answers as if it did not exist and the setup script changes nothing. Sign-in to the web app, the API for scripts and the connection to Invardia are unchanged.

## 2.1.52 · 2026-11-16 · Feature update

Your own programs can read and change Entra Policy Suite settings by code, with security controls kept for people.

### New features

- **Manage settings by code** - An application you approve can export and import settings through the API. Grants and tenant changes wait in the commit queue for a person. Sign-in, approval, audit and other security settings stay person-only.
- **Support fixes when you ask** - If you ask Invardia to fix a support ticket for you, your administrator can switch on Support fixes. Each fix is a listed, safe step on a ticket, recorded in the audit trail and mailed to you.

### Fixes

None in this version.

## 2.1.51 · 2026-11-15 · Fix-only

The hybrid worker page counts only the AD changes it really wrote.

### New features

None in this version.

### Fixes

- **Written means written** - On the hybrid worker page, the daily count of written AD changes no longer includes changes skipped because a newer value came. Those now show in their own column.

## 2.1.50 · 2026-11-15 · Feature update

The list of rights now says plainly which rights each optional feature needs.

### New features

- **Optional rights are marked by feature** - Each right that only an optional feature needs now names that feature in a fixed form, so checks of your install only expect it while the feature is switched on.

### Fixes

None in this version.

## 2.1.49 · 2026-11-15 · Fix-only

The Key Vault check no longer counts the sign-in's public app id as a secret.

### New features

None in this version.

### Fixes

- **The Key Vault check is right again** - The check that every secret is kept in Key Vault counted the web app's public sign-in id as a secret. It no longer does; any real secret outside Key Vault is still counted.

## 2.1.48 · 2026-11-15 · Fix-only

After an update, the support link reports the new version within minutes.

### New features

None in this version.

### Fixes

- **The new version is reported right away** - After an update, the support link tells Invardia support the new version within minutes instead of at its next four-hourly report, and an update no longer holds the support link back.

## 2.1.47 · 2026-11-15 · Fix-only

Each job report to Invardia support says when the job finished.

### New features

None in this version.

### Fixes

- **Job reports carry the time the job finished** - Each report to Invardia support now names when the job finished, not only when the report was sent, so an old problem is never mistaken for a new one.

## 2.1.46 · 2026-11-15 · Fix-only

A short hiccup during an update no longer looks like a failure to Invardia support.

### New features

None in this version.

### Fixes

- **A passing hiccup is reported as one** - When an update stops before it changes anything, because Azure or a download did not answer in time, the report says it will be tried again. Invardia support then waits for the next try instead of opening a ticket.

## 2.1.45 · 2026-11-15 · Fix-only

The support link sends only job reports from the last day.

### New features

None in this version.

### Fixes

- **Only recent job reports go to Invardia support** - The support link sends the reports of jobs that finished in the last 24 hours. Older reports are not sent, so an old problem that was solved long ago is never reported as new.

## 2.1.44 · 2026-11-15 · Fix-only

The support link sends the job reports again.

### New features

None in this version.

### Fixes

- **Job reports reach Invardia support again** - Since 8 November the support link sent only its regular status, not the reports of finished jobs. It now sends them again, the oldest first, and its count of reports still to send is right.

## 2.1.43 · 2026-11-15 · Feature update

The web app checks its own sign-in at start, and the support link reports which release its documentation describes.

### New features

None in this version.

### Fixes

- **The sign-in check proves itself at start** - At start, the web app runs the same check a sign-in takes, with Microsoft's library, on made-up input. If that fails, it does not start, so a problem shows right after an update, not at someone's first sign-in.
- **The documentation's release is reported** - The regular report to Invardia support now names the release the shipped documentation describes, so out-of-date documentation is noticed automatically.

## 2.1.42 · 2026-11-15 · Security

Sign-ins are now checked with Microsoft's own library - no custom sign-in code is left.

### New features

None in this version.

### Fixes

- **Microsoft's library checks every sign-in** - The web app and the engine check each person's Microsoft sign-in with Microsoft's own library instead of code of ours. Microsoft's built-in sign-in still stands in front of the web app.
- **The registry clean-up reports correctly** - Once the last earlier sign-in image is removed, the clean-up now reports the registry as empty instead of a warning.

## 2.1.41 · 2026-11-15 · Security

The earlier sign-in's leftovers are cleared, and your web session is renewed before it ends.

### New features

None in this version.

### Fixes

- **The earlier sign-in's images are removed** - Once the web app uses Microsoft's built-in sign-in, the update removes the earlier sign-in front's images from your registry. The install also removes its old key when the person running it may.
- **Your web session is renewed in time** - The web app renews your sign-in a few minutes before it ends, so you are not asked to sign in again while you work.

## 2.1.40 · 2026-11-15 · Security

The last traces of the earlier sign-in are removed from your installation.

### New features

None in this version.

### Fixes

- **The earlier sign-in's database tables are removed** - The database setup removes the tables the earlier sign-in front kept, and the web app's right to make tables, once the web app uses Microsoft's built-in sign-in.
- **Only Microsoft's sign-in address is kept** - The web app's sign-in registration now needs only the address of Microsoft's built-in sign-in; the earlier address is reported as a leftover.

## 2.1.39 · 2026-11-15 · Security

The engine can be given a much smaller Exchange right: the tag attributes only.

### New features

None in this version.

### Fixes

- **A smaller Exchange right for the engine** - A new setup script gives the engine an Exchange role that can only read recipients and write the tag attributes. It then removes the organization-wide Exchange Recipient Administrator role from the engine.

## 2.1.38 · 2026-11-15 · Security

The update job holds fewer rights, and a security update no longer waits for running jobs.

### New features

None in this version.

### Fixes

- **The update job holds fewer rights** - The update job can no longer change who administers the database. It only checks that the database setup identity is still in the admin group, and reports it when it is not.
- **Security updates install at once** - A security update now stops the jobs that are running and installs at once instead of waiting for them. The stopped jobs run again on their next schedule.

## 2.1.37 · 2026-11-15 · Security

Every public address of the install is checked for Microsoft's sign-in, and the old sign-in front is gone.

### New features

None in this version.

### Fixes

- **Every public address checked for sign-in** - Each update run now checks every address of your installation that the internet can reach, and reports any that is not behind Microsoft's sign-in.
- **The old sign-in front is removed** - The release no longer carries the earlier sign-in front. Your web app already uses Microsoft's built-in sign-in.

## 2.1.36 · 2026-11-15 · Security

The move to Microsoft's sign-in is safer, and every install is checked against one standard.

### New features

None in this version.

### Fixes

- **A safer move to Microsoft's sign-in** - The update now prepares the web app before it turns Microsoft's sign-in on, and waits while Azure is still busy with the app. A move that cannot finish leaves the earlier sign-in working.
- **Every install checked against one standard** - Each update run now checks that the web app is set up exactly as the standard says, and lists anything the earlier sign-in left behind. It only reports; nothing is removed.

## 2.1.35 · 2026-11-14 · Security

The web app now signs people in with Microsoft's built-in Container Apps sign-in.

### New features

None in this version.

### Fixes

- **Microsoft's sign-in now guards the web app** - Microsoft's own Container Apps sign-in now stands in front of the web app, so a request without a sign-in never reaches it. No secret is used, and the app still checks each sign-in itself.
- **Fewer rights for the web app** - The web app's identity holds no Key Vault right any more, and the update job can no longer change the web app's sign-in registration.

## 2.1.34 · 2026-11-14 · Security

Prepares the move to Microsoft's built-in sign-in for the web app.

### New features

None in this version.

### Fixes

- **Ready for Microsoft's built-in sign-in** - The web app's sign-in registration now also holds the address Microsoft's built-in Container Apps sign-in uses. Nothing changes for you today. The coming switch then needs no step from an admin.

## 2.1.33 · 2026-11-14 · Security

Closing a tamper alarm now needs the admin's own sign-in.

### New features

None in this version.

### Fixes

- **Tamper alarms close only after checking your sign-in** - When you accept a change on the Tamper page, the engine checks your own sign-in before it closes the alarm. The alarm closes at the next monitor run, within minutes.
- **The web app cannot change the licence** - The web app can only reset a refused licence claim. The licence itself is written only by the update job.

## 2.1.32 · 2026-11-14 · Fix-only

Start requests from the web app now expire after 15 minutes.

### New features

None in this version.

### Fixes

- **Old start requests are ignored** - When the web app asks the engine to check for work right away, the engine ignores a request older than 15 minutes. Each accepted or ignored request is logged.

## 2.1.31 · 2026-11-14 · Feature update

Security updates from Microsoft install faster and leave no old images behind.

### New features

- **Security updates install at once** - An update that only moves your installation onto Microsoft's newest images installs at once. It does not wait for running jobs and has no database step.
- **Old images are removed** - Once a job has succeeded on the new image, the previous images are removed from your registry.
- **Support sees what runs** - Your installation reports which image each job and the web app run, so Invardia support can see that every installation is patched.

### Fixes

- **The image build reads the version safely** - The image build no longer fails when the version file ends with a line break.

## 2.1.30 · 2026-11-14 · Fix-only

A stopped update reaches Invardia support right away.

### New features

None in this version.

### Fixes

- **A stopped update is reported right away** - When an update stops while preparing the new version, your installation now tells Invardia support right away, not at its next scheduled report up to four hours later.

## 2.1.28.2 · 2026-11-14 · Fix-only

Security update for the sign-in page.

### New features

None in this version.

### Fixes

- **Sign-in page on Microsoft's security release** - The sign-in page in front of the web app runs on Microsoft's newest security release of ASP.NET Core (10.0.15). Nothing else changes.
- **The previous security update installs** - Version 2.1.28.1 could not be installed and your installation kept its version. This version installs.

## 2.1.28.1 · 2026-11-14 · Fix-only

Security update for the sign-in page.

### New features

None in this version.

### Fixes

- **Sign-in page on Microsoft's security release** - The sign-in page in front of the web app runs on Microsoft's newest security release of ASP.NET Core (10.0.15). Nothing else changes.

## 2.1.28 · 2026-11-14 · Fix-only

A group-scoped test run never quietly covers fewer people.

### New features

None in this version.

### Fixes

- **A group-scoped run stops on an unclear group** - A tagging run limited to the members of an Entra group now stops with the reason when the group name matches more than one group, or its remembered group was deleted. Before, it ran on fewer people than asked.
- **Matched lists stay** - A rule's list of matched people from an earlier run no longer disappears when a later run failed or matched nobody.
- **Fewer repeated changes during an update** - An update that gets no answer from Azure sends its change at most once more.

## 2.1.27 · 2026-11-13 · Fix-only

A stuck update is reported to Invardia support at once.

### New features

None in this version.

### Fixes

- **A stopped update is reported at once** - When an update stops while preparing the new version, your installation keeps its current version and Invardia support is told at once, not only after several tries.

## 2.1.26 · 2026-11-13 · Fix-only

Pro installations update to the newest version again.

### New features

None in this version.

### Fixes

- **Pro installations update again** - A Pro installation could not install 2.1.24 or 2.1.25 and kept running the version before. It now updates straight to this version. Community installations were not affected.
- **Release notes in plain words** - The release notes now describe each fix by what you see.

## 2.1.25 · 2026-11-13 · Fix-only

Updates recover from a brief outage on Invardia's side by themselves, and say what happened.

### New features

None in this version.

### Fixes

- **Updates retry a check that got no answer** - Just before installing, an update checks its release once more. If Invardia does not answer, it now asks again a few seconds later.
- **The update's run says the real reason** - When the update still cannot confirm its release, its run says so and it tries again within the hour. It no longer claims it waited for jobs that were not running.

## 2.1.24 · 2026-11-13 · Feature update

You can now see what every release brings, in plain words, right in the app.

### New features

- **What's new in the Help menu** - Help > What's new shows every release, newest first: what is new and what was fixed. A New badge appears after an update until you open the page.
- **The same text on GitHub and invardia.com** - You read the same release notes in the app, on GitHub and on invardia.com.

### Fixes

None in this version.

## 2.1.23 · 2026-11-13 · Fix-only

The hybrid worker gets onto the new version faster after an update.

### New features

None in this version.

### Fixes

- **Hybrid worker catches up with updates sooner** - If your installation is still updating when the hybrid worker checks, it now checks again after 10 minutes instead of an hour. It still only takes the version your installation runs.

## 2.1.22 · 2026-11-13 · Fix-only

You can now see when the list of admins may be incomplete.

### New features

None in this version.

### Fixes

- **Admin views show when admins may be missing** - When the Identity report could not read some role groups, the admin views and the Admin column now say "May be incomplete" and how many groups were missed.

## 2.1.21 · 2026-11-13 · Fix-only

Tag changes meant for on-premises AD are no longer lost when a large run stops part way.

### New features

None in this version.

### Fixes

- **AD tag changes always reach the hybrid worker** - When a large tagging run stopped part way, some AD changes could wait forever and never be written. They now always reach the Hybrid worker, and no change is queued twice.
- **Runs report failure instead of false success** - If AD changes cannot be handed to the Hybrid worker, the tagging run, undo or Tamper restore now ends as failed with the reason, instead of reporting success.
- **A failed undo says why at once** - An undo that cannot record its outcome now ends as failed straight away, and the Backups / Undo page shows the reason.

## 2.1.20 · 2026-11-13 · Fix-only

On-premises AD always ends up with the newest tag value, never an older one.

### New features

None in this version.

### Fixes

- **AD always keeps the newest tag value** - The Hybrid worker now writes tag changes in the order they were queued and skips an older value when a newer one exists. The Hybrid worker page shows why a change was skipped.
- **Retry and restore respect newer values** - "Try again" on a failed AD tag change is refused when a newer value is already written or waiting. A Tamper restore waits until the newer value is written.
- **Two hybrid workers no longer block each other** - When you run two hybrid workers, they can now take work at the same time without getting in each other's way.

## 2.1.19 · 2026-11-13 · Fix-only

Brief connection drops no longer fail whole runs, and restored tags land in the right directory.

### New features

None in this version.

### Fixes

- **A dropped connection no longer fails a run** - When Microsoft Graph or Exchange Online gives no answer to a read, it is tried once more after a few seconds instead of failing the run. Changes are never sent twice.
- **Failed runs always say why** - A job run that fails now always shows the reason in its run record on the Runs page, not only in its log.
- **Tamper restores go through the right directory** - Restoring a tag on a user synced from on-premises AD is now written in AD by the Hybrid worker. The Tamper event stays open until the restored value is confirmed.
- **Tamper restores work for mail-enabled cloud users** - Restoring a tag on a mail-enabled cloud user now goes through Exchange Online when Entra refuses the change, just as tagging does.

## 2.1.18 · 2026-11-13 · Fix-only

Interrupted updates finish faster and more safely.

### New features

None in this version.

### Fixes

- **Finishing an update only redoes what's missing** - When an update that stopped part way is finished, only the parts left behind are moved. Work already done is not repeated.
- **Updates wait for a busy Azure** - When Azure is still busy with a repeated request, the update now waits up to 5 minutes instead of stopping. Repeated requests are shown in the update's run log and summary.

## 2.1.17 · 2026-11-13 · Fix-only

An update interrupted by Azure no longer leaves your installation half on the old version.

### New features

None in this version.

### Fixes

- **Updates retry when Azure does not answer** - When Azure does not answer a request during an update, the update tries it once more instead of stopping. Starting a job is never sent twice.
- **A stopped update finishes within minutes** - If an update still stops part way, the next check finishes it within minutes. Until then, the update's run shows which parts are on which version.

## 2.1.16 · 2026-11-13 · Fix-only

Every undo and restore is now fully recorded, and repeating analyzer problems no longer flood support.

### New features

None in this version.

### Fixes

- **Undo and restore are always recorded** - Undoing a tagging run and restoring a tampered tag now record each change before making it, then its outcome. No change is ever made without a record.
- **Analyzer gaps are counted and reported once** - When the CA Policy Analyzer cannot evaluate some users, the run says how many. If that repeats, Invardia support gets one item instead of one per run.
- **Partial analyzer runs are labelled reliably** - Whether a CA Policy Analyzer run was partial because of its sign-in limit is now recorded directly, so it is always shown correctly.

## 2.1.15 · 2026-11-13 · Feature update

Reports no longer present partial results as complete, so the numbers you see can be trusted.

**Action needed:** If the Identity report says Intune devices could not be read, grant that right again.

### New features

None in this version.

### Fixes

- **Partial analyzer runs are clearly marked** - A CA Policy Analyzer run that could not check every user is marked partial. Policy pages keep showing the last complete analysis, and the alert mail says it is partial.
- **Identity report never shows incomplete data** - Unknown admin roles are now shown as unknown, not as no role. If Intune devices cannot be read, the report keeps its last complete run.
- **Policy checks stay trustworthy when data is missing** - A failed policy review keeps the last review and its date. If a break-glass account cannot be found, the Conditional Access monitor says it cannot check and names the account.
- **Tags stay put when a rule is unclear** - When two Entra groups share a rule's group name, or its group is gone, the tags are left as they are. Imported v1 rules with an unknown condition are skipped and named.
- **Smaller fixes: records and mail text** - Every tag change is now recorded before it is made, then its outcome. Mails with characters such as æ, ø or å are no longer refused by Microsoft.

## 2.1.14 · 2026-11-12 · Fix-only

Missing information can no longer cause wrong tags or silently closed findings.

### New features

None in this version.

### Fixes

- **Unreadable sources never change a tag** - If tagging cannot read something a rule needs, that tag is left as it is and shown as "Unknown" on Tag changes. All other tags are applied as usual.
- **One broken rule no longer stops a run** - When a rule's condition fails, only that rule's tags are left unchanged and named. The rest of the run carries on.
- **Findings stay open until they are re-checked** - The Conditional Access monitor no longer closes a finding it could not check. The finding stays open, marked "awaiting a re-check since" with the date.

## 2.1.13 · 2026-11-12 · Fix-only

Image clean-up no longer removes the security scan results of images you still use.

### New features

None in this version.

### Fixes

- **Scan results are kept for kept images** - Microsoft Defender for Cloud's scan results and their signatures are now kept for every image the clean-up keeps. Removed images take their own scan results with them.

## 2.1.12 · 2026-11-12 · Feature update

Image clean-up can never remove anything your installation still runs or needs.

### New features

- **Clean-up keeps everything in use** - What is kept is now decided from what your installation actually runs and needs. If anything is unclear, nothing is deleted and the next update tries again.
- **Clean-up reports what it does** - The run log shows, as it happens, how many images exist, are kept and why, and are deleted. The totals also go to Audit.
- **Safe limits on each clean-up** - At most 100 images per registry folder are deleted per update, and Invardia support can switch the clean-up off for your installation. It starts with the update after this version.

### Fixes

None in this version.

## 2.1.11 · 2026-11-12 · Feature update

Old images no longer pile up and show vulnerabilities your running version does not have.

### New features

- **Old images are removed after each update** - Once an update is healthy, older Entra Policy Suite images are deleted from your own registry. The current and previous versions are kept, so you can still roll back one version.
- **Cleaner security reports in Defender** - Microsoft Defender for Cloud scans every stored image, so old images showed vulnerabilities you no longer run. Only your installation's own images are touched, and Audit shows how many were removed.

### Fixes

None in this version.

## 2.1.10 · 2026-11-12 · Fix-only

Every mail now clearly identifies which environment sent it.

### New features

None in this version.

### Fixes

- **Mails name the environment unambiguously** - Mails now name the environment by its unique handle, as Invardia holds it, instead of a display name that could be just "PROD". The display name is added only when it says more.

## 2.1.9 · 2026-11-12 · Feature update

You can see at a glance which environment and tenant every mail comes from.

### New features

- **Every mail names its environment** - Alert, report and test mails now show the environment in the subject, and the first line names the environment and tenant. Without a tenant name in Settings, your directory's own name is used.
- **Slow pages are caught earlier** - The Invardia support link now also reports the health of the database statistics, so Invardia support can catch a slowing page early.

### Fixes

None in this version.

## 2.1.8 · 2026-11-11 · Feature update

Community installations can connect to Invardia for health reports and updates, only if you choose to.

### New features

- **Optional connection to Invardia at install** - The install asks once whether to connect to Invardia; the answer is no unless you say yes. Running the install again keeps a yes; the install's no option takes it back.
- **What a connected installation shares** - Connected installations send health reports with numbers and states only, never users, devices, tag values or names. Invardia can then ask them to update now. No licence is needed.

### Fixes

None in this version.

## 2.1.7 · 2026-11-11 · Fix-only

Community installations share nothing with Invardia unless you agree.

### New features

None in this version.

### Fixes

- **No daily edition check without your consent** - A Community installation no longer checks its edition with Invardia each day unless you agreed at install to connect. It simply runs the free features. Pro installations are unchanged.

## 2.1.6 · 2026-11-11 · Feature update

Pro and Community installations are now set up the same way, so both behave predictably.

### New features

- **Same daily edition check for every installation** - Every installation now checks its edition with Invardia once a day. A licence or trial for your tenant then arrives by itself.

### Fixes

- **Installations carry their real edition** - Every installation was labelled Community in Azure, Pro included. It now shows its real edition.
- **Community installs are ready from day one** - Community installations now prepare the Invardia support link at install, like Pro, and every installation updates itself right after install, so it is current at once.

## 2.1.5 · 2026-11-11 · Feature update

Microsoft's security patches can now reach your installation within a day.

### New features

- **Same-day security patches** - When Microsoft publishes security fixes for its base images, Invardia can release them as a small patch. It reaches your installation and hybrid worker within a day, without waiting for the next release.

### Fixes

None in this version.

## 2.1.4 · 2026-11-11 · Fix-only

Applies Microsoft's latest .NET 10 security patches.

### New features

None in this version.

### Fixes

- **Latest Microsoft security patches applied** - The engine and the sign-in page now run on Microsoft's newest patched .NET 10 release. Signing in and everything else work as before, and your installation updates by itself.

## 2.1.3 · 2026-11-11 · Fix-only

Updates delayed by running jobs now install within hours instead of a day later.

### New features

None in this version.

### Fixes

- **Delayed updates are retried every hour** - When the nightly update had to wait for running jobs, it now tries again every hour for up to 24 hours. Invardia support is told if it gives up three times in a row.
- **Missing AD attributes are shown clearly** - If a rule writes an attribute your Active Directory does not have, Get started now names that attribute with what to do, and still checks the others.

## 2.1.2 · 2026-11-10 · Feature update

You and Invardia support can now see that secrets are stored safely and that updates keep running.

### New features

- **Key Vault checks in Get started** - Get started now checks every night that your Key Vault is protected against purging and that every secret is kept in it. The check shows a count, never a secret.
- **Stalled updates are noticed** - Invardia support now sees when your updater last ran and what it did, so an installation that stopped updating is noticed.

### Fixes

None in this version.

## 2.1.1 · 2026-11-10 · Feature update

The hybrid worker now stays on the same version as your installation.

### New features

- **Hybrid worker checks for updates hourly** - The Hybrid worker now checks for its update every hour instead of once a day. Existing workers switch by themselves after their next update; nothing to do on the server.

### Fixes

- **Hybrid worker no longer falls behind** - The Hybrid worker could stay a day behind after every update. It now follows your installation's current version, and Get started shows its AD check as ok or missing again.

## 2.1.0 · 2026-11-10 · Feature update

Entra Policy Suite 2.1 gathers recent improvements; nothing breaks and there is nothing to do.

### New features

- **Entra Policy Suite 2.1 installs by itself** - Your installation moves from 2.0 to 2.1 on its own, on its usual update ring. Nothing breaks and there is nothing for you to do.
- **Runs on Microsoft's current supported platform** - The whole product now runs on .NET 10 and PowerShell 7.6, both supported by Microsoft until November 2028.
- **Hanging jobs are restarted automatically** - A job that hangs is caught, stopped and started once more, and Invardia support is told at once.
- **Fewer false alarms from the support link** - One report to Invardia that could not be delivered no longer turns the Invardia support link amber, and you are never mailed about it.

### Fixes

None in this version.

## 2.0.125 · 2026-11-10 · Feature update

The Invardia support link is named and explained clearly wherever you see it.

### New features

- **Clearer name and setting for the support link** - The run log now says "Invardia support link". Its on/off setting in Settings explains that turning it off stops all reports to Invardia support.

### Fixes

None in this version.

## 2.0.124 · 2026-11-10 · Feature update

Fewer false alarms: one missed report to Invardia no longer looks like a problem.

### New features

- **The Invardia support link has its own name** - The job that sends health and run results to Invardia support is now called the Invardia support link on Jobs & schedule, the overview and Settings. It does not connect to another tenant.
- **No alarm for one missed report** - A report that could not be delivered is retried next cycle and the run stays green. Only three misses in a row turn it amber, and you are never mailed about it.

### Fixes

None in this version.

## 2.0.123 · 2026-11-10 · Feature update

A stuck job no longer blocks work for hours; it is caught and restarted.

### New features

- **Hanging jobs are stopped and restarted** - A job that makes no progress for 60 minutes, or runs far longer than usual, is stopped and started once more. Before, it ran until its time limit.
- **Repeated hangs stop and get attention** - A job that hangs again within 24 hours stays stopped and shows on Runs with the reason. Invardia support is told at once. An update is never stopped half-way.

### Fixes

None in this version.

## 2.0.121 · 2026-11-10 · Feature update

Every installation's sign-in page now gets its security update, including ones already up to date.

### New features

None in this version.

### Fixes

- **sign-in page updates on every installation** - An installation that was already up to date did not move its sign-in page to the new version. It now does on its next update run.
- **sign-in page on supported .NET 10** - The sign-in page now runs on .NET 10, the same as every Invardia product. Signing in works as before, with nothing to change in your tenant.

## 2.0.120 · 2026-11-10 · Feature update

Every part of Entra Policy Suite now runs on Microsoft-supported, patched software.

### New features

None in this version.

### Fixes

- **sign-in page moves to .NET 10** - The web app's sign-in page now runs on a small, patched .NET 10 base. Signing in works as before, with nothing to change in your tenant.

## 2.0.119 · 2026-11-10 · Feature update

The product moves off software versions that no longer receive Microsoft security fixes.

### New features

None in this version.

### Fixes

- **Moved to supported .NET 10 and PowerShell 7.6** - Microsoft ended security fixes for the previous versions on 10 November 2026. Every job and page now runs on versions supported until November 2028.
- **Patched, slimmer sign-in page** - The sign-in page moves to a smaller, patched base. Nothing changes in your directory, data, rights or settings, and the update installs like any other.

## 2.0.118 · 2026-11-10 · Feature update

Known High and Critical vulnerabilities in the base software no longer ship.

**Action needed:** If your private network firewall allows only listed hosts, add archive.ubuntu.com and security.ubuntu.com to it before the update installs.

### New features

None in this version.

### Fixes

- **Built on today's patched base software** - Every job and page is now built with the operating system's latest security updates, so fixed High and Critical vulnerabilities no longer ship.
- **Online documentation matches the product** - The pages on invardia.com now match the product: the Conditional Access changes a SuperAdmin can make, every identity and its rights, all jobs, settings and install options.

## 2.0.117 · 2026-11-10 · Feature update

You stay in control of rights: nothing is taken away unless you decide.

### New features

- **New Optional components page** - Administration > Optional components shows each optional part, whether it is on, which rights it lacks and the script that adds exactly those. The page only reads.
- **One script per component** - New scripts add the rights for user tagging, device tagging and Exchange one at a time. Each can show what it would add first, without changing anything.
- **Hybrid worker AD step completes itself** - The Hybrid worker confirms its Active Directory rights by itself, and the step clears once they are in place. Nobody has to mark it done.

### Fixes

- **Rights are never removed automatically** - Turning a feature off no longer takes its rights away; the install marks them as not needed and keeps them. You remove a right only when you choose to.
- **No false Tamper alerts for own changes** - Tamper no longer raises false alerts for Entra Policy Suite's own tag changes.

## 2.0.116 · 2026-11-09 · Feature update

Your changes take effect within seconds, and the app is clearer to read.

### New features

- **Requests start within seconds** - When you commit a change, press Run now or ask for an analysis, it now starts within seconds instead of waiting up to five minutes.
- **Identity report views explain their assumptions** - Each Identity report view now lists where its facts come from and who it leaves out, so you know what a result means.
- **Clearer Audit, Tamper and Tag changes** - The Audit page says in plain words what each request did. Tamper and Tag changes show the tag name instead of where it is stored.
- **A tidier Tagging Rules page** - New rule and Test run are the main actions, with the rest in one More menu. Rules imported from v1 carry a 'from v1' badge.
- **Smaller wording improvements** - Settings describes the alert mail choices in words, Get started folds the v1 import steps away, and the app spells 'Analyze' one way everywhere.

### Fixes

None in this version.

## 2.0.115 · 2026-11-09 · Feature update

The identity report now finds the users and admins it used to miss, and the menu shows what needs your attention.

### New features

- **Sign-in methods read per user** - An optional job reads every user's sign-in methods, admins first. Until a user is read, the report says unknown, never 'no MFA'.
- **Red markers show what waits for you** - The menu shows a red count where something waits for you or did not complete, such as queued changes, failed jobs or open tamper events. The Overview links each one.
- **Policy list shows analysis and monitors** - Each Conditional Access policy now shows the analysis it waits for or had last, and which monitors cover it.
- **Quicker cloud values in the rule editor** - Picking the value for AD-synced users now proposes the matching value for cloud users. One click accepts it, and a value you pick yourself is kept.

### Fixes

- **MFA views list the right users** - 'Active without MFA' and 'No MFA, but a company smartphone' never listed anyone. They now list enabled users who are not registered for MFA.
- **All admins are now recognised** - Anyone who can reach a directory role, directly, through a group or through PIM for Groups, now counts as an admin. Admins with a role through a group were missed before.
- **More accurate inactivity, guest and licence views** - Inactivity and guest views count background sign-ins and find every guest. Microsoft 365 E5 and E3 without Teams are now recognised, so those users are no longer listed as missing a licence.
- **Smaller fixes** - AD OU views stay empty until you set an OU pattern, monitor names may hold spaces, and row action menus no longer wrap over two lines.

## 2.0.112 · 2026-11-09 · Feature update

Committing changes without a reason works again.

### New features

None in this version.

### Fixes

- **Commit without a reason works again** - Committing queued changes without a reason failed with an error. The reason is optional again, and the commit goes through.
- **Run pages show a dash for unknowns** - A run page now shows '-' in its number cards when a number is not known, instead of a placeholder word.

## 2.0.111 · 2026-11-09 · Feature update

The web app is easier to read, and its buttons make clear what each action does.

### New features

- **Larger text and bigger buttons** - Text in the web app is larger and the buttons are bigger, so every page is easier to read.
- **Risky actions stand out in red** - The main action on each page is the filled button. Actions that write or remove something, such as Discard all or Disable, are red.
- **Clearer commit queue and policy pages** - The commit queue names each field in words, and a policy page shows its current stage as a marker.
- **Smaller layout and wording improvements** - The selected rule's panel stays in view, Settings highlights Save after a change, long explanations fold behind Read more, and Conditional Access groups say 'not read yet' instead of 0.

### Fixes

None in this version.

## 2.0.110 · 2026-11-09 · Feature update

Picking tag values is quicker, and the Tag types page loads again.

### New features

- **Tag values picked from a dropdown** - In the rule editor and the rules grid, a tag type with a value list now offers exactly those values. An older value no longer on the list stays visible and marked.

### Fixes

- **Tag types page loads again** - The Tag types page showed 'Could not load' when two rules set the same value. It loads again.

## 2.0.109 · 2026-11-09 · Feature update

Re-running the install now recognises a Pro installation correctly.

### New features

None in this version.

### Fixes

- **Install recognises Pro installations again** - On some installations, re-running the install did not see that it is Pro, and a new Pro install waited until night for its licence. Both now work at once.
- **Install guide matches today's names** - The install guide no longer lists old job names, and explains how an older installation moves to the current ones.

## 2.0.108 · 2026-11-09 · Feature update

Older installations can move to the standard names, and the hybrid worker gets only the AD rights you choose.

**Action needed:** When you set up the hybrid worker's AD rights, list the tag attributes it may write.

### New features

- **Older installs can adopt standard job names** - An installation made before 2.0.55 can switch to the standard job names with one install run. Each new job is proven before the old one is removed.
- **Hybrid worker gets only the rights you list** - The hybrid worker's AD rights now go to one permission group, for only the tag attributes you list. There is no default list any more.
- **One table of names in the guide** - The install guide lists, in one table, every name you will see in Azure and Entra ID.

### Fixes

None in this version.

## 2.0.107 · 2026-11-09 · Feature update

An install run never takes away a permission the product holds.

### New features

None in this version.

### Fixes

- **Install runs no longer remove permissions** - An install run now only adds missing Microsoft Graph permissions and names any extra ones, without removing them. The matching setup step is now a report and stays green.

## 2.0.106 · 2026-11-09 · Feature update

The product keeps only the Microsoft Graph permissions it needs.

### New features

- **Unneeded permissions are removed** - The next install run removes a Microsoft Graph permission the product no longer needs, and checks the result. Getting started shows a step that names any extra permission.

### Fixes

- **Guides describe today's identities** - The security pack and the hybrid worker guide now describe the product's identities as they are today.

## 2.0.105 · 2026-11-08 · Feature update

Every job now reports its runs, and a job that keeps failing recovers by itself.

### New features

- **Every job now shows its runs** - Database setup, support access and configuration changes now appear under Jobs & runs, like every other job.
- **Failing jobs retry with smaller batches** - A job whose last runs did not complete now works in smaller batches, halving each time. A size that keeps timing out is no longer retried unchanged.
- **New alerts to Invardia** - Invardia is now alerted when a job misses three runs in a row or when records had to be skipped. Both alerts close by themselves.

### Fixes

- **Backups open on every system** - A policy name with a character such as ':' or '?' no longer creates a backup file that Windows cannot open.
- **Identity report reads AD user ids correctly** - The identity report now reads the security identifier of on-premises AD users correctly.

## 2.0.104 · 2026-11-08 · Feature update

Repeated failures reach Invardia as one clear report instead of stalling.

### New features

None in this version.

### Fixes

- **Repeated failures reported once** - A job that fails three runs in a row is reported to Invardia as one repeated failure, and Invardia opens a fix request. A missing permission stays a step for you.
- **Reports to Invardia no longer get stuck** - One refused record no longer holds back the reports of other jobs, and it is skipped after three refusals.

## 2.0.103 · 2026-11-08 · Feature update

No change to the product: this release adds an automatic secret scan to the public code repository.

### New features

None in this version.

### Fixes

None in this version.

## 2.0.102 · 2026-11-08 · Feature update

The hybrid worker now keeps itself up to date safely, and rolls back by itself if an update fails.

**Action needed:** On each hybrid worker installed before 2.0.102, run the hybrid worker install once more; the server needs outbound HTTPS to invardia.com.

### New features

- **Hybrid worker updates itself daily** - Each worker moves once a day to the version your installation runs, never ahead and never back. It installs only releases Invardia signed.
- **Failed updates roll back by themselves** - The new version is set up next to the old one and tests itself. If the test fails, the worker switches back on its own.
- **Hybrid worker page shows last update** - The Hybrid worker page now shows each worker's last daily update.

### Fixes

None in this version.

## 2.0.101 · 2026-11-08 · Feature update

Invardia support can help with a private installation without you opening your network.

**Action needed:** Run the install once more to add support reads; an update alone does not add them.

### New features

- **Safe support reads for private installations** - Invardia support can now ask for one read from a short, fixed list, such as recent runs or settings. Every request is recorded in the audit.

### Fixes

None in this version.

## 2.0.100 · 2026-11-08 · Feature update

Entra Policy Suite now carries its own logo.

### New features

- **The Entra Policy Suite logo** - The web app header shows the Community or Pro logo for your licence, and the browser tab shows the app icon. Alert mails carry the logo too.
- **One word for tags** - The product's texts now say 'tag' everywhere they used to say 'label'.

### Fixes

None in this version.

## 2.0.99 · 2026-11-08 · Feature update

The product holds fewer standing rights, and the install checks your access before it starts.

### New features

- **Write rights only while needed** - Entra Policy Suite now reads users and devices with read-only rights, and holds write rights only while a feature that writes is on. The setup checks show which right is needed.
- **Install checks your access first** - Before it creates anything, the install checks your Azure and Entra roles and the region's capacity, and lists everything missing at once.
- **Pro: clean-up disables only when allowed** - Stale identities disables approved accounts only while a new SuperAdmin setting allows it. The setting is off by default.

### Fixes

- **Clear stop when a right is missing** - Creating a break-glass account without the needed right now stops, names the right and shows how to grant it.

## 2.0.98 · 2026-11-07 · Feature update

Update now works for Pro installations too.

### New features

None in this version.

### Fixes

- **Update now works for Pro** - On Pro installations, the quick 'update now' check did not go through. It now works for Pro as it does for Community.

## 2.0.97 · 2026-11-07 · Feature update

Urgent releases reach your installation within minutes instead of overnight.

### New features

- **Update now within 15 minutes** - When Invardia marks a release 'update now' for your ring, your installation starts the update within about 15 minutes. It does so only when updates are on.
- **Setup scripts run their own version** - The setup scripts on invardia.com now run the version they were published for, instead of the newest release.

### Fixes

None in this version.

## 2.0.96 · 2026-11-07 · Feature update

A smaller Pro package; nothing changes in how Entra Policy Suite works.

### New features

None in this version.

### Fixes

None in this version.

## 2.0.95 · 2026-11-07 · Feature update

After a support-run install, your installation fully owns its web app sign-in registration.

### New features

None in this version.

### Fixes

- **Ownership handover now completes** - When Invardia's Support app ran the install, it stayed an owner of the web app's sign-in registration. It now removes itself once the installation's own identity is in place.
- **No false owner warnings** - The install now waits briefly for Entra to show a new owner, instead of warning about one that was added.

## 2.0.94 · 2026-11-07 · Feature update

Your installation now owns its web app sign-in registration, not the tool that installed it.

### New features

- **The installation owns its sign-in registration** - The web app's sign-in registration in Entra is now owned by the installation itself. When Invardia's Support app runs the install, it removes itself as owner at the end.
- **Registration settings kept correct on updates** - Every update keeps the registration's own settings as they should be. An install run that may not change it says so, and the next update applies the change.

### Fixes

None in this version.

## 2.0.93 · 2026-11-07 · Feature update

Run reports now say clearly why a job did not start.

### New features

None in this version.

### Fixes

- **Clearer reasons when a job cannot start** - A run now names the job that could not start and why. A short storage hiccup is reported as such, not as a real failure.

## 2.0.92 · 2026-11-07 · Feature update

Every installation gets the tamper check's time limit with its next update.

### New features

None in this version.

### Fixes

- **Tamper check limit reaches every install** - The update now sets the tamper check's one-hour time limit, so every installation gets it without a new install run.

## 2.0.91 · 2026-11-07 · Feature update

Updates no longer get stuck behind a long wait or a stuck job.

### New features

None in this version.

### Fixes

- **Updates no longer fail after waiting** - An update that waited for a running job now fetches the release again before it downloads, so a long wait no longer stops it until the next night.
- **A stuck job no longer blocks updates** - A job stuck for hours is now stopped and reported instead of holding the update back. A stuck tamper check no longer holds back the next checks.
- **Smaller fixes** - Every job shows a first line in its log when it starts, the hybrid worker's database access is added without waiting for jobs, and Pro MCP tool names follow the standard form.

## 2.0.90 · 2026-11-06 · Feature update

Pro: your scripts and AI assistants can work with Entra Policy Suite, always under each person's own role.

**Action needed:** On an existing installation, run the install once more so getting your token needs no extra consent.

### New features

- **API for your own scripts (Pro)** - Your scripts reach Entra Policy Suite through its API as the signed-in person, with that person's role. There is no key to hand out, and changes go through the same checks and audit.
- **MCP server for AI assistants (Pro)** - AI assistants connect through the MCP server, with the same role, checks and audit as the pages.
- **New API and MCP page** - Administration > API and MCP shows your addresses, how to get your token, a script example and the tools your role gets.

### Fixes

None in this version.

## 2.0.89 · 2026-11-06 · Feature update

Entra Policy Suite Pro and its 60-day trial can now be ordered at invardia.com.

### New features

- **Pro and the 60-day trial** - Entra Policy Suite Pro and a 60-day trial are now ordered at invardia.com. Pro adds Passkey rollout, Stale identities, License optimization and Policy as code.
- **Header shows your edition** - The header now names the edition your licence gives, such as Pro Enterprise or Pro (trial).

### Fixes

- **License page loads again** - Administration > License showed only 'Could not load'. It now lists your edition, state, dates and Pro features.
- **Smaller fixes** - Pages no longer draw twice while Pro pages load, Stale identities asks for reasons in the app's own dialog, and Pro pages link to their own settings.

## 2.0.88 · 2026-11-06 · Feature update

Licence problems and missing rights now come with a clear reason.

**Action needed:** Ask your Key Vault administrator to grant the right Policy as code names before you use Git push and read.

### New features

- **Policy as code names its missing right** - Git push and read in Policy as code need a Key Vault right your administrator grants. Until then they stop and name the right; the zip download works without it.

### Fixes

- **Clear reason when a licence is refused** - When Invardia refuses a licence request, the update run's log now shows Invardia's reason.

## 2.0.87 · 2026-11-05 · Feature update

Entra Policy Suite Pro arrives with a self-renewing licence and four Pro features, while Community keeps everything it has.

### New features

- **Pro and the trial** - Entra Policy Suite Pro and a trial come alongside Community, which keeps every feature it has today. Pro installs from a package Invardia signs.
- **The licence arrives and renews itself** - A Pro installation requests, checks and stores its licence, and renews it before it ends. Nobody pastes or uploads a licence.
- **New License page** - Administration > License shows your edition, who it is for, how long it is valid, users against the licence and which Pro features it switches on.
- **Passkey rollout and Stale identities (Pro)** - Passkey rollout tracks, per persona, who can sign in with a passkey against a target date. Stale identities lists inactive accounts and disables them only after a SuperAdmin approves.
- **License optimization and Policy as code (Pro)** - License optimization prices the licences you could save on, without changing any. Policy as code puts your policies in Git for review and applies only what you pick.

### Fixes

None in this version.

## 2.0.85 · 2026-11-05 · Feature update

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Correct description of what Community shares** - The architecture page now says correctly that Community sends counts and states to Invardia once a key is issued, and that a SuperAdmin can switch this off.

## 2.0.84 · 2026-11-05 · Feature update

Updates keep their database access by themselves, without re-running the install.

**Action needed:** Run the install once more to grant the update job its new permissions; the update job reports any it still lacks.

### New features

- **Database access kept up to date** - Each update keeps the database setup identity in the SQL admin group and renews a time-limited assignment before it ends. You no longer re-run the install for this.
- **Safe replacement of the SQL admin group** - An optional install switch replaces a SQL admin group that is not role-assignable. It keeps the old group and moves back if sign-in fails.

### Fixes

None in this version.

## 2.0.83 · 2026-11-05 · Feature update

Test tagging changes safely before they go live, and bring over the rest of what v1 did.

**Action needed:** Run the Log Analytics setup script once, then a SuperAdmin switches on Send the report to Log Analytics in Settings > Identity report.

**Action needed:** Run the install once more to add the monthly job that reads the choices.

### New features

- **Test runs for tagging** - Test run tries your rules on the people you pick and writes nothing, or only their tags. Test queued changes before you commit, then Go live runs them on everyone.
- **Identity report in Log Analytics** - Each identity report can go to your Log Analytics workspace as v1 did, with v1's exposure lists on the Identity page.
- **Mail through your own SMTP relay** - Alert mail and the report can go through your own mail relay, with any password kept in your Key Vault. The workbook can go to its own recipients.
- **Policies edited by picking, not typing** - The Conditional Access Edit and Clone form shows names with an Add button and a dropdown for every fixed choice. The choices come from Microsoft Graph and stay current.
- **More control and safer clean-up** - Export and import the whole configuration, remove policies that are off with a backup first, restore named locations from a backup, and set log levels per feature. CA Policy Analyzer gets v1's options.

### Fixes

- **Fallback values protected from removal** - A tag type's fallback value can no longer be removed on Tag types. Change the fallback first.
- **Jobs show times in your time zone** - Jobs shows each next start in the schedule's time zone, and you pick times on a 24-hour clock.
- **Smaller fixes** - Tables no longer show a filter box over a column of buttons, and an object's tag changes are one click from Tamper.

## 2.0.82 · 2026-11-05 · Feature update

Deploy policies from templates, see your hybrid workers, and undo any change Entra Policy Suite makes.

**Action needed:** Run the install once more to grant the permission the authentication strengths need; Get started step 1 shows when it is granted.

**Action needed:** When you switch this job on in Settings, switch off v1's own named-locations job.

### New features

- **Deploy and upgrade templates** - A SuperAdmin deploys a template as a new policy, off or report-only, and missing groups are created first. A newer template version is tested next to your policy before you promote it.
- **New Hybrid worker page** - Administration > Hybrid worker shows each worker's state, version and last report, the AD changes waiting or failed, and the steps to add a worker. Several AD forests are supported.
- **Get started creates what is missing** - Get started can create v1's authentication strengths, named locations and missing break-glass accounts, each after you review it and give a reason.
- **Named locations from Azure service tags** - A daily job keeps your Azure service tag named locations up to date. It is off by default and changes no other location or policy.
- **Backups / Undo** - Your policies, named locations, strengths and tagging setup are backed up every night and before every change. You can restore from a backup or undo a change, always after approval.

### Fixes

None in this version.

## 2.0.81 · 2026-11-05 · Feature update

You can now change, copy and manage Conditional Access policies and their groups from one place, safely and with a full record.

**Action needed:** Run the install once more so the engine gets the two new group permissions; Get started, step 1, shows when they are granted.

### New features

- **Edit an adopted Conditional Access policy** - You can change any part of an adopted policy in a simple form, with names you can type. You see every change before it is sent, and you approve it with a reason.
- **Clone a policy into a new one** - Clone creates a new policy from an adopted one with your changes. The copy always starts switched off, so you move it through the stages when it is ready.
- **Edits stay safe and recorded** - Only SuperAdmins can edit or clone, and only by their own action. Changes are refused if the policy changed meanwhile or would lose the break-glass exclusion, and every change is recorded.
- **New Groups page for Conditional Access** - See every group your policies use, whether it exists, its members and whether its rule is right. SuperAdmins can create missing groups, fix rules and change pilot or exclude members.
- **Stage moves also update pilot groups** - Moving a policy to a new stage now widens or pauses its pilot group as needed. If the group cannot be set, the policy is left unchanged. Get started can also create a missing group.

### Fixes

- **Settings buttons stay on screen** - On a wide window, the Settings page now lines up each setting so Save and More info stay visible.
- **Private installs update more reliably** - An install on a private network now sets up its build resources the way Azure accepts, and finishes a replacement left over from an earlier run.

## 2.0.80 · 2026-11-05 · Feature update

Invardia now sees at once if run reports from your install fall behind.

### New features

- **Report backlog visible to Invardia** - Your install's regular health report now tells Invardia how many run reports are still waiting and how old the oldest is, so a delay is spotted quickly.

### Fixes

None in this version.

## 2.0.79 · 2026-11-05 · Feature update

Busy installs no longer fall behind in reporting their runs to Invardia.

### New features

None in this version.

### Fixes

- **Run reports catch up quickly** - An install with many runs could fall days behind in reporting them to Invardia. It now sends more at a time and clears a backlog within a few reports.
- **Failed runs are reported first** - Failed runs and update runs now reach Invardia first, while each job's runs still arrive in order so nothing is skipped.

## 2.0.78 · 2026-11-05 · Feature update

Saving a monitor now gives clear feedback, so you always know where your change stands.

### New features

None in this version.

### Fixes

- **Notices are always visible** - "Add to monitor..." seemed to do nothing because its answer appeared out of sight. Notices now float at the bottom right, wherever you are on the page.
- **Waiting monitor changes are shown** - A new or changed monitor is applied within 5 minutes. The Monitors list now shows what is still waiting, and keeps following it after a reload.
- **One change never overwrites another** - "Add to monitor..." now shows monitors that are saved but not yet applied, and waits until a pending change is done before changing that monitor again.

## 2.0.77 · 2026-11-05 · Feature update

Invardia can now see the state of a private install's update build resources.

### New features

- **Private install build state reported** - An install on a private network now tells Invardia the state of the resources it uses to build updates. Other installs send nothing for this.

### Fixes

- **Smaller fixes: zero counts reported correctly** - A count of zero in the health report to Invardia is no longer dropped as empty.

## 2.0.76 · 2026-11-05 · Feature update

Automatic updates work again and wait safely for running jobs before they install.

**Action needed:** If your install is on 2.0.74 or 2.0.75, run the install once to get this release; later updates install by themselves.

### New features

None in this version.

### Fixes

- **Automatic updates install again** - In 2.0.74 and 2.0.75 the update stopped safely before installing anything. It now waits for running jobs and then installs.
- **Only this product's jobs are waited for** - The update waits only for Entra Policy Suite's own jobs, never for another product's job in the same place.

## 2.0.75 · 2026-11-05 · Feature update

Private installs only run their update build resources while building, which keeps cost down.

### New features

- **Build resources run only when needed** - On a private network install, the resources that build updates now start only for a build and stop afterwards, even when the build fails.

### Fixes

- **Do not install this release** - This release was replaced by 2.0.76, because its update stops before installing anything. Use 2.0.76 or later.

## 2.0.74 · 2026-11-05 · Feature update

Updates now install only between runs, so a running job is never disturbed.

### New features

- **Updates wait for running jobs** - When an update is due, new jobs wait and the update installs only after running jobs finish. If they take over 45 minutes, it tries again the next night.

### Fixes

- **Do not install this release** - This release was replaced by 2.0.76, because its update stops before installing anything. Use 2.0.76 or later.

## 2.0.73 · 2026-11-05 · Feature update

Invardia can now confirm the support access your install actually applies.

### New features

- **Support access confirmed to Invardia** - Your install's health report now tells Invardia the support access level in place and until when any admin access lasts, as checked by the install itself.

### Fixes

None in this version.

## 2.0.72 · 2026-11-05 · Feature update

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Updated sign-in page wording** - The web app's sign-in page has updated wording. It works exactly as before.

## 2.0.71 · 2026-11-05 · Feature update

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Updated update-check wording** - The check that verifies updates now uses the newest wording. It checks the same things as before.

## 2.0.70 · 2026-11-04 · Feature update

You get a fuller record of who did what, and only verified releases can be installed.

### New features

- **A fuller audit trail** - Audit now also records sign-ins to the web app, who viewed the Identity report and sign-in details, alarm downloads, database setup runs and every installed update.
- **Only verified releases are installed** - The installer checks every release before it runs anything.

### Fixes

None in this version.

## 2.0.69 · 2026-11-04 · Feature update

Moving from version 1 is now done safely in the web app, with a preview before anything changes.

### New features

- **Import v1 data in the web app** - SuperAdmins can upload version 1 files on the new Import v1 page. You first see what would be added or changed, then import; rules made in the app are never touched.
- **No special database rights needed** - Importing version 1 data no longer needs database rights. Every import is recorded in the change history and Audit.
- **Simpler, consistent install options** - The install now names your Invardia Support app and its starting support level the same way as other Invardia products, and can resume an interrupted install.

### Fixes

None in this version.

## 2.0.68 · 2026-11-04 · Feature update

Setting up the external tamper alarm no longer needs database rights.

**Action needed:** After you change break-glass accounts, watched tags or known writers, download a fresh file on the Tamper page and set up the alarm again.

### New features

- **Download the alarm inputs on Tamper** - Admins and SuperAdmins can download one file from the Tamper page with everything the external Azure Monitor alarm needs. The alarm setup now builds from that file.

### Fixes

None in this version.

## 2.0.67 · 2026-11-04 · Feature update

Adding or removing a hybrid worker no longer needs database rights.

### New features

- **Hybrid worker access without database rights** - Giving or removing a Hybrid worker's access now runs inside your install and is checked afterwards. You only need the right to start a job in the install.

### Fixes

None in this version.

## 2.0.66 · 2026-11-04 · Feature update

Setting up alert mail no longer needs database rights.

### New features

- **Mail settings without database rights** - Mail settings are now stored by your install itself, which checks every value and records the change in Audit. You only need the right to start a job in the install.

### Fixes

None in this version.

## 2.0.65 · 2026-11-04 · Feature update

A private install's Key Vault now stays private, even after it is recovered.

### New features

- **Key Vault kept private automatically** - On a private network install, every update run checks that the Key Vault is still private and restores it if needed. Public installs are not changed.

### Fixes

None in this version.

## 2.0.64 · 2026-11-04 · Feature update

Every change to support access is now recorded, and naming the first SuperAdmin needs no database rights.

### New features

- **Name a SuperAdmin without database rights** - When an install has no SuperAdmin, you can now name one without database rights. Admins and Readers are still given on the Access page.

### Fixes

- **Support access changes are now audited** - Every change to Invardia's support access, and every refused support session, is now recorded in Audit.

## 2.0.63 · 2026-11-04 · Feature update

You decide in the Invardia portal how much access Invardia support has, and your install enforces it.

**Action needed:** Run the install once to add this feature.

### New features

- **Support access follows your portal setting** - Your install applies the support level you set in the Invardia customer portal: none, read only, or extra access only during an open support session, for at most 8 hours.
- **Support access is checked and recorded** - Every change is checked and recorded in Audit, and the product itself cannot raise or lower the level. If Invardia is unreachable, your last setting keeps applying.

### Fixes

None in this version.

## 2.0.62 · 2026-11-04 · Feature update

Invardia support can only work within the access your organization agreed to in the Invardia portal.

### New features

- **Support consent from the Invardia portal** - Your install keeps the support level you set in the Invardia customer portal. A support session beyond that level is refused and recorded in Audit.

### Fixes

- **Environment name read correctly** - Your install now reads its environment name from Invardia without being refused.

## 2.0.61 · 2026-11-04 · Feature update

Invardia can now see that your install's database setup and automatic updates are ready.

### New features

- **Two more setup steps reported** - Your install now tells Invardia whether its database is set up and whether automatic updates are ready, based on real records.
- **Fewer rights needed to install** - Recording the sign-in page version no longer needs database rights from the person who installs.

### Fixes

None in this version.

## 2.0.60 · 2026-11-04 · Feature update

Approved releases now install themselves overnight once you have run the install with this release, verified and checked.

**Action needed:** Run the install once with this release to switch on automatic installs; until then updates are only checked.

### New features

- **Approved updates install automatically** - Each night your install now installs a release Invardia approved for you, after verifying it. If any step fails, nothing changes and it tries again the next night.
- **Updates use limited, separate rights** - The update runs with its own rights, limited to your install only, and each step is reported to Invardia as it happens.

### Fixes

- **Database setup works for more installers** - An installer without directory read rights no longer falls back to the old database setup.

## 2.0.59 · 2026-11-04 · Feature update

Installing no longer needs database admin rights, and gives each part only the access it needs.

### New features

- **Install without database admin rights** - Your install now sets up its own database, with the least access for each part and you as the first SuperAdmin. The person who installs needs no database rights.
- **No temporary firewall opening** - The install no longer opens the database to the installer's machine, and a private install needs no machine inside your network for this step.
- **Existing installs keep their setup** - An existing install keeps its database admin. The installer tells you if it continues the old way.

### Fixes

None in this version.

## 2.0.58 · 2026-11-04 · Feature update

Invardia now sees long-running jobs clearly, and health reports arrive even when one part is refused.

### New features

- **Long runs reported to Invardia** - While a job runs, Invardia sees which job, since when, and how its length compares with normal.
- **Health reports always arrive** - If Invardia refuses one part of a health report, the rest is sent again without it.

### Fixes

- **Small databases are now enlarged** - 2.0.57 did not enlarge an existing smallest-size database. Running the install now does.

## 2.0.57 · 2026-11-04 · Feature update

Your database now starts larger.

### New features

- **A larger database from the start** - New installs start with a larger database. Running the install enlarges an existing small one; a size you chose yourself is left alone.
- **Sign-in page version reported** - Your install now tells Invardia which sign-in page version it runs, with no extra rights needed.

### Fixes

None in this version.

## 2.0.56 · 2026-11-04 · Feature update

Older installs now run with one less identity.

### New features

- **One less identity in older installs** - Installs made before 2.0.55 now run their scheduler as the engine, like new installs. Once that works, the old identity and its access are removed and checked.

### Fixes

None in this version.

## 2.0.55 · 2026-11-04 · Feature update

New installs use standard names, and private installs behind a firewall reply to your network correctly.

### New features

- **Standard names for new installs** - New installs use standard Azure names and fewer identities. Existing installs keep every name they have, and the setup tools still find them.
- **Private installs work behind a firewall** - A private install behind a central firewall can now route replies back to your network. Without this, connections from your network would time out.

### Fixes

None in this version.

## 2.0.54 · 2026-11-04 · Feature update

The install now pauses and tells you what it needs, instead of failing.

### New features

- **The install waits instead of failing** - When the install needs something from you first, such as DNS records, it shows waiting and the reason. Run the same command again and it continues there.
- **Network team tasks listed, not blocking** - When your sign-in cannot change your central network, a private install warns you and lists it as a task for your network team instead of stopping.

### Fixes

- **Smaller fixes for private installs** - Network links are checked before the install goes on, parts left broken by an earlier run are made again, and two messages no longer suggest removing shared items.

## 2.0.53 · 2026-11-04 · Feature update

Private installs keep building updates now that Azure creates new networks without internet access.

### New features

- **Private installs keep internet access for builds** - The network the install creates now allows the outbound access its update builds need. If you bring your own network without it, the install tells you what to add first.

### Fixes

None in this version.

## 2.0.52 · 2026-11-04 · Feature update

Entra Policy Suite now holds Exchange rights only when a feature you use needs them.

### New features

- **Exchange rights only when needed** - Exchange Online rights are granted only while user tagging, the Identity report or a mailbox rule is on. Running the install removes them when none is on.
- **Clearer Exchange setup step** - The Exchange setup step now says whether it is needed and how to grant or remove it.

### Fixes

None in this version.

## 2.0.51 · 2026-11-04 · Feature update

Invardia now receives your security findings by default, so serious issues get attention faster.

### New features

- **Security findings sent to Invardia** - Findings such as outside tag changes, Conditional Access drift, deleted policies or a silent Hybrid worker now go to Invardia by default. A SuperAdmin can switch it off in Settings.

### Fixes

None in this version.

## 2.0.50 · 2026-11-04 · Feature update

The install no longer stops right after renaming its identities.

### New features

None in this version.

### Fixes

- **Install waits for renamed identities** - Right after a rename, Microsoft can briefly show the old name. The install now waits up to two minutes instead of stopping.

## 2.0.49 · 2026-11-04 · Feature update

The suite's sign-in app and admin group now carry clear, standard names.

### New features

- **Standard name for the suite's app** - The suite's app in Microsoft Entra is now named Entra Policy Suite. Your next install run renames an older one in place, so nobody loses access.
- **Database admin group gets the standard name** - An admin group still named after the old product name is renamed in place. A group you named yourself keeps its name, and the install lists every rename.

### Fixes

None in this version.

## 2.0.48 · 2026-11-04 · Feature update

The nightly update check now finds and reports new versions.

### New features

None in this version.

### Fixes

- **Update check now reports new versions** - The nightly update check now asks Invardia whether an update is wanted and reports a new version, as intended. Before, it never did.

## 2.0.47 · 2026-11-04 · Feature update

You can now see why the update check did or did not ask about an update.

### New features

- **Update check explains what it did** - The update check's run log now always says whether it asked Invardia about updating now, and why not when it did not.

### Fixes

None in this version.

## 2.0.46 · 2026-11-04 · Feature update

You now see each night which approved version your install would update to.

### New features

- **Nightly check for approved updates** - Every night the suite asks Invardia which version is approved for your install and records what it would install. It installs nothing yet, and a setting switches it off.

### Fixes

None in this version.

## 2.0.45 · 2026-11-04 · Feature update

The product name is now consistent in the remaining texts.

### New features

- **Product name in the remaining places** - The installer's closing line, a few messages, the security review pack and the reference documentation now also say Entra Policy Suite.

### Fixes

None in this version.

## 2.0.44 · 2026-11-04 · Feature update

The product has one clear name everywhere you read it, with nothing renamed in Azure.

### New features

- **Entra Policy Suite name used everywhere** - The web app title, mails, alerts, help and documentation now say Entra Policy Suite. Your Azure resources keep their names, so an existing install updates in place.

### Fixes

None in this version.

## 2.0.43 · 2026-11-03 · Feature update

Smaller fixes and improvements.

### New features

None in this version.

### Fixes

- **Consistent spelling on the analyzer page** - The CA Policy Analyzer product page now uses US spelling, like the rest of the documentation.

## 2.0.42 · 2026-11-03 · Feature update

Mails now take you straight to the right page, and installs are easier to manage.

### New features

- **Mails open the right page in one click** - Every mail now has the product header, one button that opens the page it is about, and a link to the web app. All mails use the same subject format.
- **Grant or remove engine permissions after install** - A new script gives the engine a permission it is missing, or takes one away. Only the suite's own permissions can be asked for, you can preview the plan, and every change is checked.
- **Standard tags on the install's resource group** - The install now tags its resource group with product, ring, owner, purpose and more. Tags you set yourself are kept on a re-run.
- **Choose your install's update ring** - You can now set the update ring an install belongs to when you install it. It is reported to Invardia.

### Fixes

None in this version.

## 2.0.41 · 2026-11-03 · Feature update

Private network installs can now be re-run and resumed without stopping.

### New features

None in this version.

### Fixes

- **Re-installing a private install works again** - Re-installing a private network install into the same resource group no longer stops when it creates its Key Vault key.
- **Resumed installs get past the web app** - An install resumed from an early step no longer stops when it reaches the web app.

## 2.0.40 · 2026-11-03 · Feature update

Private network installs complete, and region problems are caught before anything is created.

### New features

- **Region check catches more problems up front** - The region check now also works on a fresh install and tests with the same settings as the real install, so it no longer stops installs your policies allow.

### Fixes

- **Private network install creates its key** - A private network install no longer stops when it creates its Key Vault key. The vault stays closed to the public internet.
- **Web sign-in step waits for Microsoft Entra** - The web sign-in step now waits for the new app to appear in Microsoft Entra before it gives consent, instead of failing once.

## 2.0.39 · 2026-11-03 · Feature update

The install now explains clearly when an Azure Policy blocks the region check.

### New features

- **Region check names a blocking Azure Policy** - When an Azure Policy in your subscription blocks the region check, the install now says so in plain words, names the policy and continues.

### Fixes

None in this version.

## 2.0.38 · 2026-11-03 · Feature update

Installs no longer fail halfway because of a blocked region or a private endpoint.

### New features

- **Region checked before anything is created** - Before it creates anything, the install checks that Azure accepts new resources in your chosen region. If not, it stops cleanly and names regions that work.

### Fixes

- **Private network install passes its endpoints** - A private network install no longer stops at its first private endpoint.

## 2.0.37 · 2026-11-03 · Feature update

Security reviewers get an up-to-date pack with every release.

### New features

- **Security pack with every release** - Reviewers now get a security pack with each release: architecture, identities, every permission and why, data, vendor access, hardening and more. It always matches the version you run.

### Fixes

- **Documentation describes policy stage moves correctly** - The documentation now says the suite can make one change to a Conditional Access policy: a SuperAdmin moves it to another stage after approval. The permission for it is listed.
- **Smaller fixes: outdated install description removed** - The install description no longer mentions a custom role that newer installs do not create.

## 2.0.36 · 2026-11-03 · Feature update

You can move a Conditional Access policy straight to the stage you want.

### New features

- **Move a policy to any stage** - A SuperAdmin can now move an adopted Conditional Access policy straight to any stage, up or down, or disable it. A move that skips stages says so.
- **Your Invardia environment name shown everywhere** - The page header, alert mails and reports to Invardia now use the environment name Invardia keeps for your install. The Environment name setting is the fallback.

### Fixes

- **Move dialog shows real users and groups** - The move dialog now lists the users and groups the policy covers, and no longer shows unchanged ones as a change.

## 2.0.35 · 2026-11-03 · Feature update

Installs catch missing network setup up front, and the install command is shorter.

### New features

- **Private install checks everything before starting** - A private network install now checks your networks and DNS zones first. Anything missing is listed in plain words, and nothing is created until you fix it.
- **Shorter install command** - The install command now needs only your tenant and subscription. The region is West Europe unless you choose another.
- **Support scripts come with a full guide** - The support scripts on invardia.com come with a guide: the install commands and every script with its documentation page and checksum.

### Fixes

None in this version.

## 2.0.34 · 2026-11-03 · Feature update

Setup scripts sign in reliably, and Invardia can spot slow jobs sooner.

### New features

- **Invardia sees addresses and job durations** - For installs that report to Invardia, the status report now includes the web app's addresses and how long a running job has taken compared with usual.
- **Every admin script on invardia.com** - Every script an admin runs is now available on invardia.com as one self-contained file, checked against the release before it runs.

### Fixes

- **Setup scripts sign in fresh each time** - The mail, web access and alert setup scripts now sign in again on a second run, instead of reusing an expired sign-in or one for another tenant.

## 2.0.33 · 2026-11-03 · Feature update

Every Conditional Access policy now shows its persona, and moving from v1 is explained step by step.

### New features

- **Every policy shows its persona** - A Conditional Access policy now shows a persona even when none of your managed personas takes it, taken from its template or its name. Your managed personas still come first.
- **Template library corrects persona names** - Template library 2.0-v1.1 corrects persona spelling slips in 29 templates. Conditional Access > Template updates shows each change, old against new, for you to adopt.
- **Template personas are marked** - In Manage personas, personas you do not manage yet are marked as coming from the template. Editing one makes it yours.
- **Get started explains moving from v1** - Get started now opens with how to bring your v1 setup over: tagging rules in the browser, or everything with the import script, step by step.
- **Simpler analyzer form and rules list** - The CA Policy Analyzer now reads long sign-in periods a day at a time by itself. Tagging Rules shows one run-order number per rule.

### Fixes

None in this version.

## 2.0.32 · 2026-11-03 · Feature update

The new menus now open as intended.

### New features

None in this version.

### Fixes

- **Menus now open properly** - The six menus added in the previous version stayed hidden under the menu bar. They now fold out when you click or point at them.

## 2.0.31 · 2026-11-03 · Feature update

Finding the right page is quicker with six grouped menus.

### New features

- **Six clear menus instead of sixteen tabs** - Pages are grouped in six menus: Overview, Tagging, Conditional Access, Identity report, Jobs & runs and Administration. Each page has one line on what it is for.
- **Easier-to-read product name in the header** - The full name next to EPS in the header is now light and easy to read.

### Fixes

None in this version.

## 2.0.30 · 2026-11-03 · Feature update

You can now track who follows up on each account in the Identity report, and how far they got.

### New features

- **Track follow-up actions per user** - Each user in the Identity report now has Action, Status, Who and Notes fields. They are kept across report runs and can be filtered, sorted and exported.
- **Set follow-up for many users at once** - Tick users, or take everyone a filtered view shows, and set the fields on all of them at once. Fields you leave alone stay unchanged.
- **Follow-up is a record only** - Setting the fields needs Admin and is audited. Nothing in Microsoft Entra or Active Directory changes.

### Fixes

None in this version.

## 2.0.29 · 2026-11-03 · Feature update

Alerts reach Invardia again, and Tagging Rules is easier to scan.

### New features

- **Tagging Rules easier to scan** - Rule groups start collapsed, and a search opens what it finds. The value column now says Tag Value, and Matched explains how many accounts a rule matched last run.
- **EPS in the header** - The header now shows EPS, with Entra Policy Suite in smaller letters.

### Fixes

- **Alerts to Invardia are delivered again** - For installs that report to Invardia, alerts were refused and the reporting job showed partly failed. Alerts now arrive.
- **Smaller fixes: clearer Get started text** - The mail sender step on Get started no longer reads like a command.

## 2.0.28 · 2026-11-03 · Feature update

You can see at a glance what your tenant still needs before the suite works fully.

### New features

- **Get started shows what is missing** - A new Get started page lists the 13 things the suite needs, such as permissions, break-glass accounts, groups and named locations. Check now reads your tenant, changes nothing, and marks each ready or missing.
- **Manage break-glass accounts on the page** - A SuperAdmin can now add and change the break-glass accounts list on Get started. It changes the suite's list only, never your tenant.
- **Invardia sees whether setup is complete** - For installs that report to Invardia, the status report now says whether every one-time setup step is in place, checked fresh each time.

### Fixes

None in this version.

## 2.0.27 · 2026-11-03 · Feature update

You can roll a Conditional Access policy out step by step, with a preview and safety checks.

**Action needed:** Run the install again after this update, so the engine gets the permission the stage buttons need.

### New features

- **Move policies through stages with buttons** - A SuperAdmin can now move an adopted Conditional Access policy one stage at a time, from off through pilots to production, or back. Each move first shows exactly what changes.
- **Safe moves, checked and recorded** - A move that enforces a policy needs your confirmation. The suite checks the policy first, refuses unsafe moves, keeps break-glass accounts excluded, and records every move in the policy's history.
- **Nothing changes a policy by itself** - No schedule, job, monitor or template update ever changes a Conditional Access policy. Only a move you approve does.

### Fixes

None in this version.

## 2.0.26 · 2026-11-03 · Feature update

New template versions never change your policies without your review.

### New features

- **Template updates you review first** - A new Template updates tab lists what a newer template library adds, changes or removes. Changed templates show before and after, and how your policies differ.
- **Apply or skip persona changes** - Persona changes from the library can be applied to your personas or skipped. Either way they are not offered again.
- **Your policies never change by themselves** - Taking a template change only marks it as seen; your policies stay as they are. Every take needs Admin and a reason, and is audited.

### Fixes

None in this version.

## 2.0.25 · 2026-11-02 · Feature update

You decide exactly which policies each persona and monitor covers.

### New features

- **Leave any policy out of a persona** - In Manage personas, untick a policy to keep it out of that persona, and tick it again to take it back.
- **Remove any policy from a monitor** - Remove from monitor now works for every policy, and the confirmation says what happens to each. Add to monitor takes a left-out policy back.
- **Persona column shows your personas** - On the Conditional Access page, the Persona column lists every persona that takes a policy, and filtering finds policies that are in several.
- **Personas are fully yours** - The built-in personas are only a starting list, made once from your policies. After that you can change or delete any of them.

### Fixes

None in this version.

## 2.0.24 · 2026-11-02 · Feature update

Monitoring policies is simpler with one form and personas you manage yourself.

### New features

- **One simple CA Policy Analyzer form** - Pick a new or existing monitor, choose policies and a sign-in period, then analyze now or save it as a monitor. Less common options sit under More options.
- **Manage your own personas** - Create, rename and delete personas, and add policies or name rules to them. A policy can be in several personas or none, and monitors follow a rename.
- **Add policies to monitors from Conditional Access** - Each policy shows the monitors it is in. On the Conditional Access page, select policies and add them to or remove them from a monitor.

### Fixes

- **Persona groups sort as intended** - Global comes first, then the personas A to Z, then policies without a persona.

## 2.0.23 · 2026-11-02 · Feature update

Bulk changes finish faster, and pages make full use of your screen.

### New features

- **Bulk changes apply in one go** - Adopting many Conditional Access policies at once is now applied in one engine check, instead of one per check.
- **Status bar says what really happens** - The bar at the top shows when changes are picked up and how many are applied or waiting. A second click no longer sends a change twice.
- **Pages use the full window width** - Text, settings, tables and search use the full width of your screen, on laptops and desktops alike.

### Fixes

None in this version.

## 2.0.22 · 2026-11-02 · Feature update

Long tagging rules are now easy to read and edit.

### New features

- **Tagging rules are easier to read** - Creating, editing, duplicating or restoring a rule in Tagging Rules now opens a wide dialog. Long tag types, values and notes are readable, and each condition explains itself.

### Fixes

None in this version.

## 2.0.21 · 2026-11-02 · Feature update

You can now run the suite with no public exposure, inside your own network.

### New features

- **Install inside your own private network** - You can now install the suite inside your own virtual network, with no public address for the web app or its data. Sign-in still goes through Microsoft Entra.
- **Network checks and a clear hand-off** - The install checks name resolution first, prints exactly what your network team must set up, and resumes where it stopped. A final check proves everything works from inside the network.
- **Move an existing install to private** - An existing public install moves to the private network with the same command, and you can preview the plan first.

### Fixes

None in this version.

## 2.0.20 · 2026-11-02 · Feature update

Entra Policy Suite now runs in your own Azure, with a web app your admins sign in to.

### New features

- **Install in two lines** - Install from PowerShell 7 or Azure Cloud Shell with a browser sign-in and no add-ons. You can preview the plan, a stopped install resumes, and every feature starts switched off.
- **User and device tagging with preview** - Tag users and devices with rules, preview every run before it applies, and import your v1 rule files. Tamper alerts you to tag changes the suite did not make.
- **Conditional Access templates and review** - Compare your policies with the template library, adopt or release them, and export documentation. The suite never writes a Conditional Access policy.
- **CA Policy Analyzer and Identity report** - The analyzer groups policies by persona and monitors them, with alerts per persona. The Identity report shows gaps and downloads as a workbook.
- **Hybrid worker, roles and audit** - A hybrid worker handles users synced from on-premises AD. SuperAdmin, Admin and Reader roles control access, and every change is audited.

### Fixes

None in this version.
