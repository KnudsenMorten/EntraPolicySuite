-- eps-schema.sql -- the EntraPolicySuite 2.0 store (DESIGN §3: the v1 CSV and config files move to SQL).
-- Applied by the install and by the nightly updater. Idempotent and ADDITIVE only (IF NOT EXISTS guards, PIM's model):
-- a run on an existing database creates what is missing and never drops, renames or narrows anything.
-- Identical on Azure SQL (Entra-only, managed identities as contained users) and on SQL Server 2019+.
--
-- No secret is ever stored here: break-glass passwords are shown once and never kept (DESIGN §5.1a), the product reads
-- no Key Vault, and identities are managed identities.

IF SCHEMA_ID('eps') IS NULL EXEC ('CREATE SCHEMA eps');

-- ---- schema version: one row per applied version of this file ------------------------------------------------------
IF OBJECT_ID('eps.SchemaVersion') IS NULL
CREATE TABLE eps.SchemaVersion (
    Version       INT           NOT NULL PRIMARY KEY,
    AppliedAtUtc  DATETIME2     NOT NULL CONSTRAINT DF_SchemaVersion_At DEFAULT SYSUTCDATETIME(),
    ProductVersion NVARCHAR(40) NULL
);

-- ---- settings: every behaviour a GUI setting (DESIGN §5.8, framework CONFIG-1) --------------------------------------
IF OBJECT_ID('eps.Setting') IS NULL
CREATE TABLE eps.Setting (
    Name          NVARCHAR(200)  NOT NULL PRIMARY KEY,   -- 'UserTagging.Enabled', 'NamedLocations.Region', ...
    Feature       NVARCHAR(60)   NOT NULL,               -- CA | UserTagging | DeviceTagging | IdentityReport | NamedLocations | Evaluator | TamperMonitor | Platform
    Value         NVARCHAR(MAX)  NULL,                   -- JSON or plain text
    UpdatedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_Setting_At DEFAULT SYSUTCDATETIME(),
    UpdatedBy     NVARCHAR(320)  NULL
);

-- the change journal behind undo (CONFIG-1 / AUDIT-1): every save of a setting, rule, tag type ...
IF OBJECT_ID('eps.ConfigChange') IS NULL
CREATE TABLE eps.ConfigChange (
    ChangeId      BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    AtUtc         DATETIME2      NOT NULL CONSTRAINT DF_ConfigChange_At DEFAULT SYSUTCDATETIME(),
    Actor         NVARCHAR(320)  NOT NULL,
    Entity        NVARCHAR(60)   NOT NULL,               -- Setting | UserTagRule | DeviceTagRule | TagType | ...
    EntityKey     NVARCHAR(400)  NOT NULL,
    Action        NVARCHAR(20)   NOT NULL,               -- Create | Update | Delete | Import
    BeforeJson    NVARCHAR(MAX)  NULL,
    AfterJson     NVARCHAR(MAX)  NULL,
    Source        NVARCHAR(60)   NULL                    -- gui | v1-import | updater
);

-- ---- tag types (DESIGN §5.6a) -------------------------------------------------------------------------------------
IF OBJECT_ID('eps.TagType') IS NULL
CREATE TABLE eps.TagType (
    Name                 NVARCHAR(60)   NOT NULL,
    ObjectType           NVARCHAR(10)   NOT NULL,        -- User | Device
    Description          NVARCHAR(1000) NULL,
    Attribute            NVARCHAR(60)   NOT NULL,        -- extensionAttribute1..15
    ValueMode            NVARCHAR(10)   NOT NULL CONSTRAINT DF_TagType_Mode DEFAULT 'First',   -- First | Last | Multiple
    AllowMultiple        BIT            NOT NULL CONSTRAINT DF_TagType_Multi DEFAULT 0,
    FallbackAD           NVARCHAR(1024) NULL,
    FallbackCloud        NVARCHAR(1024) NULL,
    FallbackFromProperty NVARCHAR(100)  NULL,            -- v1 Company <- companyName, only when the type has no rules
    Enabled              BIT            NOT NULL CONSTRAINT DF_TagType_Enabled DEFAULT 1,
    Shipped              BIT            NOT NULL CONSTRAINT DF_TagType_Shipped DEFAULT 0,
    UpdatedAtUtc         DATETIME2      NOT NULL CONSTRAINT DF_TagType_At DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_TagType PRIMARY KEY (ObjectType, Name),
    CONSTRAINT CK_TagType_Object CHECK (ObjectType IN ('User', 'Device')),
    CONSTRAINT CK_TagType_Mode CHECK (ValueMode IN ('First', 'Last', 'Multiple')),
    CONSTRAINT CK_TagType_Attr CHECK (Attribute LIKE 'extensionAttribute[1-9]' OR Attribute LIKE 'extensionAttribute1[0-5]')
);
-- broken-reference guard (DESIGN §5.9): two tag types of one object type on one attribute
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_TagType_Attribute' AND object_id = OBJECT_ID('eps.TagType'))
CREATE UNIQUE INDEX UX_TagType_Attribute ON eps.TagType (ObjectType, Attribute);

-- the closed list of values a tag type allows; IsPattern = a wildcard for generated values (v1 Exchange_*)
IF OBJECT_ID('eps.TagValue') IS NULL
CREATE TABLE eps.TagValue (
    ObjectType    NVARCHAR(10)   NOT NULL,
    TagType       NVARCHAR(60)   NOT NULL,
    Value         NVARCHAR(1024) NOT NULL,
    IsPattern     BIT            NOT NULL CONSTRAINT DF_TagValue_Pattern DEFAULT 0,
    Description   NVARCHAR(1000) NULL,
    CONSTRAINT PK_TagValue PRIMARY KEY (ObjectType, TagType, Value),
    CONSTRAINT FK_TagValue_Type FOREIGN KEY (ObjectType, TagType) REFERENCES eps.TagType (ObjectType, Name)
);

-- ---- condition types (DESIGN §5.6b): the customer's own property conditions; shipped ones live in the release ------
IF OBJECT_ID('eps.ConditionType') IS NULL
CREATE TABLE eps.ConditionType (
    Id            NVARCHAR(100)  NOT NULL,
    ObjectType    NVARCHAR(10)   NOT NULL,
    Property      NVARCHAR(200)  NOT NULL,               -- Graph property path, e.g. 'department', 'employeeOrgData.division'
    Operator      NVARCHAR(20)   NOT NULL,               -- like | notlike | equals | boolMatch | boolEquals | contains | notcontains
    Guard         NVARCHAR(20)   NOT NULL CONSTRAINT DF_ConditionType_Guard DEFAULT 'none',
    Description   NVARCHAR(1000) NULL,
    Enabled       BIT            NOT NULL CONSTRAINT DF_ConditionType_Enabled DEFAULT 1,
    CONSTRAINT PK_ConditionType PRIMARY KEY (ObjectType, Id)
);

-- ---- tag rules: one CARD per rule, its conditions ANDed (DESIGN §3 UserTagRule / DeviceTagRule, §5.9) --------------
-- The v1 ConditionGroup survives only as V1ConditionGroup, for the CSV export / re-import (no group number to forget).
IF OBJECT_ID('eps.UserTagRule') IS NULL
CREATE TABLE eps.UserTagRule (
    RuleId            INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    RuleSet           NVARCHAR(60)   NOT NULL CONSTRAINT DF_UserTagRule_Set DEFAULT 'default',
    [Order]           INT            NOT NULL,
    Persona           NVARCHAR(200)  NOT NULL,
    TagType           NVARCHAR(60)   NOT NULL,
    TagValueAD        NVARCHAR(1024) NULL,
    TagValueCloud     NVARCHAR(1024) NULL,
    Enabled           BIT            NOT NULL CONSTRAINT DF_UserTagRule_Enabled DEFAULT 1,
    Source            NVARCHAR(30)   NOT NULL CONSTRAINT DF_UserTagRule_Source DEFAULT 'gui',   -- gui | v1-import | pack
    V1ConditionGroup  NVARCHAR(100)  NULL,
    Notes             NVARCHAR(1000) NULL,
    UpdatedAtUtc      DATETIME2      NOT NULL CONSTRAINT DF_UserTagRule_At DEFAULT SYSUTCDATETIME()
);
IF OBJECT_ID('eps.UserTagRuleCondition') IS NULL
CREATE TABLE eps.UserTagRuleCondition (
    RuleId        INT            NOT NULL REFERENCES eps.UserTagRule (RuleId) ON DELETE CASCADE,
    Seq           INT            NOT NULL,               -- order inside the card (the last condition's Modified value wins)
    ConditionType NVARCHAR(100)  NOT NULL,
    Target        NVARCHAR(1024) NULL,
    CONSTRAINT PK_UserTagRuleCondition PRIMARY KEY (RuleId, Seq)
);
IF OBJECT_ID('eps.DeviceTagRule') IS NULL
CREATE TABLE eps.DeviceTagRule (
    RuleId            INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    RuleSet           NVARCHAR(60)   NOT NULL CONSTRAINT DF_DeviceTagRule_Set DEFAULT 'default',
    [Order]           INT            NOT NULL,
    TagType           NVARCHAR(60)   NOT NULL,
    TagValue          NVARCHAR(1024) NULL,               -- empty = clear the attribute (v1)
    Enabled           BIT            NOT NULL CONSTRAINT DF_DeviceTagRule_Enabled DEFAULT 1,
    Source            NVARCHAR(30)   NOT NULL CONSTRAINT DF_DeviceTagRule_Source DEFAULT 'gui',
    V1ConditionGroup  NVARCHAR(100)  NULL,
    Notes             NVARCHAR(1000) NULL,
    UpdatedAtUtc      DATETIME2      NOT NULL CONSTRAINT DF_DeviceTagRule_At DEFAULT SYSUTCDATETIME()
);
IF OBJECT_ID('eps.DeviceTagRuleCondition') IS NULL
CREATE TABLE eps.DeviceTagRuleCondition (
    RuleId        INT            NOT NULL REFERENCES eps.DeviceTagRule (RuleId) ON DELETE CASCADE,
    Seq           INT            NOT NULL,
    ConditionType NVARCHAR(100)  NOT NULL,
    Target        NVARCHAR(1024) NULL,
    CONSTRAINT PK_DeviceTagRuleCondition PRIMARY KEY (RuleId, Seq)
);

-- ---- saved scopes (DESIGN §5.8): one user, a list, a group, an OU, a filter ----------------------------------------
IF OBJECT_ID('eps.Scope') IS NULL
CREATE TABLE eps.Scope (
    Name          NVARCHAR(100)  NOT NULL PRIMARY KEY,
    ObjectType    NVARCHAR(10)   NOT NULL,
    Kind          NVARCHAR(20)   NOT NULL,               -- Everyone | Objects | Group | OU | Filter
    Definition    NVARCHAR(MAX)  NULL,                   -- JSON
    UpdatedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_Scope_At DEFAULT SYSUTCDATETIME()
);

-- ---- CA management inputs (v1 custom + locked config) -------------------------------------------------------------
IF OBJECT_ID('eps.BreakGlassAccount') IS NULL
CREATE TABLE eps.BreakGlassAccount (
    UserPrincipalName      NVARCHAR(320)  NOT NULL PRIMARY KEY,
    DisplayName            NVARCHAR(200)  NULL,
    AuthenticationMethod   NVARCHAR(60)   NULL,
    ClassificationTagValue NVARCHAR(200)  NULL,
    AuthenticationTagValue NVARCHAR(200)  NULL,
    Placement              NVARCHAR(1000) NULL,          -- where the key / account is kept - customer text, never a secret
    Enabled                BIT            NOT NULL CONSTRAINT DF_BreakGlass_Enabled DEFAULT 1,
    UpdatedAtUtc           DATETIME2      NOT NULL CONSTRAINT DF_BreakGlass_At DEFAULT SYSUTCDATETIME()
);
IF OBJECT_ID('eps.AdminUnit') IS NULL
CREATE TABLE eps.AdminUnit (
    DisplayName   NVARCHAR(200)  NOT NULL PRIMARY KEY,
    Purpose       NVARCHAR(20)   NOT NULL,               -- Target | Pilot | Exclude | BreakGlass
    Description   NVARCHAR(1000) NULL
);
IF OBJECT_ID('eps.TargetGroup') IS NULL
CREATE TABLE eps.TargetGroup (
    DisplayName   NVARCHAR(256)  NOT NULL PRIMARY KEY,
    VariableName  NVARCHAR(100)  NOT NULL,
    Assignment    NVARCHAR(10)   NOT NULL,               -- Dynamic | Assigned
    Description   NVARCHAR(1000) NULL,
    GroupQuery    NVARCHAR(MAX)  NULL,                   -- the dynamic membership rule
    Locked        BIT            NOT NULL CONSTRAINT DF_TargetGroup_Locked DEFAULT 1   -- shipped with the release
);
IF OBJECT_ID('eps.PolicyTemplate') IS NULL
CREATE TABLE eps.PolicyTemplate (
    TemplateId    NVARCHAR(20)   NOT NULL,               -- CA000 .. CA800
    Version       NVARCHAR(20)   NOT NULL,
    Persona       NVARCHAR(100)  NULL,
    DisplayName   NVARCHAR(256)  NOT NULL,
    BodyJson      NVARCHAR(MAX)  NOT NULL,
    Notes         NVARCHAR(MAX)  NULL,
    CONSTRAINT PK_PolicyTemplate PRIMARY KEY (TemplateId, Version)
);
IF OBJECT_ID('eps.PolicyInstance') IS NULL
CREATE TABLE eps.PolicyInstance (
    TemplateId        NVARCHAR(20)   NOT NULL PRIMARY KEY,
    TemplateVersion   NVARCHAR(20)   NOT NULL,
    Stage             NVARCHAR(20)   NOT NULL,           -- Initial | Pilot1 | Pilot2 | Pilot3 | Prod | Disabled
    TenantPolicyId    UNIQUEIDENTIFIER NULL,
    LastDeployedJson  NVARCHAR(MAX)  NULL,               -- kept for the diff and the rollback
    LastDeployedAtUtc DATETIME2      NULL
);

-- ---- named locations from Azure service tags (DESIGN §5.5) --------------------------------------------------------
IF OBJECT_ID('eps.ServiceTagLocation') IS NULL
CREATE TABLE eps.ServiceTagLocation (
    Tag           NVARCHAR(200)  NOT NULL PRIMARY KEY,
    Enabled       BIT            NOT NULL CONSTRAINT DF_ServiceTag_Enabled DEFAULT 1
);
IF OBJECT_ID('eps.ServiceTagPrefix') IS NULL
CREATE TABLE eps.ServiceTagPrefix (
    Tag           NVARCHAR(200)  NOT NULL,
    Prefix        NVARCHAR(64)   NOT NULL,
    SeenAtUtc     DATETIME2      NOT NULL CONSTRAINT DF_ServiceTagPrefix_At DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_ServiceTagPrefix PRIMARY KEY (Tag, Prefix)
);

-- ---- runs: the same run record for every job (DESIGN §2a "Monitor", §4) ---------------------------------------------
IF OBJECT_ID('eps.Run') IS NULL
CREATE TABLE eps.Run (
    RunId         UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    Job           NVARCHAR(60)   NOT NULL,               -- UserTagging | DeviceTagging | IdentityReport | NamedLocations | PolicyDeploy | Evaluator | TamperMonitor
    Mode          NVARCHAR(10)   NOT NULL,               -- Preview | Apply | Undo
    Scope         NVARCHAR(MAX)  NULL,                   -- JSON; NULL = everyone
    StartedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_Run_Started DEFAULT SYSUTCDATETIME(),
    EndedAtUtc    DATETIME2      NULL,
    Status        NVARCHAR(20)   NOT NULL CONSTRAINT DF_Run_Status DEFAULT 'Running',   -- Running | Succeeded | Failed | Held | PartlyFailed
    HeldReason    NVARCHAR(1000) NULL,                   -- the mass-change guard's counts (DESIGN §5.9)
    ApprovedBy    NVARCHAR(320)  NULL,
    Objects       INT            NULL,
    Planned       INT            NULL,
    Overwrites    INT            NULL,
    Applied       INT            NULL,
    Failed        INT            NULL,
    Skipped       INT            NULL,
    SummaryJson   NVARCHAR(MAX)  NULL,
    UndoOfRunId   UNIQUEIDENTIFIER NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Run_Job' AND object_id = OBJECT_ID('eps.Run'))
CREATE INDEX IX_Run_Job ON eps.Run (Job, StartedAtUtc DESC);

-- every tag the engine writes (or plans): the history, the tamper monitor's "engine's own" record, and undo
IF OBJECT_ID('eps.TagChange') IS NULL
CREATE TABLE eps.TagChange (
    ChangeId      BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    RunId         UNIQUEIDENTIFIER NOT NULL REFERENCES eps.Run (RunId),
    ObjectType    NVARCHAR(10)   NOT NULL,
    ObjectId      UNIQUEIDENTIFIER NOT NULL,
    ObjectName    NVARCHAR(400)  NULL,
    Directory     NVARCHAR(10)   NOT NULL,               -- Cloud | AD
    TagType       NVARCHAR(60)   NOT NULL,
    Attribute     NVARCHAR(60)   NOT NULL,
    OldValue      NVARCHAR(1024) NULL,
    NewValue      NVARCHAR(1024) NULL,
    Reason        NVARCHAR(20)   NOT NULL,               -- Rule | Fallback | CopyProperty | Undo | Restore
    Persona       NVARCHAR(400)  NULL,
    RuleIds       NVARCHAR(400)  NULL,
    Status        NVARCHAR(20)   NOT NULL CONSTRAINT DF_TagChange_Status DEFAULT 'Planned',   -- Planned | Applied | Failed | Skipped
    Error         NVARCHAR(2000) NULL,
    AtUtc         DATETIME2      NOT NULL CONSTRAINT DF_TagChange_At DEFAULT SYSUTCDATETIME()
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_TagChange_Object' AND object_id = OBJECT_ID('eps.TagChange'))
CREATE INDEX IX_TagChange_Object ON eps.TagChange (ObjectId, Attribute, AtUtc DESC);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_TagChange_Run' AND object_id = OBJECT_ID('eps.TagChange'))
CREATE INDEX IX_TagChange_Run ON eps.TagChange (RunId);

-- the run's log, per the feature's logging level (Off | Normal | Verbose, DESIGN §5.8)
IF OBJECT_ID('eps.RunLog') IS NULL
CREATE TABLE eps.RunLog (
    RunId         UNIQUEIDENTIFIER NOT NULL REFERENCES eps.Run (RunId),
    Seq           INT            NOT NULL,
    AtUtc         DATETIME2      NOT NULL CONSTRAINT DF_RunLog_At DEFAULT SYSUTCDATETIME(),
    Level         NVARCHAR(10)   NOT NULL,               -- Info | Warning | Error | Verbose
    Message       NVARCHAR(MAX)  NOT NULL,
    CONSTRAINT PK_RunLog PRIMARY KEY (RunId, Seq)
);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 1)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (1, '2.0.0');

-- ---- version 2: the scheduler (DESIGN §4) ---------------------------------------------------------------------------
-- One row per recurring job. The tick (every 5 min) starts a job's Container Apps Job when it is due. Schedule is a
-- setting the customer changes in the GUI: 'daily HH:mm' | 'weekly <ddd> HH:mm' | 'every <N>m' | 'manual', in the
-- Platform.TimeZone setting's time zone. The updater converges missing rows with the defaults, never overwrites one.
IF OBJECT_ID('eps.JobSchedule') IS NULL
CREATE TABLE eps.JobSchedule (
    Job             NVARCHAR(60)   NOT NULL PRIMARY KEY,
    Schedule        NVARCHAR(40)   NOT NULL,
    AcaJobName      NVARCHAR(32)   NOT NULL,             -- the Container Apps Job the tick starts
    Enabled         BIT            NOT NULL CONSTRAINT DF_JobSchedule_Enabled DEFAULT 1,
    LastStartedUtc  DATETIME2      NULL,                 -- the tick's claim: set atomically before the start
    LastStartResult NVARCHAR(400)  NULL,
    UpdatedAtUtc    DATETIME2      NOT NULL CONSTRAINT DF_JobSchedule_At DEFAULT SYSUTCDATETIME()
);
-- "Run now", a preview, a scoped test run, an approved re-run of a held run: written by the GUI, started by the tick,
-- taken by the job (Pending -> Dispatched -> Running -> Done | Failed | Refused)
IF OBJECT_ID('eps.JobRequest') IS NULL
CREATE TABLE eps.JobRequest (
    RequestId       UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    Job             NVARCHAR(60)   NOT NULL,
    Mode            NVARCHAR(10)   NOT NULL,             -- Preview | Apply
    Scope           NVARCHAR(MAX)  NULL,                 -- JSON; NULL = everyone
    RequestedBy     NVARCHAR(320)  NOT NULL,
    ApprovedBy      NVARCHAR(320)  NULL,                 -- an admin's approval of a held run
    RequestedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_JobRequest_At DEFAULT SYSUTCDATETIME(),
    Status          NVARCHAR(20)   NOT NULL CONSTRAINT DF_JobRequest_Status DEFAULT 'Pending',
    StatusText      NVARCHAR(1000) NULL,
    RunId           UNIQUEIDENTIFIER NULL,
    UpdatedAtUtc    DATETIME2      NOT NULL CONSTRAINT DF_JobRequest_Upd DEFAULT SYSUTCDATETIME()
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_JobRequest_Status' AND object_id = OBJECT_ID('eps.JobRequest'))
CREATE INDEX IX_JobRequest_Status ON eps.JobRequest (Status, Job, RequestedAtUtc);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 2)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (2, '2.0.0');

GO
-- ---- version 3: which path wrote a tag (Graph, or v1's Exchange fallback for a mail-enabled user) ------------------
IF COL_LENGTH('eps.TagChange', 'Via') IS NULL
ALTER TABLE eps.TagChange ADD Via NVARCHAR(40) NULL;     -- Graph | Exchange Set-Mailbox | Exchange Set-MailUser | Worker

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 3)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (3, '2.0.0');

GO
-- ---- version 4: the tag tamper monitor (DESIGN §5.7a) ------------------------------------------------------------
-- the last value the monitor saw per watched attribute (its baseline), the delta links, and every foreign change found
IF OBJECT_ID('eps.WatchedValue') IS NULL
CREATE TABLE eps.WatchedValue (
    ObjectType    NVARCHAR(10)   NOT NULL,
    ObjectId      UNIQUEIDENTIFIER NOT NULL,
    Attribute     NVARCHAR(60)   NOT NULL,
    Value         NVARCHAR(1024) NULL,
    ObjectName    NVARCHAR(400)  NULL,
    SeenAtUtc     DATETIME2      NOT NULL CONSTRAINT DF_WatchedValue_At DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_WatchedValue PRIMARY KEY (ObjectType, ObjectId, Attribute)
);
IF OBJECT_ID('eps.MonitorState') IS NULL
CREATE TABLE eps.MonitorState (
    Name          NVARCHAR(100)  NOT NULL PRIMARY KEY,   -- 'delta:User', 'delta:Device', 'fullCompare'
    Value         NVARCHAR(MAX)  NULL,                   -- the delta link / the last full compare
    UpdatedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_MonitorState_At DEFAULT SYSUTCDATETIME()
);
IF OBJECT_ID('eps.TamperEvent') IS NULL
CREATE TABLE eps.TamperEvent (
    EventId       BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    RunId         UNIQUEIDENTIFIER NULL,
    FoundAtUtc    DATETIME2      NOT NULL CONSTRAINT DF_TamperEvent_At DEFAULT SYSUTCDATETIME(),
    ObjectType    NVARCHAR(10)   NOT NULL,
    ObjectId      UNIQUEIDENTIFIER NOT NULL,
    ObjectName    NVARCHAR(400)  NULL,
    TagType       NVARCHAR(60)   NULL,
    Attribute     NVARCHAR(60)   NOT NULL,
    OldValue      NVARCHAR(1024) NULL,
    NewValue      NVARCHAR(1024) NULL,
    Severity      NVARCHAR(10)   NOT NULL,               -- High | Normal
    Initiator     NVARCHAR(400)  NULL,                   -- who, from the audit log; NULL = unknown (no audit log / not found)
    InitiatorKind NVARCHAR(20)   NULL,                   -- user | app | sync | unknown
    FoundBy       NVARCHAR(20)   NOT NULL,               -- delta | fullCompare
    Detail        NVARCHAR(2000) NULL,                   -- what it means ("is now outside ...")
    Status        NVARCHAR(20)   NOT NULL CONSTRAINT DF_TamperEvent_Status DEFAULT 'Open',   -- Open | Restored | Accepted | Allowed
    ResolvedBy    NVARCHAR(320)  NULL,
    ResolvedAtUtc DATETIME2      NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_TamperEvent_Open' AND object_id = OBJECT_ID('eps.TamperEvent'))
CREATE INDEX IX_TamperEvent_Open ON eps.TamperEvent (Status, FoundAtUtc DESC);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 4)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (4, '2.0.0');

GO
-- ---- version 5: the hybrid worker (DESIGN §6) - the cloud and the worker meet only here, never inbound ------------
IF OBJECT_ID('eps.WorkerHeartbeat') IS NULL
CREATE TABLE eps.WorkerHeartbeat (
    WorkerName    NVARCHAR(100)  NOT NULL PRIMARY KEY,
    Machine       NVARCHAR(256)  NULL,
    RunAs         NVARCHAR(256)  NULL,                   -- the gMSA the worker writes AD as
    Version       NVARCHAR(40)   NULL,
    LastSeenUtc   DATETIME2      NOT NULL,
    LastResult    NVARCHAR(1000) NULL
);
-- one AD change per package (an AD-synced user's tag): queued by the tagging job, claimed and applied by the worker
IF OBJECT_ID('eps.WorkPackage') IS NULL
CREATE TABLE eps.WorkPackage (
    PackageId     BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    Kind          NVARCHAR(30)   NOT NULL,               -- AdSetAttribute
    ChangeId      BIGINT         NULL REFERENCES eps.TagChange (ChangeId),
    RunId         UNIQUEIDENTIFIER NULL,
    Payload       NVARCHAR(MAX)  NOT NULL,               -- JSON: sid, upn, attribute, value
    Status        NVARCHAR(20)   NOT NULL CONSTRAINT DF_WorkPackage_Status DEFAULT 'Queued',   -- Queued | Claimed | Done | Failed
    Attempts      INT            NOT NULL CONSTRAINT DF_WorkPackage_Attempts DEFAULT 0,
    ClaimedBy     NVARCHAR(100)  NULL,
    ClaimedAtUtc  DATETIME2      NULL,
    DoneAtUtc     DATETIME2      NULL,
    Error         NVARCHAR(2000) NULL,
    QueuedAtUtc   DATETIME2      NOT NULL CONSTRAINT DF_WorkPackage_At DEFAULT SYSUTCDATETIME()
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_WorkPackage_Status' AND object_id = OBJECT_ID('eps.WorkPackage'))
CREATE INDEX IX_WorkPackage_Status ON eps.WorkPackage (Status, QueuedAtUtc);
-- AD group members (recursive, user objects) for the MemberOfGroup rules on AD-synced users: the job asks for a group,
-- the worker keeps its snapshot fresh
IF OBJECT_ID('eps.AdGroupSnapshotInfo') IS NULL
CREATE TABLE eps.AdGroupSnapshotInfo (
    GroupName      NVARCHAR(256)  NOT NULL PRIMARY KEY,
    Found          BIT            NULL,                  -- NULL = never read yet
    Members        INT            NULL,
    RequestedAtUtc DATETIME2      NOT NULL CONSTRAINT DF_AdGroupInfo_Req DEFAULT SYSUTCDATETIME(),
    RefreshedAtUtc DATETIME2      NULL,
    Error          NVARCHAR(1000) NULL
);
IF OBJECT_ID('eps.AdGroupMember') IS NULL
CREATE TABLE eps.AdGroupMember (
    GroupName     NVARCHAR(256)  NOT NULL,
    MemberUpn     NVARCHAR(320)  NOT NULL,
    CONSTRAINT PK_AdGroupMember PRIMARY KEY (GroupName, MemberUpn)
);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 5)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (5, '2.0.0');

GO
-- ---- version 6: the tamper alerts (DESIGN §5.7a) -------------------------------------------------------------------
-- an event is alerted once (the mail of the run that found it)
IF COL_LENGTH('eps.TamperEvent', 'AlertedAtUtc') IS NULL
ALTER TABLE eps.TamperEvent ADD AlertedAtUtc DATETIME2 NULL;
-- the break-glass accounts the Azure Monitor rules watch: Entra (UPN + object id) or AD (sAMAccountName + SID)
IF COL_LENGTH('eps.BreakGlassAccount', 'Directory') IS NULL
ALTER TABLE eps.BreakGlassAccount ADD Directory NVARCHAR(10) NOT NULL CONSTRAINT DF_BreakGlass_Directory DEFAULT 'Entra';   -- Entra | AD
IF COL_LENGTH('eps.BreakGlassAccount', 'ObjectId') IS NULL
ALTER TABLE eps.BreakGlassAccount ADD ObjectId UNIQUEIDENTIFIER NULL;          -- Entra object id
IF COL_LENGTH('eps.BreakGlassAccount', 'Sid') IS NULL
ALTER TABLE eps.BreakGlassAccount ADD Sid NVARCHAR(200) NULL;                  -- AD objectSid

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 6)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (6, '2.0.0');

GO
-- ---- version 7: the web app (DESIGN §2) - who may use it, the audit trail (framework AUDIT-1), signed requests (§12.11f)
-- who may do what in the GUI: a person (by Entra object id; the UPN only until the first sign-in fills the id). A verified
-- user with no row is a Reader (fail closed); the last SuperAdmin cannot be removed (the web app's guard).
IF OBJECT_ID('eps.WebAccess') IS NULL
CREATE TABLE eps.WebAccess (
    Principal     NVARCHAR(320)  NOT NULL PRIMARY KEY,   -- the UPN, lower-case
    ObjectId      UNIQUEIDENTIFIER NULL,
    Role          NVARCHAR(20)   NOT NULL,
    GrantedBy     NVARCHAR(320)  NOT NULL,
    GrantedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_WebAccess_At DEFAULT SYSUTCDATETIME(),
    CONSTRAINT CK_WebAccess_Role CHECK (Role IN ('SuperAdmin', 'Admin', 'Reader'))
);
-- AUDIT-1.1: one row per event, from every surface (web, job, setup). Append-only IN THE DATABASE: no runtime identity is
-- owner or ddladmin (framework §12.23), so the DENY binds every one of them, including identities added later.
IF OBJECT_ID('eps.AuditEvent') IS NULL
CREATE TABLE eps.AuditEvent (
    Id            BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    TsUtc         DATETIME2      NOT NULL CONSTRAINT DF_AuditEvent_Ts DEFAULT SYSUTCDATETIME(),
    Action        NVARCHAR(100)  NOT NULL,               -- domain.object.verb, a closed list (EPS-Audit.ps1)
    Actor         NVARCHAR(320)  NOT NULL,
    ActorSource   NVARCHAR(20)   NOT NULL,               -- web | job | setup
    Target        NVARCHAR(1000) NULL,
    Reason        NVARCHAR(1000) NULL,
    Outcome       NVARCHAR(20)   NOT NULL,               -- ok | error | refused | held
    OutcomeText   NVARCHAR(2000) NULL,
    BeforeJson    NVARCHAR(MAX)  NULL,
    AfterJson     NVARCHAR(MAX)  NULL,
    CorrelationId UNIQUEIDENTIFIER NULL,
    RunId         UNIQUEIDENTIFIER NULL,
    WhatIf        BIT            NOT NULL CONSTRAINT DF_AuditEvent_WhatIf DEFAULT 0
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_AuditEvent_Ts' AND object_id = OBJECT_ID('eps.AuditEvent'))
CREATE INDEX IX_AuditEvent_Ts ON eps.AuditEvent (TsUtc DESC);
DENY UPDATE, DELETE ON eps.AuditEvent TO public;
-- a request that leads to an outside change carries the requester's signed token and when the web app verified it; the
-- engine verifies it again before it acts. CorrelationId = the audit event of the request (request -> run -> changes).
IF COL_LENGTH('eps.JobRequest', 'SignedToken') IS NULL
ALTER TABLE eps.JobRequest ADD SignedToken NVARCHAR(MAX) NULL, SignedVerifiedAtUtc DATETIME2 NULL, CorrelationId UNIQUEIDENTIFIER NULL, Reason NVARCHAR(1000) NULL;

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 7)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (7, '2.0.0');

-- ---- version 8: the CA Policy Analyzer (DESIGN §5.7; v1 CAPolicyEvaluator) - READ ONLY towards the tenant ----------------
-- the tenant's CA policies as the analyzer last read them (the GUI picks from it: the web app never calls Graph)
IF OBJECT_ID('eps.CaPolicy') IS NULL
CREATE TABLE eps.CaPolicy (
    PolicyId      UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    DisplayName   NVARCHAR(256)  NOT NULL,
    State         NVARCHAR(60)   NULL,                   -- enabled | disabled | enabledForReportingButNotEnforced
    ModifiedAtUtc DATETIMEOFFSET NULL,
    SeenAtUtc     DATETIME2      NOT NULL CONSTRAINT DF_CaPolicy_Seen DEFAULT SYSUTCDATETIME()
);
-- one analysis = one policy in one run (an ad-hoc run or a monitor's)
IF OBJECT_ID('eps.CaAnalysis') IS NULL
CREATE TABLE eps.CaAnalysis (
    AnalysisId     UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    RunId          UNIQUEIDENTIFIER NOT NULL,
    PolicyId       UNIQUEIDENTIFIER NOT NULL,
    DisplayName    NVARCHAR(256)  NOT NULL,
    PolicyState    NVARCHAR(60)   NULL,
    Mode           NVARCHAR(20)   NOT NULL,              -- SignInLogs | WhatIf
    WindowStartUtc DATETIME2      NULL,
    WindowEndUtc   DATETIME2      NULL,
    InScope        INT            NOT NULL,
    Impacted       INT            NOT NULL,
    NotImpacted    INT            NOT NULL,
    Errors         INT            NOT NULL,
    ByClassJson    NVARCHAR(MAX)  NULL,
    ConditionsJson NVARCHAR(MAX)  NULL,                  -- WhatIf: the simulated sign-in
    UnresolvedJson NVARCHAR(MAX)  NULL,                  -- conditions that could not be simulated (said, never guessed)
    WarningsJson   NVARCHAR(MAX)  NULL,
    Monitor        NVARCHAR(100)  NULL,                  -- the monitor that ran it; NULL = ad hoc
    CreatedAtUtc   DATETIME2      NOT NULL CONSTRAINT DF_CaAnalysis_At DEFAULT SYSUTCDATETIME(),
    CONSTRAINT CK_CaAnalysis_Mode CHECK (Mode IN ('SignInLogs', 'WhatIf'))
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CaAnalysis_At' AND object_id = OBJECT_ID('eps.CaAnalysis'))
CREATE INDEX IX_CaAnalysis_At ON eps.CaAnalysis (CreatedAtUtc DESC);
-- per user (or service principal): the classification and why
IF OBJECT_ID('eps.CaAnalysisResult') IS NULL
CREATE TABLE eps.CaAnalysisResult (
    AnalysisId        UNIQUEIDENTIFIER NOT NULL REFERENCES eps.CaAnalysis (AnalysisId) ON DELETE CASCADE,
    Seq               INT            NOT NULL,
    UserId            NVARCHAR(64)   NULL,
    UserPrincipalName NVARCHAR(320)  NULL,
    DisplayName       NVARCHAR(400)  NULL,
    IsSpn             BIT            NOT NULL CONSTRAINT DF_CaAnalysisResult_Spn DEFAULT 0,
    Classification    NVARCHAR(30)   NOT NULL,           -- BLOCKED | REGRESSED | CHALLENGED | RECOVERED | OK | NO_SIGNIN | ALLOWED | NOT_IN_SCOPE | ERROR | SPN_*
    Impacted          BIT            NOT NULL,
    Reason            NVARCHAR(1000) NULL,
    GrantControls     NVARCHAR(400)  NULL,
    SessionControls   NVARCHAR(400)  NULL,
    LastSignInUtc     DATETIME2      NULL,
    Country           NVARCHAR(10)   NULL,
    City              NVARCHAR(200)  NULL,
    IPAddress         NVARCHAR(64)   NULL,
    DeviceOS          NVARCHAR(100)  NULL,
    Browser           NVARCHAR(200)  NULL,
    ClientApp         NVARCHAR(100)  NULL,
    Application       NVARCHAR(400)  NULL,
    RiskLevel         NVARCHAR(30)   NULL,
    RiskState         NVARCHAR(60)   NULL,
    CAResult          NVARCHAR(60)   NULL,
    FailureReason     NVARCHAR(1000) NULL,
    SignInCount       INT            NULL,
    CountriesSeen     NVARCHAR(400)  NULL,
    DistinctIPCount   INT            NULL,
    CONSTRAINT PK_CaAnalysisResult PRIMARY KEY (AnalysisId, Seq)
);
-- the monitors (owner 2026-10-30: several, in parallel, each with its own policy set and parameters)
IF OBJECT_ID('eps.CaMonitor') IS NULL
CREATE TABLE eps.CaMonitor (
    Name          NVARCHAR(100)  NOT NULL PRIMARY KEY,
    Definition    NVARCHAR(MAX)  NOT NULL,               -- JSON: the policy set, mode, window, switches, scale parameters
    Schedule      NVARCHAR(60)   NOT NULL,               -- the tick's schedule grammar (daily 07:00, every 4h, ...)
    Enabled       BIT            NOT NULL CONSTRAINT DF_CaMonitor_Enabled DEFAULT 0,
    LastStartedUtc DATETIME2     NULL,
    LastStartResult NVARCHAR(400) NULL,
    UpdatedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_CaMonitor_At DEFAULT SYSUTCDATETIME()
);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 8)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (8, '2.0.0');

-- ---- the commit queue (owner 2026-10-31: "so an admin can make changes and then we manually approve from a commit
-- queue", "it must not instantly start when a single chg is made", "same setup" as PIM) --------------------------------
-- A rule / tag type / tag value / condition type change is STAGED here instead of written; a commit replays it through
-- the same save (validation, journal) and then requests the tagging run. Rows are never deleted: Pending -> Applied |
-- Failed | Discarded | Superseded (a later change to the same thing replaced it).
IF OBJECT_ID('eps.PendingChange') IS NULL
CREATE TABLE eps.PendingChange (
    Id             BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    ObjectType     NVARCHAR(10)   NOT NULL,               -- User | Device
    Entity         NVARCHAR(60)   NOT NULL,               -- UserTagRule | DeviceTagRule | TagType | TagValue | ConditionType
    EntityKey      NVARCHAR(400)  NOT NULL,
    Op             NVARCHAR(20)   NOT NULL,               -- Create | Update | Delete | Move
    Summary        NVARCHAR(1000) NOT NULL,
    Action         NVARCHAR(60)   NOT NULL,               -- the audit action of the save it replays (rule.update ...)
    Method         NVARCHAR(10)   NOT NULL,
    Path           NVARCHAR(400)  NOT NULL,
    BodyJson       NVARCHAR(MAX)  NULL,                   -- the staged request body (the "after")
    BeforeJson     NVARCHAR(MAX)  NULL,                   -- what it was when staged (the "before")
    StagedBy       NVARCHAR(320)  NOT NULL,
    StagedAtUtc    DATETIME2      NOT NULL CONSTRAINT DF_PendingChange_At DEFAULT SYSUTCDATETIME(),
    StageReason    NVARCHAR(1000) NULL,
    Status         NVARCHAR(20)   NOT NULL CONSTRAINT DF_PendingChange_Status DEFAULT 'Pending',
    CommitId       UNIQUEIDENTIFIER NULL,
    CommittedBy    NVARCHAR(320)  NULL,
    CommittedAtUtc DATETIME2      NULL,
    Error          NVARCHAR(2000) NULL,
    DiscardedBy    NVARCHAR(320)  NULL,
    DiscardedAtUtc DATETIME2      NULL,
    DiscardReason  NVARCHAR(1000) NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_PendingChange_Status' AND object_id = OBJECT_ID('eps.PendingChange'))
CREATE INDEX IX_PendingChange_Status ON eps.PendingChange (Status, Id);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 9)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (9, '2.0.3');

GO
-- ---- version 10: the identity report (DESIGN §5.4; owner 2026-10-31: "make identyreport as gui view with filters",
-- "that shows gaps", "similar to excel pivots", "save views like fx si can") ---------------------------------------------
-- One SNAPSHOT per report run: every user and device as a JSON row (the GUI filters any column over it, LIST-1), the
-- gap views as membership, the ready-made pivots computed at the run. Old snapshots are pruned (IdentityReport.KeepRuns).
IF OBJECT_ID('eps.IdentitySnapshot') IS NULL
CREATE TABLE eps.IdentitySnapshot (
    RunId          UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    CreatedAtUtc   DATETIME2      NOT NULL CONSTRAINT DF_IdentitySnapshot_At DEFAULT SYSUTCDATETIME(),
    Users          INT            NOT NULL,
    Devices        INT            NOT NULL,
    ViewCountsJson NVARCHAR(MAX)  NULL,                   -- { view name: count }
    PivotsJson     NVARCHAR(MAX)  NULL,                   -- the ready-made pivots
    NotesJson      NVARCHAR(MAX)  NULL,                   -- what the run could not see (no AD snapshot, ...)
    ConfigJson     NVARCHAR(MAX)  NULL                    -- the settings the run used
);
IF OBJECT_ID('eps.IdentityRow') IS NULL
CREATE TABLE eps.IdentityRow (
    RunId          UNIQUEIDENTIFIER NOT NULL REFERENCES eps.IdentitySnapshot (RunId) ON DELETE CASCADE,
    Kind           NVARCHAR(10)   NOT NULL,               -- User | Device
    ObjectId       NVARCHAR(64)   NOT NULL,
    Name           NVARCHAR(400)  NULL,                   -- display name / device name (the default order)
    Data           NVARCHAR(MAX)  NOT NULL,               -- the row, every column (JSON)
    CONSTRAINT PK_IdentityRow PRIMARY KEY (RunId, Kind, ObjectId),
    CONSTRAINT CK_IdentityRow_Kind CHECK (Kind IN ('User', 'Device'))
);
IF OBJECT_ID('eps.IdentityViewMember') IS NULL
CREATE TABLE eps.IdentityViewMember (
    RunId          UNIQUEIDENTIFIER NOT NULL REFERENCES eps.IdentitySnapshot (RunId) ON DELETE CASCADE,
    ViewName       NVARCHAR(60)   NOT NULL,
    Kind           NVARCHAR(10)   NOT NULL,
    ObjectId       NVARCHAR(64)   NOT NULL,
    CONSTRAINT PK_IdentityViewMember PRIMARY KEY (RunId, ViewName, Kind, ObjectId)
);
-- saved views (LIST-1 layouts + the base view + a pivot): personal, or shared (SuperAdmin) with one default per page
IF OBJECT_ID('eps.SavedView') IS NULL
CREATE TABLE eps.SavedView (
    ViewId         UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    Page           NVARCHAR(40)   NOT NULL,               -- identity
    Name           NVARCHAR(100)  NOT NULL,
    Owner          NVARCHAR(320)  NOT NULL,               -- who saved it
    Shared         BIT            NOT NULL CONSTRAINT DF_SavedView_Shared DEFAULT 0,
    IsDefault      BIT            NOT NULL CONSTRAINT DF_SavedView_Default DEFAULT 0,
    Definition     NVARCHAR(MAX)  NOT NULL,               -- { v: 1, base, columns, hidden, sort, search, filters, pageSize, pivot }
    UpdatedAtUtc   DATETIME2      NOT NULL CONSTRAINT DF_SavedView_At DEFAULT SYSUTCDATETIME()
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SavedView_Page' AND object_id = OBJECT_ID('eps.SavedView'))
CREATE INDEX IX_SavedView_Page ON eps.SavedView (Page, Shared, Owner);
-- the hybrid worker's AD snapshot of every user (the report's AD_* columns; B5: joined on the SID)
IF OBJECT_ID('eps.AdUserSnapshot') IS NULL
CREATE TABLE eps.AdUserSnapshot (
    Sid                  NVARCHAR(200)  NOT NULL PRIMARY KEY,
    SamAccountName       NVARCHAR(256)  NULL,
    UserPrincipalName    NVARCHAR(320)  NULL,
    Enabled              BIT            NULL,
    LockedOut            BIT            NULL,
    PasswordNeverExpires BIT            NULL,
    CannotChangePassword BIT            NULL,
    LastLogonUtc         DATETIME2      NULL,             -- lastLogonTimestamp (replicated; within ~14 days)
    AccountExpiresUtc    DATETIME2      NULL,
    WhenCreatedUtc       DATETIME2      NULL,
    Description          NVARCHAR(1024) NULL,
    RefreshedAtUtc       DATETIME2      NOT NULL
);
IF OBJECT_ID('eps.AdUserSnapshotInfo') IS NULL
CREATE TABLE eps.AdUserSnapshotInfo (
    Id             INT            NOT NULL PRIMARY KEY CONSTRAINT CK_AdUserSnapshotInfo_One CHECK (Id = 1),
    RequestedAtUtc DATETIME2      NULL,                   -- the report asks; the worker reads AD on its next cycle
    RefreshedAtUtc DATETIME2      NULL,
    Users          INT            NULL,
    Error          NVARCHAR(2000) NULL
);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 10)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (10, '2.0.5');

GO
-- ---- version 11: SEC-AUDIT-1 hardening (2.0.7) ------------------------------------------------------------------------
-- S2: a group a rule names is pinned to its object id the first time the name resolves to exactly one group
IF OBJECT_ID('eps.GroupPin') IS NULL
CREATE TABLE eps.GroupPin (
    Source         NVARCHAR(10)     NOT NULL,             -- Entra
    Name           NVARCHAR(256)    NOT NULL,
    ObjectId       UNIQUEIDENTIFIER NOT NULL,
    PinnedAtUtc    DATETIME2        NOT NULL CONSTRAINT DF_GroupPin_At DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_GroupPin PRIMARY KEY (Source, Name)
);
-- S7: a saved view belongs to an OBJECT ID (a name can be given to someone else)
IF COL_LENGTH('eps.SavedView', 'OwnerId') IS NULL
ALTER TABLE eps.SavedView ADD OwnerId UNIQUEIDENTIFIER NULL;
GO
-- S1: a request's times are the DATABASE's, never the writer's: the engine checks the requester's token at the time the
-- row was written, so a token copied from an old request into a new one is outside its life and refused
CREATE OR ALTER TRIGGER eps.TR_JobRequest_Stamp ON eps.JobRequest AFTER INSERT AS
BEGIN
    SET NOCOUNT ON;
    UPDATE q SET RequestedAtUtc = SYSUTCDATETIME(),
                 SignedVerifiedAtUtc = CASE WHEN q.SignedToken IS NULL THEN NULL ELSE SYSUTCDATETIME() END
    FROM eps.JobRequest q JOIN inserted i ON i.RequestId = q.RequestId;
END
GO
IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 11)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (11, '2.0.7');
GO
-- ---- version 12: Conditional Access management, the READ-ONLY half (DESIGN §5.1; owner 2026-10-30: "dont touch any ca
-- policy stuff ... it must not automatically do things i have not approved"). Nothing here is an order to the engine: it is
-- what the engine READ (the bodies, the names) and what the operator RECORDED (an adoption). No table holds a desired state.
-- the policy's whole body as last read, and the engine's review of it (template match, stage, the diff, break-glass)
IF COL_LENGTH('eps.CaPolicy', 'BodyJson') IS NULL
ALTER TABLE eps.CaPolicy ADD BodyJson NVARCHAR(MAX) NULL;
IF COL_LENGTH('eps.CaPolicy', 'ReviewJson') IS NULL
ALTER TABLE eps.CaPolicy ADD ReviewJson NVARCHAR(MAX) NULL;
GO
-- the names of the objects the policies name (groups, users, roles, named locations, applications), as last read - the
-- documentation and the diff show names, the web app never calls Graph
IF OBJECT_ID('eps.CaDirectoryName') IS NULL
CREATE TABLE eps.CaDirectoryName (
    Kind          NVARCHAR(20)   NOT NULL,               -- user | group | role | location | application
    ObjectId      NVARCHAR(100)  NOT NULL,
    Name          NVARCHAR(400)  NULL,
    Detail        NVARCHAR(MAX)  NULL,                   -- a group's membership rule, a user's UPN
    CONSTRAINT PK_CaDirectoryName PRIMARY KEY (Kind, ObjectId)
);
-- the operator's RECORD that he adopted a policy (owner 2026-10-30: "adopt them into eps"): nothing in the tenant changes
IF OBJECT_ID('eps.CaAdoption') IS NULL
CREATE TABLE eps.CaAdoption (
    PolicyId        UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,
    DisplayName     NVARCHAR(256)  NOT NULL,
    TemplateId      NVARCHAR(20)   NULL,                 -- CA000 .. CA800; NULL = adopted without a template
    TemplateVersion NVARCHAR(20)   NULL,
    StageAtAdopt    NVARCHAR(20)   NULL,                 -- Initial | Pilot1 | Pilot2 | Pilot3 | Prod | Custom
    Status          NVARCHAR(10)   NOT NULL,             -- Adopted | Released
    AdoptedBodyJson NVARCHAR(MAX)  NOT NULL,             -- the body as the operator adopted it: the drift baseline
    AdoptedBodyHash CHAR(64)       NOT NULL,
    AdoptedBy       NVARCHAR(320)  NOT NULL,
    AdoptedAtUtc    DATETIME2      NOT NULL CONSTRAINT DF_CaAdoption_At DEFAULT SYSUTCDATETIME(),
    AdoptReason     NVARCHAR(1000) NULL,
    ReleasedBy      NVARCHAR(320)  NULL,
    ReleasedAtUtc   DATETIME2      NULL,
    ReleaseReason   NVARCHAR(1000) NULL,
    CONSTRAINT CK_CaAdoption_Status CHECK (Status IN ('Adopted', 'Released'))
);
-- what the CA monitor found on an adopted policy (CA.Monitoring.Enabled): SHOWN and alerted, never acted on
IF OBJECT_ID('eps.CaFinding') IS NULL
CREATE TABLE eps.CaFinding (
    FindingId     BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    PolicyId      UNIQUEIDENTIFIER NOT NULL,
    DisplayName   NVARCHAR(256)  NOT NULL,
    Kind          NVARCHAR(20)   NOT NULL,               -- Drift | BreakGlass | Missing
    Detail        NVARCHAR(2000) NOT NULL,
    DetailJson    NVARCHAR(MAX)  NULL,
    Status        NVARCHAR(10)   NOT NULL CONSTRAINT DF_CaFinding_Status DEFAULT 'Open',   -- Open | Cleared
    FirstSeenUtc  DATETIME2      NOT NULL CONSTRAINT DF_CaFinding_First DEFAULT SYSUTCDATETIME(),
    LastSeenUtc   DATETIME2      NOT NULL CONSTRAINT DF_CaFinding_Last DEFAULT SYSUTCDATETIME(),
    ClearedAtUtc  DATETIME2      NULL,
    AlertedAtUtc  DATETIME2      NULL,
    CONSTRAINT CK_CaFinding_Kind CHECK (Kind IN ('Drift', 'BreakGlass', 'Missing')),
    CONSTRAINT CK_CaFinding_Status CHECK (Status IN ('Open', 'Cleared'))
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CaFinding_Open' AND object_id = OBJECT_ID('eps.CaFinding'))
CREATE INDEX IX_CaFinding_Open ON eps.CaFinding (Status, PolicyId, Kind);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 12)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (12, '2.0.13');

-- ---- v13: the Invardia uplink (UPLINK-1, owner 2026-11-01: "Yes, identified only") ------------------------------------
-- the uplink job's own state: one watermark per job ('watermark:eps-<job>' = the newest run end Invardia took), the
-- heartbeat ('heartbeat' = the last interval Invardia answered 2xx), each alert's episode ('alert:<AlertId>') and the
-- last cycle's plain result ('last'). The per-install key is NEVER stored here: it stays in the install's Key Vault.
IF OBJECT_ID('eps.UplinkState') IS NULL
CREATE TABLE eps.UplinkState (
    Name          NVARCHAR(150)  NOT NULL PRIMARY KEY,
    Value         NVARCHAR(4000) NULL,
    UpdatedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_UplinkState_At DEFAULT SYSUTCDATETIME()
);
-- the support state Invardia answers to the heartbeat (framework SECAUDIT-1a): RECORDED and SHOWN only - nothing is
-- granted from it yet (the just-in-time grant is a separate, owner-proven step). One row per change of state; the same
-- state again only moves LastSeenUtc / MaxUntilUtc.
IF OBJECT_ID('eps.SupportEvent') IS NULL
CREATE TABLE eps.SupportEvent (
    SupportEventId BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    ReceivedAtUtc DATETIME2      NOT NULL CONSTRAINT DF_SupportEvent_At DEFAULT SYSUTCDATETIME(),
    LastSeenUtc   DATETIME2      NOT NULL CONSTRAINT DF_SupportEvent_Seen DEFAULT SYSUTCDATETIME(),
    State         NVARCHAR(10)   NOT NULL,               -- open | closed
    AccessLevel   NVARCHAR(50)   NULL,                   -- the consented level Invardia names
    Reason        NVARCHAR(300)  NULL,
    TicketNumber  NVARCHAR(40)   NULL,
    OpenedBy      NVARCHAR(200)  NULL,
    MaxUntilUtc   DATETIME2      NULL,                   -- open: support ends at the latest then
    EnvironmentId UNIQUEIDENTIFIER NULL,
    CONSTRAINT CK_SupportEvent_State CHECK (State IN ('open', 'closed'))
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SupportEvent_Latest' AND object_id = OBJECT_ID('eps.SupportEvent'))
CREATE INDEX IX_SupportEvent_Latest ON eps.SupportEvent (ReceivedAtUtc DESC);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 13)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (13, '2.0.16');

-- ---- v14: the CA Policy Analyzer's personas (CA-PERSONA, owner 2026-11-02: "it should be possible edit/delete/create
-- existing monitors persona. this functionality replaces the series button") ---------------------------------------------
-- A persona = a name + picked policies (ids) + name rules (CA2 = every CA2xx; CA006 = only the CA006 variants; CA6* a
-- wildcard). The engine seeds the template personas ONCE (each as rules = its template numbers) when the list is empty,
-- and writes every change from the signed request (journaled in eps.ConfigChange). A monitor names personas and resolves
-- them at each run, so a change joins. The web app only reads it.
IF OBJECT_ID('eps.CaPersona') IS NULL
CREATE TABLE eps.CaPersona (
    Name          NVARCHAR(100)  NOT NULL PRIMARY KEY,
    PolicyIdsJson NVARCHAR(MAX)  NOT NULL CONSTRAINT DF_CaPersona_Ids DEFAULT N'[]',      -- JSON array of policy ids
    RulesJson     NVARCHAR(MAX)  NOT NULL CONSTRAINT DF_CaPersona_Rules DEFAULT N'[]',    -- JSON array of name rules
    Source        NVARCHAR(20)   NOT NULL CONSTRAINT DF_CaPersona_Source DEFAULT 'custom', -- template (seeded) | custom
    UpdatedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_CaPersona_At DEFAULT SYSUTCDATETIME(),
    UpdatedBy     NVARCHAR(320)  NULL,
    CONSTRAINT CK_CaPersona_Source CHECK (Source IN ('template', 'custom'))
);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 14)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (14, '2.0.24');

-- ---- v15: a persona's exclude list (CA-LIMITS, owner 2026-11-02: "fix all 4 limits") ----------------------------------
-- A persona takes (its picked policies + the policies its rules take) minus ExcludeIdsJson. The seed is now marked once
-- in eps.Setting 'CaAnalyzer.PersonasSeeded' (written by the engine), so an empty list after the seed stays empty.
IF COL_LENGTH('eps.CaPersona', 'ExcludeIdsJson') IS NULL
ALTER TABLE eps.CaPersona ADD ExcludeIdsJson NVARCHAR(MAX) NOT NULL CONSTRAINT DF_CaPersona_Excl DEFAULT N'[]';  -- JSON array of policy ids

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 15)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (15, '2.0.25');

-- ---- v16: what the install has TAKEN of the template library (TEMPLATE-UPDATES, owner 2026-11-02: "templates can be used
-- for updates if new features are added but always operator controlled. easy to see chg is importantant") ----------------
-- One row per CA number: the template as taken (the "before" of the next update; NULL = not taken / its removal taken) and
-- the persona its number was taken into (NULL = none taken). The engine writes the baseline once (the library the install
-- imported) and what the operator takes from the Template updates view; the web app only reads it. A newer library changes
-- nothing by itself, and nothing here ever writes a Conditional Access policy.
IF OBJECT_ID('eps.CaTemplateTaken') IS NULL
CREATE TABLE eps.CaTemplateTaken (
    TemplateId    NVARCHAR(20)   NOT NULL PRIMARY KEY,   -- CA000 .. CA800
    Version       NVARCHAR(20)   NULL,
    TemplateJson  NVARCHAR(MAX)  NULL,                   -- the compared parts of the template, canonical JSON
    TemplateHash  CHAR(64)       NULL,
    Persona       NVARCHAR(100)  NULL,                   -- the persona the number was taken into ('' = none)
    Library       NVARCHAR(40)   NOT NULL,               -- the library it was taken from
    TakenAtUtc    DATETIME2      NOT NULL CONSTRAINT DF_CaTemplateTaken_At DEFAULT SYSUTCDATETIME(),
    TakenBy       NVARCHAR(320)  NULL
);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 16)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (16, '2.0.26');
