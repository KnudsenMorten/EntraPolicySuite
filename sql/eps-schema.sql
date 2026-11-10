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

-- ---- v17: the Conditional Access stage moves (CA-LIFECYCLE, owner 2026-11-03: "in ca policy i need buttons to easily
-- controll and movevto another lufecycle phase like pilot1, pilot2"; "Write on approval", "SuperAdmin only") -----------------
-- One row per move the engine made from a SuperAdmin's signed request: the policy before (as read live just before the
-- write) and after (as read back), for the history and a step back. Written only by the engine; the web app reads it.
IF OBJECT_ID('eps.CaStageMove') IS NULL
CREATE TABLE eps.CaStageMove (
    MoveId        BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    PolicyId      UNIQUEIDENTIFIER NOT NULL,
    DisplayName   NVARCHAR(256)  NOT NULL,                -- the name after the move
    FromStage     NVARCHAR(20)   NOT NULL,
    ToStage       NVARCHAR(20)   NOT NULL,                -- Pilot1 .. Prod, or Disabled
    BeforeJson    NVARCHAR(MAX)  NOT NULL,
    AfterJson     NVARCHAR(MAX)  NOT NULL,
    Result        NVARCHAR(40)   NOT NULL,                -- applied | applied, differs
    ResultText    NVARCHAR(2000) NULL,
    RequestedBy   NVARCHAR(320)  NOT NULL,
    Reason        NVARCHAR(2000) NULL,
    MovedAtUtc    DATETIME2      NOT NULL CONSTRAINT DF_CaStageMove_At DEFAULT SYSUTCDATETIME()
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_CaStageMove_Policy')
CREATE INDEX IX_CaStageMove_Policy ON eps.CaStageMove (PolicyId, MovedAtUtc DESC);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 17)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (17, '2.0.27');

-- ---- v18: GET-STARTED, the onboarding check (owner 2026-11-03: "i also need a get started wizard to onboard fxbreak
-- glass, auth methods, naming conv for groups etc. see all req in v1 scripts"; DESIGN §5.10) ----------------------------
-- One row per item the engine checked (step, item, state ok | missing | check | info | unknown, what it found). The engine
-- replaces the rows at each check; the web app's Get started page reads them. Nothing in the tenant is written.
IF OBJECT_ID('eps.OnboardingCheck') IS NULL
CREATE TABLE eps.OnboardingCheck (
    CheckId       BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    Step          NVARCHAR(40)   NOT NULL,
    Item          NVARCHAR(200)  NOT NULL,
    Title         NVARCHAR(400)  NOT NULL,
    State         NVARCHAR(20)   NOT NULL,
    Detail        NVARCHAR(2000) NULL,
    CheckedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_OnboardingCheck_At DEFAULT SYSUTCDATETIME(),
    CheckedBy     NVARCHAR(320)  NULL
);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 18)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (18, '2.0.28');

-- ---- v19: ID-ACTIONS, an action per user in the identity report (owner 2026-11-03: "we need a way to add 4 fields per
-- user: notes + action (dropdwn) like disable, delete, investigate, remove sync cloud + ActionWho (text field) +
-- ActionStatus (not started, in progress, closed)") -----------------------------------------------------------------------
-- Kept by the object id, so it stays across report runs; merged into each row when the report is read (filter, sort,
-- pivot, export). A record for follow-up: EPS does not act on it. The engine writes it (an Admin's request); the web reads.
IF OBJECT_ID('eps.IdentityAction') IS NULL
CREATE TABLE eps.IdentityAction (
    Kind          NVARCHAR(10)   NOT NULL,                -- User
    ObjectId      NVARCHAR(64)   NOT NULL,
    Name          NVARCHAR(400)  NULL,                    -- the display name when it was set (for the journal)
    Notes         NVARCHAR(2000) NULL,
    Action        NVARCHAR(40)   NULL,                    -- Disable | Delete | Investigate | Remove from cloud sync
    ActionWho     NVARCHAR(200)  NULL,
    ActionStatus  NVARCHAR(20)   NULL,                    -- Not started | In progress | Closed
    UpdatedBy     NVARCHAR(320)  NULL,
    UpdatedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_IdentityAction_At DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_IdentityAction PRIMARY KEY (Kind, ObjectId)
);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 19)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (19, '2.0.30');

-- v20 (2.0.63, OPEN-01 / framework SUPPORT ACCESS): the support access level the support job (caj-eps-support, as the
-- database setup identity - the database owner) last read from Invardia ITSELF, and what it applied. NO product role has
-- any grant on it: the engine, the web app and the worker can neither raise nor lower support access through it.
IF OBJECT_ID('eps.SupportAccess') IS NULL
CREATE TABLE eps.SupportAccess (
    Id            INT            NOT NULL CONSTRAINT PK_SupportAccess PRIMARY KEY CONSTRAINT CK_SupportAccess_One CHECK (Id = 1),
    Level         NVARCHAR(20)   NOT NULL,                -- none | read | troubleshoot
    AppId         NVARCHAR(36)   NULL,                    -- the Support app's client id (lower case)
    SessionUntil  DATETIME2      NULL,                    -- admin until (an open session from Invardia), else NULL
    Applied       NVARCHAR(400)  NULL,                    -- what the last run did, in plain words
    CheckedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_SupportAccess_At DEFAULT SYSUTCDATETIME(),
    CONSTRAINT CK_SupportAccess_Level CHECK (Level IN ('none', 'read', 'troubleshoot'))
);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 20)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (20, '2.0.63');

-- v21 (2.0.73, OPEN-01 auto-check #4): what the support-access job READ BACK after it applied the level - the heartbeat
-- reports it (the engine may only read this table; only the job, as the database owner, writes it)
IF COL_LENGTH('eps.SupportAccess', 'ReadUser') IS NULL ALTER TABLE eps.SupportAccess ADD ReadUser BIT NULL;
IF COL_LENGTH('eps.SupportAccess', 'AdminNow') IS NULL ALTER TABLE eps.SupportAccess ADD AdminNow BIT NULL;

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 21)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (21, '2.0.73');

-- v22 (2.0.81, CA-GROUPS - owner 2026-11-05: "make sure to also include the underlying groups that must be provisioned
-- and managed"): the groups (and administrative units, Name 'au:<name>') Entra Policy Suite manages, as the engine last
-- read them in the tenant. The engine writes it (a read, a group change); the web app shows it.
IF OBJECT_ID('eps.ManagedGroup') IS NULL
CREATE TABLE eps.ManagedGroup (
    Name          NVARCHAR(300)  NOT NULL CONSTRAINT PK_ManagedGroup PRIMARY KEY,
    ObjectId      NVARCHAR(64)   NULL,
    Found         BIT            NULL,                    -- NULL = could not be read
    Dynamic       BIT            NULL,
    RuleInTenant  NVARCHAR(MAX)  NULL,
    Processing    NVARCHAR(20)   NULL,                    -- On | Paused
    Members       INT            NULL,
    AdminUnit     NVARCHAR(256)  NULL,                    -- the unit it is in ('' none, NULL not readable)
    Error         NVARCHAR(400)  NULL,
    CheckedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_ManagedGroup_At DEFAULT SYSUTCDATETIME()
);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 22)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (22, '2.0.81');

-- v23 (2.0.82, CA-TEMPLATES - owner 2026-11-05: Templates "Side-by-side only"; V1-PARITY P5 / P6): a new template version
-- tested NEXT TO the policy it replaces (v1's Install_Latest_Policy_Disabled), then promoted (the new one to Prod, the old
-- one off and kept), rolled back (the old one back as it was, the new one off) or the old one removed. One row per pair;
-- OldBeforeJson = the old policy's name, state and users as they were before the promote (what a roll back puts back).
-- The engine writes it from a SuperAdmin's signed request; the web app shows it on both policies' pages.
IF OBJECT_ID('eps.CaVersionPair') IS NULL
CREATE TABLE eps.CaVersionPair (
    PairId        BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_CaVersionPair PRIMARY KEY,
    TemplateId    NVARCHAR(20)   NOT NULL,
    OldPolicyId   UNIQUEIDENTIFIER NOT NULL,
    NewPolicyId   UNIQUEIDENTIFIER NOT NULL,
    OldVersion    NVARCHAR(20)   NULL,
    NewVersion    NVARCHAR(20)   NOT NULL,
    Status        NVARCHAR(12)   NOT NULL,                -- Testing | Promoted | RolledBack | Removed
    OldBeforeJson NVARCHAR(MAX)  NULL,
    CreatedBy     NVARCHAR(320)  NOT NULL,
    CreatedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_CaVersionPair_At DEFAULT SYSUTCDATETIME(),
    ChangedBy     NVARCHAR(320)  NULL,
    ChangedAtUtc  DATETIME2      NULL,
    Reason        NVARCHAR(2000) NULL,
    CONSTRAINT CK_CaVersionPair_Status CHECK (Status IN ('Testing', 'Promoted', 'RolledBack', 'Removed'))
);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 23)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (23, '2.0.82');

GO
-- v24 (2.0.82, WORKER-GUI - owner 2026-11-05: "i didnt see the ad hybrid worker anywhere in the gui or where to configure
-- it or see the services" / "is that not built"; V1-PARITY P14 several AD environments): the worker reports its scheduled
-- task (state, on / off, last / next run, last result), its AD domain + domain controller and its AD environment; a work
-- package carries the AD environment it is for (NULL = any worker) and the answer of a read-only connection test.
IF COL_LENGTH('eps.WorkerHeartbeat', 'AdDomain') IS NULL
ALTER TABLE eps.WorkerHeartbeat ADD
    AdDomain       NVARCHAR(256) NULL,              -- the domain the worker reads / writes (from RootDSE)
    AdServer       NVARCHAR(256) NULL,              -- the domain controller it used
    Environment    NVARCHAR(50)  NULL,              -- its AD environment (v1: Internal_Prod / DMZ_Prod / ...), NULL = the only one
    HostType       NVARCHAR(20)  NULL,              -- AzureVm | Arc
    TaskState      NVARCHAR(20)  NULL,              -- the scheduled task as the worker read it: Ready | Running | Disabled | Queued | Unknown
    TaskEnabled    BIT           NULL,
    TaskLastRunUtc DATETIME2     NULL,
    TaskLastResult NVARCHAR(40)  NULL,              -- the previous run's result code (0x0 = ok)
    TaskNextRunUtc DATETIME2     NULL;
IF COL_LENGTH('eps.WorkPackage', 'Environment') IS NULL
ALTER TABLE eps.WorkPackage ADD
    Environment    NVARCHAR(50)   NULL,             -- the AD environment the package is for; NULL = any worker
    Result         NVARCHAR(2000) NULL,             -- what the worker answered (a connection test)
    RequestedBy    NVARCHAR(320)  NULL;             -- a person's test or retry (the tagging job leaves it empty)

GO
IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 24)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (24, '2.0.82');

-- v25 (2.0.82, UNDO-BACKUP - owner 2026-11-05: "i need to have both a new feature Undo + another new feature
-- backup/restore. look at how PIM does it"; "it must work for both ca policies + tagging so i can recover"; "ok go with
-- daily keep 30"; V1-PARITY P10 = v1's JSON export of every CA policy): immutable backup sets. A CA set holds every
-- policy (adopted or not), named location and authentication strength as read (one row each, v1's JSON); a configuration
-- set holds the tagging configuration (rules as this app's CSV, tag types, values, condition types, scopes) and the
-- non-secret settings. Kind: Daily (the Backup job, the newest 30 kept), BeforeChange (taken by the engine BEFORE each of
-- its CA writes / before each commit - kept 30 days), Manual ("Back up now", kept 30 days). Nothing ever UPDATEs a set:
-- the engine inserts and prunes, the web app reads.
IF OBJECT_ID('eps.CaBackup') IS NULL
CREATE TABLE eps.CaBackup (
    BackupId       BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_CaBackup PRIMARY KEY,
    Kind           NVARCHAR(16)   NOT NULL,
    TakenAtUtc     DATETIME2      NOT NULL CONSTRAINT DF_CaBackup_At DEFAULT SYSUTCDATETIME(),
    TakenBy        NVARCHAR(320)  NOT NULL,
    Cause          NVARCHAR(400)  NULL,
    Policies       INT            NOT NULL CONSTRAINT DF_CaBackup_P DEFAULT 0,
    NamedLocations INT            NOT NULL CONSTRAINT DF_CaBackup_N DEFAULT 0,
    AuthStrengths  INT            NOT NULL CONSTRAINT DF_CaBackup_A DEFAULT 0,
    CONSTRAINT CK_CaBackup_Kind CHECK (Kind IN ('Daily', 'BeforeChange', 'Manual'))
);
IF OBJECT_ID('eps.CaBackupItem') IS NULL
CREATE TABLE eps.CaBackupItem (
    BackupId       BIGINT         NOT NULL CONSTRAINT FK_CaBackupItem_Set REFERENCES eps.CaBackup (BackupId),
    ItemType       NVARCHAR(20)   NOT NULL,
    ObjectId       NVARCHAR(64)   NOT NULL,
    DisplayName    NVARCHAR(400)  NULL,
    BodyJson       NVARCHAR(MAX)  NOT NULL,
    CONSTRAINT PK_CaBackupItem PRIMARY KEY (BackupId, ItemType, ObjectId),
    CONSTRAINT CK_CaBackupItem_Type CHECK (ItemType IN ('policy', 'namedLocation', 'authStrength'))
);
IF OBJECT_ID('eps.ConfigBackup') IS NULL
CREATE TABLE eps.ConfigBackup (
    BackupId       BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ConfigBackup PRIMARY KEY,
    Kind           NVARCHAR(16)   NOT NULL,
    TakenAtUtc     DATETIME2      NOT NULL CONSTRAINT DF_ConfigBackup_At DEFAULT SYSUTCDATETIME(),
    TakenBy        NVARCHAR(320)  NOT NULL,
    Cause          NVARCHAR(400)  NULL,
    RefId          NVARCHAR(64)   NULL,                    -- the commit it was taken before
    CountsJson     NVARCHAR(MAX)  NULL,
    CONSTRAINT CK_ConfigBackup_Kind CHECK (Kind IN ('Daily', 'BeforeChange', 'Manual'))
);
IF OBJECT_ID('eps.ConfigBackupItem') IS NULL
CREATE TABLE eps.ConfigBackupItem (
    BackupId       BIGINT         NOT NULL CONSTRAINT FK_ConfigBackupItem_Set REFERENCES eps.ConfigBackup (BackupId),
    Entity         NVARCHAR(40)   NOT NULL,               -- Setting | TagType | TagValue | ConditionType | Scope | Rules
    ItemKey        NVARCHAR(400)  NOT NULL,
    BodyJson       NVARCHAR(MAX)  NOT NULL,
    CONSTRAINT PK_ConfigBackupItem PRIMARY KEY (BackupId, Entity, ItemKey)
);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 25)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (25, '2.0.82');
GO
-- v26 (V1-PARITY P11, owner 2026-11-05 "solution must be min 1:1 on pair with the old eps script solution"): per identity
-- report run, what went to Log Analytics (v1's EntraUsersMetadata_CL) and v1's exposure lists read back from it - written
-- by the engine after the run, shown on the Identity page; it goes with its snapshot
IF OBJECT_ID('eps.IdentityLaRun') IS NULL
CREATE TABLE eps.IdentityLaRun (
    RunId          UNIQUEIDENTIFIER NOT NULL PRIMARY KEY REFERENCES eps.IdentitySnapshot (RunId) ON DELETE CASCADE,
    CheckedAtUtc   DATETIME2      NOT NULL,
    UploadRows     INT            NOT NULL,             -- the report's users
    UploadSent     INT            NOT NULL,             -- taken by the Logs Ingestion API
    UploadOk       BIT            NOT NULL,
    UploadText     NVARCHAR(2000) NULL,                 -- what happened, in words
    TablesJson     NVARCHAR(400)  NULL,                 -- the tables with data in 90 days (the sign-in logs?)
    ExposureJson   NVARCHAR(MAX)  NULL,                 -- the eight lists: [{ name, set, count, truncated, columns, rows, error }]
    Note           NVARCHAR(2000) NULL                  -- why a list could not be built
);
GO
IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 26)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (26, '2.0.83');
GO
-- v30 (2.0.83, GROUPS-ACTIONS - owner 2026-11-05: "should i see buttn here like edit so i can modify a group dynamic
-- membership or create or validate etc"): a dynamic group's rule the OPERATOR set on Conditional Access > Groups (Edit
-- rule). It is this install's rule for that group: "Set rule", the group force update and a stage move keep it (a pilot
-- group's custom rule is its Pilot1 base, widened per stage) until the operator picks "back to v1's rule" (the row goes).
-- The engine writes it with the group change; the web app shows it.
IF OBJECT_ID('eps.GroupRuleOverride') IS NULL
CREATE TABLE eps.GroupRuleOverride (
    Name           NVARCHAR(300)  NOT NULL CONSTRAINT PK_GroupRuleOverride PRIMARY KEY,
    MembershipRule NVARCHAR(MAX)  NOT NULL,
    SetBy          NVARCHAR(256)  NOT NULL,
    Reason         NVARCHAR(1000) NULL,
    SetAtUtc       DATETIME2      NOT NULL CONSTRAINT DF_GroupRuleOverride_At DEFAULT SYSUTCDATETIME()
);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 30)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (30, '2.0.83');

-- ---- version 31: CA-EDIT-PICKERS (owner 2026-11-05: "talk with graph to understand the optins per field" / "consider a
-- discovery process monthly to get available options per field via graph"): the options per Conditional Access policy
-- field as the monthly CaOptions job discovered them - the enum members from Graph v1.0's $metadata (Source = metadata)
-- and the tenant's lists (Source = tenant: authentication strengths, named locations, terms of use, role definitions;
-- Value = the object's id, Label = its name). The Edit form offers these; the shipped engine/ca/graph-enums.json is the
-- fall-back while the table is empty. Written by the engine only; the web app reads it.
IF OBJECT_ID('eps.CaGraphOption') IS NULL
CREATE TABLE eps.CaGraphOption (
    Field          NVARCHAR(200)  NOT NULL,                -- conditions.clientAppTypes | tenant.authStrength | ...
    Value          NVARCHAR(200)  NOT NULL,
    Label          NVARCHAR(400)  NULL,
    Detail         NVARCHAR(400)  NULL,                    -- a strength's type (builtIn / custom), a location's kind
    Source         NVARCHAR(20)   NOT NULL,                -- metadata | tenant
    InCatalog      BIT            NOT NULL CONSTRAINT DF_CaGraphOption_InCat DEFAULT 0,   -- 0 = new from Graph (not in the shipped catalog)
    FirstSeenUtc   DATETIME2      NOT NULL CONSTRAINT DF_CaGraphOption_First DEFAULT SYSUTCDATETIME(),
    LastSeenUtc    DATETIME2      NOT NULL CONSTRAINT DF_CaGraphOption_Last DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_CaGraphOption PRIMARY KEY (Field, Value),
    CONSTRAINT CK_CaGraphOption_Source CHECK (Source IN ('metadata', 'tenant'))
);

IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 31)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (31, '2.0.83');
GO
-- v27 (2.0.83, SQL-STATS - framework §12.27; found by SI 2026-11-05: views took 1-2 min with the right indexes because
-- statistics were stale and AUTO_UPDATE_STATISTICS_ASYNC was OFF, so the first read after a big write rebuilt them
-- synchronously inside the user's request). (1) statistics are rebuilt in the BACKGROUND: the database setting, set once,
-- in its own batch (ALTER DATABASE cannot run in a transaction) by the identity that applies this file (the database
-- setup job, a member of the server's admin group - never a component).
IF (SELECT is_auto_update_stats_async_on FROM sys.databases WHERE database_id = DB_ID()) = 0
    ALTER DATABASE CURRENT SET AUTO_UPDATE_STATISTICS_ASYNC ON;
GO
-- (2) after a bulk write the engine refreshes what that write made stale: ONE procedure, EXECUTE AS OWNER, so the engine
-- holds EXECUTE on it and never ALTER on a table. Only statistics whose modifications pass 20 % of the rows + 500,
-- SAMPLED (the default sample, never FULLSCAN), at most @MaxStats per call and @MaxSeconds in all; it changes no data.
-- Returns one row per statistic it looked at: TableName, StatName, RowCnt, Mods, Result ('updated' or the error).
CREATE OR ALTER PROCEDURE eps.RefreshChangedStats @MaxStats INT = 40, @MaxSeconds INT = 120
WITH EXECUTE AS OWNER
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @t0 DATETIME2 = SYSUTCDATETIME(), @sql NVARCHAR(600), @tbl SYSNAME, @st SYSNAME, @rows BIGINT, @mods BIGINT;
    DECLARE @out TABLE (TableName SYSNAME, StatName SYSNAME, RowCnt BIGINT, Mods BIGINT, Result NVARCHAR(400));
    IF @MaxStats IS NULL OR @MaxStats < 1 OR @MaxStats > 200 SET @MaxStats = 40;
    IF @MaxSeconds IS NULL OR @MaxSeconds < 5 OR @MaxSeconds > 900 SET @MaxSeconds = 120;
    DECLARE c CURSOR LOCAL FAST_FORWARD FOR
        SELECT TOP (@MaxStats) o.name, s.name, sp.rows, sp.modification_counter
        FROM sys.stats s
        JOIN sys.objects o ON o.object_id = s.object_id AND o.type = 'U' AND o.schema_id = SCHEMA_ID('eps')
        CROSS APPLY sys.dm_db_stats_properties(s.object_id, s.stats_id) sp
        WHERE sp.modification_counter > 0.2 * sp.rows + 500
        ORDER BY sp.modification_counter DESC;
    OPEN c;
    FETCH NEXT FROM c INTO @tbl, @st, @rows, @mods;
    WHILE @@FETCH_STATUS = 0 AND DATEDIFF(SECOND, @t0, SYSUTCDATETIME()) < @MaxSeconds
    BEGIN
        SET @sql = N'UPDATE STATISTICS eps.' + QUOTENAME(@tbl) + N' ' + QUOTENAME(@st) + N';';
        BEGIN TRY
            EXEC sys.sp_executesql @sql;
            INSERT INTO @out VALUES (@tbl, @st, @rows, @mods, N'updated');
        END TRY
        BEGIN CATCH
            INSERT INTO @out VALUES (@tbl, @st, @rows, @mods, LEFT(ERROR_MESSAGE(), 400));
        END CATCH
        FETCH NEXT FROM c INTO @tbl, @st, @rows, @mods;
    END
    CLOSE c; DEALLOCATE c;
    SELECT TableName, StatName, RowCnt, Mods, Result FROM @out;
END
GO
IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 27)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (27, '2.0.83');

-- v32 (RULES-MATCHED, owner 2026-11-03: "maybe give more context here which users are in scope like a list" / "a button
-- with more context"): WHO each tagging rule decided in a run (changed or already right) - at most 10,000 per rule and
-- run (the run's Matched count stays exact), written by the tagging job, read by the Rules page's Matched button; the
-- lists of older runs are dropped by the job (no foreign key: a run row can go without its list)
IF OBJECT_ID('eps.TagRuleHit') IS NULL
CREATE TABLE eps.TagRuleHit (
    RunId         UNIQUEIDENTIFIER NOT NULL,
    ObjectType    NVARCHAR(10)   NOT NULL,
    RuleId        INT            NOT NULL,
    ObjectId      UNIQUEIDENTIFIER NOT NULL,
    ObjectName    NVARCHAR(400)  NULL,
    TagType       NVARCHAR(60)   NOT NULL,
    Value         NVARCHAR(1024) NULL,                   -- what the rule set
    CurrentValue  NVARCHAR(1024) NULL,                   -- what the object had when the run read it
    Changed       BIT            NOT NULL
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_TagRuleHit_RunRule')
CREATE CLUSTERED INDEX IX_TagRuleHit_RunRule ON eps.TagRuleHit (RunId, RuleId, ObjectName);
GO
IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 32)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (32, '2.0.83');

-- v33 (INSTALL-PRO, Invardia GO 2026-11-05; the owner: "it must be on par with other 2"): THE install's Pro licence - one
-- row, the licence FILE text as Invardia signed it (verified on every read, never trusted as stored). Framework §12.25:
-- written ONLY by the update job (it knocks, pulls, verifies, then stores it in the install's Key Vault AND here); no person
-- pastes or uploads a licence. Also the knock / pull state (shown on the Licence page) and the install-key claim's state
-- (LIC-01: claimed / refused with Invardia's reason / retry; a refused claim is not asked again until the licence changes -
-- ClaimLicenceHash - or "Claim again"). The web app reads it and may only clear the claim / a rejected request. No secret
-- here: the install key goes to the install's Key Vault (uplink-key); the pull token to eps.LicensePull (engine only).
IF OBJECT_ID('eps.License') IS NULL
CREATE TABLE eps.License (
    Id               INT            NOT NULL CONSTRAINT PK_Licence PRIMARY KEY CONSTRAINT CK_Licence_One CHECK (Id = 1),
    LicenceText      NVARCHAR(MAX)  NULL,
    SetBy            NVARCHAR(256)  NULL,
    SetAtUtc         DATETIME2      NULL,
    ClaimAction      NVARCHAR(20)   NULL,
    ClaimMessage     NVARCHAR(1000) NULL,
    ClaimAtUtc       DATETIME2      NULL,
    ClaimLicenceHash NVARCHAR(64)   NULL,
    RequestStatus    NVARCHAR(20)   NULL,     -- Pending | Rejected | Installed | Expired | Error
    RequestMessage   NVARCHAR(1000) NULL,
    RequestId        NVARCHAR(100)  NULL,
    RequestAtUtc     DATETIME2      NULL,
    NextPollUtc      DATETIME2      NULL,
    SupersededBy     NVARCHAR(100)  NULL,     -- the heartbeat answer's supersededBy (a licence id): the update job knocks for the successor
    UsersInScope     INT            NULL,     -- the Business cap: users in scope at the last user tagging run
    UsageState       NVARCHAR(10)   NULL      -- none | ok | warn | at | over (a warning only; nothing ever stops)
);
GO
IF OBJECT_ID('eps.LicensePull') IS NULL
CREATE TABLE eps.LicensePull (
    Id           INT            NOT NULL CONSTRAINT PK_LicencePull PRIMARY KEY CONSTRAINT CK_LicencePull_One CHECK (Id = 1),
    PullToken    NVARCHAR(400)  NULL,
    InstallId    NVARCHAR(36)   NULL,         -- the install's lasting id (INV-S16): created once, kept
    UpdatedAtUtc DATETIME2      NOT NULL CONSTRAINT DF_LicencePull_At DEFAULT SYSUTCDATETIME()
);
GO
IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 33)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (33, '2.0.86');

-- v34 (EPS PRO, 2026-11-05 - Pro features, read and written only when a Pro licence enables them; DESIGN §12):
-- 'passkey-tracker': a target date and an owner (the digest's recipient) per persona, and the daily count per persona
IF OBJECT_ID('eps.ProPasskeyTarget') IS NULL
CREATE TABLE eps.ProPasskeyTarget (
    Persona       NVARCHAR(200)  NOT NULL PRIMARY KEY,
    TargetDate    DATE           NULL,
    Owner         NVARCHAR(320)  NULL,                   -- who gets the digest (ProPasskey.DigestEnabled)
    LastDigestUtc DATETIME2      NULL,
    UpdatedBy     NVARCHAR(320)  NOT NULL,
    UpdatedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_ProPasskeyTarget_At DEFAULT SYSUTCDATETIME()
);
IF OBJECT_ID('eps.ProPasskeyProgress') IS NULL
CREATE TABLE eps.ProPasskeyProgress (
    Day           DATE           NOT NULL,
    Persona       NVARCHAR(200)  NOT NULL,
    Users         INT            NOT NULL,
    Ready         INT            NOT NULL,
    AtUtc         DATETIME2      NOT NULL CONSTRAINT DF_ProPasskeyProgress_At DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_ProPasskeyProgress PRIMARY KEY (Day, Persona)
);
-- 'stale-identities': an Admin's review of one account (keep / disable, why), the SuperAdmin's approval and what the
-- engine did (disabled / reenabled / failed) - the undo reads it
IF OBJECT_ID('eps.ProStaleDecision') IS NULL
CREATE TABLE eps.ProStaleDecision (
    ObjectId      NVARCHAR(64)   NOT NULL PRIMARY KEY,
    Upn           NVARCHAR(320)  NULL,
    Decision      NVARCHAR(10)   NOT NULL,               -- keep | disable
    Reason        NVARCHAR(1000) NOT NULL,
    DecidedBy     NVARCHAR(320)  NOT NULL,
    DecidedAtUtc  DATETIME2      NOT NULL CONSTRAINT DF_ProStaleDecision_At DEFAULT SYSUTCDATETIME(),
    Status        NVARCHAR(20)   NOT NULL,               -- marked | disabled | reenabled | failed
    ApprovedBy    NVARCHAR(320)  NULL,
    ApprovedAtUtc DATETIME2      NULL,
    ResultText    NVARCHAR(1000) NULL,
    DoneAtUtc     DATETIME2      NULL,
    CONSTRAINT CK_ProStaleDecision_Decision CHECK (Decision IN ('keep', 'disable')),
    CONSTRAINT CK_ProStaleDecision_Status CHECK (Status IN ('marked', 'disabled', 'reenabled', 'failed'))
);
GO
IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 34)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (34, '2.0.86');
-- ---- version 35: EPS Pro - license optimization + policy as code (owner 2026-11-05: "continue build all pending incl pro
-- features"; Invardia: every existing feature stays Community, these are Pro - gated by the license) -------------------
-- eps.ProLicensePrice: the customer's own price per license (SKU part number), EUR per user per month - seeded once with a
-- starting point the customer edits; never fetched. Read by the license optimization page to price a saving.
IF OBJECT_ID('eps.ProLicensePrice') IS NULL
CREATE TABLE eps.ProLicensePrice (
    SkuPartNumber  NVARCHAR(100)  NOT NULL CONSTRAINT PK_ProLicensePrice PRIMARY KEY,
    Name           NVARCHAR(200)  NULL,
    MonthlyEur     DECIMAL(10, 2) NOT NULL,
    Source         NVARCHAR(20)   NOT NULL CONSTRAINT DF_ProLicensePrice_Src DEFAULT 'customer',   -- seed | customer
    UpdatedBy      NVARCHAR(320)  NULL,
    UpdatedAtUtc   DATETIME2      NOT NULL CONSTRAINT DF_ProLicensePrice_At DEFAULT SYSUTCDATETIME(),
    CONSTRAINT CK_ProLicensePrice_Src CHECK (Source IN ('seed', 'customer')),
    CONSTRAINT CK_ProLicensePrice_Eur CHECK (MonthlyEur >= 0)
);
GO
IF NOT EXISTS (SELECT 1 FROM eps.ProLicensePrice)
INSERT INTO eps.ProLicensePrice (SkuPartNumber, Name, MonthlyEur, Source) VALUES
 ('SPE_E5', 'Microsoft 365 E5', 54.75, 'seed'), ('SPE_E3', 'Microsoft 365 E3', 33.75, 'seed'),
 ('ENTERPRISEPREMIUM', 'Office 365 E5', 35.70, 'seed'), ('ENTERPRISEPACK', 'Office 365 E3', 21.80, 'seed'),
 ('STANDARDPACK', 'Office 365 E1', 9.40, 'seed'), ('SPB', 'Microsoft 365 Business Premium', 20.60, 'seed'),
 ('O365_BUSINESS_PREMIUM', 'Microsoft 365 Business Standard', 11.70, 'seed'), ('O365_BUSINESS_ESSENTIALS', 'Microsoft 365 Business Basic', 5.60, 'seed'),
 ('EMSPREMIUM', 'Enterprise Mobility + Security E5', 15.40, 'seed'), ('EMS', 'Enterprise Mobility + Security E3', 9.90, 'seed'),
 ('AAD_PREMIUM', 'Microsoft Entra ID P1', 5.60, 'seed'), ('AAD_PREMIUM_P2', 'Microsoft Entra ID P2', 8.40, 'seed'),
 ('INTUNE_A', 'Microsoft Intune Plan 1', 7.50, 'seed'), ('EXCHANGESTANDARD', 'Exchange Online (Plan 1)', 3.70, 'seed'),
 ('EXCHANGEENTERPRISE', 'Exchange Online (Plan 2)', 7.50, 'seed'), ('ATP_ENTERPRISE', 'Defender for Office 365 (Plan 1)', 1.90, 'seed'),
 ('THREAT_INTELLIGENCE', 'Defender for Office 365 (Plan 2)', 4.70, 'seed');
GO
-- eps.ProPolicyCodeSync: each push to / read from the customer's Git repository (policy as code) - what, when, which commit.
-- The Git access key is NEVER here: it is a Key Vault secret the engine reads at the call.
IF OBJECT_ID('eps.ProPolicyCodeSync') IS NULL
CREATE TABLE eps.ProPolicyCodeSync (
    SyncId         BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_ProPolicyCodeSync PRIMARY KEY,
    Kind           NVARCHAR(10)   NOT NULL,                -- push | import
    AtUtc          DATETIME2      NOT NULL CONSTRAINT DF_ProPolicyCodeSync_At DEFAULT SYSUTCDATETIME(),
    RequestedBy    NVARCHAR(320)  NOT NULL,
    Provider       NVARCHAR(20)   NOT NULL,                -- github | azuredevops
    Repository     NVARCHAR(300)  NOT NULL,
    Ref            NVARCHAR(200)  NULL,                    -- the branch / tag / commit asked for
    CommitSha      NVARCHAR(64)   NULL,                    -- the commit written / read
    Files          INT            NOT NULL CONSTRAINT DF_ProPolicyCodeSync_F DEFAULT 0,
    -- an import: the CA backup set it was stored as (Kind Manual, so the EXISTING restore path - plan, break-glass check,
    -- a backup first, ONE write per policy, a new policy created OFF, never a delete - applies it); this link is what
    -- marks a set as read from Git
    BackupId       BIGINT         NULL,
    Result         NVARCHAR(20)   NOT NULL,                -- ok | failed
    ResultText     NVARCHAR(2000) NULL,
    CONSTRAINT CK_ProPolicyCodeSync_Kind CHECK (Kind IN ('push', 'import'))
);
GO
IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 35)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (35, '2.0.86');

GO
-- v36 (2.0.102, WORKER-UPD - framework §5.5, Invardia 2026-11-08): the hybrid worker updates itself once a day (a task as
-- SYSTEM, Invardia's signed Community release of the version this install runs) and reports the outcome here - the page
-- and the support read show it beside the worker's heartbeat.
IF COL_LENGTH('eps.WorkerHeartbeat', 'UpdateResult') IS NULL
ALTER TABLE eps.WorkerHeartbeat ADD
    UpdateResult   NVARCHAR(1000) NULL,             -- the last daily update: updated | current | waiting | refused | switched back | failed + why
    UpdateAtUtc    DATETIME2      NULL;
GO
IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 36)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (36, '2.0.102');

GO
-- v37 (2.0.115, the per-user sign-in methods - SecurityInsight's design; owner 2026-11-09 "Both, as SI (Recommended)" /
-- "remember to do the cachin"): one row per user - the change key the identity report saw (CurrentStamp / CurrentHash),
-- the key its detail was read under (ReadStamp / ReadHash), when it was read and tried, and the detail (JSON:
-- every method, the device behind WHfB / Authenticator, a phone number masked). The SignInMethods job fills it; the
-- report only writes the current key and reads the detail.
IF OBJECT_ID('eps.UserSignInMethods') IS NULL
CREATE TABLE eps.UserSignInMethods (
    UserId         NVARCHAR(64)   NOT NULL PRIMARY KEY,   -- the Entra object id, lower case
    Upn            NVARCHAR(320)  NULL,
    Privileged     BIT            NOT NULL CONSTRAINT DF_UserSignInMethods_Priv DEFAULT 0,
    CurrentStamp   NVARCHAR(64)   NULL,                   -- the registration report's lastUpdatedDateTime (as the report saw it)
    CurrentHash    NVARCHAR(64)   NULL,                   -- SHA-256 of its registered methods (lower case, sorted, once each)
    ReadStamp      NVARCHAR(64)   NULL,                   -- the key the detail was read under
    ReadHash       NVARCHAR(64)   NULL,
    ReadAtUtc      DATETIME2      NULL,                   -- NULL = never read: unknown, never "no MFA"
    LastTryAtUtc   DATETIME2      NULL,                   -- a user tried in the last 10 minutes is not picked again
    SeenAtUtc      DATETIME2      NOT NULL,               -- the last identity report that listed the user
    DevicesRead    BIT            NULL,
    Detail         NVARCHAR(MAX)  NULL,                   -- JSON: every method, the device behind WHfB / Authenticator
    Error          NVARCHAR(1000) NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_UserSignInMethods_Pick' AND object_id = OBJECT_ID('eps.UserSignInMethods'))
CREATE INDEX IX_UserSignInMethods_Pick ON eps.UserSignInMethods (Privileged DESC, ReadAtUtc, LastTryAtUtc) INCLUDE (SeenAtUtc, CurrentStamp, CurrentHash, ReadStamp, ReadHash, DevicesRead);
GO
IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 37)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (37, '2.0.115');
GO
-- STALL-1 (framework 8.18, owner via Invardia 2026-11-10: a hanging job at a customer was not detected): a run that
-- keeps going without progress is caught. The job's watchdog (EPS-Watchdog.ps1) writes how many SQL statements and Graph
-- pages the run has finished (Progress) and when that number last moved (ProgressAtUtc); NULL = no watchdog (older image).
IF COL_LENGTH('eps.Run', 'Progress') IS NULL ALTER TABLE eps.Run ADD Progress BIGINT NULL;
IF COL_LENGTH('eps.Run', 'ProgressAtUtc') IS NULL ALTER TABLE eps.Run ADD ProgressAtUtc DATETIME2 NULL;
GO
IF NOT EXISTS (SELECT 1 FROM eps.SchemaVersion WHERE Version = 38)
INSERT INTO eps.SchemaVersion (Version, ProductVersion) VALUES (38, '2.0.122');
