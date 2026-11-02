# EntraPolicySuite -- the fast path of the rule engine (owner 2026-10-29: "we cannot run it on 200000 users").
# At 200,000 users x ~120 rules the PowerShell condition loop is ~24 million interpreted checks a run. This compiles the
# PROPERTY conditions of every card once (C#, Add-Type - in-box in pwsh, no module) and, per object, returns the
# cards whose property conditions ALL pass, in card order. The engine then walks only those candidates and evaluates
# what is left (module conditions: groups, Exchange, licences) and First / Last / Multiple exactly as before.
#
# Same semantics as Test-EpsCondition, by construction: PowerShell's own WildcardPattern (what -like uses),
# LanguagePrimitives.IsTrue (what [bool] does), OrdinalIgnoreCase for -eq / -contains on strings, and v1's guards
# (notNull / notEmpty / emptyMatches). Test-EpsFastEval.ps1 runs every catalog condition through both paths and
# fails on any difference.

Set-StrictMode -Off

if (-not ('Eps.FastEval' -as [type])) {
    # no -ReferencedAssemblies: it REPLACES pwsh's defaults (System.Collections went missing); the defaults already
    # include System.Management.Automation
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;

namespace Eps {
    public sealed class Cond {
        public string[] Path; public int Op; public int Guard; public string Target; public WildcardPattern Wild; public bool TargetTrue; public bool TargetFalse;
    }
    public sealed class Card {
        public Cond[] Conds; public bool Impossible;   // Impossible = an unknown condition type: never matches (v1)
    }
    public static class FastEval {
        // ops: 0 like, 1 notlike, 2 equals, 3 boolMatch, 4 boolEquals, 5 contains, 6 notcontains
        // guards: 0 none, 1 notNull, 2 notEmpty, 3 emptyMatches
        public static object Get(object o, string[] path) {
            object cur = o;
            foreach (var part in path) {
                if (cur == null) return null;
                var pso = cur as PSObject;
                object b = pso != null ? pso.BaseObject : cur;
                var d = b as IDictionary;
                if (d != null) {
                    if (d.Contains(part)) { cur = d[part]; continue; }
                    object hit = null; bool found = false;
                    foreach (DictionaryEntry e in d) { if (string.Equals(e.Key as string, part, StringComparison.OrdinalIgnoreCase)) { hit = e.Value; found = true; break; } }
                    if (!found) return null;
                    cur = hit; continue;
                }
                if (pso == null) pso = PSObject.AsPSObject(cur);
                var p = pso.Properties[part];
                if (p == null) return null;
                cur = p.Value;
            }
            var r = cur as PSObject;
            return (r != null && !(r.BaseObject is PSCustomObject)) ? r.BaseObject : cur;
        }
        static string Str(object raw) {
            if (raw == null) return "";
            var e = raw as IEnumerable;
            if (e != null && !(raw is string)) { return LanguagePrimitives.ConvertTo<string>(raw); }
            return raw.ToString();
        }
        // PowerShell's -contains: -eq per element, and -eq converts the target to the ELEMENT's type ($true -eq 'a*' is
        // $true: a non-empty string is $true) - so PowerShell's own comparer, case-insensitive, invariant culture
        static bool Eq(object element, string target) {
            if (element == null) return false;
            try { return LanguagePrimitives.Equals(element, target, true, System.Globalization.CultureInfo.InvariantCulture); }
            catch { return false; }
        }
        static bool Contains(object raw, string target) {
            if (raw == null) return false;
            var e = raw as IEnumerable;
            if (e == null || raw is string) return Eq(raw, target);
            foreach (var x in e) {
                object v = x is PSObject ? ((PSObject)x).BaseObject : x;
                if (Eq(v, target)) return true;
            }
            return false;
        }
        public static bool Test(Cond c, object obj) {
            object raw = Get(obj, c.Path);
            string s = Str(raw);
            switch (c.Guard) {
                case 1: if (raw == null) return false; break;
                case 2: if (s.Length == 0) return false; break;
                case 3: if (s.Length == 0) return true; break;
            }
            switch (c.Op) {
                case 0: return c.Wild.IsMatch(s);
                case 1: return !c.Wild.IsMatch(s);
                case 2: return string.Equals(s, c.Target, StringComparison.OrdinalIgnoreCase);
                case 3: case 4: { bool t = LanguagePrimitives.IsTrue(raw); return (c.TargetTrue && t) || (c.TargetFalse && !t); }
                case 5: return Contains(raw, c.Target);
                case 6: return !Contains(raw, c.Target);
            }
            return false;
        }
        // the indexes of the cards whose property conditions all pass, in order
        public static int[] Candidates(object obj, Card[] cards) {
            var list = new List<int>();
            for (int i = 0; i < cards.Length; i++) {
                var card = cards[i];
                if (card.Impossible) continue;
                bool ok = true;
                foreach (var c in card.Conds) { if (!Test(c, obj)) { ok = false; break; } }
                if (ok) list.Add(i);
            }
            return list.ToArray();
        }
    }
}
'@
}

function New-EpsFastCards {
    # Compiles the cards' PROPERTY conditions. Returns @{ Cards = [Eps.Card[]] (index = card order); Rest = per card the
    # conditions PowerShell still evaluates (modules, and unknown types - reported Unavailable, never a match), in
    # their original order; LastIsRest = per card: is its LAST condition one of those? (v1: the Modified value comes
    # from the card's last condition, so a property condition after an Exchange one means no Modified value) }.
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Cards, [Parameter(Mandatory)][hashtable]$Catalog, [Parameter(Mandatory)][string]$ObjectType)
    $ops = @{ like = 0; notlike = 1; equals = 2; boolMatch = 3; boolEquals = 4; contains = 5; notcontains = 6 }
    $guards = @{ none = 0; notNull = 1; notEmpty = 2; emptyMatches = 3 }
    $fast = [Eps.Card[]]::new($Cards.Count); $rest = [object[]]::new($Cards.Count); $lastIsRest = [bool[]]::new($Cards.Count)
    for ($i = 0; $i -lt $Cards.Count; $i++) {
        $fc = [Eps.Card]::new(); $conds = [System.Collections.Generic.List[Eps.Cond]]::new(); $mods = [System.Collections.Generic.List[object]]::new()
        $lastIsRest[$i] = $false
        foreach ($k in $Cards[$i].Conditions) {
            $def = $Catalog["${ObjectType}:$($k.ConditionType)"]
            if (-not $def -or $def.Kind -eq 'Module') { $mods.Add(@{ Def = $def; ConditionType = [string]$k.ConditionType; Target = [string]$k.Target }); $lastIsRest[$i] = $true; continue }
            $lastIsRest[$i] = $false
            $t = [string]$k.Target
            $c = [Eps.Cond]::new()
            $c.Path = ([string]$def.Property).Split('.'); $c.Op = $ops[$def.Operator]; $c.Guard = $guards[$def.Guard]; $c.Target = $t
            if ($c.Op -le 1) { $c.Wild = [System.Management.Automation.WildcardPattern]::new($t, [System.Management.Automation.WildcardOptions]::IgnoreCase) }
            # v1: user conditions test the target with -match 'TRUE' / 'FALSE' (a case-insensitive regex = "contains"),
            # device conditions with -eq 'TRUE' / 'FALSE'
            if ($c.Op -eq 3) { $c.TargetTrue = $t -match 'TRUE'; $c.TargetFalse = $t -match 'FALSE' }
            if ($c.Op -eq 4) { $c.TargetTrue = $t -eq 'TRUE'; $c.TargetFalse = $t -eq 'FALSE' }
            $conds.Add($c)
        }
        if (@($Cards[$i].Conditions).Count -eq 0) { $fc.Impossible = $true }   # a card without conditions never matches
        $fc.Conds = $conds.ToArray(); $fast[$i] = $fc; $rest[$i] = $mods.ToArray()
    }
    @{ Cards = $fast; Rest = $rest; LastIsRest = $lastIsRest }
}
