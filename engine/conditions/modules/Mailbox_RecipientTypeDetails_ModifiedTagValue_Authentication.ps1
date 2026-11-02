# Condition module Mailbox_RecipientTypeDetails_ModifiedTagValue_Authentication. v1 1:1: met when the user has an Exchange
# recipient, and the rule's value is REPLACED by 'Exchange_<RecipientTypeDetails>_NoSignin' - the engine then inserts
# 'Cloud_' / 'AD_Synced_' after the first '_' (Exchange_Cloud_SharedMailbox...). The replacement counts only when this
# is the LAST condition of the rule, exactly as in v1 (the value of the last condition evaluated wins).
@{
    Id          = 'Mailbox_RecipientTypeDetails_ModifiedTagValue_Authentication'
    ObjectType  = 'User'
    Description = 'the user has an Exchange recipient; the Authentication value is built from its recipient type'
    Select      = @('id')
    Needs       = @('Mailboxes')
    ModifiesValue = $true
    Evaluate    = {
        param($Object, $Target, $Context)
        if ($null -eq $Context.Mailboxes) { return @{ Met = $false; Unavailable = 'Exchange recipients were not read' } }
        $rtd = $Context.Mailboxes[[string](Get-EpsValue $Object 'id')]
        if (-not $rtd) { return @{ Met = $false; Actual = 'no Exchange recipient' } }
        @{ Met = $true; Modified = 'Exchange_' + $rtd + '_NoSignin'; Actual = "RecipientTypeDetails is '$rtd'" }
    }
}
