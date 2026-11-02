# Condition module Mailbox_RecipientTypeDetails_NotLike. v1 1:1: the user has an Exchange recipient and its
# RecipientTypeDetails does not match the pattern (no recipient = no match). Exchange data comes from the Exchange Online admin
# REST API in one pass per run (DESIGN D6), keyed by the user's object id.
@{
    Id          = 'Mailbox_RecipientTypeDetails_NotLike'
    ObjectType  = 'User'
    Description = 'the Exchange recipient type does not match a pattern'
    Select      = @('id')
    Needs       = @('Mailboxes')
    Evaluate    = {
        param($Object, $Target, $Context)
        if ($null -eq $Context.Mailboxes) { return @{ Met = $false; Unavailable = 'Exchange recipients were not read' } }
        $rtd = $Context.Mailboxes[[string](Get-EpsValue $Object 'id')]
        if ($null -eq $rtd) { return @{ Met = $false; Actual = 'no Exchange recipient' } }
        @{ Met = [bool]($rtd -notlike "$Target"); Actual = "RecipientTypeDetails is '$rtd'" }
    }
}
