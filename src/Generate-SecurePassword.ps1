Function Generate-SecurePassword {
    param (
        [int]$length = 16
    )
    # Define the characters to use in the password
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+[]{}|;:,.<>?'
    # Generate the password
    $password = -join ((1..$length) | ForEach-Object { $characters[(Get-Random -Maximum $characters.Length)] })
    return $password
}
