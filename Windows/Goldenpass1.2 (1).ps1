#--------------------------------------------------------------
# Golden Ticket Password Reset | AD Server
# Made by Logan Schultz
# Version | 1.2
#--------------------------------------------------------------

# Get Password last reset time
#--------------------------------------------------------------
Get-ADUser "Krbtgt" -Property PasswordLastSet

# Function to Generate a Random Password
#--------------------------------------------------------------
function Generate-RandomPassword {
    param (
        [int]$Length = 256 # Default password length set to 16
    )

    # Define the character set (letters, numbers, special characters)
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'

    # Generate the password by randomly selecting characters
    $password = -join ((1..$Length) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })

    return $password
}

# Function to Display Last Password Reset Time for Krbtgt
#--------------------------------------------------------------
function Show-LastPasswordReset {
    $user = Get-ADUser "Krbtgt" -Property PasswordLastSet
    Write-Output "Last password reset for Krbtgt: $($user.PasswordLastSet)"
}

# Generate and Set Password for Krbtgt
#--------------------------------------------------------------
function Reset-KrbtgtPassword {
    $newPassword = Generate-RandomPassword
    Write-Output "Generated New Password: $newPassword"
    Set-ADAccountPassword -Identity "Krbtgt" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force)
    Show-LastPasswordReset
}

# Main Execution Block
#--------------------------------------------------------------
Write-Output "Starting Krbtgt Password Reset Process..."

# Display Initial Last Reset Time
#--------------------------------------------------------------
Show-LastPasswordReset

# Reset Password Three Times
#--------------------------------------------------------------
Reset-KrbtgtPassword
Reset-KrbtgtPassword

Write-Output "Password Reset Process Completed."

# Get Password last reset time
#--------------------------------------------------------------
Get-ADUser "Krbtgt" -Property PasswordLastSet

