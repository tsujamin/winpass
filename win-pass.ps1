# Copyright (c) 2017 Benjamin George Roberts
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

class ShadowCredentialVault {


    hidden [byte[]] $MasterKey
    hidden [byte[]] $EncryptedMasterKey
    hidden [byte[]] $Salt
    hidden [byte[]] $DerivedKey
    hidden [byte[]] $EncrypredDerivedKey
    hidden [byte[]] $HashedDerivedKey # TODO Hash the user key or the master key? 
    hidden [byte[]] $MessageContent
    hidden [byte[]] $EncryptedMessageContent

    hidden static [int] $KeySizeBytes = 32
    hidden static [int] $HashSizeBytes = 32
    hidden static [int] $PBKDF2Iterations = 1000
    hidden static [byte[]] $IV = (New-Object byte[] 16)


    ShadowCredentialVault([byte[]] $MasterKey,
                          [byte[]] $EncryptedMasterKey,
                          [byte[]] $Salt,
                          [byte[]] $DerivedKey,
                          [byte[]] $EncrypredDerivedKey,
                          [byte[]] $HashedDerivedKey,
                          [byte[]] $EncryptedMessageContent) {
        $this.MasterKey = $MasterKey
        $this.EncryptedMasterKey = $EncryptedMasterKey
        $this.Salt = $Salt
        $this.DerivedKey = $DerivedKey
        $this.EncrypredDerivedKey = $EncrypredDerivedKey
        $this.HashedDerivedKey = $HashedDerivedKey
        $this.MessageContent = $null
        $this.EncryptedMessageContent = $EncryptedMessageContent
    }

    [bool] IsUnlocked() {
        return (-not (($this.MasterKey -eq $null) -and ($this.DerivedKey -eq $null)))
    }

    [bool] Unlock([string] $Passphrase) {
        # Don't unlock if masterkey already exists
        if ($this.IsUnlocked()) {
            return $true
        }

        # Get the Derived key and check it against the hash
        $PossibleDerivedKey = [ShadowCredentialVault]::GetDerivedKey($Passphrase, $this.Salt)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()

        if (-not ((Compare-Object $this.HashedDerivedKey $sha256.ComputeHash($PossibleDerivedKey)).length -eq 0)) {
            return $false
        }

        $this.DerivedKey = $PossibleDerivedKey

        # Decrypt the master key
        $aes = [System.Security.Cryptography.AesCng]::Create().CreateDecryptor($this.DerivedKey, [ShadowCredentialVault]::IV)
        $this.MasterKey = $aes.TransformFinalBlock($this.EncryptedMasterKey, 0, $this.EncryptedMasterKey.Length)

        return $true
    }

    [void] Lock() {
        $this.MasterKey = $null
        $this.DerivedKey = $null
        $this.MessageContent = $null
    }

    [bool] SaveContent() {
        # Can't encrypt if no keys available
        if (-not $this.IsUnlocked()) {
            return $false
        }

        $message = New-Object byte[] 0 # Placeholder for new vaults
        if (-not ($this.MessageContent -eq $null)) {
            $message = $this.MessageContent
        }

        # Build the encryptor and encrypt
        $aes = [System.Security.Cryptography.AesCng]::Create().CreateEncryptor($this.MasterKey, [ShadowCredentialVault]::IV)
        $this.EncryptedMessageContent = $aes.TransformFinalBlock($message, 0, $message.Length)

        return $true
    }

    [byte[]] GetContent() {
        # Return decrypted contents if able
        if (-not ($this.MessageContent -eq $null)) {
            return $this.MessageContent
        }

        if ($this.EncryptedMessageContent -eq $null) {
            $this.SaveContent() # Force the empty message contents to get saved
        }

        if (-not ($this.IsUnlocked())) {
            return $null
        }

        # Build the decryptor and decrypt
        $aes = [System.Security.Cryptography.AesCng]::Create().CreateDecryptor($this.MasterKey, [ShadowCredentialVault]::IV)
        $this.MessageContent = $aes.TransformFinalBlock($this.EncryptedMessageContent, 0, $this.EncryptedMessageContent.Length)

        return $this.MessageContent
    }

    [bool] SetContent([byte[]] $Content) {
        if (-not $this.IsUnlocked()) {
            return $false
        }

        $this.MessageContent = $Content

        return $true
    }

    [bool] ChangePassphrase([string] $Passphrase) {
        if (-not ($this.IsUnlocked())) {
            return $false
        }

        # Get the new derived key
        $NewDerivedKey = [ShadowCredentialVault]::GetDerivedKey($Passphrase, $this.Salt)
        
        # Compute new hash
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $NewHashedDerivedKey = $sha256.ComputeHash($NewDerivedKey)

         # Encrypt Master Key
        $aes = [System.Security.Cryptography.AesCng]::Create().CreateEncryptor($NewDerivedKey, [ShadowCredentialVault]::IV)
        $NewEncryptedMasterKey = $aes.TransformFinalBlock($this.MasterKey, 0, $this.MasterKey.Length)

        # Save changes
        $this.DerivedKey = $NewDerivedKey
        $this.HashedDerivedKey = $NewHashedDerivedKey
        $this.EncryptedMasterKey = $NewEncryptedMasterKey

        return $true
    }

    static [ShadowCredentialVault] CreateWithPassphrase([string] $Passphrase) {
        $NewMasterKey = New-Object byte[] ([ShadowCredentialVault]::KeySizeBytes)
        $NewEncryptedMasterKey = New-Object byte[] ([ShadowCredentialVault]::KeySizeBytes)
        $NewSalt = New-Object byte[] ([ShadowCredentialVault]::KeySizeBytes)
        $NewDerivedKey = $null
        $NewHashedDerivedKey = New-Object byte[] ([ShadowCredentialVault]::HashSizeBytes )

        # Generate key material
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($NewMasterKey)
        $rng.GetBytes($NewSalt)

        # Derive user key
        $NewDerivedKey = [ShadowCredentialVault]::GetDerivedKey($Passphrase, $NewSalt)

        # Store hashed user key
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $NewHashedDerivedKey = $sha256.ComputeHash($NewDerivedKey)

        # Encrypt Master Key
        $aes = [System.Security.Cryptography.AesCng]::Create().CreateEncryptor($NewDerivedKey, [ShadowCredentialVault]::IV)
        $NewEncryptedMasterKey = $aes.TransformFinalBlock($NewMasterKey, 0, $NewMasterKey.Length)

        return [ShadowCredentialVault]::new($NewMasterKey, $NewEncryptedMasterKey, $NewSalt, $NewDerivedKey, $NewEncryptedMasterKey, $NewHashedDerivedKey, $null)     
    }

    hidden static [byte[]] GetDerivedKey([String] $Passphrase, [byte[]] $Salt) {
        $NewDerivedKey = new-object byte[] ([ShadowCredentialVault]::KeySizeBytes)

        # Generate Derived key using PBKDF2
        $utf8 = [System.Text.Encoding]::UTF8
        $PBKDF2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($utf8.GetBytes($Passphrase),
                                                                         $Salt,
                                                                         [ShadowCredentialVault]::PBKDF2Iterations)
        $NewDerivedKey = $PBKDF2.GetBytes([ShadowCredentialVault]::KeySizeBytes)

        return $NewDerivedKey
    }

    static [ShadowCredentialVault] CreateFromFile([string] $file) {
        return $null $TODO
    }

}
