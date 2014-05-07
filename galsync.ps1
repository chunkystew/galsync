<#
GALSync written by Matthew Saunier, 18 Oct 2013
Last update by Matthew Saunier, 22 Dec 2013

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
#>
Function EncryptString{
    Param ([string]$cleartext)
    $ciphertext = $cleartext | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
    return $ciphertext}
Function DecryptString{
    Param ([string]$ciphertext)
    $secureString = $ciphertext | ConvertTo-SecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString) 
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)}
Function LogWrite{
    Param ([string]$logString, [int]$severity)
    if((($verbosity -eq 0) -and ($severity -lt 2)) -or (($verbosity -eq 1) -and ($severity -lt 1))){return}
    switch ($severity){
        0{$logString = "Debug: $logString"}
        1{$logString = "Information: $logString"}
        2{$logString = "Warning: $logString"}
        3{$logString = "Error: $logString"}}
    Write-Host $logString
    if($logging -eq "True"){Add-Content $logfile $logString}}
$unixEpochStart = new-object DateTime 1970,1,1,0,0,0,([DateTimeKind]::Utc)
$epochTime = [int]([DateTime]::UtcNow - $unixEpochStart).TotalSeconds
$logFile = $epochTime.ToString() + ".txt"
$myName =  $MyInvocation.MyCommand.Name
$iniName = $myName.Split(".")[0] += ".ini"
$user = ""
$pass = ""
$encryptedPass = ""
$discoveryAddress = ""
$commit = "False"
$verbosity = 1
$logging = "False"
for ($i=0; $i -lt $args.Count; $i++){
    $thisArg = $args[$i]
    switch ($thisArg){
        {($_ -eq "-u") -or ($_ -eq "--user")}{
        $i++
        $user = $args[$i]}
        {($_ -eq "-p") -or ($_ -eq "--pass")}{
        $i++
        $pass = $args[$i]}
        {($_ -eq "-e") -or ($_ -eq "--encryptedPass")}{
        $i++
        $encryptedPass = $args[$i]}
        {($_ -eq "-d") -or ($_ -eq "--discoveryAddress")}{
        $i++
        $discoveryAddress = $args[$i]}
        {($_ -eq "-c") -or ($_ -eq "--commit")}{$commit = "True"}
        {($_ -eq "-v") -or ($_ -eq "--verbose")}{$verbosity = 2}
        {($_ -eq "-s") -or ($_ -eq "--silent")}{$verbosity = 0}
        {($_ -eq "-l") -or ($_ -eq "--log")}{$logging = "True"}
        {($_ -eq "-h") -or ($_ -eq "--help")}{
            Write-Host ""
            Write-Host "GALSync revision 22 Dec 2013, written by Matthew Saunier"
            Write-Host ""
            Write-Host "Usage: $myName [[-u value] [[-p value] [-e value]] [-d value] [-c] [[-v] [-s]] [-l]] [-h]"
            Write-Host ""
            Write-Host "Options:"
            Write-Host "-u, --user [value]: The username that will be used to log in to Exchange. This must be in user@domain format."
            Write-Host "-p, --pass [value]: The password that will be used to log in to Exchange, as plaintext."
            Write-Host "-e, --encryptedPass [value]: The password that will be used to log in to Exchange, as a Secure-String. This Secure-String must be decodable by the current user."
            Write-Host "-d, --discoveryAddress [value]: Any valid SMTP address in the target Exchange organization, used for Exchange Autodiscovery. This should ideally be an administrative address not subject to change or deletion."
            Write-Host "-c, --commit: Commit any changes to the preference file $iniName. For this to work, this script must have Create/Append permissions in the working directory. Verbosity and logging are not saved."
            Write-Host "-v, --verbose: Maximum verbosity. Display all possible diagnostic information. Note, this output can be many megabytes."
            Write-Host "-s, --silent: Run without displaying any diagnostic information except warnings and errors."
            Write-Host "-l, --log: Write diagnostic information to a log file in addition to the console. This file is always named [UNIX epoch time].txt and placed in the working directory."
            Write-Host "-h, --help: Display this information."
            Write-Host ""
            Write-Host "Notice: If run in an interactive shell, it is possible for this script to leak credentials. For secure use, always run as a scheduled process, or terminate the invoking shell." 
            }
        default{
            Write-Host "Bad argument at position $i, $thisArg. Invoke this script with the --help option for more information."
            Exit}}}
if(!(Test-Path "${env:ProgramFiles}\Microsoft\Exchange\Web Services\2.0\Microsoft.Exchange.WebServices.dll")){
    LogWrite "Error: This script requires the Exchange Web Services Managed API, version 2.0 or greater. This API can be obtained at http://www.microsoft.com/en-us/download/details.aspx?id=35371." 3
    Exit}
if(!(Test-Path .\$iniName)){
    if($args.Count -eq 0){
        LogWrite "Error: The preference file $iniName appears to be missing, and no arguments were specified. Invoke this script with the --help option for more information." 3
        Exit}
    LogWrite "Warning: The preference file $iniName appears to be missing. This file can be generated by using the --commit option. Invoke this script with the --help option for more information." 2}
    else{
        Get-Content .\$iniName | Foreach-Object{
            $value = $_.Split(" ")[0]
            $data = $_.Split(" ")[1]
            switch ($value){
                "user"{if($user -eq ""){$user = $data}}
                "encryptedPass"{if(($pass -eq "") -and ($encryptedPass -eq "")){$encryptedPass = $data}}
                "discoveryAddress"{if($discoveryAddress -eq ""){$discoveryAddress = $data}}}}}
if((!($encryptedPass -eq "")) -and $pass -eq ""){$pass = DecryptString $encryptedPass}
if($commit -eq "True"){
    New-Item .\$iniName -type file -force | Out-Null
    Add-Content .\$iniName "user $user"
    $encryptedPass = EncryptString $pass
    Add-Content .\$iniName "encryptedPass $encryptedPass"
    Add-Content .\$iniName "discoveryAddress $discoveryAddress"}
[void][Reflection.Assembly]::LoadFile("${env:ProgramFiles}\Microsoft\Exchange\Web Services\2.0\Microsoft.Exchange.WebServices.dll")
add-pssnapin Microsoft.Exchange.Management.PowerShell.E2010
$exchCredentials = New-Object Microsoft.Exchange.WebServices.Data.WebCredentials($user.Split("@")[0], $pass, $user.Split("@")[1])
$exchService = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService([Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2010_SP2)
$exchService.Credentials = $exchCredentials
$exchService.AutodiscoverUrl("$discoveryAddress", {$true})
$time = Get-Date
LogWrite "Run started at $time" 1
$contactsExchange = Get-Recipient | Where-Object{$_.HiddenFromAddressListsEnabled -ne $true} | Where-Object{$_.RecipientType -eq "UserMailbox"} | Select-Object DisplayName,FirstName,MiddleName,LastName,PrimarySmtpAddress,Phone,Company,Department
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = '(objectclass=contact)'
$contactsNonExchange = $searcher.FindAll()
Get-Recipient | Where-Object{$_.HiddenFromAddressListsEnabled -ne $true -and $_.RecipientType -eq "UserMailbox"} | Select-Object PrimarySmtpAddress | ForEach-Object{
    $thisUser = $_.PrimarySmtpAddress
    LogWrite "Processing user $thisUser" 1
    $exchImpersonatedUID = New-Object Microsoft.Exchange.WebServices.Data.ImpersonatedUserId([Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress, $_.PrimarySmtpAddress.ToString())
    $exchService.ImpersonatedUserId = $exchImpersonatedUID
    $propSet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly,[Microsoft.Exchange.WebServices.Data.FolderSchema]::TotalCount)
    $userContactsFolder = [Microsoft.Exchange.WebServices.Data.ContactsFolder]::Bind($exchService,[Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Contacts, $propSet)
    if($userContactsFolder.TotalCount -gt 0){
        $itemView = New-Object Microsoft.Exchange.WebServices.Data.ItemView($userContactsFolder.TotalCount)
        LogWrite "Deleting stale contacts..." 0
        $exchService.FindItems([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Contacts, $itemView) | Where-Object{$_.Subject -eq "GALSync"} | Select-Object Id | ForEach-Object{
            $id = New-Object Microsoft.Exchange.WebServices.Data.ItemId($_.Id)
            $staleContact = [Microsoft.Exchange.WebServices.Data.Contact]::Bind($exchService,$id)
            $staleContact.Delete([Microsoft.Exchange.WebServices.Data.DeleteMode]::HardDelete)
            $displayString = $staleContact.DisplayName
            $emailString = $staleContact.EmailAddresses.Item([Microsoft.Exchange.WebServices.Data.EmailAddressKey]::EmailAddress1)
            $phoneString = $staleContact.PhoneNumbers.Item([Microsoft.Exchange.WebServices.Data.PhoneNumberKey]::BusinessPhone)
            LogWrite "Deleted $displayString $emailString $phoneString" 0}}
    LogWrite "Writing Exchange contacts..." 0
    $contactsExchange | ForEach-Object{
        $newContact = New-Object Microsoft.Exchange.WebServices.Data.Contact($exchService)
        $displayString = $_.DisplayName
    	$newContact.DisplayName = $displayString
      	$newContact.FileAs = $displayString
        $newContact.GivenName = $_.FirstName
	    $newContact.MiddleName = $_.MiddleName
	    $newContact.Surname = $_.LastName
        $emailString = $_.PrimarySmtpAddress
        $emailAddress = new-object Microsoft.Exchange.WebServices.Data.EmailAddress($emailString)
        $newContact.EmailAddresses.Item([Microsoft.Exchange.WebServices.Data.EmailAddressKey]::EmailAddress1) = $emailAddress
        $phoneString = $_.Phone
        $newContact.PhoneNumbers.Item([Microsoft.Exchange.WebServices.Data.PhoneNumberKey]::BusinessPhone) = $phoneString
        $newContact.CompanyName = $_.Company
        $newContact.Department = $_.Department
        $newContact.Subject = "GALSync"
        $newContact.Save()
        LogWrite "Wrote $displayString $emailString $phoneString" 0}
    LogWrite "Writing Active Directory contacts..." 0
    $contactsNonExchange | ForEach-Object{
        $newContact = New-Object Microsoft.Exchange.WebServices.Data.Contact($exchService)     
        if($_.Properties.givenname){$gnString = $_.Properties.givenname[0]}
        else{$gnString=""}
        if($_.Properties.sn){$snString = $_.Properties.sn[0]}
        else{$snString=""}        
        $newContact.GivenName = $gnString
	    $newContact.Surname = $snString
        if($_.Properties.displayname){$displayString = $_.Properties.displayname[0]}
        else{$displayString = $gnString + " " + $snString}
        $newContact.DisplayName = $displayString
      	$newContact.FileAs = $displayString
        if($_.Properties.mail){$emailString = $_.Properties.mail[0]}
        else{$emailString = "nomail@address.invalid"}
        $emailAddress = new-object Microsoft.Exchange.WebServices.Data.EmailAddress($emailString)
        $newContact.EmailAddresses.Item([Microsoft.Exchange.WebServices.Data.EmailAddressKey]::EmailAddress1) = $emailAddress
        if($_.Properties.telephonenumber){$phoneString = $_.Properties.telephonenumber[0]}
        else{$phoneString=""}
        $newContact.PhoneNumbers.Item([Microsoft.Exchange.WebServices.Data.PhoneNumberKey]::BusinessPhone) = $phoneString
        $newContact.Subject = "GALSync"
        $newContact.Save()
        LogWrite "Wrote $displayString $emailString $phoneString" 0}}     
$time = Get-Date
LogWrite "Run ended at $time" 1
