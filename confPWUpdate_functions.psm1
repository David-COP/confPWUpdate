Write-Host "Importing Functions"
function Get-ADAccountList
 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCredential]$credential,
        [Parameter(Mandatory=$true)]
        [string]$SafeName
    )
$BaseURI = "https://passwordvault.conocophillips.net"
New-PASSession -Credential $credential -BaseURI $BaseURI
$accounts = Get-PASAccount -SafeName $SafeName

$AD_Account_list = Foreach($Account in $accounts) {
    $ErrorActionPreference = "SilentlyContinue"
    $AD_Object = get-aduser $Account.userName -properties employeeType,Enabled,LastLogonDate,PasswordLastSet,LockedOut -erroraction silentlycontinue
    $Datestr = '{0:yyyyMMdd_hh_mm}' -f $AD_Object.PasswordLastSet
    $Datestr_LastLogonDate = '{0:yyyyMMdd_hh_mm}' -f $AD_Object.LastLogonDate
    $PWChangedKey = $Account.userName + "_" + $Datestr
    $ErrorActionPreference = 'Continue'
    if($null -ne $AD_Object){
        [PSCustomObject]@{
            userID = $Account.userName
            safeName = $Account.safeName
            MTR = $Account.name
            userID_employeeType = $AD_Object.employeeType
            userID_Enabled = $AD_Object.Enabled
            userID_Locked = $AD_Object.LockedOut
            userID_LastLogonDate = $Datestr_LastLogonDate
            userID_PasswordLastSet = $Datestr
            pwchanged_key = $PWChangedKey
        }
    }
}
return $AD_Account_list
 }

function Update-Table
 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Array]$AD_Account_list,
        [Parameter(Mandatory=$true)]
        [string]$SafeName
    )    
# static variables
$resourceGroup = "GSSDevOps"
$storageAccount = "gssassetstorage01"
$tableName = "confUpdate"

#inialize variables
$upload = $false
$rows_updated = 0
$rows_added = 0
$rows_deleted = 0
$rows_not_updated = 0
$rows_not_added = 0
$rows_not_deleted = 0
$upload_rows_added = 0
$date = Get-Date

#get cloudTable context
$StorageKey=(Get-AzStorageAccountKey -ResourceGroupName $resourceGroup -Name $storageAccount).Value[0]
$ctx = New-AzStorageContext -StorageAccountName $storageAccount -StorageAccountKey $StorageKey
$cloudTable = (Get-AzStorageTable –Name $tableName –Context $ctx).CloudTable

#get all rows from confUpdate table
[array]$v_confUpdate = Get-AzTableRow -table $cloudTable -partitionKey $SafeName
$v_confUpdate_Active = Foreach($account in $v_confUpdate){
    $tableTimestamp = $account.TableTimestamp.DateTime
    #$days = ($date-$TableTimestamp).Days
    #if($days -le 1)
    #{
        $account
    #}
}

###determine if this is an intial upload
if($null -eq $v_confUpdate_Active){$upload = $true}

#This will delete any row that matches via rowkey and then recreate with the new data. While updating storage it is checking keys to find if the password changed.
$Password_Change_List = Foreach($account in $AD_Account_list){
    #if upload is true it will only add the row to the table.
    if($upload){
        $add_row = Add-AzTableRow -table $cloudTable -partitionKey $SafeName -RowKey ($account.userID) -property @{"userID"=$account.userID;"safeName"=$account.safeName;"userID_employeeType"=$account.userID_employeeType;"userID_Enabled"=$account.userID_Enabled;"userID_Locked"=$account.userID_Locked;"userID_LastLogonDate"=$account.userID_LastLogonDate;"userID_PasswordLastSet"=$account.userID_PasswordLastSet;"pwchanged_key"=$account.pwchanged_key}
        if($add_row.HttpStatusCode -eq 204){
		$upload_rows_added += 1 }
	} Else {
	$RowKey = $account.userID
    $pwchanged_key = $account.pwchanged_key

    ###check if this userID is already contained in storage
	if($v_confUpdate_Active.RowKey.Contains($RowKey)){

        #check if password changed on each account and store the results in Password_Change_List
        if(!($v_confUpdate_Active.pwchanged_key.Contains($pwchanged_key))){
            [PSCustomObject]@{
                account = $account.userID
                password_changed = $true
				MTR = $account.MTR
            }
        } else {
            [PSCustomObject]@{
                account = $account.userID
                password_changed = $false
				MTR = $account.MTR
            }
        }
        #remove this row
		$accountremove = Get-AzTableRow -table $cloudTable -partitionKey $safeName -RowKey $RowKey | Remove-AzTableRow -table $cloudTable

		if($accountremove.HttpStatusCode -eq 204) {
            ###if row removal was successfull - add the row back with the new data.
			$replace_row = Add-AzTableRow -table $cloudTable -partitionKey $SafeName -RowKey ($account.userID) -property @{"userID"=$account.userID;"safeName"=$account.safeName;"userID_employeeType"=$account.userID_employeeType;"userID_Enabled"=$account.userID_Enabled;"userID_Locked"=$account.userID_Locked;"userID_LastLogonDate"=$account.userID_LastLogonDate;"userID_PasswordLastSet"=$account.userID_PasswordLastSet;"pwchanged_key"=$account.pwchanged_key}
            $rows_deleted += 1
		} Else { $rows_not_deleted += 1}

		if($replace_row.HttpStatusCode -eq 204){
			$rows_updated += 1
		} Else {$rows_not_updated += 1}
	} Else {
        #If there is a new userID it will add to cloudtable
		$add_row = Add-AzTableRow -table $cloudTable -partitionKey $SafeName -RowKey ($account.userID) -property @{"userID"=$account.userID;"safeName"=$account.safeName;"userID_employeeType"=$account.userID_employeeType;"userID_Enabled"=$account.userID_Enabled;"userID_Locked"=$account.userID_Locked;"userID_LastLogonDate"=$account.userID_LastLogonDate;"userID_PasswordLastSet"=$account.userID_PasswordLastSet;"pwchanged_key"=$account.pwchanged_key}
        if($add_row.HttpStatusCode -eq 204){
		$rows_added += 1
		} else {
			$rows_not_added +=1
			
		}
	}
    }
}

#Verifies that all all records were updated in table storage - will return true/false based on if $upload_count = $rows_updated + $rows_added
$total_updates = $rows_updated + $rows_added
$table_update_successfull = $total_updates -eq $AD_Account_list.count
if($upload){
$upload_successfull = $AD_Account_list.count -eq $upload_rows_added
}

#returns results of the upload
if($upload){
    if($upload_successfull){
    return "Upload Successfull, all records loaded to storage."
    } else {
        $returnObject = [PSCustomObject]@{
            upload_successfull = $upload_successfull
            upload_rows_added = $upload_rows_added
        }
        return $returnObject
    }
} else {
    #will return the Password_Change_List if table_update_sucessfull is true.
    if($table_update_successfull){
        return $Password_Change_List
    } else {
        $returnObject = [PSCustomObject]@{
            table_update_successfull = $table_update_successfull
            rows_updated = $rows_updated
            rows_added = $rows_added
            rows_deleted = $rows_deleted
            rows_not_updated = $rows_not_updated
            rows_not_added = $rows_not_added
            rows_not_deleted = $rows_not_deleted
        }
        return $returnObject
    }
}
 }

function Get-PWVCred
 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCredential]$credential,
        [Parameter(Mandatory=$true)]
        [string]$SafeName,
        [Parameter(Mandatory=$true)]
        [string]$Account
    )
try{
    Import-Module -Name psPAS -Scope Local
} catch {
    Write-Output "Error Loading Module. Function stopped executing."
    break
    }
$BaseURI = "https://passwordvault.conocophillips.net"
New-PASSession -Credential $credential -BaseURI $BaseURI
[SecureString]$Password = (Get-PASAccount -SafeName $SafeName | Where-Object userName -eq $Account).GetPassword().Password | ConvertTo-SecureString -AsPlainText -Force
return [SecureString]$Password
 }

function Build-XML
 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [SecureString]$password_secure,
        [Parameter(Mandatory=$true)]
		[string]$account
    )
$cred = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password_secure))
$XMLbase = @"
<SkypeSettings>
    <UserAccount>
        <SkypeSignInAddress>TUSER@conocophillips.com</SkypeSignInAddress>
        <ExchangeAddress>TUSER@conocophillips.com</ExchangeAddress>
        <DomainUsername>conoco\TUSER</DomainUsername>
        <Password>TPASSWORD</Password>
		<ModernAuthEnabled>true</ModernAuthEnabled>
    </UserAccount>
</SkypeSettings>
"@

$find1 = "TUSER"
$find2 = "TPASSWORD"
$XMLbase2 = $XMLbase -replace $find1, $account
$XMLbase3 = $XMLbase2 -replace $find2, $cred
return $XMLbase3
 }

function Get-Authorization
 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Computer,
        [Parameter(Mandatory=$true)]
        [string]$Account,
        [Parameter(Mandatory=$true)]
        [SecureString]$password_secure,
        [Parameter(Mandatory=$true)]
        [PSCredential]$remote_access_creds
    )
$Proceed_Final = $True
$Test_PC_Length = $Computer.length
$remote_access_username = $remote_access_creds.UserName
#Checks to make sure Machine name does not exceed 15 characters
if($Test_PC_Length -ge 16) { 
    $LengthTest = $False
    $Proceed_Final = $False
} Else { 
    $LengthTest = $True 
}

#This is True if Credentials are able to authenticate
[pscredential]$credObject = New-Object System.Management.Automation.PSCredential ($Account, $password_secure)
$CredentialTest = Test-SWADCredential -Credential $credObject  
if($CredentialTest) {
    $LogonStatus = $True
} Else {
    $LogonStatus = $False
    $Proceed_Final = $False 
}

#Verifies if credentials are able to start a PSSession
$session = New-PSSession –ComputerName $Computer -credential $remote_access_creds
$session_id = $session.Id
$RemoteVerify = $session.ComputerName -eq $Computer #$RemoteVerify is True if Remote session is working
if($RemoteVerify -eq $False) {
    $Remote_Access = $False
    $Proceed_Final = $False
} else {
    $Remote_Access = $True
}
Remove-PSSession -Id $Session_id

#Verifies if machine is online
If (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
    $TargetStat = $True
}else {
    $TargetStat = $False
    $Proceed_Final = $False
}

#Gets Locked out status of the account
$LockedStat = Get-ADUser $Account -Properties * | Select-Object -ExpandProperty LockedOut

#Gets AD PasswordLastSet
$LastPWChangeStat = Get-ADUser $Account -Properties * | Select-Object -ExpandProperty PasswordLastSet

###Return Results
$Results = [PSCustomObject]@{
    computer = $Computer
    computer_length_verified = $LengthTest
    computer_online = $TargetStat
    room_account = $Account
    room_account_locked = $LockedStat
    room_account_credentials = $LogonStatus 
    remote_user = $remote_access_username
    remote_user_verified = $Remote_Access
    LastPasswordSet = $LastPWChangeStat
    Proceed = $Proceed_Final
}
Return $Results
 }

function Test-SWADCredential
 {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [pscredential]$Credential
    )
$load_assembly = [reflection.assembly]::LoadWithPartialName("System.DirectoryServices.AccountManagement")
$PrincipalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext("Domain")
$Cred_Test = $PrincipalContext.ValidateCredentials($Credential.UserName, $Credential.GetNetworkCredential().Password,"Negotiate")
Return $Cred_Test
 }

function Send-XML
 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Computer,
        [Parameter(Mandatory=$true)]
        [pscredential]$remote_access_creds,
        $XML
    )
$XMLtempPath = ".\SkypeSettings.xml"
$XML > $XMLtempPath
$targetDevice = "C:\Users\Skype\AppData\Local\Packages\Microsoft.SkypeRoomSystem_8wekyb3d8bbwe\LocalState\SkypeSettings.xml"

$session = New-PSSession –ComputerName $Computer -credential $remote_access_creds
$session_id = $session.Id

#remove comment on below line when actually running the script
Copy-Item -path $XMLtempPath -Destination $targetDevice –ToSession $session

#Verifies if file was copied
$verifycopy = Invoke-Command -ComputerName $Computer -credential $remote_access_creds -ScriptBlock { Get-ChildItem C:\Users\Skype\AppData\Local\Packages\Microsoft.SkypeRoomSystem_8wekyb3d8bbwe\LocalState\ }
$Test = $verifycopy | Select-String -Pattern "SkypeSettings.xml"
    
#If verified - restart Room
if($Test -like "SkypeSettings.xml") {
    
    invoke-command { Shutdown /r /t 0 } -ComputerName $Computer -credential $remote_access_creds
    $Result = @{
        computer = $Computer
        xml_copied = $true
        room_rebooted = $true
    }
} Else { 
    $Result = @{
        computer = $Computer
        xml_copied = $false
        room_rebooted = $false
    }
}
New-Variable -Name return_object -value $Result
$remove_session = Remove-PSSession -Id $Session_id
Remove-Item -Path $XMLtempPath
Return ${return_object}
 }