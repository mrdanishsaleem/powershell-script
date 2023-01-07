param(
    [Parameter(Mandatory=$true)]
    [string] $FileName
)

Add-Type -AssemblyName System.Security
$ErrorActionPreference = 'Stop'

function Unprotect-String([string] $base64String)
{
    return [System.Text.Encoding]::Unicode.GetString([System.Security.Cryptography.ProtectedData]::Unprotect([System.Convert]::FromBase64String($base64String), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
}

$document = [xml] (Get-Content $FileName)
$nsm = New-Object 'System.Xml.XmlNamespaceManager' ($document.NameTable)
$nsm.AddNamespace('rs', 'http://schemas.microsoft.com/sqlserver/RegisteredServers/2007/08')

$attr = $document.DocumentElement.GetAttribute('plainText')
if ($attr -ne '' -and $Operation -ieq 'Decrypt')
{    
    throw "The file does not contain encrypted passwords."	
}

$servers = $document.SelectNodes("//rs:RegisteredServer", $nsm)

foreach ($server in $servers)
{
    $connString = $server.ConnectionStringWithEncryptedPassword.InnerText
	echo ""
	echo "Encrypted Connection String:"
	echo $connString
	echo ""
    if ($connString -inotmatch 'password="?([^";]+)"?') {continue}
    $password = $Matches[1]
	
	$password = Unprotect-String $password  
	echo ""
	echo "Decrypted Connection String:"
    $connString = $connString -ireplace 'password="?([^";]+)"?', "password=`"$password`""
	echo $connString
	echo ""
}