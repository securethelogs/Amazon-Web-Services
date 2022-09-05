<#
Author: Xstag0.com
Github: https://github.com/Securethelogs
Description: This script is used to scan for risky S3 Buckets

Using profiles - 
More info: https://docs.aws.amazon.com/powershell/latest/userguide/specifying-your-aws-credentials.html

Modules to install: Install-AWSToolsModule AWS.Tools.s3

#>

$logo = '
  ,_     _
  |\\_,-~/
  / _  _ |    ,--.
 (  @  @ )   / ,-"
  \  _T_/-._( ( ~ AWS S3 Exposure!
 /         `. \
 |         _  \ |
 \ \ ,  /      |
  || |-_\__   / 
 ((_/`(____,-" 
 
 @Xstag0

'

$logo

$aprofiles = @(Get-AWSCredential -ListProfileDetail)

if ($aprofiles.Count -eq 0)
{
    Write-Host "[!] No profiles found. Please create a profile and run the script again." -ForegroundColor Red
    exit

} else {

  Write-Host "[*] Profiles Found:"
  $aprofiles | Format-Table


}

$prof = Read-Host -Prompt "Enter Profile Name: "

$publics3 = @()
$nocond = @()
$cond = @()
$enc = @()
$noenc = @()
$lge = @()
$lgne = @()
$failed = @()
$riskys3 = @()


Write-Output ""
Write-Host "[*] Scanning S3 Buckets..." -ForegroundColor Yellow

    $s3bnames = @((Get-S3Bucket -ProfileName $prof -Select *).Buckets.BucketName)


   foreach ($s3 in $s3bnames){

    $pub = $false

    Write-Host "Scanning Bucket: $s3" -ForegroundColor Blue

    try { Get-S3PublicAccessBlock -BucketName $s3 -ProfileName $prof | Out-Null } catch { 
        
        Write-Host "[!] $s3 is potentially exposed!" -ForegroundColor Red
        $publics3 += $s3 
        $pub = $true
    
    }

    # If Public

    if ($pub){

        $ptb = New-Object psobject
        $ptb | Add-Member -MemberType NoteProperty -Name 'BucketName' -Value $s3
      

        # Policy Conditions
        try { $pol = Get-S3BucketPolicy -ProfileName $prof -BucketName $s3 | Select-String "Condition" } catch { $failed += $s3 }
        if ($pol){ 
            
            $cond += $ps3
            $ptb | Add-Member -MemberType NoteProperty -Name 'PolicyConditions' -Value "X"
        
        
        } else { 
            
            $nocond += $ps3
            $ptb | Add-Member -MemberType NoteProperty -Name 'PolicyConditions' -Value ""
        
        }

        # Encyption 
        try { $enc = (Get-S3BucketEncryption -ProfileName $prof -BucketName $s3).ServerSideEncryptionRules }catch{ $failed += $s3 }
        if ($enc){ 
            
            $enc += $s3
            $ptb | Add-Member -MemberType NoteProperty -Name 'EncryptionEnabled' -Value "X"
        
        } else { 
            
            $noenc += $s3
            $ptb | Add-Member -MemberType NoteProperty -Name 'EncryptionEnabled' -Value ""
        
        }

        # Logging
        try {$l = (Get-S3BucketLogging -ProfileName $prof -BucketName $s3).TargetBucketName}catch{ $failed += $s3 }
        if ($l){ 
            
            $lge += $s3
            $ptb | Add-Member -MemberType NoteProperty -Name 'LoggingEnabled' -Value "X"
        
        } else { 
            
            $lgne += $s3
            $ptb | Add-Member -MemberType NoteProperty -Name 'LoggingEnabled' -Value ""
        
        }


        $riskys3 += $ptb



    }



   }

      ### Output Results 

      Write-Output ""
      Write-Host "----"
      Write-Output ""
      Write-Host "[*] Findings:"
   
      Write-Host "Total Buckets: $($s3bnames.Count)"
      Write-Host " - Public Facing: $($publics3.count)" -ForegroundColor Red
      Write-Host " - PublicAccessBlocked: $($s3bnames.Count - $publics3.count)" -ForegroundColor Green
      Write-Host " - PublicAccess with Conditions: $($cond.count)" -ForegroundColor Yellow
      Write-Host " - PublicAccess with Encryption: $($enc.count)" -ForegroundColor Yellow
      Write-Host " - PublicAccess with Logging: $($lge.count)" -ForegroundColor Yellow

   
   
      Write-Output ""
      Write-Host "[*] Failed Access! Manual Review Required: $(($failed | Sort-Object | Get-Unique).Count )" -ForegroundColor Yellow
      $failed | Sort-Object | Get-Unique
   
   
      Write-Output ""
      Write-Host "[*] Risky S3 Buckets Found: $($riskys3.count)" -foregroundcolor Red

      $riskys3 | Format-Table -AutoSize


