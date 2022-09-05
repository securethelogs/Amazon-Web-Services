<#
Author: Xstag0.com
Github: https://github.com/Securethelogs
Description: This script is used to scan for ALL rules within Security Groups quickly via Powershell CLI.

Using profiles - 
More info: https://docs.aws.amazon.com/powershell/latest/userguide/specifying-your-aws-credentials.html

Modules to install: Install-AWSToolsModule AWS.Tools.Ec2

#>


$logo = '
  ,_     _
  |\\_,-~/
  / _  _ |    ,--.
 (  @  @ )   / ,-"
  \  _T_/-._( ( ~ AWS Open SecGroups 
 /         `. \
 |         _  \ |
 \ \ ,  /      |
  || |-_\__   / 
 ((_/`(____,-" 
 
 @Xstag0

'

$logo

$aprofiles = @(Get-AWSCredential -ListProfileDetail)
$regions = @((Get-AWSRegion).Region)
#$regions = @("us-east-1", "us-east-2", "us-west-1", "us-west-2")

if ($aprofiles.Count -eq 0)
{
    Write-Host "[!] No profiles found. Please create a profile and run the script again." -ForegroundColor Red
    exit

} else {

  Write-Host "[*] Profiles Found:"
  $aprofiles | Format-Table


}

$prof = Read-Host -Prompt "Enter Profile Name: "



Write-Output ""
Write-Host "[*] Scanning Regions..." -ForegroundColor Blue



foreach ($rg in $regions){

$ruleset = @()
$openrulesets = @()


try {$sg = Get-EC2SecurityGroup -ProfileName $prof -Region $rg} catch { $sg = $null }
if ($sg){


foreach ($s in $sg){

    $inbd = @($s.IpPermissions)
    $otbd = @($s.IpPermissionsEgress)


    # Inbound

        foreach ($r in $inbd){

            $rips = @($r.Ipv4Ranges)

                foreach ($i in $rips){

                    $rule = New-Object PSObject

                    # Security Group
                    $rule | Add-Member -MemberType NoteProperty -Name 'GroupName' -Value $s.GroupName
                    $rule | Add-Member -MemberType NoteProperty -Name 'GroupID' -Value $s.GroupId
                    $rule | Add-Member -MemberType NoteProperty -Name 'VPC' -Value $s.VpcId
                    $rule | Add-Member -MemberType NoteProperty -Name 'Direction' -Value "Inbound"

                    # The Sources
                    $rule | Add-Member -MemberType NoteProperty -Name 'IPs' -Value $i.CidrIp
                    $rule | Add-Member -MemberType NoteProperty -Name 'Description' -Value $i.Description

                    # The Ports
                    $rule | Add-Member -MemberType NoteProperty -Name 'Protocol' -Value $r.IpProtocol
                    $rule | Add-Member -MemberType NoteProperty -Name 'SPort' -Value $r.FromPort
                    $rule | Add-Member -MemberType NoteProperty -Name 'DPort' -Value $r.ToPort


                    # Add to the array
                    $ruleset += $rule

                    if ($i.CidrIp -eq "0.0.0.0/0"){

                        $openrulesets += $rule


                    }


                }




     } # Inbound

     # Outbound

     foreach ($r in $otbd){

        $rips = @($r.Ipv4Ranges)

            foreach ($i in $rips){

                $rule = New-Object PSObject

                # Security Group
                $rule | Add-Member -MemberType NoteProperty -Name 'GroupName' -Value $s.GroupName
                $rule | Add-Member -MemberType NoteProperty -Name 'GroupID' -Value $s.GroupId
                $rule | Add-Member -MemberType NoteProperty -Name 'VPC' -Value $s.VpcId
                $rule | Add-Member -MemberType NoteProperty -Name 'Direction' -Value "Outbound"

                # The Sources
                $rule | Add-Member -MemberType NoteProperty -Name 'IPs' -Value $i.CidrIp
                $rule | Add-Member -MemberType NoteProperty -Name 'Description' -Value $i.Description

                # The Ports
                $rule | Add-Member -MemberType NoteProperty -Name 'Protocol' -Value $r.IpProtocol
                $rule | Add-Member -MemberType NoteProperty -Name 'SPort' -Value $r.FromPort
                $rule | Add-Member -MemberType NoteProperty -Name 'DPort' -Value $r.ToPort


                # Add to the array
                $ruleset += $rule

                if ($i.CidrIp -eq "0.0.0.0/0"){

                    $openrulesets += $rule


                }


            }




    } # Outbound



}

# Output #
Write-output ""
Write-Host "[*] Region: $($rg.ToUpper())" -foregroundcolor Blue
Write-output ""
Write-Host "[*] All Security Groups:" -ForegroundColor Yellow

$ruleset | Sort-Object -property Direction | Format-Table -AutoSize

Write-Output ""
Write-Host "[!] Open Security Groups To Review" -ForegroundColor Red

$openrulesets | Sort-Object -property Direction | Format-Table -AutoSize

####

$riskvpc = @($openrulesets.VPC)
$riskinst = @()

    
$inst = @((Get-EC2Instance -ProfileName $prof -Region $rg).Instances)

    foreach ($is in $inst){

        if ($riskvpc -contains $is.VpcId){

            $riskinst += $is

        }

    }

if ($riskinst.Count -gt 0){

    Write-Output ""
    Write-Host "[!] Instances At Risk" -ForegroundColor Red
    $riskinst | Sort-Object -property Direction | Format-Table -AutoSize

}


Write-Output ""
Read-Host -Prompt "Press Enter to continue..."


} 

}
