<#
Author: Xstag0.com
Github: https://github.com/Securethelogs
Description: This script is used to scan regions for a quick inventory check.

Using profiles - 
More info: https://docs.aws.amazon.com/powershell/latest/userguide/specifying-your-aws-credentials.html

Modules to install: Install-AWSToolsModule AWS.Tools.Ec2, AWS.Tools.RDS, AWS.Tools.ECS, AWS.Tools.EKS, AWS.Tools.ECR, AWS.Tools.Lambda

#>

$logo = '
  ,_     _
  |\\_,-~/
  / _  _ |    ,--.
 (  @  @ )   / ,-"
  \  _T_/-._( ( ~ AWS Region Check 
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

$inv = @()


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




foreach ($r in $regions){

  $tbl = New-Object psobject


  $tbl | Add-Member -MemberType NoteProperty -Name 'Region' -Value $r


    # Scan for instances
    try { $ec2i = Get-EC2Instance -ProfileName $prof -Region $r } catch {$ec2i = $null}
    if ($ec2i){ $tbl | Add-Member -MemberType NoteProperty -Name 'Ec2Instances' -Value $ec2i.count } else { $tbl | Add-Member -MemberType NoteProperty -Name 'Ec2Instances' -Value " " }


    # Scan for Elastic IPs
    try { $ec2eip = Get-EC2Address -ProfileName $prof -Region $r } catch {$ec2eip = $null}
    if ($ec2eip ){ $tbl | Add-Member -MemberType NoteProperty -Name 'Ec2ElasticIPs' -Value $ec2eip.count } else { $tbl | Add-Member -MemberType NoteProperty -Name 'Ec2ElasticIPs' -Value " " }


    # Scan for VPC
    try { $vpc = Get-EC2Vpc -ProfileName $prof -Region $r } catch {$vpc = $null} 
    if ($vpc){ $tbl | Add-Member -MemberType NoteProperty -Name 'VPC' -Value $vpc.count } else { $tbl | Add-Member -MemberType NoteProperty -Name 'VPC' -Value " " }

    # Scan for RDS

    try { $rds = Get-RDSDBCluster -ProfileName $prof -Region $r } catch {$rds = $null} 
    if ($rds){ $tbl | Add-Member -MemberType NoteProperty -Name 'RDS' -Value $rds.count } else { $tbl | Add-Member -MemberType NoteProperty -Name 'RDS' -Value " " }


    # Scan for ECS

    try { $ecs = Get-ECSClusters -ProfileName $prof -Region $r } catch {$ecs = $null} 
    if ($ecs){ $tbl | Add-Member -MemberType NoteProperty -Name 'ECS' -Value $ecs.count } else { $tbl | Add-Member -MemberType NoteProperty -Name 'ECS' -Value " " }



    # Scan for EKS

    try { $eks = Get-EKSClusterList -ProfileName $prof -Region $r } catch {$eks = $null} 
    if ($eks){ $tbl | Add-Member -MemberType NoteProperty -Name 'EKS' -Value $eks.count } else { $tbl | Add-Member -MemberType NoteProperty -Name 'EKS' -Value " " }


    # Scan for ECR

    try { $ecr = Get-ECRRepository -ProfileName $prof -Region $r } catch {$ecr = $null} 
    if ($ecr){ $tbl | Add-Member -MemberType NoteProperty -Name 'ECR' -Value $ecr.count } else { $tbl | Add-Member -MemberType NoteProperty -Name 'ECR' -Value " " }



    # Scan for Lambda

    try { $lambda = Get-LMFunctionList -ProfileName $prof -Region $r } catch {$lambda = $null} 
    if ($lambda){ $tbl | Add-Member -MemberType NoteProperty -Name 'Lambda' -Value $lambda.count } else { $tbl | Add-Member -MemberType NoteProperty -Name 'Lambda' -Value " " }



    $inv += $tbl



  }

  $inv | Format-Table

