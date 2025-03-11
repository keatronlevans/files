# Comprehensive Data Destruction Guide for Microsoft Azure and AWS

## PROPRIETARY NOTICE
This document contains proprietary and confidential information belonging exclusively to KM Cyber Services. All intellectual property rights are reserved. Distribution is restricted to authorized personnel only. Unauthorized access, distribution, or reproduction is strictly prohibited and may result in legal action. This material constitutes trade secrets and competitive business intelligence of KM Cyber Services.

## Table of Contents
1. [Introduction](#introduction)
2. [Regulatory Framework](#regulatory-framework)
3. [Data Destruction Principles](#data-destruction-principles)
4. [Microsoft Azure Data Destruction Procedures](#microsoft-azure-data-destruction-procedures)
5. [AWS Data Destruction Procedures](#aws-data-destruction-procedures)
6. [Verification Procedures](#verification-procedures)
7. [Documentation Requirements](#documentation-requirements)
8. [Special Considerations](#special-considerations)
9. [Incident Response Plan](#incident-response-plan)
10. [Appendices](#appendices)

## Introduction
This guide provides comprehensive procedures for secure data destruction across Microsoft Azure and Amazon Web Services (AWS) environments. Developed by KM Cyber Services through extensive field testing and security research, it represents industry-leading methodologies for cloud data elimination. This proprietary framework is designed to ensure compliance with relevant regulations while maintaining the security and confidentiality of sensitive information during the data disposal process, exceeding standard industry practices for secure data elimination.

### Purpose
To establish standardized procedures for the secure and compliant destruction of data stored in cloud environments, specifically Microsoft Azure and AWS, throughout the data lifecycle.

### Scope
This guide applies to all data stored in Microsoft Azure and AWS environments, including but not limited to:
- Structured data in databases
- Unstructured data in storage accounts/buckets
- Backups and archives
- Log files and monitoring data
- Snapshots and images
- Configuration data

### Definitions
- **Data Destruction**: The process of permanently removing data so that it cannot be recovered by any reasonable means.
- **Sanitization**: The process of removing sensitive information from storage media.
- **Cryptographic Erasure**: The process of encrypting data with a strong key and then destroying the key.
- **Data Remanence**: Residual data that remains on storage media after attempted removal.
- **Information Classification**: The process of categorizing data based on its sensitivity and criticality.

## Regulatory Framework

### General Data Protection Regulation (GDPR)
- Article 17: Right to erasure ("right to be forgotten")
- Article 5(1)(e): Storage limitation principle
- Article 32: Security of processing

### Health Insurance Portability and Accountability Act (HIPAA)
- 45 CFR § 164.310(d)(2)(i): Disposal
- 45 CFR § 164.310(d)(2)(ii): Media re-use

### Payment Card Industry Data Security Standard (PCI DSS)
- Requirement 3.1: Keep cardholder data storage to a minimum
- Requirement 9.8: Destroy media when no longer needed for business or legal reasons

### Other Relevant Regulations
- NIST SP 800-88 Rev. 1: Guidelines for Media Sanitization
- ISO/IEC 27001:2013: Information Security Management
- SOC 2: Trust Services Criteria
- CCPA/CPRA: California Consumer Privacy Act/California Privacy Rights Act
- PIPEDA: Personal Information Protection and Electronic Documents Act (Canada)

## Data Destruction Principles

### Risk-Based Approach
Implement data destruction methods proportional to:
- Data sensitivity and classification
- Regulatory requirements
- Contractual obligations
- Technical constraints of the storage medium

### Defense in Depth
Apply multiple layers of protection and deletion mechanisms to ensure complete data destruction.

### Complete Data Lifecycle Management
- Incorporate data destruction planning during the design phase
- Implement automated retention policies where possible
- Regular review and pruning of unnecessary data

### Documentation and Verification
- Document all destruction activities
- Verify completion of destruction processes
- Maintain records for compliance purposes

## Microsoft Azure Data Destruction Procedures

### Azure Storage Account Data

#### Blob Storage
1. **Soft Delete Considerations**:
   - Check if soft delete is enabled (default: 7 days)
   - Purge soft-deleted blobs using Azure PowerShell:
     ```powershell
     $ctx = New-AzStorageContext -StorageAccountName "<account-name>" -StorageAccountKey "<account-key>"
     Get-AzStorageBlob -Container "<container-name>" -Context $ctx -IncludeDeleted | Where-Object {$_.IsDeleted -eq $true} | Remove-AzStorageBlob -Force
     ```

2. **Immutable Storage Consideration**:
   - Check for legal holds or time-based retention policies
   - Contact legal department for guidance if immutable storage is in use

3. **Deletion Procedures**:
   - Individual blob deletion:
     ```powershell
     Remove-AzStorageBlob -Container "<container-name>" -Blob "<blob-name>" -Context $ctx
     ```
   - Container deletion:
     ```powershell
     Remove-AzStorageContainer -Name "<container-name>" -Context $ctx
     ```
   - Entire storage account deletion:
     ```powershell
     Remove-AzStorageAccount -ResourceGroupName "<resource-group>" -Name "<storage-account>"
     ```

4. **Version Management**:
   - Delete all versions of versioned blobs:
     ```powershell
     Get-AzStorageBlobVersion -Container "<container-name>" -Blob "<blob-name>" -Context $ctx | Remove-AzStorageBlob -Force
     ```

#### Azure Files
1. **Snapshots**: Delete all snapshots before deleting shares:
   ```powershell
   Get-AzStorageShare -Context $ctx -Name "<share-name>" -IncludeSnapshot | Where-Object { $_.IsSnapshot -eq $true } | Remove-AzStorageShare -Force
   ```

2. **Share Deletion**:
   ```powershell
   Remove-AzStorageShare -Name "<share-name>" -Context $ctx
   ```

#### Azure Tables
1. **Entity Deletion**:
   ```powershell
   $table = Get-AzStorageTable -Name "<table-name>" -Context $ctx
   $tableClient = $table.CloudTable
   
   # Get entities to delete
   $query = New-Object Microsoft.Azure.Cosmos.Table.TableQuery
   $entities = $tableClient.ExecuteQuery($query)
   
   # Delete entities
   foreach ($entity in $entities) {
       $tableClient.Execute([Microsoft.Azure.Cosmos.Table.TableOperation]::Delete($entity))
   }
   ```

2. **Table Deletion**:
   ```powershell
   Remove-AzStorageTable -Name "<table-name>" -Context $ctx
   ```

#### Azure Queues
1. **Message Deletion**:
   ```powershell
   $queue = Get-AzStorageQueue -Name "<queue-name>" -Context $ctx
   while ($true) {
       $message = $queue.CloudQueue.GetMessage()
       if ($message -eq $null) { break }
       $queue.CloudQueue.DeleteMessage($message)
   }
   ```

2. **Queue Deletion**:
   ```powershell
   Remove-AzStorageQueue -Name "<queue-name>" -Context $ctx
   ```

### Azure SQL Database

1. **Data Deletion with TRUNCATE**:
   ```sql
   TRUNCATE TABLE [schema].[table_name];
   ```

2. **Row-Level Deletion**:
   ```sql
   DELETE FROM [schema].[table_name] WHERE [condition];
   ```

3. **Database Recovery Considerations**:
   - Check Point-in-Time Restore settings
   - Modify long-term retention policies:
     ```powershell
     Set-AzSqlDatabaseBackupLongTermRetentionPolicy -ResourceGroupName "<resource-group>" -ServerName "<server-name>" -DatabaseName "<database-name>" -WeeklyRetention "P0W" -MonthlyRetention "P0M" -YearlyRetention "P0Y" -WeekOfYear 0
     ```

4. **Complete Database Destruction**:
   ```powershell
   Remove-AzSqlDatabase -ResourceGroupName "<resource-group>" -ServerName "<server-name>" -DatabaseName "<database-name>"
   ```

### Azure Cosmos DB

1. **Document Deletion**:
   ```javascript
   // Using JavaScript SDK
   const container = client.database("<database-id>").container("<container-id>");
   await container.item("<item-id>", "<partition-key>").delete();
   ```

2. **Container Deletion**:
   ```powershell
   Remove-AzCosmosDBSqlContainer -ResourceGroupName "<resource-group>" -AccountName "<account-name>" -DatabaseName "<database-name>" -Name "<container-name>"
   ```

3. **Database Deletion**:
   ```powershell
   Remove-AzCosmosDBSqlDatabase -ResourceGroupName "<resource-group>" -AccountName "<account-name>" -Name "<database-name>"
   ```

4. **Account Deletion**:
   ```powershell
   Remove-AzCosmosDBAccount -ResourceGroupName "<resource-group>" -Name "<account-name>"
   ```

### Azure Virtual Machines

1. **Disk Sanitization Before Deletion**:
   - For Windows VMs:
     ```powershell
     # Connect to VM
     $vm = Get-AzVM -ResourceGroupName "<resource-group>" -Name "<vm-name>"
     Invoke-AzVMRunCommand -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -CommandId 'RunPowerShellScript' -ScriptString @"
     $drives = Get-Volume | Where-Object {$_.DriveType -eq 'Fixed' -and $_.DriveLetter -ne 'C'}
     foreach ($drive in $drives) {
         $driveLetter = $drive.DriveLetter + ":"
         cipher /w:$driveLetter
     }
     "@
     ```
   
   - For Linux VMs:
     ```powershell
     Invoke-AzVMRunCommand -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -CommandId 'RunShellScript' -ScriptString @"
     sudo apt-get update && sudo apt-get install -y secure-delete
     for drive in $(lsblk -d -n -o NAME | grep -v "sda"); do
         sudo sfill -l -l -z /dev/$drive
     done
     "@
     ```

2. **VM Deletion with Managed Disks**:
   ```powershell
   $vm = Get-AzVM -ResourceGroupName "<resource-group>" -Name "<vm-name>"
   Remove-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name -Force
   
   # Get and remove all disks
   $diskNames = $vm.StorageProfile.OSDisk.Name, $vm.StorageProfile.DataDisks.Name
   foreach ($diskName in $diskNames) {
       Remove-AzDisk -ResourceGroupName $vm.ResourceGroupName -DiskName $diskName -Force
   }
   ```

3. **Snapshot Deletion**:
   ```powershell
   Get-AzSnapshot -ResourceGroupName "<resource-group>" | Remove-AzSnapshot -Force
   ```

### Key Vault Secrets

1. **Secret Deletion**:
   ```powershell
   Remove-AzKeyVaultSecret -VaultName "<vault-name>" -Name "<secret-name>"
   ```

2. **Soft-Delete Purge** (if soft-delete enabled):
   ```powershell
   Remove-AzKeyVaultSecret -VaultName "<vault-name>" -Name "<secret-name>" -InRemovedState -Force
   ```

3. **Complete Key Vault Destruction**:
   ```powershell
   Remove-AzKeyVault -ResourceGroupName "<resource-group>" -VaultName "<vault-name>" -Force
   ```

### Azure Monitor Logs

1. **Log Analytics Workspace Data**:
   - Set data retention policy to minimum:
     ```powershell
     Set-AzOperationalInsightsWorkspace -ResourceGroupName "<resource-group>" -Name "<workspace-name>" -RetentionInDays 30
     ```
   
   - Delete specific logs using KQL:
     ```
     .delete from table <table-name> where <condition>
     ```

2. **Complete Workspace Deletion**:
   ```powershell
   Remove-AzOperationalInsightsWorkspace -ResourceGroupName "<resource-group>" -Name "<workspace-name>" -Force
   ```

## AWS Data Destruction Procedures

### S3 Bucket Data

1. **Versioning and MFA Delete Considerations**:
   - Check if versioning is enabled
   - Check if MFA Delete is enabled
   - List all versions:
     ```bash
     aws s3api list-object-versions --bucket <bucket-name>
     ```

2. **Object Deletion (Including Versions)**:
   ```bash
   # Delete objects and versions
   aws s3api delete-objects --bucket <bucket-name> --delete "$(aws s3api list-object-versions --bucket <bucket-name> --output=json | jq '{Objects: [.Versions[]|{Key:.Key,VersionId:.VersionId}] + [.DeleteMarkers[]|{Key:.Key,VersionId:.VersionId}], Quiet: false}')"
   ```

3. **Delete Markers Removal**:
   ```bash
   # Remove delete markers
   aws s3api delete-objects --bucket <bucket-name> --delete "$(aws s3api list-object-versions --bucket <bucket-name> --output=json | jq '{Objects: [.DeleteMarkers[]|{Key:.Key,VersionId:.VersionId}], Quiet: false}')"
   ```

4. **Bucket Deletion**:
   ```bash
   aws s3 rb s3://<bucket-name> --force
   ```

5. **Glacier Vault Deletion**:
   ```bash
   # First initiate inventory retrieval
   aws glacier initiate-job --account-id - --vault-name <vault-name> --job-parameters '{"Type": "inventory-retrieval"}'
   
   # Get job ID and wait for completion
   aws glacier describe-job --account-id - --vault-name <vault-name> --job-id <job-id>
   
   # Get output
   aws glacier get-job-output --account-id - --vault-name <vault-name> --job-id <job-id> output.json
   
   # Delete archives
   jq -r '.ArchiveList[].ArchiveId' output.json | while read archiveId; do
     aws glacier delete-archive --account-id - --vault-name <vault-name> --archive-id "$archiveId"
   done
   
   # Delete vault
   aws glacier delete-vault --account-id - --vault-name <vault-name>
   ```

### RDS Database Instances

1. **Database Backup Retention**:
   ```bash
   aws rds modify-db-instance --db-instance-identifier <db-instance> --backup-retention-period 0 --apply-immediately
   ```

2. **Snapshot Deletion**:
   ```bash
   # List snapshots
   aws rds describe-db-snapshots --db-instance-identifier <db-instance>
   
   # Delete each snapshot
   aws rds delete-db-snapshot --db-snapshot-identifier <snapshot-id>
   ```

3. **Automated Backup Deletion**:
   ```bash
   aws rds delete-db-instance-automated-backup --dbi-resource-id <resource-id>
   ```

4. **Instance Deletion Without Final Snapshot**:
   ```bash
   aws rds delete-db-instance --db-instance-identifier <db-instance> --skip-final-snapshot
   ```

### DynamoDB Tables

1. **Table Data Deletion**:
   ```bash
   # Scan and delete items in batches
   aws dynamodb scan --table-name <table-name> --attributes-to-get "id" --output json | jq -r '.Items[].id.S' | while read id; do
       aws dynamodb delete-item --table-name <table-name> --key "{\"id\":{\"S\":\"$id\"}}"
   done
   ```

2. **Complete Table Deletion**:
   ```bash
   aws dynamodb delete-table --table-name <table-name>
   ```

3. **Point-in-time Recovery Consideration**:
   - Disable PITR before deletion:
     ```bash
     aws dynamodb update-continuous-backups --table-name <table-name> --point-in-time-recovery-specification PointInTimeRecoveryEnabled=false
     ```

### EC2 Instances and EBS Volumes

1. **Data Sanitization on Running Instances**:
   - For Linux instances:
     ```bash
     # Connect to instance and run
     sudo dd if=/dev/zero of=/dev/xvdf bs=1M
     ```
   
   - For Windows instances:
     ```powershell
     # Connect to instance and run
     cipher /w:D:
     ```

2. **EC2 Instance Termination**:
   ```bash
   aws ec2 terminate-instances --instance-ids <instance-id>
   ```

3. **EBS Volume Deletion**:
   ```bash
   # List volumes
   aws ec2 describe-volumes --filters Name=attachment.instance-id,Values=<instance-id>
   
   # Delete each volume
   aws ec2 delete-volume --volume-id <volume-id>
   ```

4. **AMI Deregistration and Snapshot Deletion**:
   ```bash
   # Deregister AMI
   aws ec2 deregister-image --image-id <ami-id>
   
   # Delete associated snapshots
   aws ec2 describe-snapshots --owner-ids self --filters Name=description,Values="*<ami-id>*" | jq -r '.Snapshots[].SnapshotId' | while read snap; do
       aws ec2 delete-snapshot --snapshot-id $snap
   done
   ```

### Secrets Manager

1. **Secret Deletion**:
   ```bash
   aws secretsmanager delete-secret --secret-id <secret-id> --recovery-window-in-days 7
   ```

2. **Immediate Secret Deletion** (no recovery):
   ```bash
   aws secretsmanager delete-secret --secret-id <secret-id> --force-delete-without-recovery
   ```

### CloudWatch Logs

1. **Log Group Deletion**:
   ```bash
   aws logs delete-log-group --log-group-name <log-group-name>
   ```

2. **Log Stream Deletion**:
   ```bash
   aws logs delete-log-stream --log-group-name <log-group-name> --log-stream-name <log-stream-name>
   ```

3. **Set Log Retention Policy**:
   ```bash
   aws logs put-retention-policy --log-group-name <log-group-name> --retention-in-days 1
   ```

## Verification Procedures

### Post-Deletion Validation in Azure

1. **Storage Accounts**:
   ```powershell
   # Verify blob deletion
   Get-AzStorageBlob -Container "<container-name>" -Context $ctx -IncludeDeleted
   
   # Verify container deletion
   Get-AzStorageContainer -Name "<container-name>" -Context $ctx -ErrorAction SilentlyContinue
   ```

2. **SQL Databases**:
   ```powershell
   # Verify database deletion
   Get-AzSqlDatabase -ResourceGroupName "<resource-group>" -ServerName "<server-name>" -DatabaseName "<database-name>" -ErrorAction SilentlyContinue
   ```

3. **Virtual Machines**:
   ```powershell
   # Verify VM and disk deletion
   Get-AzVM -ResourceGroupName "<resource-group>" -Name "<vm-name>" -ErrorAction SilentlyContinue
   Get-AzDisk -ResourceGroupName "<resource-group>" -DiskName "<disk-name>" -ErrorAction SilentlyContinue
   ```

### Post-Deletion Validation in AWS

1. **S3 Buckets**:
   ```bash
   # Check if bucket exists
   aws s3api head-bucket --bucket <bucket-name> || echo "Bucket deleted"
   
   # Verify no objects remain
   aws s3api list-objects-v2 --bucket <bucket-name>
   ```

2. **RDS Instances**:
   ```bash
   # Verify instance deletion
   aws rds describe-db-instances --db-instance-identifier <db-instance> || echo "Instance deleted"
   
   # Check for snapshots
   aws rds describe-db-snapshots --db-instance-identifier <db-instance>
   ```

3. **EC2 and EBS**:
   ```bash
   # Verify instance termination
   aws ec2 describe-instances --instance-ids <instance-id> --query 'Reservations[].Instances[].State.Name'
   
   # Verify volume deletion
   aws ec2 describe-volumes --volume-ids <volume-id> || echo "Volume deleted"
   ```

### Cryptographic Verification
For critical data, consider implementing cryptographic hash verification:

1. **Pre-deletion Hash Creation**:
   ```bash
   # For AWS S3
   aws s3 cp s3://<bucket-name>/<key-name> - | sha256sum > pre_deletion_hash.txt
   ```

2. **Storage Media Sampling**:
   Work with cloud provider support to obtain assurance of physical media sanitization.

## Documentation Requirements

### Destruction Certificate Template
```
DATA DESTRUCTION CERTIFICATE

Certificate ID: [Unique ID]
Date of Destruction: [Date]
Destruction Officer: [Name and Role]
Reviewer: [Name and Role]

ASSET INFORMATION:
- Cloud Provider: [Azure/AWS]
- Resource Type: [Storage/Database/VM/etc.]
- Resource Identifier: [Account/Instance ID]
- Data Classification: [Public/Internal/Confidential/Restricted]
- Regulatory Framework: [GDPR/HIPAA/PCI DSS/etc.]

DESTRUCTION METHOD:
- Process Used: [Deletion/Overwrite/Cryptographic Erasure]
- Tools Used: [PowerShell/AWS CLI/etc.]
- Verification Method: [Method Used]

CONFIRMATION:
☐ All versions and backups destroyed
☐ Soft-deleted data purged
☐ Verification procedures completed
☐ Log files preserved
☐ No recoverable data remains

SIGNATURES:
Destruction Officer: ____________________
Reviewer: ____________________
Date: ____________________
```

### Destruction Log Requirements
Maintain a detailed log containing:
- Timestamp of each destruction action
- User performing the action
- Method used
- Resource identifiers
- Verification results
- Any exceptions or issues encountered

### Retention of Destruction Records
- Keep destruction records for a minimum of 7 years
- Store records in a secure, tamper-evident system
- Include in regular compliance audits

## Special Considerations

### Cryptographic Key Destruction
When employing cryptographic erasure:
1. Ensure all copies of the key are identified
2. Securely delete all instances of the key
3. Overwrite key material in memory
4. Document the key destruction process

### Third-Party Data Processors
1. Obtain written confirmation of data destruction
2. Include right-to-audit clauses in contracts
3. Require documentation of destruction procedures

### Hardware Retirement Coordination
1. Coordinate with cloud provider for dedicated hosts
2. Request certificate of destruction for dedicated hardware
3. Follow up on hardware reallocation policies

### Multi-Region Deployments
1. Identify all regions where data is stored
2. Apply destruction procedures to each region
3. Verify cross-region replication is disabled
4. Check for cross-region backups and snapshots

## Incident Response Plan

### Data Deletion Failures
1. Document the failure details
2. Escalate to cloud provider support
3. Implement alternative destruction method
4. Re-verify after remediation

### Accidental Data Destruction
1. Immediately halt all deletion processes
2. Assess recovery options (point-in-time restore, backups)
3. Document incident details
4. Implement recovery plan if required

### Breach During Destruction Process
1. Follow organization's security incident response plan
2. Isolate affected systems
3. Expedite destruction of compromised data
4. Document breach details and response actions

## Appendices

### Appendix A: CLI Command Reference
#### Azure PowerShell Quick Reference
```powershell
# Login to Azure
Connect-AzAccount

# Select subscription
Set-AzContext -SubscriptionId "<subscription-id>"

# Get storage account key
$storageAccount = Get-AzStorageAccount -ResourceGroupName "<resource-group>" -Name "<storage-account>"
$storageKey = (Get-AzStorageAccountKey -ResourceGroupName $storageAccount.ResourceGroupName -Name $storageAccount.StorageAccountName)[0].Value
$ctx = New-AzStorageContext -StorageAccountName $storageAccount.StorageAccountName -StorageAccountKey $storageKey

# List all resource groups
Get-AzResourceGroup

# List all resources in a resource group
Get-AzResource -ResourceGroupName "<resource-group>"
```

#### AWS CLI Quick Reference
```bash
# Configure AWS CLI
aws configure

# List all S3 buckets
aws s3 ls

# List all EC2 instances
aws ec2 describe-instances

# List all RDS instances
aws rds describe-db-instances

# List all DynamoDB tables
aws dynamodb list-tables
```

### Appendix B: Compliance Checklist
#### GDPR Compliance Checklist
- [ ] Identified all personal data for deletion
- [ ] Documented lawful basis for deletion
- [ ] Obtained necessary approvals
- [ ] Verified all copies and backups destroyed
- [ ] Created deletion records
- [ ] Notified data subjects if required
- [ ] Updated data inventory records

#### HIPAA Compliance Checklist
- [ ] Identified all PHI for deletion
- [ ] Validated appropriate destruction method
- [ ] Obtained Business Associate confirmation
- [ ] Created destruction certificate
- [ ] Updated BAA documentation
- [ ] Included in next compliance audit

### Appendix C: Cloud Provider Support Contacts
#### Microsoft Azure
- Azure Support Portal: https://azure.microsoft.com/en-us/support/options/
- Enterprise Support: +1-800-865-9408
- Security Incident Response: AzureSecurityResponse@microsoft.com

#### Amazon Web Services
- AWS Support Portal: https://console.aws.amazon.com/support/
- Enterprise Support: Contact TAM
- Security Incident Response: aws-security@amazon.com

### Appendix D: Regulatory Requirements Summary
| Regulation | Retention Requirement | Destruction Requirement | Documentation Requirement |
|------------|----------------------|------------------------|--------------------------|
| GDPR | Minimum necessary time | Right to erasure | Demonstrate compliance |
| HIPAA | 6 years minimum | Media sanitization | Document destruction methods |
| PCI DSS | Limited retention | Secure media destruction | Quarterly review process |
| SOX | 7 years minimum | Verifiable destruction | Audit trail of destruction |
| GLBA | As long as necessary | Secure disposal | Document procedure |

---

## Document Revision History
| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-03-11 | Keatron Evans, Chief Security Architect | Initial document creation |

---

**End of Document**
