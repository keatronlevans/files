# Data Destruction Guide: AWS and Microsoft Azure

## Introduction

This comprehensive guide outlines step-by-step procedures for securely destroying data in Amazon Web Services (AWS) and Microsoft Azure environments. Following these procedures helps ensure compliance with data protection regulations and security best practices when decommissioning resources or implementing data lifecycle management.

---

## Part 1: AWS Data Destruction

### Section 1: AWS S3 Object and Bucket Destruction

#### Step 1: Enable Versioning and Configure Lifecycle Policies
1. Sign in to the AWS Management Console
2. Navigate to Amazon S3
3. Select the target bucket
4. Go to the "Properties" tab
5. Enable "Versioning" if not already enabled
6. Configure lifecycle rules:
   - Navigate to the "Management" tab
   - Select "Create lifecycle rule"
   - Name your rule (e.g., "Data-Destruction-Policy")
   - Define the scope (specific prefix or entire bucket)
   - Configure expiration actions for current and non-current versions
   - Set appropriate transition periods based on retention requirements
   - Save the rule

#### Step 2: Delete Individual Objects
1. Navigate to the target S3 bucket
2. Select objects to delete
3. Click "Delete"
4. Confirm deletion by typing "delete" in the confirmation field
5. Click "Delete objects"

#### Step 3: Empty and Delete Bucket
1. Select the bucket to delete
2. Click "Empty"
3. Type the bucket name to confirm
4. After emptying is complete, click "Delete"
5. Confirm deletion

#### Step 4: Delete MFA-Protected Buckets (if applicable)
1. Use AWS CLI with MFA token:
```bash
aws s3api delete-bucket --bucket bucket-name --mfa "serial-number mfa-code"
```

### Section 2: AWS EBS Volume Destruction

#### Step 1: Create Snapshot (for backup if needed)
1. Go to EC2 dashboard
2. Select "Volumes" from the navigation pane
3. Select the target volume
4. Click "Actions" > "Create Snapshot"
5. Provide a description
6. Click "Create Snapshot"

#### Step 2: Detach Volume
1. Select the volume
2. Click "Actions" > "Detach Volume"
3. Confirm the detachment
4. Wait until the state changes to "available"

#### Step 3: Delete Volume
1. Select the detached volume
2. Click "Actions" > "Delete Volume"
3. Confirm deletion

#### Step 4: Clean Snapshots (if needed)
1. Navigate to "Snapshots"
2. Select the snapshots to delete
3. Click "Actions" > "Delete Snapshot"
4. Confirm deletion

### Section 3: AWS RDS Database Destruction

#### Step 1: Create Final Backup (if needed)
1. Go to RDS dashboard
2. Select the database instance
3. Click "Actions" > "Take snapshot"
4. Name the snapshot
5. Click "Take Snapshot"

#### Step 2: Disable Deletion Protection
1. Select the database instance
2. Click "Modify"
3. Uncheck "Deletion protection"
4. Select "Apply immediately"
5. Click "Continue" and "Modify DB Instance"

#### Step 3: Delete Database Instance
1. Select the database instance
2. Click "Actions" > "Delete"
3. For the final snapshot, select "Create final snapshot" or "No final snapshot"
4. Check "Acknowledge" checkbox
5. Type the database name to confirm
6. Click "Delete"

#### Step 4: Delete Automated Backups
1. Go to "Automated backups"
2. Select backups to delete
3. Click "Delete"
4. Confirm deletion

### Section 4: AWS DynamoDB Table Destruction

#### Step 1: Create Backup (if needed)
1. Go to DynamoDB dashboard
2. Select the table
3. Click "Backup"
4. Name the backup
5. Click "Create"

#### Step 2: Delete Table
1. Select the table
2. Click "Delete table"
3. Confirm deletion by typing the table name
4. Click "Delete"

### Section 5: AWS Redshift Cluster Destruction

#### Step 1: Create Final Snapshot (if needed)
1. Go to Redshift dashboard
2. Select the cluster
3. Click "Actions" > "Create snapshot"
4. Name the snapshot
5. Click "Create snapshot"

#### Step 2: Delete Cluster
1. Select the cluster
2. Click "Actions" > "Delete"
3. Choose whether to create a final snapshot
4. Type "delete" to confirm
5. Click "Delete"

### Section 6: AWS Data Shredding with Lambda

#### Step 1: Create Lambda Function for Data Shredding
1. Go to Lambda dashboard
2. Click "Create function"
3. Select "Author from scratch"
4. Name your function (e.g., "DataShredder")
5. Select runtime (Python recommended)
6. Create or assign an appropriate IAM role
7. Click "Create function"
8. Enter code to overwrite data with random values before deletion:

```python
import boto3
import random
import string

def lambda_handler(event, context):
    s3 = boto3.resource('s3')
    
    bucket_name = event['bucket']
    object_key = event['key']
    
    # Generate random data
    random_data = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(1024 * 1024))
    
    # Overwrite file multiple times (DoD 5220.22-M style)
    for i in range(3):
        s3.Object(bucket_name, object_key).put(Body=random_data)
    
    # Final deletion
    s3.Object(bucket_name, object_key).delete()
    
    return {
        'statusCode': 200,
        'body': 'Object securely deleted'
    }
```

#### Step 2: Configure Trigger
1. Click "Add trigger"
2. Select an appropriate trigger (e.g., EventBridge for scheduled shredding)
3. Configure trigger details
4. Click "Add"

#### Step 3: Test and Execute
1. Click "Test"
2. Create a test event with bucket and key information
3. Execute the test
4. Verify results

---

## Part 2: Microsoft Azure Data Destruction

### Section 1: Azure Blob Storage Destruction

#### Step 1: Enable Soft Delete and Configure Lifecycle Management
1. Sign in to the Azure Portal
2. Navigate to your Storage Account
3. Select "Data protection" under Blob service
4. Enable "Soft delete for blobs"
5. Set retention period (1-365 days)
6. Save changes
7. Go to "Lifecycle management"
8. Create a new rule:
   - Name the rule
   - Define scope (containers/blobs)
   - Set "Delete blob" action
   - Configure base blobs and snapshots deletion
   - Save the rule

#### Step 2: Delete Individual Blobs
1. Navigate to the Storage Account
2. Go to "Containers"
3. Select the container
4. Select the blob(s) to delete
5. Click "Delete"
6. Confirm deletion

#### Step 3: Delete Container
1. Go to "Containers"
2. Select the container
3. Click "Delete"
4. Confirm deletion

#### Step 4: Purge Soft-Deleted Data (if immediate destruction required)
1. Go to "Containers"
2. Click "Show deleted containers"
3. Select the deleted container
4. Click "Undelete" if you need to recover data, or wait for automatic purge after retention period
5. For immediate purge, use Azure CLI:
```bash
az storage container delete-policy --account-name <storage-account> --name <container-name>
```

### Section 2: Azure Managed Disk Destruction

#### Step 1: Create Snapshot (if needed)
1. Go to "Disks" in Azure Portal
2. Select the target disk
3. Click "Create snapshot"
4. Configure snapshot options
5. Click "Create"

#### Step 2: Detach Disk from VM
1. Go to the VM using the disk
2. Click "Disks"
3. Find the data disk
4. Click the "Detach" icon
5. Save changes

#### Step 3: Delete the Disk
1. Go to "Disks"
2. Select the disk
3. Click "Delete"
4. Confirm deletion

#### Step 4: Secure Erase for Confidential Data
For confidential data, use disk encryption before deletion:
1. Go to "Disks"
2. Select the disk
3. Click "Encryption"
4. Enable encryption with platform-managed key
5. Save changes
6. After encryption completes, delete the disk

### Section 3: Azure SQL Database Destruction

#### Step 1: Create Final Backup (if needed)
1. Go to SQL databases
2. Select the database
3. Click "Export"
4. Configure export settings
5. Click "OK"

#### Step 2: Delete Database
1. Select the database
2. Click "Delete"
3. Confirm deletion by typing the database name
4. Click "Delete"

#### Step 3: Delete Backups
1. Go to the SQL Server
2. Click "Manage backups"
3. Select retention policies
4. Modify backup retention or click "Delete" for specific backups
5. Confirm changes

### Section 4: Azure Cosmos DB Destruction

#### Step 1: Export Data (if needed)
1. Go to Azure Cosmos DB accounts
2. Select the account
3. Go to "Data Explorer"
4. Click "Export" for collections needed
5. Configure export settings
6. Complete the export

#### Step 2: Delete Collections/Containers
1. Go to "Data Explorer"
2. Select the collection/container
3. Click "Delete Container"
4. Confirm deletion

#### Step 3: Delete Database
1. In "Data Explorer"
2. Select the database
3. Click "Delete Database"
4. Confirm deletion

#### Step 4: Delete Cosmos DB Account
1. Go to Cosmos DB accounts
2. Select the account
3. Click "Delete"
4. Type the account name to confirm
5. Click "Delete"

### Section 5: Azure Data Factory Pipeline for Data Destruction

#### Step 1: Create a Data Destruction Pipeline
1. Go to Azure Data Factory
2. Click "Author & Monitor"
3. Create a new pipeline
4. Name it (e.g., "Data-Destruction-Pipeline")
5. Add a "Set Variable" activity:
   - Define a variable to store confirmation
6. Add a "For Each" activity:
   - Configure it to iterate through data locations
7. Add a "Delete" activity inside the For Each:
   - Configure connection to your storage
   - Set parameters to identify data
8. Add error handling and logging activities

#### Step 2: Add Data Overwrite Step (for sensitive data)
1. Before the "Delete" activity, add a "Copy Data" activity
2. Configure source as a "Random data generator"
3. Set destination as the target files
4. Configure mapping to overwrite original data
5. Connect this to the "Delete" activity

#### Step 3: Execute and Monitor
1. Validate the pipeline
2. Publish changes
3. Click "Trigger" > "Trigger Now"
4. Confirm pipeline parameters
5. Monitor execution in the "Monitor" tab

### Section 6: Azure Key Vault Destruction (for Encrypted Data)

#### Step 1: Identify Keys and Secrets
1. Go to Key Vault
2. Select your vault
3. Go to "Keys" and "Secrets" sections
4. List all active keys and secrets

#### Step 2: Disable Keys and Secrets
1. Select each key/secret
2. Click "Disable"
3. Confirm disabling

#### Step 3: Delete Keys and Secrets
1. Select disabled key/secret
2. Click "Delete"
3. Confirm deletion
4. Note the purge protection period

#### Step 4: Enable Purge Protection (if not already enabled)
1. Go to Key Vault properties
2. Enable "Purge protection"
3. Save changes

---

## Part 3: Cross-Platform Considerations

### Section 1: Compliance Verification

#### Step 1: Document Destruction Process
1. Create detailed logs of all deletion activities
2. Include timestamps, resource identifiers, and personnel
3. Document verification steps
4. Store documentation according to compliance requirements

#### Step 2: Run Audit Reports
1. AWS: Use CloudTrail to verify deletion actions
2. Azure: Use Activity Log and Azure Monitor to confirm destruction
3. Generate comprehensive audit reports
4. Have a second person verify deletion completion

#### Step 3: Perform Data Discovery
1. AWS: Use Amazon Macie to scan for persistent sensitive data
2. Azure: Use Azure Purview to discover any remaining data
3. Document findings
4. Address any discovered data instances

### Section 2: Legal and Compliance Holds

#### Step 1: Verify Legal Requirements
1. Consult with legal department before destruction
2. Verify no legal holds exist on target data
3. Document legal approval for destruction
4. Ensure compliance with industry regulations (GDPR, HIPAA, etc.)

#### Step 2: Implement Destruction Certificates
1. Generate certificates of destruction
2. Include detailed inventory of destroyed resources
3. Have authorized personnel sign certificates
4. Store certificates according to policy

---

## Appendix A: CLI Commands for Automated Destruction

### AWS CLI Commands

```bash
# Delete all objects in a bucket
aws s3 rm s3://bucket-name --recursive

# Delete bucket
aws s3 rb s3://bucket-name --force

# Delete EBS volume
aws ec2 delete-volume --volume-id vol-1234567890abcdef0

# Delete RDS instance without final snapshot
aws rds delete-db-instance --db-instance-identifier mydbinstance --skip-final-snapshot
```

### Azure CLI Commands

```bash
# Delete Azure Storage container
az storage container delete --name container-name --account-name storageaccount

# Delete all blobs in a container
az storage blob delete-batch --source container-name --account-name storageaccount

# Delete managed disk
az disk delete --name diskname --resource-group resourcegroupname

# Delete SQL database
az sql db delete --name dbname --resource-group resourcegroupname --server servername
```

### PowerShell Commands

```powershell
# AWS PowerShell
Remove-S3Bucket -BucketName bucket-name -Force

# Azure PowerShell
Remove-AzStorageContainer -Name container-name -Context $ctx -Force
Remove-AzDisk -ResourceGroupName resourcegroupname -DiskName diskname -Force
```

## Appendix B: Data Destruction Verification Checklist

- [ ] All production data deleted from primary storage
- [ ] All backup copies identified and deleted
- [ ] All snapshots deleted
- [ ] Soft-deleted resources purged
- [ ] Encryption keys revoked/deleted where applicable
- [ ] Access permissions revoked for all users
- [ ] Audit logs verified for deletion actions
- [ ] Discovery scan performed to confirm deletion
- [ ] Destruction certificate generated
- [ ] Compliance documentation completed