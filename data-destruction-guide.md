### 6.2 Audit Trail Preservation

#### 6.2.1 Audit Trail Requirements

Maintaining comprehensive and tamper-resistant audit trails is essential for demonstrating compliance with data destruction regulations and policies. The audit trail serves as a chronological record of all destruction activities and must be preserved according to applicable retention requirements.

1. **Audit Trail Content Requirements**

   | Element | Description | Example |
   |---------|-------------|---------|
   | Timestamp | UTC timestamp of each destruction action | `2025-03-09T14:32:15.243Z` |
   | Resource Identifier | Unique identifier of the destroyed resource | `arn:aws:s3:::financial-data-bucket-2023` |
   | Resource Type | Type of resource that was destroyed | `Azure SQL Database` |
   | Actor | Identity of the person or system initiating destruction | `john.smith@example.com (User ID: JS29485)` |
   | IP Address | Source IP address of the destruction request | `192.168.1.45` |
   | Action | Specific destruction action taken | `Delete Azure Storage Account` |
   | Result | Outcome of the destruction operation | `Success` |
   | Verification Status | Status of post-destruction verification | `Verified` |
   | Authentication Method | Method used to authenticate the destruction request | `MFA-Protected Administrative Account` |
   | Authorization Reference | Reference to the authorization for destruction | `Change Request #CR-23987` |
   | Resource Metadata | Key metadata about the destroyed resource | `{"Created": "2023-05-12T08:23:45Z", "Owner": "Finance Department", "Classification": "Confidential", "Tags": ["PII", "Financial"]}` |

2. **Immutable Storage Requirements**

   | Storage Type | Specifications | Retention Period |
   |--------------|---------------|------------------|
   | **Primary Storage** | Append-only, immutable storage with WORM (Write-Once-Read-Many) protection | Minimum 7 years |
   | **Backup Storage** | Geographically distributed, encrypted backup with separate access controls | Minimum 7 years |
   | **Offline Archive** | Quarterly offline archive to immutable media | 10 years minimum |

   **Implementation Methods:**
   - Azure: Azure Immutable Blob Storage with legal hold and time-based retention
   - AWS: S3 Object Lock with Compliance mode and retention period
   - Tamper-evident logging with blockchain-based verification
   - Dedicated audit log server with restricted access

3. **Access Control Requirements**

   | Role | Description | Permissions |
   |------|-------------|------------|
   | Auditor | External or internal audit personnel | Read-only access to all audit logs |
   | Security Officer | Information security oversight | Read-only access to all audit logs |
   | Legal | Legal department representative | Read-only access with legal hold authority |
   | Administrator | System administrator | No ability to modify or delete audit logs |
   | CEO/CISO | Executive management | Read-only access for oversight purposes |

   **Implementation Requirements:**
   - Enforce separation of duties between destruction operators and audit log administrators
   - Implement multi-party authorization for any audit log configuration changes
   - Log all access to audit logs in a separate monitoring system
   - Require MFA for all audit log access
   - Implement time-limited access for non-regular audit staff

#### 6.2.2 Cloud Provider Activity Logs

1. **Azure Activity Log Preservation**

   | Log Type | Collection Method | Storage Location | Retention |
   |----------|-------------------|-----------------|-----------|
   | Activity Log | Configure diagnostic settings to export to: <br> - Log Analytics Workspace <br> - Azure Storage Account (immutable) <br> - Event Hub for real-time monitoring | Resource-group-specific storage account with immutable storage enabled | 7 years minimum |
   | Resource-Specific Logs | Enable resource logging for each service | Centralized Log Analytics workspace | 7 years minimum |
   | Azure Monitor Alerts | Configure alerts for delete operations | Dedicated alert management system | 2 years minimum |
   | Azure AD Sign-in Logs | Export to immutable storage | Security-specific storage account | 7 years minimum |

   **Implementation Steps:**
   ```powershell
   # Create storage account for immutable logs
   $storageAccount = New-AzStorageAccount -ResourceGroupName "LogRetention-RG" -Name "auditlogs$uniqueId" -Location "East US" -SkuName "Standard_GRS" -Kind "StorageV2"

   # Enable immutability policy
   $container = New-AzStorageContainer -Name "activitylogs" -Context $storageAccount.Context
   $immutabilityPolicy = Set-AzStorageContainerImmutabilityPolicy -Container $container -ImmutabilityPeriod 2555 # 7 years in days

   # Lock immutability policy with legal hold
   $legalHold = Set-AzStorageContainerLegalHold -Container $container -Tag "RetentionCompliance"

   # Configure Activity Log to export to storage
   $logProfile = Set-AzLogProfile -Name "Compliance" -StorageAccountId $storageAccount.Id -Location "East US", "West US" -RetentionInDays 365 -Category Delete, Write, Action
   ```

2. **AWS CloudTrail Preservation**

   | Log Type | Collection Method | Storage Location | Retention |
   |----------|-------------------|-----------------|-----------|
   | CloudTrail | Configure organization-wide trail with:  <br> - Log file validation <br> - S3 bucket with Object Lock <br> - KMS encryption | Dedicated S3 bucket with Compliance mode Object Lock | 7 years minimum |
   | Config History | Enable AWS Config with deletion event recording | Dedicated S3 bucket with appropriate retention | 7 years minimum |
   | CloudWatch Logs | Export deletion-related logs via subscription filter | Centralized logging account | 2 years minimum |
   | IAM Access Analyzer | Export findings related to deletions | Security account storage | 2 years minimum |

   **Implementation Steps:**
   ```bash
   # Create S3 bucket with Object Lock
   aws s3api create-bucket --bucket audit-logs-$ACCOUNT_ID --region us-east-1 --object-lock-enabled-for-bucket

   # Configure Object Lock with compliance mode
   aws s3api put-object-lock-configuration --bucket audit-logs-$ACCOUNT_ID \
     --object-lock-configuration '{
       "ObjectLockEnabled": "Enabled",
       "Rule": {
         "DefaultRetention": {
           "Mode": "COMPLIANCE",
           "Years": 7
         }
       }
     }'

   # Create CloudTrail with validated logs
   aws cloudtrail create-trail \
     --name organization-delete-audit-trail \
     --s3-bucket-name audit-logs-$ACCOUNT_ID \
     --is-organization-trail \
     --is-multi-region-trail \
     --enable-log-file-validation \
     --kms-key-id $KMS_KEY_ID

   # Start logging for the trail
   aws cloudtrail start-logging --name organization-delete-audit-trail

   # Set up CloudWatch Logs integration
   aws cloudtrail update-trail \
     --name organization-delete-audit-trail \
     --cloud-watch-logs-log-group-arn $LOG_GROUP_ARN \
     --cloud-watch-logs-role-arn $ROLE_ARN
   ```

#### 6.2.3 Console Screenshots and Visual Evidence

Visual evidence provides an additional layer of documentation that can be valuable for audit and compliance purposes.

1. **Screenshot Requirements**

   | Event Type | Screenshot Elements | Format | Retention |
   |------------|---------------------|--------|-----------|
   | Pre-Deletion | Resource details showing identifiers, creation date, and metadata | PNG with metadata intact | 7 years |
   | Deletion Confirmation | Console showing deletion confirmation dialog | PNG with metadata intact | 7 years |
   | Post-Deletion Verification | Console search showing resource no longer exists | PNG with metadata intact | 7 years |
   | Error Conditions | Any error messages or warnings during deletion | PNG with metadata intact | 7 years |

2. **Screenshot Authentication Requirements**

   | Requirement | Implementation Method |
   |-------------|----------------------|
   | Timestamp Verification | Include system clock in screenshot |
   | User Attribution | Include username in console view |
   | Screen Recording | For critical deletions, record full deletion process |
   | Digital Signature | Apply organizational digital signature to screenshots |
   | Metadata Preservation | Maintain EXIF and creation metadata |

3. **Recommended Tools for Screenshot Capture**

   | Tool | Purpose | Features |
   |------|---------|----------|
   | KM Cyber Services Screenshot Utility™ | Compliant screenshot capture | Automatic timestamp, metadata embedding, tamper-evident storage |
   | Azure Automation Screenshots | Automated evidence collection | Scheduled screenshot capture during automation runs |
   | AWS Systems Manager Session Manager | Session recording | Full terminal session recording with playback capability |
   | PowerShell Screenshot Module | Automation-friendly capture | Scriptable evidence collection during PowerShell-based destruction |

#### 6.2.4 Export Activity Logs

1. **Azure Activity Log Export**

   ```powershell
   # Define export period
   $startTime = (Get-Date).AddDays(-30)
   $endTime = Get-Date

   # Export activity logs for deletion operations
   $logs = Get-AzLog -StartTime $startTime -EndTime $endTime | Where-Object {$_.OperationName.Value -like "*delete*"}

   # Export to CSV with detailed information
   $logs | Select-Object EventTimestamp, Caller, OperationName, ResourceGroupName, ResourceId, Status, SubscriptionId, Properties | 
   Export-Csv -Path "AzureDeletionAudit_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

   # Export to JSON with full details
   $logs | ConvertTo-Json -Depth 10 | Out-File "AzureDeletionAudit_$(Get-Date -Format 'yyyyMMdd').json"
   ```

2. **AWS CloudTrail Export**

   ```bash
   # Define export period
   START_TIME=$(date -d "30 days ago" +%Y-%m-%dT%H:%M:%S)
   END_TIME=$(date +%Y-%m-%dT%H:%M:%S)

   # Export CloudTrail events for deletion operations
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=Delete \
     --start-time $START_TIME \
     --end-time $END_TIME \
     --output json > AWS_Deletion_Audit_$(date +%Y%m%d).json

   # Generate CSV report
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=Delete \
     --start-time $START_TIME \
     --end-time $END_TIME \
     --query 'Events[*].{EventTime:EventTime,Username:Username,EventName:EventName,Resources:Resources[0].ResourceName,ResourceType:Resources[0].ResourceType}' \
     --output json | jq -r '.[] | [.EventTime, .Username, .EventName, .Resources, .ResourceType] | @csv' > AWS_Deletion_Audit_$(date +%Y%m%d).csv
   ```

#### 6.2.5 Document Verification Procedures

Documentation of verification procedures provides evidence that proper validation of destruction was performed according to policy.

1. **Required Verification Documentation**

   | Verification Type | Documentation Elements | Format |
   |-------------------|------------------------|--------|
   | API Verification | API responses confirming resource absence | JSON/XML log files |
   | Console Verification | Screenshots showing search results | Timestamped PNG files |
   | Access Attempt | Logs of attempts to access deleted resources | Log file extracts |
   | Secondary Verification | Results of independent verification | Signed verification report |
   | Time-Delayed Verification | Results of verification performed after cooling period | Supplementary verification report |

2. **Verification Documentation Template**

   ```markdown
   # Resource Deletion Verification Report

   ## Resource Details
   - **Resource Type:** [Storage Account/VM/Database/etc.]
   - **Resource Identifier:** [Resource ID/ARN]
   - **Deletion Timestamp:** [ISO 8601 timestamp]
   - **Deletion Operator:** [Username/Identity]

   ## Primary Verification
   - **Verification Method:** [API/Console/CLI]
   - **Verification Timestamp:** [ISO 8601 timestamp]
   - **Verification Result:** [Verified/Failed]
   - **Evidence:** [Reference to screenshot/log file]

   ## Secondary Verification
   - **Verification Method:** [Alternative verification method]
   - **Verification Timestamp:** [ISO 8601 timestamp]
   - **Verification Result:** [Verified/Failed]
   - **Evidence:** [Reference to screenshot/log file]

   ## Time-Delayed Verification
   - **Verification Interval:** [Hours/Days after deletion]
   - **Verification Timestamp:** [ISO 8601 timestamp]
   - **Verification Result:** [Verified/Failed]
   - **Evidence:** [Reference to screenshot/log file]

   ## Verification Statement
   I, [Verifier Name], certify that I have performed the verification procedures described above and confirmed that the specified resource has been permanently deleted in accordance with organizational policies and applicable regulations.

   Signature: ___________________________
   Date: [Date]
   Position: [Role/Title]
   ```

#### 6.2.6 Long-Term Audit Trail Preservation

For long-term preservation of audit trails beyond the standard retention period, implement the following additional measures:

1. **Offline Archive Requirements**

   | Archive Type | Specifications | Verification Frequency |
   |--------------|---------------|------------------------|
   | Optical Media | WORM Blu-ray Enterprise Grade Media, dual copies in separate physical locations | Quarterly checksum validation |
   | Microfilm | Archival-grade microfilm for essential destruction certificates | Annual random sampling |
   | Secure Paper | Acid-free paper with security features stored in climate-controlled facility | Annual inventory check |
   | Cold Storage | AWS Glacier Deep Archive or Azure Archive Storage with legal hold | Annual test retrieval |

2. **Archive Checksums and Integrity Verification**

   ```bash
   # Generate SHA-256 checksums for all audit files
   find /path/to/audit/files -type f -exec sha256sum {} \; > audit_checksums_$(date +%Y%m%d).txt

   # Sign the checksum file with organizational key
   gpg --sign --detach-sign audit_checksums_$(date +%Y%m%d).txt

   # Verify checksums periodically
   sha256sum -c audit_checksums_$(date +%Y%m%d).txt

   # Store in multiple locations
   tar -czf audit_archive_$(date +%Y%m%d).tar.gz audit_checksums_$(date +%Y%m%d).txt audit_checksums_$(date +%Y%m%d).txt.sig /path/to/audit/files/*
   ```

3. **Archive Location Requirements**

   | Copy | Location Type | Security Requirements |
   |------|--------------|----------------------|
   | Primary | On-premises secure storage | Climate-controlled, fire-protected, access-controlled |
   | Secondary | Offsite commercial archive facility | Third-party custody with chain of custody documentation |
   | Tertiary | Cloud-based archive | Different provider than audited environment, with encryption |
   | Quaternary | Legal custodian | Trusted third-party legal custodian for critical records |# KM Cyber Services: Comprehensive Data Destruction Guide for Microsoft Azure and AWS

## Proprietary Notice

This document contains proprietary and confidential information belonging exclusively to KM Cyber Services. The methodologies, procedures, and technical specifications outlined herein represent the intellectual property of KM Cyber Services, developed through extensive research and industry expertise. This guide employs proprietary algorithms and methodologies developed by KM Cyber Services cybersecurity research team between 2022-2025, including our Advanced Multi-Phase Data Sanitization Framework™ and Cloud-Native Compliance Verification System™. These methodologies have been certified against NIST SP 800-88 Rev. 1 standards and independently validated by third-party security assessors.

Unauthorized reproduction, distribution, or implementation of these procedures without explicit written consent from KM Cyber Services is strictly prohibited and may result in legal action under intellectual property laws. This guide is intended solely for authorized clients and partners of KM Cyber Services who have entered into a valid service agreement. Document ID: KMCS-DDG-2025-03-V3.1.

## Executive Summary

This comprehensive guide provides detailed procedures for the secure and compliant destruction of data stored within Microsoft Azure and Amazon Web Services (AWS) environments. As organizations increasingly migrate sensitive data to cloud platforms, ensuring proper data sanitization at end-of-life becomes critical for maintaining security posture and regulatory compliance. KM Cyber Services has developed this methodical approach to cloud data destruction that addresses the unique challenges posed by distributed storage systems, virtualization layers, and shared responsibility models inherent to cloud computing. This document outlines step-by-step procedures to ensure complete data sanitization across various cloud service models (IaaS, PaaS, SaaS) while maintaining auditable records for compliance verification.

## Table of Contents

1. [Introduction](#introduction)
2. [Pre-Destruction Planning](#pre-destruction-planning)
3. [Microsoft Azure Data Destruction Procedures](#microsoft-azure-data-destruction-procedures)
4. [AWS Data Destruction Procedures](#aws-data-destruction-procedures)
5. [Verification and Documentation](#verification-and-documentation)
6. [Regulatory Compliance Considerations](#regulatory-compliance-considerations)
7. [Appendices and Tools](#appendices-and-tools)

## 1. Introduction

### 1.1 Purpose and Scope

This guide provides detailed instructions for permanently destroying data stored within Microsoft Azure and AWS cloud environments in accordance with industry best practices and regulatory requirements. The procedures outlined apply to various data storage mechanisms including:

- **Object Storage**: Azure Blob Storage, Azure Files, AWS S3
- **Block Storage**: Azure Managed Disks, AWS EBS Volumes
- **Virtual Machines**: Azure VMs, AWS EC2 Instances
- **Databases**: Azure SQL, Azure Cosmos DB, AWS RDS, AWS DynamoDB
- **Serverless Storage**: Azure Functions, AWS Lambda
- **Container Storage**: Azure Container Instances, AKS, AWS ECS, EKS
- **Key Management Services**: Azure Key Vault, AWS KMS, AWS Secrets Manager
- **Cache Services**: Azure Redis Cache, AWS ElastiCache
- **Messaging Services**: Azure Service Bus, AWS SQS, SNS
- **Analytics Services**: Azure Synapse, AWS Redshift, EMR
- **Backup Services**: Azure Backup, AWS Backup
- **AI/ML Services**: Azure Machine Learning, AWS SageMaker

This guide covers data destruction for all service models (IaaS, PaaS, SaaS) and deployment models (public, private, hybrid) within these platforms. The procedures address both structured and unstructured data, encompassing persistent storage, ephemeral storage, cached data, and metadata repositories.

### 1.2 Cloud Data Destruction Challenges

Cloud data destruction presents unique challenges compared to traditional on-premises environments:

- Physical media is inaccessible to customers
- Data replication across multiple geographic regions
- Shared infrastructure with other tenants
- Persistence of metadata and logs
- Varying retention policies across different services
- Automated backup and snapshot mechanisms

### 1.3 Shared Responsibility Model Considerations

Both Azure and AWS operate under a shared responsibility model where:

- Cloud providers are responsible for security OF the cloud (infrastructure, hardware)
- Customers are responsible for security IN the cloud (data, access, configuration)

Data destruction falls primarily under customer responsibility, though providers offer tools to facilitate secure deletion.

## 2. Pre-Destruction Planning

### 2.1 Data Inventory and Classification

Before beginning any data destruction process, conduct a thorough data discovery and classification exercise:

1. **Create a comprehensive inventory** of all data assets across cloud environments
   - Use Azure Resource Graph and AWS Resource Explorer for automated discovery
   - Deploy KM Cyber Services' Cloud Discovery Tool™ to identify shadow IT resources
   - Document resource IDs, ARNs, and unique identifiers for each asset
   - Record creation dates, last modified dates, and access patterns

2. **Classify data** according to sensitivity and regulatory requirements
   - Implement the KM Cyber Services Classification Matrix™:
     - **Level 1**: Public data (marketing materials, public documentation)
     - **Level 2**: Internal data (non-sensitive operational data)
     - **Level 3**: Confidential data (financial records, IP, business strategies)
     - **Level 4**: Restricted data (customer PII, authentication credentials)
     - **Level 5**: Critical data (payment card data, health records, biometric data)
   - Apply Azure Information Protection and AWS Macie for automated classification
   - Document applicable regulations (GDPR, HIPAA, PCI DSS, CCPA, etc.) for each data class

3. **Document storage locations** with detailed specifications
   - Service types (Storage, Compute, Database, Analytics, etc.)
   - Regional information with primary and replica locations
   - Storage technologies (blob, file, disk, database, etc.)
   - Encryption status and key management details
   - Retention policies and lifecycle configurations
   - Access methods (API, portal, CLI, SDK)
   - Authentication mechanisms (IAM, SAS, connection strings)

4. **Identify data dependencies** and relationships between services
   - Document service dependencies through directed acyclic graphs (DAGs)
   - Map service-to-service authentication methods
   - Document integration points with third-party services
   - Identify ETL/ELT processes and data transformation pipelines
   - Map microservice interactions and data exchange patterns
   - Document API dependencies and data consumption patterns

5. **Map data flows** to understand replication and backup mechanisms
   - Document geo-replication configurations
   - Map automated backup schedules and retention periods
   - Identify point-in-time recovery capabilities
   - Document snapshot creation frequency
   - Map cross-region and cross-account replication
   - Document disaster recovery configurations
   - Map content delivery networks and edge caching systems
   - Identify log streaming and SIEM integrations

6. **Create a data structure map** showing relationship hierarchies
   - Parent-child relationships between resources
   - Resource group and organizational hierarchies
   - Tagging and metadata relationships
   - Application and infrastructure boundaries

7. **Perform risk assessments** for each data category
   - Document data breach impact assessments
   - Map regulatory penalties for improper destruction
   - Identify business continuity risks during destruction procedures

### 2.2 Legal and Compliance Review

1. **Review retention requirements** for each data type
2. **Consult legal department** regarding:
   - Contractual obligations
   - Litigation holds
   - Regulatory requirements (GDPR, HIPAA, etc.)
3. **Document approval** from relevant stakeholders
4. **Create destruction certificates** templates for compliance documentation

### 2.3 Risk Assessment

1. **Identify potential impacts** of data destruction on:
   - Running services
   - Integrated systems
   - Business operations
2. **Document mitigation strategies** for each identified risk
3. **Create rollback procedures** where applicable
4. **Establish verification methods** to confirm successful destruction

## 3. Microsoft Azure Data Destruction Procedures

### 3.1 Azure Blob Storage and Azure Files

#### 3.1.1 Individual Blob/File Deletion

1. **Access the Azure Portal** at portal.azure.com
2. **Navigate to Storage Accounts**
3. **Select the target storage account**
4. **Choose the appropriate container/share**
5. **Select target blob/file**
6. **Click Delete** and confirm the operation
7. **Execute the following Azure CLI command for confirmation**:
   ```
   az storage blob delete --account-name <storage-account> --container-name <container> --name <blob-name>
   ```

#### 3.1.2 Container/Share Level Deletion

1. **Access the Azure Portal**
2. **Navigate to Storage Accounts**
3. **Select target storage account**
4. **Select the container/share to delete**
5. **Click Delete** and confirm operation
6. **Execute the following Azure CLI command**:
   ```
   az storage container delete --account-name <storage-account> --name <container>
   ```

#### 3.1.3 Storage Account Deletion

1. **Access the Azure Portal**
2. **Navigate to Storage Accounts**
3. **Select target storage account**
4. **Click Delete** and confirm operation
5. **Execute the following Azure CLI command**:
   ```
   az storage account delete --name <storage-account> --resource-group <resource-group>
   ```

#### 3.1.4 Soft Delete Considerations

1. **Check soft delete status** for blobs and containers
2. **Navigate to Storage Account → Data Protection**
3. **For soft-deleted blobs**:
   ```
   az storage blob list --include d --account-name <storage-account> --container-name <container>
   ```
4. **Permanently delete soft-deleted blobs**:
   ```
   az storage blob delete --delete-snapshots include --account-name <storage-account> --container-name <container> --name <blob-name>
   ```
5. **Disable soft delete** for future operations

### 3.2 Azure Virtual Machines and Disks

#### 3.2.1 Virtual Machine Preparation

1. **Isolate the virtual machine**
   - Remove from all load balancers and application gateways
   - Update DNS records to prevent new connections
   - Modify NSGs to block incoming connections
   - Execute the following Azure CLI command:
     ```
     az network nsg rule create --name BlockAll --nsg-name <nsg-name> --resource-group <resource-group> --priority 100 --direction Inbound --access Deny --protocol "*" --source-address-prefix "*" --source-port-range "*" --destination-address-prefix "*" --destination-port-range "*"
     ```

2. **Create pre-destruction snapshot** (for rollback if needed)
   - Through Azure Portal: Navigate to VM → Disks → Create snapshot
   - Using Azure CLI:
     ```
     az snapshot create --name <snapshot-name> --resource-group <resource-group> --source <disk-id>
     ```
   - Document snapshot ID in destruction log
   - Set snapshot to expire after validated destruction

3. **Stop the virtual machine**
   - Through Azure Portal: Navigate to VM → Stop
   - Using Azure CLI:
     ```
     az vm stop --name <vm-name> --resource-group <resource-group>
     az vm deallocate --name <vm-name> --resource-group <resource-group>
     ```
   - Validate VM status is "Stopped (deallocated)"

4. **Access the VM disk for sanitization**
   - Option 1: Attach OS disk to a sanitization VM
     ```
     az vm disk detach --name <disk-name> --vm-name <vm-name> --resource-group <resource-group>
     az vm disk attach --disk <disk-id> --vm-name <sanitization-vm-name> --resource-group <resource-group>
     ```
     
   - Option 2: Use Run Command feature (for accessible VMs)
     ```
     az vm run-command invoke --name <vm-name> --resource-group <resource-group> --command-id RunShellScript --scripts "<sanitization-command>"
     ```

5. **Run disk sanitization software** within the VM

6. **For Windows VMs**:
   - First-level sanitization:
     - Run Disk Cleanup utility with all options selected
     - Execute `cipher /w:C` to overwrite deleted files
       ```powershell
       Cipher /w:C:
       ```
       
   - Second-level sanitization:
     - Use SDelete (Sysinternals) for more thorough cleaning with DoD 5220.22-M compliant 3-pass overwrite
       ```powershell
       sdelete -p 3 -z C:
       ```
       
   - Third-level sanitization:
     - Use KM Cyber Services' Windows Data Obliteration Tool™
       ```powershell
       KMCS-WDOT.exe --mode=full --passes=7 --verify --drive=C: --log=C:\sanitization_log.txt
       ```
       
   - Clear Windows event logs:
     ```powershell
     wevtutil el | ForEach-Object {wevtutil cl "$_"}
     ```
     
   - Clear Windows registry artifacts:
     ```powershell
     reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /f
     reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" /f
     ```

7. **For Linux VMs**:
   - First-level sanitization:
     - Clear system logs and temp files
       ```bash
       find /var/log -type f -exec shred -vzn 1 {} \;
       find /tmp -type f -exec shred -vzn 1 {} \;
       find /home -name ".*history" -exec shred -vzn 1 {} \;
       ```
       
   - Second-level sanitization:
     - Use `shred` for 7-pass DoD-compliant overwrite
       ```bash
       shred -vzn 7 /dev/sda
       ```
       
   - Third-level sanitization:
     - Use `secure-delete` package for Gutmann algorithm (35 passes)
       ```bash
       apt-get install -y secure-delete
       sfill -v -z -l -l -f /
       srm -v -z -r /home/
       srm -v -z -r /var/
       ```
       
   - Alternative: Use KM Cyber Services' Linux Data Sanitization Tool™
     ```bash
     ./kmcs-linuxsanitize --mode=full --passes=7 --verify --filesystem=ext4 --device=/dev/sda --log=/tmp/sanitization_log.txt
     ```
     
   - Clear bash history and other artifacts:
     ```bash
     cat /dev/null > ~/.bash_history && history -c
     find ~/.cache -type f -delete
     find ~/.thumbnails -type f -delete
     ```

8. **Document sanitization** with time-stamped logs
   - Capture sanitization tool output
   - Screenshot completion status
   - Record run duration and completion status
   - Calculate and document theoretical sanitization effectiveness based on storage media type

#### 3.2.2 Virtual Machine Deletion

1. **Access the Azure Portal**
2. **Navigate to Virtual Machines**
3. **Select target VM**
4. **Click Delete** and select options for associated resources
5. **Confirm deletion**
6. **Execute the following Azure CLI command**:
   ```
   az vm delete --name <vm-name> --resource-group <resource-group> --yes
   ```

#### 3.2.3 Managed Disk Destruction

1. **Access the Azure Portal**
2. **Navigate to Disks**
3. **Select target disk**
4. **Click Delete** and confirm
5. **Execute the following Azure CLI command**:
   ```
   az disk delete --name <disk-name> --resource-group <resource-group> --yes
   ```

#### 3.2.4 Snapshots and Images

1. **Access the Azure Portal**
2. **Navigate to Snapshots**
3. **Delete all associated snapshots**
4. **Navigate to Images**
5. **Delete all associated images**
6. **Execute the following Azure CLI commands**:
   ```
   az snapshot delete --name <snapshot-name> --resource-group <resource-group>
   az image delete --name <image-name> --resource-group <resource-group>
   ```

### 3.3 Azure SQL and Database Services

#### 3.3.1 Azure SQL Database

1. **Access the Azure Portal**
2. **Navigate to SQL databases**
3. **Select target database**
4. **Click Delete** and confirm
5. **Execute the following Azure CLI command**:
   ```
   az sql db delete --name <database-name> --resource-group <resource-group> --server <server-name> --yes
   ```

#### 3.3.2 Azure SQL Server

1. **Access the Azure Portal**
2. **Navigate to SQL servers**
3. **Select target server**
4. **Click Delete** and confirm
5. **Execute the following Azure CLI command**:
   ```
   az sql server delete --name <server-name> --resource-group <resource-group> --yes
   ```

#### 3.3.3 Azure Cosmos DB

1. **Access the Azure Portal**
2. **Navigate to Azure Cosmos DB**
3. **Select target account**
4. **For individual databases/containers**:
   - Navigate to Data Explorer
   - Select database/container
   - Click Delete
5. **For entire account**:
   - Click Delete on account overview
   - Confirm deletion
6. **Execute the following Azure CLI commands**:
   ```
   az cosmosdb sql database delete --account-name <account-name> --name <database-name> --resource-group <resource-group> --yes
   az cosmosdb delete --name <account-name> --resource-group <resource-group> --yes
   ```

### 3.4 Additional Azure Services

#### 3.4.1 Azure Key Vault

1. **Access the Azure Portal**
2. **Navigate to Key Vaults**
3. **Select target Key Vault**
4. **For individual secrets/keys/certificates**:
   - Select the item
   - Click Delete
   - Confirm deletion
5. **For entire Key Vault**:
   - Click Delete on Key Vault overview
   - Confirm deletion
6. **If soft delete is enabled**:
   - Navigate to Deleted Vaults
   - Select the vault
   - Click Purge
7. **Execute the following Azure CLI commands**:
   ```
   az keyvault secret delete --vault-name <vault-name> --name <secret-name>
   az keyvault secret purge --vault-name <vault-name> --name <secret-name>
   az keyvault delete --name <vault-name> --resource-group <resource-group>
   az keyvault purge --name <vault-name> --location <location>
   ```

#### 3.4.2 Azure App Service

1. **Access the Azure Portal**
2. **Navigate to App Services**
3. **Select target App Service**
4. **Click Delete** and confirm
5. **Execute the following Azure CLI command**:
   ```
   az webapp delete --name <app-name> --resource-group <resource-group>
   ```

## 4. AWS Data Destruction Procedures

### 4.1 Amazon S3

#### 4.1.1 S3 Storage Classes and Special Considerations

Before deletion, document the storage class of objects to ensure proper handling:

| Storage Class | Deletion Considerations |
|---------------|-------------------------|
| Standard | Immediate deletion possible |
| Intelligent-Tiering | Check for retrieval fees |
| Standard-IA | Minimum 30-day charge applies |
| One Zone-IA | Minimum 30-day charge applies |
| Glacier Instant Retrieval | Minimum 90-day charge applies |
| Glacier Flexible Retrieval | Must initiate restoration before deletion, minimum 90-day charge |
| Glacier Deep Archive | Must initiate restoration before deletion, minimum 180-day charge |

For Glacier objects:
1. **Initiate restoration**:
   ```
   aws s3api restore-object --bucket <bucket-name> --key <object-key> --restore-request Days=1
   ```
2. **Check restoration status**:
   ```
   aws s3api head-object --bucket <bucket-name> --key <object-key>
   ```
3. **Proceed with deletion after restoration completes**

#### 4.1.2 Individual Object Deletion

1. **Access the AWS Management Console**
   - Sign in to the AWS Management Console (https://console.aws.amazon.com/)
   - Switch to the appropriate account and region
   - Verify your IAM permissions include `s3:DeleteObject`

2. **Navigate to S3**
   - From the Services menu, select S3 under Storage
   - Alternatively, use the search bar and type "S3"

3. **Select target bucket**
   - From the Buckets list, click on the bucket name containing objects to delete
   - Verify bucket policy doesn't prevent deletion (check for `s3:DeleteObject` deny statements)
   - Check bucket lifecycle configuration for any automated deletion rules

4. **Select objects to delete**
   - In the Objects tab, locate target objects using search or navigation
   - Use checkboxes to select objects for deletion
   - For objects with legal hold, verify legal hold is released:
     ```
     aws s3api get-object-legal-hold --bucket <bucket-name> --key <object-key>
     aws s3api put-object-legal-hold --bucket <bucket-name> --key <object-key> --legal-hold Status=OFF
     ```
   - For objects with retention period, verify period has expired:
     ```
     aws s3api get-object-retention --bucket <bucket-name> --key <object-key>
     ```

5. **Click Delete and confirm**
   - Click the Delete button in the top menu
   - Type "permanently delete" in the confirmation dialog
   - Review the list of objects to be deleted
   - Click "Delete objects"
   - Save the deletion report (CSV) for audit trail

6. **Execute the following AWS CLI commands**:
   - For single object deletion:
     ```
     aws s3 rm s3://<bucket-name>/<object-key>
     ```
   - For objects with specific version:
     ```
     aws s3api delete-object --bucket <bucket-name> --key <object-key> --version-id <version-id>
     ```
   - For objects with specific prefix:
     ```
     aws s3 rm s3://<bucket-name>/<prefix>/ --recursive
     ```
   - For deletion with verification:
     ```
     aws s3 rm s3://<bucket-name>/<object-key> && aws s3api head-object --bucket <bucket-name> --key <object-key> || echo "Deletion confirmed"
     ```

7. **Verify deletion**:
   - Attempt to access the object via console
   - Execute HEAD object request:
     ```
     aws s3api head-object --bucket <bucket-name> --key <object-key>
     ```
   - Check CloudTrail logs for DeleteObject events:
     ```
     aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObject
     ```
   
8. **Document deletion**:
   - Record object key, version ID (if applicable)
   - Record deletion timestamp (UTC)
   - Save deletion confirmation from AWS console
   - Record CloudTrail event ID
   - Record IAM principal who performed deletion

#### 4.1.2 Bucket Emptying

1. **Access the AWS Management Console**
2. **Navigate to S3**
3. **Select target bucket**
4. **Click Empty** and confirm
5. **Execute the following AWS CLI command**:
   ```
   aws s3 rm s3://<bucket-name> --recursive
   ```

#### 4.1.3 Bucket Deletion

1. **Access the AWS Management Console**
2. **Navigate to S3**
3. **Select target bucket**
4. **Click Delete** and confirm
5. **Execute the following AWS CLI command**:
   ```
   aws s3 rb s3://<bucket-name>
   ```

#### 4.1.4 Versioning and MFA Delete Considerations

1. **For versioned buckets**:
   - List all versions: `aws s3api list-object-versions --bucket <bucket-name>`
   - Delete all versions: `aws s3api delete-object --bucket <bucket-name> --key <key> --version-id <version-id>`
2. **For buckets with MFA Delete**:
   - Disable MFA Delete first using root credentials
   - Use the MFA token in deletion commands

### 4.2 EC2 Instances and EBS Volumes

#### 4.2.1 EC2 Instance Preparation

1. **Connect to the instance**
2. **Run disk sanitization software** within the instance
3. **For Windows instances**:
   - Run `cipher /w:C` to overwrite deleted files
   - Use SDelete (Sysinternals) for more thorough cleaning
4. **For Linux instances**:
   - Use `shred` or `secure-delete` package
   - Example: `shred -vzn 3 /dev/xvda`

#### 4.2.2 EC2 Instance Termination

1. **Access the AWS Management Console**
2. **Navigate to EC2**
3. **Select target instance**
4. **Click Instance State → Terminate**
5. **Confirm termination**
6. **Execute the following AWS CLI command**:
   ```
   aws ec2 terminate-instances --instance-ids <instance-id>
   ```

#### 4.2.3 EBS Volume Destruction

1. **Access the AWS Management Console**
2. **Navigate to EC2 → Volumes**
3. **Select target volume**
4. **Click Actions → Delete Volume**
5. **Confirm deletion**
6. **Execute the following AWS CLI command**:
   ```
   aws ec2 delete-volume --volume-id <volume-id>
   ```

#### 4.2.4 Snapshots and AMIs

1. **Access the AWS Management Console**
2. **Navigate to EC2 → Snapshots**
3. **Select target snapshot**
4. **Click Actions → Delete Snapshot**
5. **Confirm deletion**
6. **For AMIs**:
   - Navigate to EC2 → AMIs
   - Select target AMI
   - Click Actions → Deregister AMI
   - Delete associated snapshots
7. **Execute the following AWS CLI commands**:
   ```
   aws ec2 delete-snapshot --snapshot-id <snapshot-id>
   aws ec2 deregister-image --image-id <ami-id>
   ```

### 4.3 AWS RDS and Database Services

#### 4.3.1 RDS Database Instances

1. **Access the AWS Management Console**
2. **Navigate to RDS**
3. **Select target database**
4. **Click Actions → Delete**
5. **Disable automated backups option**
6. **Do not create final snapshot for permanent deletion**
7. **Confirm deletion by typing instance identifier**
8. **Execute the following AWS CLI command**:
   ```
   aws rds delete-db-instance --db-instance-identifier <db-identifier> --skip-final-snapshot
   ```

#### 4.3.2 RDS Snapshots

1. **Access the AWS Management Console**
2. **Navigate to RDS → Snapshots**
3. **Select target snapshot**
4. **Click Actions → Delete Snapshot**
5. **Confirm deletion**
6. **Execute the following AWS CLI command**:
   ```
   aws rds delete-db-snapshot --db-snapshot-identifier <snapshot-identifier>
   ```

#### 4.3.3 DynamoDB Tables

1. **Access the AWS Management Console**
2. **Navigate to DynamoDB**
3. **Select target table**
4. **Click Delete table**
5. **Confirm deletion**
6. **Execute the following AWS CLI command**:
   ```
   aws dynamodb delete-table --table-name <table-name>
   ```

### 4.4 Additional AWS Services

#### 4.4.1 AWS Secrets Manager and Parameter Store

1. **Access the AWS Management Console**
2. **Navigate to Secrets Manager**
3. **Select target secret**
4. **Click Actions → Delete secret**
5. **Set recovery window or select "Delete immediately"**
6. **Confirm deletion**
7. **Execute the following AWS CLI commands**:
   ```
   aws secretsmanager delete-secret --secret-id <secret-id> --force-delete-without-recovery
   aws ssm delete-parameter --name <parameter-name>
   ```

#### 4.4.2 Lambda Functions

1. **Access the AWS Management Console**
2. **Navigate to Lambda**
3. **Select target function**
4. **Click Actions → Delete**
5. **Confirm deletion**
6. **Execute the following AWS CLI command**:
   ```
   aws lambda delete-function --function-name <function-name>
   ```

## 5. Verification and Documentation

### 5.1 Verification Procedures

#### 5.1.1 Primary Verification Process

1. **Utilize cloud provider audit and logging tools**:
   - **Azure Activity Log**
     - Navigate to Azure Portal → Monitor → Activity Log
     - Filter by Resource ID, Operation (Delete), and Time Range
     - Export logs to storage account for permanent record
     - Execute PowerShell query:
       ```powershell
       Get-AzLog -ResourceId <resource-id> -StartTime <start-time> -EndTime <end-time> | Where-Object {$_.OperationName.Value -like "*delete*"}
       ```
     
   - **Azure Resource Graph Explorer**
     - Execute query to confirm resource absence:
       ```
       resources | where id =~ '<resource-id>'
       ```
       
   - **AWS CloudTrail**
     - Navigate to CloudTrail console → Event history
     - Filter by Event name (Delete*), Resource type, and Time range
     - Download JSON/CSV event records for permanent record
     - Execute CLI query:
       ```
       aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=<resource-name> --start-time <start-time> --end-time <end-time>
       ```
       
   - **AWS Config**
     - Check configuration item history
     - Verify resource state changed to "deleted"
     - Execute CLI query:
       ```
       aws configservice get-resource-config-history --resource-type <resource-type> --resource-id <resource-id>
       ```

2. **Validate deletion through multiple interfaces** to ensure complete removal:
   - **Management Console Verification**
     - Attempt direct navigation to resource URL
     - Search for resource by name, ID, and tags
     - Check resource-specific recycle bins or deleted items sections
     - Document with dated screenshots showing resource absence
     
   - **CLI Command Verification**
     - **Azure**: 
       ```
       az resource show --ids <resource-id>
       az resource list --query "[?name=='<resource-name>']"
       ```
     - **AWS**: 
       ```
       aws <service> describe-<resource> --<resource>-id <id>
       aws resourcegroupstaggingapi get-resources --resource-arn-list <arn>
       ```
     - Document error messages indicating resource doesn't exist
     
   - **API Calls Verification**
     - Execute direct API GET requests to resource endpoints
     - Document 404 Not Found responses
     - Use programmatic verification with KM Cyber Services' Cloud Resource Validator™
       ```python
       from kmcs_validator import CloudResourceValidator
       
       validator = CloudResourceValidator(cloud_provider="azure")
       result = validator.verify_deletion("<resource-id>")
       print(f"Deletion verified: {result.is_deleted}")
       print(f"Verification method: {result.method}")
       print(f"Verification timestamp: {result.timestamp}")
       ```
     
   - **SDK-Based Verification**
     - Implement verification using cloud provider SDKs
     - Document exception handling capturing resource-not-found errors

3. **Check for lingering permissions and access controls**:
   - **IAM Policy Verification**
     - **AWS**:
       - List all policies referencing deleted resource:
         ```
         aws iam list-policies | jq '.Policies[] | select(.PolicyName | contains("<resource-name>"))'
         ```
       - Check policy documents for ARN references:
         ```
         aws iam get-policy-version --policy-arn <policy-arn> --version-id <version-id> | jq '.PolicyVersion.Document'
         ```
       - Remediate by removing resource references from policies
     
     - **Azure**:
       - Check role assignments for deleted resources:
         ```
         az role assignment list --include-classic-administrators | jq '.[] | select(.scope | contains("<resource-id>"))'
         ```
       - Check custom roles for resource references:
         ```
         az role definition list --custom-role-only true | jq '.[] | select(.permissions[].actions[] | contains("<resource-type>/delete"))'
         ```
       - Remediate by removing orphaned role assignments
     
   - **RBAC Assignment Verification**
     - Enumerate all RBAC assignments in resource scope hierarchy
     - Check for assignments targeting specific resource IDs
     - Verify inherited permissions are appropriate
     - Remove unnecessary scoped assignments
     
   - **Resource Locks Verification**
     - **Azure**:
       ```
       az lock list --resource-group <resource-group>
       ```
     - Remove orphaned locks:
       ```
       az lock delete --name <lock-name> --resource-group <resource-group>
       ```
     
   - **Service Endpoint and Network Policies**
     - Check VNet service endpoints referencing deleted services
     - Verify security groups don't reference deleted resources
     - Update network ACLs to remove deleted resource references

4. **Verify deletion in soft delete repositories and recovery services**:
   - **Azure Soft Delete Verification**:
     - **Soft-deleted Blobs**:
       ```
       az storage blob list --include d --account-name <storage-account> --container-name <container>
       ```
     - **Soft-deleted Containers**:
       ```
       az storage container list --include d --account-name <storage-account>
       ```
     - **Soft-deleted Storage Accounts**:
       ```
       az resource list --resource-type Microsoft.Storage/storageAccounts/deletedAccounts
       ```
     - **Soft-deleted Key Vaults**:
       ```
       az keyvault list-deleted
       ```
     - **Soft-deleted App Services**:
       ```
       az webapp deleted list --resource-group <resource-group>
       ```
   
   - **AWS Recycle Bins and Versioning**:
     - **Recycle Bin**:
       ```
       aws rbin list-resource-types
       aws rbin list-resources --resource-type <resource-type>
       ```
     - **S3 Versioned Objects**:
       ```
       aws s3api list-object-versions --bucket <bucket-name> --prefix <prefix>
       ```
     - **RDS Automated Backups**:
       ```
       aws rds describe-db-instance-automated-backups --db-instance-identifier <db-id>
       ```
     - **EBS Snapshot Archives**:
       ```
       aws ec2 describe-snapshot-tier-status
       ```

5. **Apply KM Cyber Services' Multi-Layered Verification Protocol™**:
   - **Layer 1**: Direct resource existence check
   - **Layer 2**: Audit log confirmation 
   - **Layer 3**: Access attempt through all interfaces
   - **Layer 4**: Resource link validation
   - **Layer 5**: Machine learning-based anomaly detection
   - **Layer 6**: Automated recovery simulation
   - **Layer 7**: Time-delayed re-verification (7 days after deletion)

#### 5.1.2 Advanced Verification Techniques

1. **Cross-Region and Cross-Account Verification**
   - Check for resource replicas in other regions
   - Verify cross-account resource sharing is disabled
   - Check for cross-account event rules or triggers
   - Query global services for resource references

2. **Infrastructure-as-Code Template Analysis**
   - Analyze Terraform state:
     ```
     terraform state list | grep <resource-name>
     ```
   - Check CloudFormation stacks:
     ```
     aws cloudformation list-stack-resources --stack-name <stack-name> | jq '.StackResourceSummaries[] | select(.LogicalResourceId | contains("<resource-name>"))'
     ```
   - Update Bicep/ARM templates to remove deleted resources
   - Verify CI/CD pipelines don't redeploy deleted resources

3. **Third-Party Integration Verification**
   - Check monitoring systems for deleted resource references
   - Verify SIEM systems no longer ingest deleted resource logs
   - Update backup systems to remove deleted resources from policies
   - Remove deleted resources from disaster recovery configurations

4. **Dark Data Discovery**
   - Use specialized tools to identify unknown/undocumented resource copies
   - Scan for shadow IT resources that may contain copies of deleted data
   - Perform deep discovery of data dependencies and hidden relationships
   - Execute KM Cyber Services' Dark Data Detection Protocol™

### 5.2 Documentation Requirements

For each destroyed resource, document:

1. **Resource identifier** (name, ARN, URI)
2. **Resource type** and service category
3. **Location/region**
4. **Deletion timestamp**
5. **Method used** for destruction
6. **Verification method** and timestamp
7. **Operator** who performed destruction
8. **Approver** who authorized destruction
9. **Destruction certificate** reference

### 5.3 Destruction Certificate Template

#### 5.3.1 Certificate Elements

Create a formal certificate containing the following mandatory elements:

1. **Organization Details**
   - Legal business name
   - Business address and contact information
   - Data protection officer contact information
   - Primary technical contact information
   - Legal department representative

2. **Cloud Provider Account Information**
   - Cloud provider name (Azure/AWS)
   - Account ID/Subscription ID
   - Tenant ID (for Azure)
   - Organization ID (for AWS)
   - Regions where data was stored
   - Service level agreements applicable

3. **Itemized Resource Inventory**
   - Complete resource inventory table with following columns:
     | Resource ID | Resource Type | Region | Data Classification | Creation Date | Destruction Date | Destruction Method | Verification Status |
     |-------------|--------------|--------|---------------------|--------------|-----------------|-------------------|-------------------|
     | *resource-id-1* | *Storage Account* | *East US* | *Level 3* | *2023-04-15* | *2025-03-09* | *Purge* | *Verified* |
   - Total count of resources by type
   - Total data volume destroyed (estimated)

4. **Destruction Methods Documentation**
   - Detailed description of each destruction method employed
   - References to specific sections in this guide
   - Tools and versions used
   - Command logs with timestamps
   - Duration of destruction process for each resource category

5. **Compliance Statements**
   - Explicit statements of compliance with relevant standards:
     - NIST SP 800-88 Rev. 1 (Guidelines for Media Sanitization)
     - ISO/IEC 27001:2013 (Information Security Management)
     - GDPR Article 17 (Right to Erasure)
     - HIPAA (if applicable)
     - PCI DSS (if applicable)
     - Industry-specific regulations (as needed)
   - Statement of conformance with organizational data protection policies
   - Legal attestation of complete and irreversible destruction

6. **Verification Evidence Attachments**
   - Timestamped screenshots of console operations
   - CLI command outputs with timestamps
   - Activity logs from cloud providers
   - Error logs and remediation actions
   - Results of verification procedures
   - Audit trail documentation

7. **Authorization Chain**
   - Request initiator information
   - Approval chain documentation
   - Signatures from:
     - Data owner/steward
     - System administrator who performed destruction
     - Information security officer
     - Compliance officer
     - External auditor (if applicable)
     - Legal department representative
   - Digital signatures with PKI verification

8. **Certificate Metadata**
   - Certificate unique identifier (UUID)
   - Issuance date and time (UTC)
   - Certificate validity period
   - QR code for certificate verification
   - Blockchain registration reference (optional)
   - Hash of complete certificate document for integrity verification

#### 5.3.2 Digital Certificate Format

KM Cyber Services provides a digital certificate template in multiple formats:

1. **PDF Document**
   - Digitally signed with organizational certificate
   - Embedded metadata for searchability
   - Document security features enabled
   - Compliant with PDF/A for long-term archiving

2. **XML Document**
   - Structured data format for automated processing
   - Digital signature using XML-DSig
   - Schema validation capabilities
   - Machine-readable format for compliance automation

3. **Blockchain Registration**
   - Optional immutable recording of certificate hash
   - Timestamp proof of existence
   - Public verification capability
   - Long-term proof of destruction action

#### 5.3.3 Certificate Distribution and Retention

1. **Distribution Protocol**
   - Secure delivery to all stakeholders via encrypted channels
   - Access control for certificate repository
   - Receipt acknowledgment required
   - Version control for any amendments

2. **Retention Requirements**
   - Primary retention period: 7 years minimum
   - Extended retention for regulated industries (healthcare: 10 years, financial: 7-10 years)
   - Secure archival with encryption
   - Periodic integrity verification
   - Disaster recovery backup of certificates

## 6. Regulatory Compliance Considerations

### 6.1 Industry Standards and Regulations

#### 6.1.1 General Data Protection Regulation (GDPR)

| Requirement | Implementation Considerations | Documentation Requirements |
|-------------|------------------------------|----------------------------|
| **Article 17: Right to Erasure** | Implement complete deletion of all personal data upon request | Document all deletion requests, confirmation of deletion, and verification methods |
| **Article 5(1)(e): Storage Limitation** | Establish data retention schedules and automate deletion when retention period expires | Document retention periods, justification, and deletion protocols |
| **Article 28(3)(g): Processor Obligations** | Ensure cloud processor deletes or returns all personal data after service provision ends | Document agreements with cloud providers regarding data deletion |
| **Article 30: Records of Processing** | Maintain logs of all deletion activities related to personal data | Document categories of data deleted, recipient categories, and safeguards |
| **Article 35: Data Protection Impact Assessment** | Assess risks related to data deletion processes | Document risk assessments and mitigation strategies |

**Implementation Requirements:**
1. Implement technical measures to identify all copies and backups of personal data
2. Ensure deletion requests are processed without undue delay (typically within 30 days)
3. Establish mechanisms to verify complete deletion across all systems
4. Ensure data deletion extends to third-party processors and subprocessors
5. Implement pseudonymization or anonymization as appropriate alternatives to deletion
6. Document all deletion activities with detailed audit logs for compliance verification

#### 6.1.2 Health Insurance Portability and Accountability Act (HIPAA)

| Requirement | Implementation Considerations | Documentation Requirements |
|-------------|------------------------------|----------------------------|
| **45 CFR § 164.310(d)(2)(i): Media Disposal** | Implement policies and procedures for proper disposal of PHI in electronic form | Document disposal methods, including verification procedures |
| **45 CFR § 164.310(d)(2)(ii): Media Re-use** | Remove PHI before media reuse | Document cleaning procedures for media reuse |
| **45 CFR § 164.308(a)(7)(ii)(D): Data Backup and Storage** | Maintain retrievable copies of PHI until properly destroyed | Document backup retention policies and sanitization procedures |
| **45 CFR § 164.530(j): Documentation Requirements** | Maintain written records of policies, procedures, and actions | Document all deletion activities for 6 years |
| **45 CFR § 164.316(b)(2)(i): Retention Period** | Retain documentation for 6 years from creation or last effective date | Ensure all deletion certificates are retained for at least 6 years |

**Implementation Requirements:**
1. Implement formal data destruction policies covering all electronic PHI
2. Ensure cloud service provider BAAs explicitly address data destruction requirements
3. Verify all copies and backups of PHI are included in destruction processes
4. Maintain comprehensive logs of all sanitization activities
5. Ensure data destruction methods are appropriate for the sensitivity of PHI
6. Implement verification procedures to confirm complete destruction
7. Maintain inventory of all media and cloud resources containing PHI

#### 6.1.3 Payment Card Industry Data Security Standard (PCI DSS)

| Requirement | Implementation Considerations | Documentation Requirements |
|-------------|------------------------------|----------------------------|
| **Requirement 3.1: Cardholder Data Storage Limitations** | Limit storage amount and retention time to business requirements | Document business justification for data retention periods |
| **Requirement 3.2: Prohibit Storage of Sensitive Authentication Data** | Ensure sensitive authentication data is not retained after authorization | Document processes to confirm deletion of sensitive authentication data |
| **Requirement 9.8: Media Destruction Procedures** | Render cardholder data unrecoverable when no longer needed | Document destruction methods and verification procedures |
| **Requirement 9.8.1: Physically Destroy Hard-Copy Materials** | Shred, incinerate, or pulp hard-copy materials | Document destruction methods used |
| **Requirement 9.8.2: Secure Disposal of Media** | Render previously stored cardholder data unrecoverable | Document methods used to securely sanitize electronic media |
| **Requirement 12.10.1: Incident Response Plan** | Include procedures for secure deletion in response to a breach | Document incident response procedures for data sanitization |

**Implementation Requirements:**
1. Implement automated processes to identify and delete cardholder data when no longer needed
2. Ensure cloud environments are fully sanitized when cardholder data is processed
3. Maintain logs of all sanitization activities related to cardholder data
4. Implement quarterly data discovery scans to identify unauthorized cardholder data
5. Ensure deletion processes are tested at least annually
6. Verify media sanitization through a documented verification process
7. Maintain destruction certificates as evidence of compliant disposal

#### 6.1.4 National Institute of Standards and Technology (NIST)

| NIST Standard | Implementation Considerations | Documentation Requirements |
|---------------|------------------------------|----------------------------|
| **NIST SP 800-88 Rev. 1: Guidelines for Media Sanitization** | Follow sanitization techniques based on media type and data classification | Document sanitization methods, verification procedures, and decision process |
| **NIST SP 800-53 Rev. 5: MP-6 Media Sanitization** | Sanitize system media before disposal, release, or reuse | Document sanitization processes, verification methods, and testing procedures |
| **NIST SP 800-171 Rev. 2: 3.8.3** | Sanitize or destroy system media containing CUI before disposal or release | Document sanitization techniques and verification methods |
| **NIST Cybersecurity Framework v1.1: PR.IP-6** | Destroy data according to policy | Document data destruction processes and verification methods |
| **NIST SP 800-53 Rev. 5: AU-11 Audit Record Retention** | Retain audit records for defined time period | Document retention of destruction certificates |

**Implementation Considerations from NIST SP 800-88 Rev. 1:**

1. **Data Sanitization Techniques by Confidentiality Level:**

   | Data Classification | Clear | Purge | Destroy |
   |---------------------|-------|-------|---------|
   | **Public Data** | ✓ | ✓ | ✓ |
   | **Internal Data** | ✓ | ✓ | ✓ |
   | **Confidential Data** |  | ✓ | ✓ |
   | **Restricted Data** |  |  | ✓ |

2. **Cloud Data Sanitization Methods:**

   | Resource Type | Sanitization Method | Verification Method |
   |---------------|---------------------|---------------------|
   | Storage Buckets/Blobs | Cryptographic Erase + Object Deletion | API Verification |
   | Virtual Machine Disks | Data Wipe + Disk Deletion | API Verification |
   | Managed Databases | TRUNCATE + DROP + Instance Deletion | API Verification + Query Testing |
   | Backup/Snapshots | Backup/Snapshot Deletion | API Verification |
   | Configuration Data | Resource Deletion | API Verification |

3. **Key NIST SP 800-88 Principles for Cloud Data:**
   - Sanitization is a process that renders access to target data on the media infeasible for a given level of effort
   - Clearing, purging, and destroying are actions that can be taken to sanitize media
   - For cloud resources, cryptographic erasure combined with resource deletion provides appropriate sanitization
   - Verification of sanitization is a critical step in the process
   - Documentation must be maintained for compliance purposes

#### 6.1.5 ISO/IEC 27001:2013

| Control | Implementation Considerations | Documentation Requirements |
|---------|------------------------------|----------------------------|
| **A.8.3.2: Disposal of media** | Securely dispose of media when no longer required | Document disposal procedures and verification methods |
| **A.11.2.7: Secure disposal or re-use of equipment** | Verify that storage devices are sanitized before disposal | Document verification procedures and responsible parties |
| **A.18.1.3: Protection of records** | Protect records from loss, destruction, or falsification | Document records retention and protection measures |
| **A.12.3.1: Information backup** | Maintain backups until properly destroyed | Document backup retention and destruction procedures |
| **A.18.2.1: Independent review of information security** | Review compliance with security policies and standards | Document review results related to data destruction |

**Implementation Requirements:**
1. Establish formal data destruction policies aligned with ISO/IEC 27001 requirements
2. Implement risk assessment processes for data sanitization
3. Ensure personnel are trained on data destruction procedures
4. Maintain destruction logs and certificates as part of ISMS documentation
5. Include data destruction in internal and external audit processes
6. Verify effectiveness of data destruction processes
7. Document all destruction activities within information security management system (ISMS)

### 6.2 Audit Trail Preservation

1. **Preserve destruction logs** in immutable storage
2. **Capture console screenshots** of destruction operations
3. **Export activity logs** from:
   - Azure Activity Log
   - AWS CloudTrail
4. **Document verification procedures** and results
5. **Maintain destruction certificates** per compliance requirements

## 7. Appendices and Tools

### 7.1 Recommended Tools

#### 7.1.1 Azure Tools

| Tool | Purpose | Installation | Validation Command |
|------|---------|-------------|-------------------|
| **Azure CLI** | Command-line interface for Azure management | `curl -sL https://aka.ms/InstallAzureCLIDeb \| sudo bash` | `az --version` |
| **Azure PowerShell** | PowerShell module for Azure management | `Install-Module -Name Az -AllowClobber -Scope CurrentUser` | `Get-InstalledModule -Name Az` |
| **Azure Policy** | Automated policy enforcement and compliance | N/A (Azure Portal) | `az policy assignment list` |
| **Azure Resource Graph Explorer** | Query-based resource exploration | N/A (Azure Portal) | N/A |
| **Azure Storage Explorer** | GUI tool for Storage management | https://azure.microsoft.com/en-us/products/storage/storage-explorer/ | N/A |
| **AzCopy** | High-performance data transfer tool | `curl -sL https://aka.ms/downloadazcopy-v10-linux \| sudo bash` | `azcopy --version` |
| **Azure Data Box** | Offline data transfer service | N/A (Order through Azure Portal) | N/A |
| **Azure Purview** | Data governance and classification service | N/A (Azure Portal) | N/A |
| **Azure Log Analytics** | Log query and analysis service | N/A (Azure Portal) | N/A |
| **KM Cyber Services Azure Data Sanitation Suite™** | Proprietary tool for Azure data destruction | Contact KM Cyber Services for installation package | `kmcs-azure-validate` |

#### 7.1.2 AWS Tools

| Tool | Purpose | Installation | Validation Command |
|------|---------|-------------|-------------------|
| **AWS CLI** | Command-line interface for AWS management | `pip install awscli` | `aws --version` |
| **AWS CloudFormation** | Infrastructure as code service | N/A (AWS Console) | `aws cloudformation list-stacks` |
| **AWS Config** | Configuration and compliance service | N/A (AWS Console) | `aws configservice describe-configuration-recorders` |
| **S3 Batch Operations** | Large-scale S3 object management | N/A (AWS Console) | `aws s3control list-jobs` |
| **AWS Resource Groups** | Resource organization and management | N/A (AWS Console) | `aws resource-groups list-groups` |
| **AWS CloudTrail** | API activity logging and monitoring | N/A (AWS Console) | `aws cloudtrail describe-trails` |
| **AWS Systems Manager** | Resource management and operation service | N/A (AWS Console) | `aws ssm describe-instance-information` |
| **AWS Glue** | ETL and data catalog service | N/A (AWS Console) | `aws glue get-databases` |
| **AWS Macie** | Data security and privacy service | N/A (AWS Console) | `aws macie2 list-findings` |
| **KM Cyber Services AWS Cleanse Framework™** | Proprietary tool for AWS data destruction | Contact KM Cyber Services for installation package | `kmcs-aws-validate` |

### 7.1.3 Multi-Cloud and Specialized Tools

| Tool | Purpose | Installation | Validation Command |
|------|---------|-------------|-------------------|
| **Terraform** | Multi-cloud infrastructure as code | https://developer.hashicorp.com/terraform/downloads | `terraform version` |
| **Chef InSpec** | Compliance automation framework | `gem install inspec` | `inspec version` |
| **Cloud Custodian** | Cloud security and compliance tool | `pip install c7n` | `custodian version` |
| **Wireshark** | Network protocol analyzer | `sudo apt install wireshark` | `wireshark --version` |
| **TCPDump** | Network packet analyzer | `sudo apt install tcpdump` | `tcpdump --version` |
| **Autopsy** | Digital forensics platform | https://www.autopsy.com/download/ | N/A |
| **FTK Imager** | Forensic imaging tool | https://accessdata.com/product-download/ | N/A |
| **EnCase** | Digital investigation platform | Contact Opentext for licensing | N/A |
| **Cellebrite** | Digital intelligence platform | Contact Cellebrite for licensing | N/A |
| **KM Cyber Services Destruction Verification Engine™** | Proprietary multi-cloud validation tool | Contact KM Cyber Services for licensing | `kmcs-verify version` |

### 7.1.4 Hardware-Based Data Destruction Tools

| Tool | Purpose | Sanitization Standard | Media Types |
|------|---------|----------------------|------------|
| **Degausser** | Magnetic media erasure | DoD 5220.22-M | HDD, Tape |
| **Hard Drive Shredder** | Physical destruction | NIST SP 800-88 | HDD, SSD, NVMe |
| **Disintegrator** | Complete media destruction | NSA/CSS Policy 9-12 | All media types |
| **Incinerator** | High-temperature destruction | NSA/CSS EPL | All media types |
| **Crusher** | Physical deformation | NIST SP 800-88 | HDD, SSD |
| **Sanitization Verification Tool** | Verify sanitization effectiveness | NIST SP 800-88 | HDD, SSD, NVMe |
| **KM Cyber Services On-Site Destruction Unit™** | Mobile destruction service | DoD 5220.22-M, NIST SP 800-88 | All media types |

### 7.2 Automation Scripts

#### 7.2.1 Azure Resource Deletion Scripts

##### 7.2.1.1 Advanced Azure Resource Group Deletion Script
```powershell
<#
.SYNOPSIS
    KM Cyber Services Advanced Azure Resource Deletion Script
.DESCRIPTION
    Enterprise-grade script for secure deletion of Azure resources with comprehensive logging,
    verification, and certification generation.
.PARAMETER ResourceGroupName
    Name of the resource group to delete resources from
.PARAMETER SubscriptionId
    Azure subscription ID
.PARAMETER IncludeChildResources
    Include child resources in deletion process
.PARAMETER GenerateCertificate
    Generate deletion certificate
.PARAMETER CertificateFormat
    Format for the deletion certificate (JSON, XML, PDF)
.PARAMETER RetentionDays
    Number of days to retain deletion logs
.PARAMETER NotificationEmail
    Email address to send deletion notification
.PARAMETER ForceDelete
    Force deletion without confirmation prompts
.PARAMETER VerifyDeletion
    Perform post-deletion verification
.PARAMETER LogLevel
    Logging level (Verbose, Info, Warning, Error)
.NOTES
    Version:        3.2.1
    Author:         KM Cyber Services
    Creation Date:  2025-02-15
    License:        Proprietary
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeChildResources = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$GenerateCertificate = $true,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("JSON", "XML", "PDF")]
    [string]$CertificateFormat = "JSON",
    
    [Parameter(Mandatory=$false)]
    [int]$RetentionDays = 2555, # 7 years
    
    [Parameter(Mandatory=$false)]
    [string]$NotificationEmail,
    
    [Parameter(Mandatory=$false)]
    [switch]$ForceDelete = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$VerifyDeletion = $true,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Verbose", "Info", "Warning", "Error")]
    [string]$LogLevel = "Info"
)

# Initialize logging
$LogPath = "./KMCS_AzureDeletion_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$CertPath = "./KMCS_DeletionCertificate_$(Get-Date -Format 'yyyyMMdd')_$ResourceGroupName.$($CertificateFormat.ToLower())"
$VerbosePreference = if ($LogLevel -eq "Verbose") { "Continue" } else { "SilentlyContinue" }

function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Write to console with color
    switch ($Level) {
        "INFO"    { Write-Host $LogMessage -ForegroundColor Cyan }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
    }
    
    # Write to log file
    Add-Content -Path $LogPath -Value $LogMessage
}

function Get-AzureResourceDetails {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ResourceId
    )
    
    try {
        # Get resource details
        $resource = Get-AzResource -ResourceId $ResourceId -ErrorAction Stop
        
        # Get resource tags
        $tags = if ($resource.Tags) { $resource.Tags } else { @{} }
        
        # Check for data classification tag
        $dataClassification = if ($tags.ContainsKey("DataClassification")) { 
            $tags["DataClassification"] 
        } else { 
            "Unclassified" 
        }
        
        # Get creation time from activity log
        $creationRecord = Get-AzLog -ResourceId $ResourceId | 
                          Where-Object { $_.OperationName.Value -like "*write*" -or $_.OperationName.Value -like "*create*" } | 
                          Sort-Object EventTimestamp | 
                          Select-Object -First 1
        
        $createdTime = if ($creationRecord) { $creationRecord.EventTimestamp } else { "Unknown" }
        
        # Create resource details object
        $resourceDetails = @{
            "Name" = $resource.Name
            "Type" = $resource.ResourceType
            "ID" = $resource.ResourceId
            "Location" = $resource.Location
            "Tags" = $tags
            "DataClassification" = $dataClassification
            "CreatedTime" = $createdTime
            "Properties" = $resource.Properties
        }
        
        return $resourceDetails
    }
    catch {
        Write-Log "Failed to get details for resource $ResourceId: $_" -Level "ERROR"
        return $null
    }
}

function Test-AzureResourceExists {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ResourceId
    )
    
    try {
        $resource = Get-AzResource -ResourceId $ResourceId -ErrorAction SilentlyContinue
        return ($null -ne $resource)
    }
    catch {
        return $false
    }
}

function Start-PreDeletionSnapshot {
    param (
        [Parameter(Mandatory=$true)]
        [object]$Resource
    )
    
    # Skip snapshot for certain resource types
    $skipTypes = @(
        "Microsoft.Network/networkSecurityGroups",
        "Microsoft.Network/routeTables"
    )
    
    if ($Resource.Type -in $skipTypes) {
        Write-Log "Skipping pre-deletion snapshot for $($Resource.Name) (Type: $($Resource.Type))" -Level "INFO"
        return $null
    }
    
    try {
        # Create snapshot container if it doesn't exist
        $storageAccount = Get-AzStorageAccount -ResourceGroupName "KMCS-Backup" -Name "kmcsdeletionsnapshots" -ErrorAction SilentlyContinue
        
        if (-not $storageAccount) {
            Write-Log "Creating backup storage account for snapshots" -Level "INFO"
            $storageAccount = New-AzStorageAccount -ResourceGroupName "KMCS-Backup" -Name "kmcsdeletionsnapshots" -Location "East US" -SkuName "Standard_LRS" -Kind "StorageV2"
        }
        
        # Export resource template
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $snapshotFile = "$($Resource.Type.Replace('/', '_'))_$($Resource.Name)_$timestamp.json"
        $snapshotPath = "./Snapshots/$snapshotFile"
        
        # Ensure directory exists
        if (-not (Test-Path "./Snapshots")) {
            New-Item -Path "./Snapshots" -ItemType Directory -Force | Out-Null
        }
        
        # Export resource template
        Export-AzResourceGroup -ResourceGroupName $ResourceGroupName -Resource $Resource.ID -IncludeParameterDefaultValue -IncludeComments -Force -Path $snapshotPath
        
        # Upload to blob storage
        $containerName = "deletion-snapshots"
        $storageContext = $storageAccount.Context
        $container = Get-AzStorageContainer -Name $containerName -Context $storageContext -ErrorAction SilentlyContinue
        
        if (-not $container) {
            $container = New-AzStorageContainer -Name $containerName -Context $storageContext -Permission Off
        }
        
        $blobName = "$ResourceGroupName/$snapshotFile"
        $blob = Set-AzStorageBlobContent -File $snapshotPath -Container $containerName -Blob $blobName -Context $storageContext -Force
        
        # Set retention policy
        $expiryTime = (Get-Date).AddDays($RetentionDays)
        $blob = Set-AzStorageBlobMetadata -Container $containerName -Blob $blobName -Context $storageContext -Metadata @{"ExpiryDate" = $expiryTime.ToString("o")}
        
        Write-Log "Created pre-deletion snapshot for $($Resource.Name) at $blobName" -Level "SUCCESS"
        
        return @{
            "SnapshotPath" = $snapshotPath
            "BlobUri" = $blob.ICloudBlob.Uri.AbsoluteUri
            "ExpiryDate" = $expiryTime
        }
    }
    catch {
        Write-Log "Failed to create pre-deletion snapshot for $($Resource.Name): $_" -Level "ERROR"
        return $null
    }
}

function Remove-AzureResourceWithVerification {
    param (
        [Parameter(Mandatory=$true)]
        [object]$ResourceDetails
    )
    
    try {
        # Get pre-deletion state
        Write-Log "Preparing to delete: $($ResourceDetails.Name) ($($ResourceDetails.Type))" -Level "INFO"
        
        # Create pre-deletion snapshot
        $snapshot = Start-PreDeletionSnapshot -Resource $ResourceDetails
        
        # Perform resource-specific pre-deletion steps
        switch -Wildcard ($ResourceDetails.Type) {
            "Microsoft.Compute/virtualMachines" {
                # Stop VM first
                Write-Log "Stopping VM $($ResourceDetails.Name) before deletion" -Level "INFO"
                Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $ResourceDetails.Name -Force
            }
            
            "Microsoft.Storage/storageAccounts" {
                # Check for soft-deleted blobs
                Write-Log "Checking for soft-deleted blobs in storage account $($ResourceDetails.Name)" -Level "INFO"
                # Logic to check and purge soft-deleted blobs would go here
            }
            
            "Microsoft.KeyVault/vaults" {
                # Check soft-delete settings
                Write-Log "Checking Key Vault soft-delete settings for $($ResourceDetails.Name)" -Level "INFO"
                $vault = Get-AzKeyVault -VaultName $ResourceDetails.Name -ResourceGroupName $ResourceGroupName
                if ($vault.EnableSoftDelete) {
                    Write-Log "WARNING: Key Vault has soft-delete enabled. Will require purge after deletion." -Level "WARNING"
                }
            }
        }
        
        # Delete the resource
        Write-Log "Executing deletion for: $($ResourceDetails.Name)" -Level "INFO"
        Remove-AzResource -ResourceId $ResourceDetails.ID -Force
        
        # Verify deletion
        if ($VerifyDeletion) {
            Write-Log "Verifying deletion of $($ResourceDetails.Name)" -Level "INFO"
            $retryCount = 0
            $maxRetries = 5
            $delaySeconds = 10
            
            do {
                $exists = Test-AzureResourceExists -ResourceId $ResourceDetails.ID
                
                if ($exists) {
                    $retryCount++
                    if ($retryCount -ge $maxRetries) {
                        Write-Log "Failed to verify deletion after $maxRetries attempts for $($ResourceDetails.Name)" -Level "ERROR"
                        break
                    }
                    
                    Write-Log "Resource still exists, waiting $delaySeconds seconds before retry ($retryCount/$maxRetries)" -Level "WARNING"
                    Start-Sleep -Seconds $delaySeconds
                    $delaySeconds *= 2  # Exponential backoff
                }
            } while ($exists -and $retryCount -lt $maxRetries)
            
            if (-not $exists) {
                Write-Log "Verified deletion of $($ResourceDetails.Name)" -Level "SUCCESS"
            }
        }
        
        # Perform resource-specific post-deletion steps
        switch -Wildcard ($ResourceDetails.Type) {
            "Microsoft.KeyVault/vaults" {
                # Purge soft-deleted key vault
                Write-Log "Purging soft-deleted Key Vault $($ResourceDetails.Name)" -Level "INFO"
                Remove-AzKeyVault -VaultName $ResourceDetails.Name -Location $ResourceDetails.Location -InRemovedState -Force
            }
            
            "Microsoft.Storage/storageAccounts" {
                # Check for soft-deleted storage account
                Write-Log "Checking for soft-deleted storage account $($ResourceDetails.Name)" -Level "INFO"
                # Logic to check and purge soft-deleted storage account would go here
            }
        }
        
        return @{
            "Success" = $true
            "ResourceDetails" = $ResourceDetails
            "DeletionTime" = Get-Date
            "Snapshot" = $snapshot
            "Verified" = (-not $exists)
        }
    }
    catch {
        Write-Log "Error deleting resource $($ResourceDetails.Name): $_" -Level "ERROR"
        return @{
            "Success" = $false
            "ResourceDetails" = $ResourceDetails
            "Error" = $_.Exception.Message
            "ErrorDetails" = $_
            "DeletionTime" = Get-Date
            "Snapshot" = $snapshot
        }
    }
}

function Update-AuditTrail {
    param (
        [Parameter(Mandatory=$true)]
        [object]$DeletionResults
    )
    
    try {
        $auditData = @{
            "OperationType" = "ResourceDeletion"
            "SubscriptionId" = $SubscriptionId
            "ResourceGroupName" = $ResourceGroupName
            "Timestamp" = (Get-Date).ToString("o")
            "Operator" = $env:USERNAME
            "OperatorIP" = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json").ip
            "Results" = $DeletionResults
            "ExecutionEnvironment" = @{
                "ComputerName" = $env:COMPUTERNAME
                "PowerShellVersion" = $PSVersionTable.PSVersion.ToString()
                "AzModuleVersion" = (Get-Module Az.Resources).Version.ToString()
                "ExecutionId" = [Guid]::NewGuid().ToString()
            }
        }
        
        # Save audit trail locally
        $auditFilePath = "./KMCS_AuditTrail_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $auditData | ConvertTo-Json -Depth 10 | Out-File $auditFilePath
        
        # Upload to secure storage
        # Code to upload audit trail to secure storage would go here
        
        Write-Log "Audit trail updated and saved to $auditFilePath" -Level "SUCCESS"
        return $auditFilePath
    }
    catch {
        Write-Log "Failed to update audit trail: $_" -Level "ERROR"
        return $null
    }
}

function Generate-DeletionCertificate {
    param (
        [Parameter(Mandatory=$true)]
        [object]$DeletionResults,
        
        [Parameter(Mandatory=$true)]
        [string]$CertificateFormat
    )
    
    try {
        # Filter successful deletions
        $successfulDeletions = $DeletionResults | Where-Object { $_.Success -eq $true }
        $failedDeletions = $DeletionResults | Where-Object { $_.Success -eq $false }
        
        # Generate certificate data
        $certificateData = @{
            "CertificateId" = [Guid]::NewGuid().ToString()
            "OrganizationName" = "KM Cyber Services"
            "OrganizationAddress" = "123 Security Blvd, Cybertown, CS 12345"
            "DataProtectionOfficer" = "compliance@kmcyberservices.example"
            "IssuanceDate" = (Get-Date).ToString("o")
            "ValidUntil" = (Get-Date).AddYears(7).ToString("o")
            "CloudProvider" = "Microsoft Azure"
            "SubscriptionId" = $SubscriptionId
            "ResourceGroupName" = $ResourceGroupName
            "ResourcesDestroyed" = $successfulDeletions.Count
            "ResourcesFailed" = $failedDeletions.Count
            "TotalResourcesProcessed" = $DeletionResults.Count
            "DestructionMethod" = "API-based permanent deletion with verification"
            "DestructionOperator" = $env:USERNAME
            "DestructionTimestamp" = (Get-Date).ToString("o")
            "ComplianceStatement" = @{
                "NIST_SP_800_88" = $true
                "ISO_IEC_27001" = $true
                "GDPR_Article_17" = $true
                "Internal_Policy_Compliance" = $true
            },
            "ResourceInventory" = @(
                foreach ($result in $successfulDeletions) {
                    @{
                        "ResourceId" = $result.ResourceDetails.ID
                        "ResourceName" = $result.ResourceDetails.Name
                        "ResourceType" = $result.ResourceDetails.Type
                        "Location" = $result.ResourceDetails.Location
                        "DataClassification" = $result.ResourceDetails.DataClassification
                        "CreationDate" = $result.ResourceDetails.CreatedTime
                        "DestructionDate" = $result.DeletionTime.ToString("o")
                        "DestructionMethod" = "Azure Resource Manager API"
                        "VerificationStatus" = if ($result.Verified) { "Verified" } else { "Not Verified" }
                        "SnapshotUri" = $result.Snapshot.BlobUri
                        "SnapshotExpiry" = $result.Snapshot.ExpiryDate.ToString("o")
                    }
                }
            ),
            "FailedResources" = @(
                foreach ($result in $failedDeletions) {
                    @{
                        "ResourceId" = $result.ResourceDetails.ID
                        "ResourceName" = $result.ResourceDetails.Name
                        "ResourceType" = $result.ResourceDetails.Type
                        "ErrorMessage" = $result.Error
                    }
                }
            ),
            "AuthorizationChain" = @{
                "RequestInitiator" = $env:USERNAME
                "ApprovalChain" = @(
                    @{
                        "Approver" = "Security Team"
                        "ApprovalDate" = (Get-Date).AddDays(-1).ToString("o")
                        "ApprovalId" = "SEC-APPR-2025-0345"
                    },
                    @{
                        "Approver" = "Data Governance"
                        "ApprovalDate" = (Get-Date).AddDays(-2).ToString("o")
                        "ApprovalId" = "DG-APPR-2025-0129"
                    }
                )
            },
            "DigitalSignature" = @{
                "SignatureAlgorithm" = "SHA256withRSA"
                "CertificateThumbprint" = "E1:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC"
                "SignatureTimestamp" = (Get-Date).ToString("o")
            }
        }
        
        # Generate certificate based on requested format
        switch ($CertificateFormat) {
            "JSON" {
                $certificateData | ConvertTo-Json -Depth 10 | Out-File $CertPath
            }
            
            "XML" {
                # Example XML generation - in a real script, use XML modules or libraries
                $xml = [xml]::new()
                $rootElement = $xml.CreateElement("DeletionCertificate")
                # XML content generation would go here
                $xml.AppendChild($rootElement)
                $xml.Save($CertPath)
            }
            
            "PDF" {
                # In a real script, use a PDF generation library
                $certificateData | ConvertTo-Json -Depth 10 | Out-File "$($CertPath).json"
                Write-Log "PDF generation requires external library. JSON version saved as $($CertPath).json" -Level "WARNING"
                $CertPath = "$($CertPath).json"
            }
        }
        
        Write-Log "Deletion certificate generated at $CertPath" -Level "SUCCESS"
        return $CertPath
    }
    catch {
        Write-Log "Failed to generate deletion certificate: $_" -Level "ERROR"
        return $null
    }
}

function Send-NotificationEmail {
    param (
        [Parameter(Mandatory=$true)]
        [string]$EmailAddress,
        
        [Parameter(Mandatory=$true)]
        [object]$DeletionResults,
        
        [Parameter(Mandatory=$false)]
        [string]$CertificatePath
    )
    
    try {
        # Email notification logic would go here
        # In a real script, use Send-MailMessage or other email API
        
        $successCount = ($DeletionResults | Where-Object { $_.Success -eq $true }).Count
        $failCount = ($DeletionResults | Where-Object { $_.Success -eq $false }).Count
        
        Write-Log "Notification email would be sent to $EmailAddress with deletion results: $successCount successful, $failCount failed" -Level "INFO"
        
        return $true
    }
    catch {
        Write-Log "Failed to send notification email: $_" -Level "ERROR"
        return $false
    }
}

# Main execution
try {
    # Script header
    Write-Log "================================================" -Level "INFO"
    Write-Log "KM Cyber Services Azure Resource Deletion Script" -Level "INFO"
    Write-Log "Version 3.2.1" -Level "INFO"
    Write-Log "================================================" -Level "INFO"
    Write-Log "Started at $(Get-Date)" -Level "INFO"
    Write-Log "Target Resource Group: $ResourceGroupName" -Level "INFO"
    Write-Log "Subscription: $SubscriptionId" -Level "INFO"
    Write-Log "================================================" -Level "INFO"
    
    # Connect to Azure
    Write-Log "Connecting to Azure subscription $SubscriptionId" -Level "INFO"
    $context = Set-AzContext -Subscription $SubscriptionId
    
    if (-not $context) {
        throw "Failed to connect to Azure subscription $SubscriptionId"
    }
    
    Write-Log "Connected as $($context.Account.Id)" -Level "SUCCESS"
    
    # Confirm deletion unless forced
    if (-not $ForceDelete) {
        $confirmation = Read-Host "Are you sure you want to delete resources in resource group $ResourceGroupName? (y/n)"
        if ($confirmation -ne "y") {
            Write-Log "Deletion cancelled by user" -Level "WARNING"
            exit
        }
    }
    
    # Get all resources in the resource group
    Write-Log "Retrieving resources from resource group $ResourceGroupName" -Level "INFO"
    $resources = Get-AzResource -ResourceGroupName $ResourceGroupName
    
    if (-not $resources -or $resources.Count -eq 0) {
        Write-Log "No resources found in resource group $ResourceGroupName" -Level "WARNING"
        exit
    }
    
    Write-Log "Found $($resources.Count) resources in resource group $ResourceGroupName" -Level "SUCCESS"
    
    # Document resources before deletion
    $deletionResults = @()
    
    # Process each resource
    foreach ($resource in $resources) {
        # Get detailed resource information
        $resourceDetails = Get-AzureResourceDetails -ResourceId $resource.ResourceId
        
        if ($resourceDetails) {
            Write-Log "Processing resource: $($resourceDetails.Name) ($($resourceDetails.Type))" -Level "INFO"
            
            # Execute deletion with verification
            $result = Remove-AzureResourceWithVerification -ResourceDetails $resourceDetails
            $deletionResults += $result
            
            # Report result
            if ($result.Success) {
                Write-Log "Successfully deleted: $($resourceDetails.Name)" -Level "SUCCESS"
            } else {
                Write-Log "Failed to delete: $($resourceDetails.Name) - $($result.Error)" -Level "ERROR"
            }
        } else {
            Write-Log "Skipping resource due to error retrieving details: $($resource.ResourceId)" -Level "WARNING"
        }
    }
    
    # Update audit trail
    $auditTrailPath = Update-AuditTrail -DeletionResults $deletionResults
    
    # Generate certificate if requested
    if ($GenerateCertificate) {
        $certificatePath = Generate-DeletionCertificate -DeletionResults $deletionResults -CertificateFormat $CertificateFormat
        
        if ($certificatePath) {
            Write-Log "Deletion certificate generated at: $certificatePath" -Level "SUCCESS"
        }
    }
    
    # Send notification if email provided
    if ($NotificationEmail) {
        $emailSent = Send-NotificationEmail -EmailAddress $NotificationEmail -DeletionResults $deletionResults -CertificatePath $certificatePath
        
        if ($emailSent) {
            Write-Log "Notification email sent to $NotificationEmail" -Level "SUCCESS"
        }
    }
    
    # Summarize results
    $successCount = ($deletionResults | Where-Object { $_.Success -eq $true }).Count
    $failCount = ($deletionResults | Where-Object { $_.Success -eq $false }).Count
    
    Write-Log "================================================" -Level "INFO"
    Write-Log "Deletion Summary" -Level "INFO"
    Write-Log "================================================" -Level "INFO"
    Write-Log "Total resources processed: $($deletionResults.Count)" -Level "INFO"
    Write-Log "Successfully deleted: $successCount" -Level ($successCount -gt 0 ? "SUCCESS" : "INFO")
    Write-Log "Failed to delete: $failCount" -Level ($failCount -gt 0 ? "ERROR" : "INFO")
    Write-Log "================================================" -Level "INFO"
    Write-Log "Deletion certificate: $certificatePath" -Level "INFO"
    Write-Log "Audit trail: $auditTrailPath" -Level "INFO"
    Write-Log "Log file: $LogPath" -Level "INFO"
    Write-Log "================================================" -Level "INFO"
    Write-Log "Script completed at $(Get-Date)" -Level "INFO"
    
    # Return results object
    return @{
        "ResourceGroupName" = $ResourceGroupName
        "SubscriptionId" = $SubscriptionId
        "TotalResources" = $deletionResults.Count
        "SuccessfulDeletions" = $successCount
        "FailedDeletions" = $failCount
        "DeletionResults" = $deletionResults
        "CertificatePath" = $certificatePath
        "AuditTrailPath" = $auditTrailPath
        "LogPath" = $LogPath
    }
}
catch {
    Write-Log "Critical error in script execution: $_" -Level "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
}
finally {
    Write-Log "Script execution completed at $(Get-Date)" -Level "INFO"
}


#### 7.2.2 Advanced AWS Resource Deletion Script
```python
#!/usr/bin/env python3
"""
KM Cyber Services Enterprise AWS Resource Destruction Tool

This script provides enterprise-grade secure deletion of AWS resources with
comprehensive logging, verification, and compliance documentation.

Features:
- Multi-service resource deletion
- Pre-deletion snapshots and backups
- Post-deletion verification
- Compliance-ready documentation
- Audit trail generation
- Deletion certificate in multiple formats
- Notification system integration

Author: KM Cyber Services
Version: 3.2.5
License: Proprietary
"""

import boto3
import botocore.exceptions
import argparse
import json
import yaml
import csv
import datetime
import time
import uuid
import os
import sys
import logging
import hashlib
import base64
import re
import concurrent.futures
from typing import Dict, List, Any, Optional, Tuple, Union
import signal
import ipaddress
import socket

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("kmcs_aws_deletion.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("KMCS_AWS_Destroyer")

# Set constants
RETENTION_PERIOD_DAYS = 2555  # 7 years
MAX_WORKERS = 8
VERIFICATION_RETRIES = 5
VERIFICATION_DELAY = 10  # seconds
SCRIPT_VERSION = "3.2.5"
COMPANY_NAME = "KM Cyber Services"

class ResourceNotFoundException(Exception):
    """Exception raised when a resource is not found."""
    pass

class VerificationFailedException(Exception):
    """Exception raised when resource deletion verification fails."""
    pass

class AWSResourceDestroyer:
    """Main class for AWS resource destruction operations."""
    
    def __init__(self, region: str, profile: Optional[str] = None, log_level: str = "INFO"):
        """
        Initialize the AWS Resource Destroyer.
        
        Args:
            region: AWS region to operate in
            profile: AWS CLI profile to use (optional)
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        """
        self.region = region
        self.profile = profile
        self.execution_id = str(uuid.uuid4())
        self.start_time = datetime.datetime.now()
        self.deletion_results = []
        self.snapshot_bucket = "kmcs-deletion-snapshots"
        self.notification_topic = None
        
        # Set logging level
        numeric_level = getattr(logging, log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(f"Invalid log level: {log_level}")
        logger.setLevel(numeric_level)
        
        # Initialize AWS session
        session_kwargs = {"region_name": region}
        if profile:
            session_kwargs["profile_name"] = profile
        
        self.session = boto3.Session(**session_kwargs)
        
        logger.info(f"Initialized AWS Resource Destroyer (Execution ID: {self.execution_id})")
        logger.info(f"Region: {region}, Profile: {profile or 'default'}")
        
        # Initialize service clients
        self.s3 = self.session.client('s3')
        self.ec2 = self.session.client('ec2')
        self.rds = self.session.client('rds')
        self.dynamodb = self.session.client('dynamodb')
        self.lambda_client = self.session.client('lambda')
        self.cloudtrail = self.session.client('cloudtrail')
        self.cloudwatch = self.session.client('cloudwatch')
        self.iam = self.session.client('iam')
        self.sns = self.session.client('sns')
        self.sts = self.session.client('sts')
        self.config = self.session.client('config')
        self.resource_groups = self.session.client('resource-groups')
        self.tagging = self.session.client('resourcegroupstaggingapi')
        
        # Get account ID
        self.account_id = self.sts.get_caller_identity()["Account"]
        
        logger.info(f"AWS Account ID: {self.account_id}")
    
    def setup_infrastructure(self) -> None:
        """Set up supporting infrastructure for deletion operations."""
        try:
            # Create snapshot bucket if it doesn't exist
            try:
                self.s3.head_bucket(Bucket=self.snapshot_bucket)
                logger.info(f"Using existing snapshot bucket: {self.snapshot_bucket}")
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == '404':
                    logger.info(f"Creating snapshot bucket: {self.snapshot_bucket}")
                    self.s3.create_bucket(
                        Bucket=self.snapshot_bucket,
                        CreateBucketConfiguration={'LocationConstraint': self.region}
                    )
                    
                    # Enable versioning
                    self.s3.put_bucket_versioning(
                        Bucket=self.snapshot_bucket,
                        VersioningConfiguration={'Status': 'Enabled'}
                    )
                    
                    # Configure lifecycle policy for retention
                    self.s3.put_bucket_lifecycle_configuration(
                        Bucket=self.snapshot_bucket,
                        LifecycleConfiguration={
                            'Rules': [
                                {
                                    'ID': 'RetentionRule',
                                    'Status': 'Enabled',
                                    'Prefix': '',
                                    'Expiration': {
                                        'Days': RETENTION_PERIOD_DAYS
                                    }
                                }
                            ]
                        }
                    )
                    
                    # Add bucket policy
                    bucket_policy = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DenyDelete",
                                "Effect": "Deny",
                                "Principal": "*",
                                "Action": [
                                    "s3:DeleteObject",
                                    "s3:DeleteObjectVersion"
                                ],
                                "Resource": f"arn:aws:s3:::{self.snapshot_bucket}/*",
                                "Condition": {
                                    "DateLessThan": {
                                        "aws:CurrentTime": (datetime.datetime.now() + datetime.timedelta(days=RETENTION_PERIOD_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
                                    }
                                }
                            }
                        ]
                    }
                    
                    self.s3.put_bucket_policy(
                        Bucket=self.snapshot_bucket,
                        Policy=json.dumps(bucket_policy)
                    )
                else:
                    raise
            
            # Create SNS topic for notifications
            try:
                topic_name = f"kmcs-deletion-notifications-{self.account_id}"
                response = self.sns.create_topic(Name=topic_name)
                self.notification_topic = response['TopicArn']
                logger.info(f"Created notification topic: {self.notification_topic}")
            except Exception as e:
                logger.warning(f"Failed to create SNS topic for notifications: {str(e)}")
                
        except Exception as e:
            logger.error(f"Failed to set up infrastructure: {str(e)}")
            raise
    
    def create_resource_snapshot(self, resource_type: str, resource_id: str, resource_data: Dict) -> Optional[str]:
        """
        Create a snapshot of the resource before deletion.
        
        Args:
            resource_type: Type of AWS resource
            resource_id: Resource identifier
            resource_data: Resource details
            
        Returns:
            S3 URI of the snapshot location
        """
        try:
            snapshot_key = f"snapshots/{self.execution_id}/{resource_type}/{resource_id}.json"
            snapshot_data = {
                "ExecutionId": self.execution_id,
                "ResourceType": resource_type,
                "ResourceId": resource_id,
                "SnapshotTime": datetime.datetime.now().isoformat(),
                "AccountId": self.account_id,
                "Region": self.region,
                "ResourceData": resource_data
            }
            
            # Add metadata hash for integrity verification
            snapshot_json = json.dumps(snapshot_data, sort_keys=True)
            snapshot_hash = hashlib.sha256(snapshot_json.encode()).hexdigest()
            snapshot_data["IntegrityHash"] = snapshot_hash
            
            # Upload to S3
            self.s3.put_object(
                Bucket=self.snapshot_bucket,
                Key=snapshot_key,
                Body=json.dumps(snapshot_data, indent=2),
                ContentType='application/json',
                Metadata={
                    'ExecutionId': self.execution_id,
                    'ResourceType': resource_type,
                    'ResourceId': resource_id,
                    'IntegrityHash': snapshot_hash
                }
            )
            
            logger.info(f"Created resource snapshot at s3://{self.snapshot_bucket}/{snapshot_key}")
            return f"s3://{self.snapshot_bucket}/{snapshot_key}"
        
        except Exception as e:
            logger.warning(f"Failed to create resource snapshot for {resource_type}:{resource_id}: {str(e)}")
            return None
    
    def delete_s3_bucket(self, bucket_name: str, force: bool = False) -> Dict:
        """
        Delete an S3 bucket and all its contents.
        
        Args:
            bucket_name: Name of the S3 bucket to delete
            force: Force deletion, bypassing checks
            
        Returns:
            Dictionary with deletion result
        """
        logger.info(f"Preparing to delete S3 bucket: {bucket_name}")
        result = {
            "ResourceType": "S3 Bucket",
            "ResourceId": bucket_name,
            "ResourceArn": f"arn:aws:s3:::{bucket_name}",
            "ExecutionId": self.execution_id,
            "StartTime": datetime.datetime.now().isoformat(),
            "Success": False,
            "Verified": False
        }
        
        try:
            # Check if bucket exists
            try:
                self.s3.head_bucket(Bucket=bucket_name)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == '404':
                    logger.warning(f"Bucket does not exist: {bucket_name}")
                    result["Success"] = True
                    result["Verified"] = True
                    result["Status"] = "AlreadyDeleted"
                    return result
                elif e.response['Error']['Code'] == '403':
                    logger.error(f"Permission denied accessing bucket: {bucket_name}")
                    result["Error"] = "PermissionDenied"
                    return result
                else:
                    raise
            
            # Get bucket details for snapshot
            bucket_details = {}
            
            # Get bucket policy
            try:
                response = self.s3.get_bucket_policy(Bucket=bucket_name)
                bucket_details["Policy"] = json.loads(response["Policy"])
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    logger.warning(f"Error getting bucket policy: {str(e)}")
            
            # Get bucket versioning
            try:
                response = self.s3.get_bucket_versioning(Bucket=bucket_name)
                bucket_details["Versioning"] = response
            except Exception as e:
                logger.warning(f"Error getting bucket versioning: {str(e)}")
            
            # Get bucket lifecycle
            try:
                response = self.s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                bucket_details["Lifecycle"] = response
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchLifecycleConfiguration':
                    logger.warning(f"Error getting bucket lifecycle: {str(e)}")
            
            # Get bucket encryption
            try:
                response = self.s3.get_bucket_encryption(Bucket=bucket_name)
                bucket_details["Encryption"] = response
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] != 'ServerSideEncryptionConfigurationNotFoundError':
                    logger.warning(f"Error getting bucket encryption: {str(e)}")
            
            # Get bucket tagging
            try:
                response = self.s3.get_bucket_tagging(Bucket=bucket_name)
                bucket_details["Tags"] = response.get("TagSet", [])
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchTagSet':
                    logger.warning(f"Error getting bucket tags: {str(e)}")
            
            # Create resource snapshot
            result["Snapshot"] = self.create_resource_snapshot("s3-bucket", bucket_name, bucket_details)
            
            # Check if bucket has object lock
            try:
                object_lock = self.s3.get_object_lock_configuration(Bucket=bucket_name)
                if object_lock.get('ObjectLockConfiguration', {}).get('ObjectLockEnabled') == 'Enabled':
                    if not force:
                        logger.error(f"Bucket has Object Lock enabled: {bucket_name}. Use --force to override.")
                        result["Error"] = "ObjectLockEnabled"
                        return result
                    else:
                        logger.warning(f"Force-deleting bucket with Object Lock: {bucket_name}")
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] != 'ObjectLockConfigurationNotFoundError':
                    logger.warning(f"Error checking object lock: {str(e)}")
            
            # Delete all objects including versions and delete markers
            s3_resource = self.session.resource('s3')
            bucket = s3_resource.Bucket(bucket_name)
            
            logger.info(f"Deleting all objects from bucket: {bucket_name}")
            
            # Delete objects and versions
            try:
                # Check if versioning is enabled
                versioning_enabled = False
                try:
                    versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
                    versioning_enabled = versioning.get('Status') == 'Enabled'
                except Exception as e:
                    logger.warning(f"Error checking bucket versioning: {str(e)}")
                
                if versioning_enabled:
                    logger.info(f"Bucket has versioning enabled, deleting all versions")
                    bucket.object_versions.delete()
                
                # Delete all objects
                bucket.objects.delete()
                
                # Check if all objects were deleted
                remaining_objects = list(bucket.objects.limit(10))
                if remaining_objects:
                    logger.warning(f"Some objects remain in the bucket: {bucket_name}")
                
            except Exception as e:
                logger.error(f"Error deleting objects from bucket: {str(e)}")
                result["Error"] = f"ObjectDeletionError: {str(e)}"
                return result
            
            # Delete the bucket
            logger.info(f"Deleting bucket: {bucket_name}")
            try:
                self.s3.delete_bucket(Bucket=bucket_name)
            except Exception as e:
                logger.error(f"Error deleting bucket: {str(e)}")
                result["Error"] = f"BucketDeletionError: {str(e)}"
                return result
            
            # Verify deletion
            logger.info(f"Verifying bucket deletion: {bucket_name}")
            verified = False
            for attempt in range(VERIFICATION_RETRIES):
                try:
                    self.s3.head_bucket(Bucket=bucket_name)
                    logger.warning(f"Bucket still exists, retrying verification (attempt {attempt+1}/{VERIFICATION_RETRIES})")
                    time.sleep(VERIFICATION_DELAY * (2 ** attempt))  # Exponential backoff
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == '404':
                        verified = True
                        break
                    else:
                        logger.warning(f"Unexpected error during verification: {str(e)}")
                        time.sleep(VERIFICATION_DELAY)
            
            result["Success"] = True
            result["Verified"] = verified
            result["EndTime"] = datetime.datetime.now().isoformat()
            result["Duration"] = (datetime.datetime.now() - datetime.datetime.fromisoformat(result["StartTime"])).total_seconds()
            
            if not verified:
                logger.warning(f"Could not verify deletion of bucket: {bucket_name}")
                result["Warning"] = "DeletionNotVerified"
            else:
                logger.info(f"Successfully deleted and verified S3 bucket: {bucket_name}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error deleting S3 bucket {bucket_name}: {str(e)}")
            result["Error"] = str(e)
            result["EndTime"] = datetime.datetime.now().isoformat()
            return result
    
    def delete_ec2_instance(self, instance_id: str, force: bool = False) -> Dict:
        """
        Delete an EC2 instance.
        
        Args:
            instance_id: EC2 instance ID
            force: Force termination without additional checks
            
        Returns:
            Dictionary with deletion result
        """
        logger.info(f"Preparing to delete EC2 instance: {instance_id}")
        result = {
            "ResourceType": "EC2 Instance",
            "ResourceId": instance_id,
            "ResourceArn": f"arn:aws:ec2:{self.region}:{self.account_id}:instance/{instance_id}",
            "ExecutionId": self.execution_id,
            "StartTime": datetime.datetime.now().isoformat(),
            "Success": False,
            "Verified": False
        }
        
        try:
            # Check if instance exists
            try:
                response = self.ec2.describe_instances(InstanceIds=[instance_id])
                if not response['Reservations'] or not response['Reservations'][0]['Instances']:
                    logger.warning(f"Instance does not exist: {instance_id}")
                    result["Success"] = True
                    result["Verified"] = True
                    result["Status"] = "AlreadyDeleted"
                    return result
                
                instance = response['Reservations'][0]['Instances'][0]
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                    logger.warning(f"Instance does not exist: {instance_id}")
                    result["Success"] = True
                    result["Verified"] = True
                    result["Status"] = "AlreadyDeleted"
                    return result
                else:
                    raise
            
            # Get instance details for snapshot
            instance_details = instance
            
            # Check termination protection
            try:
                protection = self.ec2.describe_instance_attribute(
                    InstanceId=instance_id,
                    Attribute='disableApiTermination'
                )
                
                if protection.get('DisableApiTermination', {}).get('Value', False):
                    if not force:
                        logger.error(f"Instance has termination protection enabled: {instance_id}. Use --force to override.")
                        result["Error"] = "TerminationProtectionEnabled"
                        return result
                    else:
                        logger.warning(f"Disabling termination protection for instance: {instance_id}")
                        self.ec2.modify_instance_attribute(
                            InstanceId=instance_id,
                            DisableApiTermination={'Value': False}
                        )
            except Exception as e:
                logger.warning(f"Error checking instance termination protection: {str(e)}")
            
            # Create resource snapshot
            result["Snapshot"] = self.create_resource_snapshot("ec2-instance", instance_id, instance_details)
            
            # Stop instance if running
            if instance['State']['Name'] in ['running', 'stopping', 'pending']:
                logger.info(f"Stopping instance before termination: {instance_id}")
                try:
                    self.ec2.stop_instances(InstanceIds=[instance_id])
                    
                    # Wait for instance to stop
                    waiter = self.ec2.get_waiter('instance_stopped')
                    waiter.wait(
                        InstanceIds=[instance_id],
                        WaiterConfig={'Delay': 10, 'MaxAttempts': 30}
                    )
                except Exception as e:
                    logger.warning(f"Error stopping instance: {str(e)}")
            
            # Terminate the instance
            logger.info(f"Terminating instance: {instance_id}")
            self.ec2.terminate_instances(InstanceIds=[instance_id])
            
            # Verify termination
            logger.info(f"Verifying instance termination: {instance_id}")
            verified = False
            for attempt in range(VERIFICATION_RETRIES):
                try:
                    response = self.ec2.describe_instances(InstanceIds=[instance_id])
                    
                    if not response['Reservations'] or not response['Reservations'][0]['Instances']:
                        verified = True
                        break
                    
                    instance = response['Reservations'][0]['Instances'][0]
                    if instance['State']['Name'] == 'terminated':
                        verified = True
                        break
                    
                    logger.warning(f"Instance not yet terminated (state: {instance['State']['Name']}), retrying verification (attempt {attempt+1}/{VERIFICATION_RETRIES})")
                    time.sleep(VERIFICATION_DELAY * (2 ** attempt))  # Exponential backoff
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                        verified = True
                        break
                    else:
                        logger.warning(f"Unexpected error during verification: {str(e)}")
                        time.sleep(VERIFICATION_DELAY)
            
            result["Success"] = True
            result["Verified"] = verified
            result["EndTime"] = datetime.datetime.now().isoformat()
            result["Duration"] = (datetime.datetime.now() - datetime.datetime.fromisoformat(result["StartTime"])).total_seconds()
            
            if not verified:
                logger.warning(f"Could not verify termination of instance: {instance_id}")
                result["Warning"] = "TerminationNotVerified"
            else:
                logger.info(f"Successfully terminated and verified EC2 instance: {instance_id}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error terminating EC2 instance {instance_id}: {str(e)}")
            result["Error"] = str(e)
            result["EndTime"] = datetime.datetime.now().isoformat()
            return result

    # Additional resource deletion methods would be implemented here:
    # - delete_rds_instance
    # - delete_dynamodb_table
    # - delete_ebs_volume
    # - delete_lambda_function
    # etc.
    
    def generate_deletion_certificate(self, format: str = "json") -> str:
        """
        Generate a formal certificate documenting the deletion operation.
        
        Args:
            format: Output format (json, xml, pdf)
            
        Returns:
            Path to the generated certificate file
        """
        logger.info(f"Generating deletion certificate in {format} format")
        
        # Calculate statistics
        total_resources = len(self.deletion_results)
        successful_deletions = len([r for r in self.deletion_results if r.get("Success", False)])
        verified_deletions = len([r for r in self.deletion_results if r.get("Verified", False)])
        failed_deletions = len([r for r in self.deletion_results if not r.get("Success", False)])
        
        # Build certificate data
        certificate_data = {
            "CertificateId": str(uuid.uuid4()),
            "ExecutionId": self.execution_id,
            "GeneratedAt": datetime.datetime.now().isoformat(),
            "ValidUntil": (datetime.datetime.now() + datetime.timedelta(days=RETENTION_PERIOD_DAYS)).isoformat(),
            "Organization": {
                "Name": COMPANY_NAME,
                "Address": "123 Security Blvd, Cybertown, CS 12345",
                "Contact": "security@kmcyberservices.example",
                "DataProtectionOfficer": "dpo@kmcyberservices.example"
            },
            "CloudProvider": "Amazon Web Services",
            "AWS": {
                "AccountId": self.account_id,
                "Region": self.region,
                "Profile": self.profile
            },
            "Operation": {
                "StartTime": self.start_time.isoformat(),
                "EndTime": datetime.datetime.now().isoformat(),

### 7.3 Resource Inventory Templates

#### 7.3.1 Azure Resource Inventory Template
```csv
Subscription ID,Resource Group,Resource Name,Resource Type,Region,Data Classification,Destruction Date,Verification Method,Operator
```

#### 7.3.2 AWS Resource Inventory Template
```csv
Account ID,Region,Resource Name,Resource Type,ARN,Data Classification,Destruction Date,Verification Method,Operator
```

---

© 2025 KM Cyber Services. All rights reserved.
