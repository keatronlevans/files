                     "requestId": "@triggerBody().requestId",
                     "resourceType": "@triggerBody().resourceType",
                     "resourceIds": "@triggerBody().resourceIds",
                     "backupInfo": "@body('BackupData').backupInfo"
                   }
                 },
                 "runAfter": {
                   "BackupData": [
                     "Succeeded"
                   ]
                 }
               },
               "OverwriteData": {
                 "type": "Function",
                 "inputs": {
                   "function": {
                     "id": "[resourceId('Microsoft.Web/sites/functions', 'DestructionFunctions', 'OverwriteDataWithRandom')]"
                   },
                   "body": {
                     "requestId": "@triggerBody().requestId",
                     "resourceType": "@triggerBody().resourceType",
                     "resourceIds": "@triggerBody().resourceIds",
                     "accessInfo": "@body('DisableAccess').accessInfo"
                   }
                 },
                 "runAfter": {
                   "DisableAccess": [
                     "Succeeded"
                   ]
                 }
               },
               "DeleteData": {
                 "type": "Function",
                 "inputs": {
                   "function": {
                     "id": "[resourceId('Microsoft.Web/sites/functions', 'DestructionFunctions', 'DeleteData')]"
                   },
                   "body": {
                     "requestId": "@triggerBody().requestId",
                     "resourceType": "@triggerBody().resourceType",
                     "resourceIds": "@triggerBody().resourceIds",
                     "overwriteInfo": "@body('OverwriteData').overwriteInfo"
                   }
                 },
                 "runAfter": {
                   "OverwriteData": [
                     "Succeeded"
                   ]
                 }
               },
               "VerifyDeletion": {
                 "type": "Function",
                 "inputs": {
                   "function": {
                     "id": "[resourceId('Microsoft.Web/sites/functions', 'DestructionFunctions', 'VerifyDataDestruction')]"
                   },
                   "body": {
                     "requestId": "@triggerBody().requestId",
                     "resourceType": "@triggerBody().resourceType",
                     "resourceIds": "@triggerBody().resourceIds",
                     "deletionInfo": "@body('DeleteData').deletionInfo"
                   }
                 },
                 "runAfter": {
                   "DeleteData": [
                     "Succeeded"
                   ]
                 }
               },
               "GenerateCertificate": {
                 "type": "Function",
                 "inputs": {
                   "function": {
                     "id": "[resourceId('Microsoft.Web/sites/functions', 'DestructionFunctions', 'GenerateDestructionCertificate')]"
                   },
                   "body": {
                     "requestId": "@triggerBody().requestId",
                     "resourceType": "@triggerBody().resourceType",
                     "resourceIds": "@triggerBody().resourceIds",
                     "reason": "@triggerBody().reason",
                     "requestor": "@triggerBody().requestor",
                     "verificationInfo": "@body('VerifyDeletion').verificationInfo"
                   }
                 },
                 "runAfter": {
                   "VerifyDeletion": [
                     "Succeeded"
                   ]
                 }
               },
               "SendCompletionNotification": {
                 "type": "ApiConnection",
                 "inputs": {
                   "host": {
                     "connection": {
                       "name": "@parameters('$connections')['office365']['connectionId']"
                     }
                   },
                   "method": "post",
                   "body": {
                     "To": "@triggerBody().requestor",
                     "Subject": "Data Destruction Completed: @{triggerBody().requestId}",
                     "Body": "<p>Your data destruction request has been completed:</p><p>Request ID: @{triggerBody().requestId}</p><p>Resource Type: @{triggerBody().resourceType}</p><p>Resources: @{join(triggerBody().resourceIds, ', ')}</p><p>Certificate ID: @{body('GenerateCertificate').certificateId}</p><p>Please find the destruction certificate attached.</p>",
                     "Attachments": [
                       {
                         "Name": "Destruction_Certificate_@{triggerBody().requestId}.pdf",
                         "ContentBytes": "@{body('GenerateCertificate').certificatePdf}"
                       }
                     ]
                   },
                   "path": "/v2/Mail"
                 },
                 "runAfter": {
                   "GenerateCertificate": [
                     "Succeeded"
                   ]
                 }
               },
               "RespondToRequest": {
                 "type": "Response",
                 "kind": "Http",
                 "inputs": {
                   "statusCode": 200,
                   "body": {
                     "requestId": "@triggerBody().requestId",
                     "status": "Completed",
                     "certificateId": "@body('GenerateCertificate').certificateId",
                     "completionTime": "@utcNow()"
                   }
                 },
                 "runAfter": {
                   "SendCompletionNotification": [
                     "Succeeded"
                   ]
                 }
               }
             },
             "outputs": {}
           },
           "parameters": {
             "$connections": {
               "value": {
                 "office365": {
                   "connectionId": "[resourceId('Microsoft.Web/connections', 'office365')]",
                   "connectionName": "office365",
                   "id": "[subscriptionResourceId('Microsoft.Web/locations/managedApis', parameters('location'), 'office365')]"
                 },
                 "http": {
                   "connectionId": "[resourceId('Microsoft.Web/connections', 'http')]",
                   "connectionName": "http",
                   "id": "[subscriptionResourceId('Microsoft.Web/locations/managedApis', parameters('location'), 'http')]"
                 }
               }
             }
           }
         }
       },
       {
         "type": "Microsoft.Web/connections",
         "apiVersion": "2016-06-01",
         "name": "office365",
         "location": "[parameters('location')]",
         "properties": {
           "displayName": "Office 365 Outlook",
           "api": {
             "id": "[subscriptionResourceId('Microsoft.Web/locations/managedApis', parameters('location'), 'office365')]"
           }
         }
       },
       {
         "type": "Microsoft.Web/connections",
         "apiVersion": "2016-06-01",
         "name": "http",
         "location": "[parameters('location')]",
         "properties": {
           "displayName": "HTTP",
           "api": {
             "id": "[subscriptionResourceId('Microsoft.Web/locations/managedApis', parameters('location'), 'http')]"
           }
         }
       }
     ],
     "outputs": {
       "logicAppUrl": {
         "type": "string",
         "value": "[listCallbackUrl(resourceId('Microsoft.Logic/workflows/triggers', parameters('logicAppName'), 'manual'), '2019-05-01').value]"
       }
     }
   }
   ```

2. Implement Azure Functions for key workflow steps:

   Example of the validation function:
   ```csharp
   using System;
   using System.IO;
   using System.Threading.Tasks;
   using Microsoft.AspNetCore.Mvc;
   using Microsoft.Azure.WebJobs;
   using Microsoft.Azure.WebJobs.Extensions.Http;
   using Microsoft.AspNetCore.Http;
   using Microsoft.Extensions.Logging;
   using Newtonsoft.Json;
   using Microsoft.Azure.Management.Storage;
   using Microsoft.Azure.Management.Storage.Models;
   using Microsoft.Azure.Management.Compute;
   using Microsoft.Azure.Management.Compute.Models;
   using Microsoft.Azure.Management.Sql;
   using Microsoft.Azure.Management.Sql.Models;
   using Microsoft.Azure.Management.CosmosDB;
   using Microsoft.Azure.Management.CosmosDB.Models;
   using Microsoft.Rest.Azure.Authentication;
   using Microsoft.Identity.Client;
   using System.Linq;
   using System.Collections.Generic;
   
   namespace DestructionFunctions
   {
       public static class ValidateDestructionRequest
       {
           [FunctionName("ValidateDestructionRequest")]
           public static async Task<IActionResult> Run(
               [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
               ILogger log)
           {
               log.LogInformation("Validating destruction request");
   
               // Read the request body
               string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
               dynamic data = JsonConvert.DeserializeObject(requestBody);
   
               // Validate required fields
               if (data?.requestId == null || data?.resourceType == null || 
                   data?.resourceIds == null || data?.reason == null || data?.requestor == null)
               {
                   return new BadRequestObjectResult("Missing required fields");
               }
   
               // Validate resource type
               string resourceType = data.resourceType.ToString().ToLower();
               string[] validResourceTypes = { "storage", "disk", "sql", "cosmosdb", "function", "monitor" };
               if (!validResourceTypes.Contains(resourceType))
               {
                   return new BadRequestObjectResult($"Invalid resource type: {resourceType}");
               }
   
               // Validate email format
               string requestor = data.requestor.ToString();
               if (!System.Text.RegularExpressions.Regex.IsMatch(
                   requestor, @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"))
               {
                   return new BadRequestObjectResult($"Invalid email format: {requestor}");
               }
   
               // Get resource IDs
               string[] resourceIds = ((Newtonsoft.Json.Linq.JArray)data.resourceIds).ToObject<string[]>();
               if (resourceIds.Length == 0)
               {
                   return new BadRequestObjectResult("No resource IDs provided");
               }
   
               // Get authentication credentials for Azure management
               string clientId = Environment.GetEnvironmentVariable("CLIENT_ID");
               string clientSecret = Environment.GetEnvironmentVariable("CLIENT_SECRET");
               string tenantId = Environment.GetEnvironmentVariable("TENANT_ID");
               string subscriptionId = Environment.GetEnvironmentVariable("SUBSCRIPTION_ID");
   
               var credentials = await ApplicationTokenProvider.LoginSilentAsync(
                   tenantId, clientId, clientSecret);
   
               bool requiresApproval = false;
               string approvalUrl = String.Empty;
               string rejectUrl = String.Empty;
               string approvalStatusUrl = String.Empty;
   
               // Validate resources exist and check size for approval requirements
               try
               {
                   switch (resourceType)
                   {
                       case "storage":
                           var storageClient = new StorageManagementClient(credentials)
                           {
                               SubscriptionId = subscriptionId
                           };
   
                           long totalStorageSize = 0;
                           foreach (string resourceId in resourceIds)
                           {
                               // Parse resource ID to get resource group and name
                               var parts = resourceId.Split('/');
                               string resourceGroup = parts.SkipWhile(p => p != "resourceGroups")
                                   .Skip(1).FirstOrDefault();
                               string name = parts.Last();
   
                               if (string.IsNullOrEmpty(resourceGroup) || string.IsNullOrEmpty(name))
                               {
                                   return new BadRequestObjectResult($"Invalid resource ID format: {resourceId}");
                               }
   
                               try
                               {
                                   // Check if storage account exists
                                   var storageAccount = await storageClient.StorageAccounts.GetPropertiesAsync(
                                       resourceGroup, name);
   
                                   // For storage accounts, we don't have a direct size API
                                   // This is a simplification - in real implementation, use Storage Resource Provider metrics
                                   totalStorageSize += 1_000_000_000; // Assume 1GB per storage account for demo
                               }
                               catch (Exception ex)
                               {
                                   log.LogError($"Error checking storage account {name}: {ex.Message}");
                                   return new BadRequestObjectResult($"Resource not found or no access: {resourceId}");
                               }
                           }
   
                           requiresApproval = totalStorageSize > 10_000_000_000; // 10GB threshold
                           break;
   
                       // Similar validation for other resource types
                       case "disk":
                           var computeClient = new ComputeManagementClient(credentials)
                           {
                               SubscriptionId = subscriptionId
                           };
   
                           long totalDiskSize = 0;
                           foreach (string resourceId in resourceIds)
                           {
                               // Parse resource ID
                               var parts = resourceId.Split('/');
                               string resourceGroup = parts.SkipWhile(p => p != "resourceGroups")
                                   .Skip(1).FirstOrDefault();
                               string name = parts.Last();
   
                               try
                               {
                                   var disk = await computeClient.Disks.GetAsync(resourceGroup, name);
                                   totalDiskSize += disk.DiskSizeGB.GetValueOrDefault() * 1024 * 1024 * 1024;
                               }
                               catch (Exception ex)
                               {
                                   log.LogError($"Error checking disk {name}: {ex.Message}");
                                   return new BadRequestObjectResult($"Resource not found or no access: {resourceId}");
                               }
                           }
   
                           requiresApproval = totalDiskSize > 10_000_000_000; // 10GB threshold
                           break;
   
                       // Add cases for other resource types (sql, cosmosdb, etc.)
                       
                       default:
                           // Default to requiring approval for unknown types
                           requiresApproval = true;
                           break;
                   }
               }
               catch (Exception ex)
               {
                   log.LogError($"Error during validation: {ex.Message}");
                   return new BadRequestObjectResult($"Validation error: {ex.Message}");
               }
   
               // For approval flow, generate URLs
               if (requiresApproval)
               {
                   string requestId = data.requestId.ToString();
                   string approvalKey = Guid.NewGuid().ToString();
                   
                   // In a real implementation, save approval information to a durable store
                   // For this example, we'll generate placeholder URLs
                   string approvalBaseUrl = Environment.GetEnvironmentVariable("APPROVAL_BASE_URL");
                   approvalUrl = $"{approvalBaseUrl}/approve?requestId={requestId}&key={approvalKey}";
                   rejectUrl = $"{approvalBaseUrl}/reject?requestId={requestId}&key={approvalKey}";
                   approvalStatusUrl = $"{approvalBaseUrl}/status?requestId={requestId}";
               }
   
               // Return validation result
               var result = new
               {
                   requestId = data.requestId,
                   resourceType = resourceType,
                   resourceIds = resourceIds,
                   reason = data.reason,
                   requestor = requestor,
                   requiresApproval = requiresApproval,
                   approvalUrl = approvalUrl,
                   rejectUrl = rejectUrl,
                   approvalStatusUrl = approvalStatusUrl,
                   validationTime = DateTime.UtcNow.ToString("o")
               };
   
               return new OkObjectResult(result);
           }
       }
   }
   ```

3. Deploy the Logic App with Azure Resource Manager:
   ```bash
   # Create a resource group if needed
   az group create --name DataDestructionGroup --location eastus
   
   # Deploy the Logic App template
   az deployment group create \
     --resource-group DataDestructionGroup \
     --template-file data-destruction-workflow.json \
     --parameters logicAppName=DataDestructionWorkflow \
                  approverEmail=approver@example.com
   
   # Get the Logic App HTTP trigger URL
   az logic workflow show \
     --resource-group DataDestructionGroup \
     --name DataDestructionWorkflow \
     --query "accessEndpoint" \
     --output tsv
   ```

### Section 3: Security Considerations for Destruction Automation

#### 3.1 Least Privilege Principles

When implementing data destruction automation, apply least privilege principles:

1. **Create dedicated IAM roles for destruction process:**
   ```bash
   # AWS example of a restricted destruction role
   cat > destruction-policy.json << EOF
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "s3:GetObject",
           "s3:PutObject",
           "s3:DeleteObject",
           "s3:ListBucket",
           "s3:DeleteBucket"
         ],
         "Resource": [
           "arn:aws:s3:::${BUCKET_NAME}",
           "arn:aws:s3:::${BUCKET_NAME}/*"
         ]
       },
       {
         "Effect": "Allow",
         "Action": [
           "logs:CreateLogGroup",
           "logs:CreateLogStream",
           "logs:PutLogEvents"
         ],
         "Resource": "arn:aws:logs:*:*:*"
       }
     ]
   }
   EOF
   
   # Create role
   aws iam create-role \
     --role-name DataDestructionRole \
     --assume-role-policy-document file://trust-policy.json
   
   # Attach policy
   aws iam put-role-policy \
     --role-name DataDestructionRole \
     --policy-name DestructionPermissions \
     --policy-document file://destruction-policy.json
   ```

2. **Azure RBAC for destruction:**
   ```bash
   # Create custom role definition
   cat > destruction-role.json << EOF
   {
     "Name": "Data Destruction Operator",
     "Description": "Can perform secure data destruction operations",
     "Actions": [
       "Microsoft.Storage/storageAccounts/read",
       "Microsoft.Storage/storageAccounts/listKeys/action",
       "Microsoft.Storage/storageAccounts/blobServices/containers/read",
       "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
       "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
       "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
       "Microsoft.Compute/disks/read",
       "Microsoft.Compute/disks/write",
       "Microsoft.Compute/disks/delete",
       "Microsoft.Sql/servers/databases/read",
       "Microsoft.Sql/servers/databases/write",
       "Microsoft.Sql/servers/databases/delete",
       "Microsoft.DocumentDB/databaseAccounts/read",
       "Microsoft.DocumentDB/databaseAccounts/listKeys/action",
       "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/read",
       "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/delete",
       "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/read",
       "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/delete"
     ],
     "NotActions": [],
     "AssignableScopes": [
       "/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}"
     ]
   }
   EOF
   
   # Create the custom role
   az role definition create --role-definition @destruction-role.json
   
   # Assign role to destruction service principal
   az role assignment create \
     --role "Data Destruction Operator" \
     --assignee-object-id ${SERVICE_PRINCIPAL_ID} \
     --resource-group ${RESOURCE_GROUP} \
     --assignee-principal-type ServicePrincipal
   ```

#### 3.2 Secure Approval Process

Implement a secure multi-step approval process:

1. **Two-person approval for sensitive data:**
   ```javascript
   // Node.js example for a secure approval function
   
   const crypto = require('crypto');
   const { CosmosClient } = require('@azure/cosmos');
   
   // Initialize database connection
   const client = new CosmosClient({
     endpoint: process.env.COSMOS_ENDPOINT,
     key: process.env.COSMOS_KEY
   });
   const database = client.database('DestructionSystem');
   const approvals = database.container('Approvals');
   
   module.exports = async function (context, req) {
     // Validate request
     if (!req.query.requestId || !req.query.key || !req.query.approver) {
       context.res = {
         status: 400,
         body: "Missing required parameters"
       };
       return;
     }
     
     const requestId = req.query.requestId;
     const approvalKey = req.query.key;
     const approver = req.query.approver;
     const action = req.query.action || 'approve';
     
     try {
       // Get the request
       const { resource: request } = await approvals.item(requestId, requestId).read();
       
       // Verify approval key
       const expectedHash = crypto.createHmac('sha256', process.env.SECRET_KEY)
         .update(requestId + request.approvalSalt)
         .digest('hex');
       
       if (approvalKey !== expectedHash) {
         context.res = {
           status: 403,
           body: "Invalid approval key"
         };
         return;
       }
       
       // Check if approver is authorized
       if (!request.approvers.includes(approver)) {
         context.res = {
           status: 403,
           body: "Unauthorized approver"
         };
         return;
       }
       
       // Update approval status
       if (action === 'approve') {
         // Add this approval
         if (!request.approvedBy.includes(approver)) {
           request.approvedBy.push(approver);
         }
         
         // Check if we have all required approvals
         if (request.requiredApprovals <= request.approvedBy.length) {
           request.status = 'approved';
           request.approvalDate = new Date().toISOString();
         }
       } else if (action === 'reject') {
         request.status = 'rejected';
         request.rejectedBy = approver;
         request.rejectionDate = new Date().toISOString();
       }
       
       // Update the record
       await approvals.item(requestId, requestId).replace(request);
       
       // Return current status
       context.res = {
         status: 200,
         body: {
           requestId: requestId,
           status: request.status,
           approvedBy: request.approvedBy,
           requiredApprovals: request.requiredApprovals,
           message: action === 'approve' ? 
             "Approval recorded successfully" : 
             "Rejection recorded successfully"
         }
       };
     } catch (error) {
       context.log.error(`Error processing approval: ${error.message}`);
       context.res = {
         status: 500,
         body: "Error processing approval request"
       };
     }
   };
   ```

2. **Email with secure one-time links:**
   ```html
   <!-- Example email template with secure links -->
   <html>
   <head>
     <style>
       body { font-family: Arial, sans-serif; }
       .request-details { margin: 20px 0; padding: 10px; border: 1px solid #ddd; }
       .approval-buttons { margin: 20px 0; }
       .approve-button { 
         display: inline-block; 
         padding: 10px 20px; 
         background-color: #0078d4; 
         color: white; 
         text-decoration: none;
         margin-right: 10px;
       }
       .reject-button { 
         display: inline-block; 
         padding: 10px 20px; 
         background-color: #d13438; 
         color: white; 
         text-decoration: none;
       }
     </style>
   </head>
   <body>
     <h2>Data Destruction Approval Required</h2>
     <p>A request for data destruction requires your approval:</p>
     
     <div class="request-details">
       <p><strong>Request ID:</strong> {{requestId}}</p>
       <p><strong>Requestor:</strong> {{requestor}}</p>
       <p><strong>Resource Type:</strong> {{resourceType}}</p>
       <p><strong>Resources:</strong></p>
       <ul>
         {{#each resourceIds}}
         <li>{{this}}</li>
         {{/each}}
       </ul>
       <p><strong>Reason:</strong> {{reason}}</p>
       <p><strong>Date Requested:</strong> {{requestDate}}</p>
     </div>
     
     <p>This approval link is unique to you and will expire in 24 hours.</p>
     
     <div class="approval-buttons">
       <a href="{{approveUrl}}" class="approve-button">Approve Destruction</a>
       <a href="{{rejectUrl}}" class="reject-button">Reject Request</a>
     </div>
     
     <p>If you received this email in error, please contact security@example.com immediately.</p>
     
     <p>Request Details Hash: {{requestHash}}</p>
   </body>
   </html>
   ```

#### 3.3 Audit and Monitoring

Implement comprehensive audit trails for destruction activities:

1. **AWS CloudTrail enhanced monitoring:**
   ```bash
   # Create CloudTrail trail for destruction activities
   aws cloudtrail create-trail \
     --name DataDestructionTrail \
     --s3-bucket-name secure-audit-bucket \
     --is-multi-region-trail \
     --include-global-service-events \
     --enable-log-file-validation \
     --kms-key-id arn:aws:kms:region:account-id:key/key-id
   
   # Enable the trail
   aws cloudtrail start-logging --name DataDestructionTrail
   
   # Create a CloudWatch Logs group for the trail
   aws logs create-log-group --log-group-name DataDestructionAudit
   
   # Update trail to send events to CloudWatch Logs
   aws cloudtrail update-trail \
     --name DataDestructionTrail \
     --cloud-watch-logs-log-group-arn arn:aws:logs:region:account-id:log-group:DataDestructionAudit:* \
     --cloud-watch-logs-role-arn arn:aws:iam::account-id:role/CloudTrailToCloudWatchLogs
   
   # Create metric filter for destruction events
   aws logs put-metric-filter \
     --log-group-name DataDestructionAudit \
     --filter-name "DestructionEvents" \
     --filter-pattern '{$.eventName = "DeleteBucket" || $.eventName = "DeleteObject" || $.eventName = "DeleteDBInstance" || $.eventName = "DeleteTable" || $.eventName = "DeleteVolume"}' \
     --metric-transformations \
         metricName=DestructionEventCount,metricNamespace=DataSecurity,metricValue=1
   
   # Create alarm for high volume of destruction events
   aws cloudwatch put-metric-alarm \
     --alarm-name DestructionVolumeAlarm \
     --metric-name DestructionEventCount \
     --namespace DataSecurity \
     --statistic Sum \
     --period 300 \
     --evaluation-periods 1 \
     --threshold 10 \
     --comparison-operator GreaterThanOrEqualToThreshold \
     --alarm-actions arn:aws:sns:region:account-id:DestructionAlertTopic
   ```

2. **Azure Activity Log alerts:**
   ```bash
   # Create Action Group for alerts
   az monitor action-group create \
     --resource-group SecurityMonitoring \
     --name DestructionAlerts \
     --short-name Destroy \
     --action email security-team=security@example.com

   # Create Activity Log Alert for deletion operations
   az monitor activity-log alert create \
     --resource-group SecurityMonitoring \
     --name DestructionActivityAlert \
     --action-group DestructionAlerts \
     --condition category=Administrative \
     --condition-all operation=Microsoft.Storage/storageAccounts/delete \
     --condition-all operation=Microsoft.Compute/disks/delete \
     --condition-all operation=Microsoft.Sql/servers/databases/delete \
     --condition-all operation=Microsoft.DocumentDB/databaseAccounts/delete \
     --description "Alert on all resource deletion operations"
   ```

3. **Custom destruction event logging:**
   ```python
   # Python example for detailed event logging
   
   import json
   import logging
   import datetime
   import hashlib
   import boto3
   import uuid
   
   # Set up logger
   logger = logging.getLogger()
   logger.setLevel(logging.INFO)
   
   # Initialize clients
   s3 = boto3.client('s3')
   dynamodb = boto3.resource('dynamodb')
   table = dynamodb.Table('DestructionAuditLog')
   
   def log_destruction_event(event):
       """Log a destruction event with detailed metadata"""
       try:
           # Create event ID
           event_id = str(uuid.uuid4())
           
           # Get caller identity
           sts = boto3.client('sts')
           identity = sts.get_caller_identity()
           
           # Current timestamp
           timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
           
           # Create event signature
           signature_data = f"{event_id}:{timestamp}:{identity['UserId']}:{json.dumps(event)}"
           signature = hashlib.sha256(signature_data.encode()).hexdigest()
           
           # Build complete audit record
           audit_record = {
               'EventId': event_id,
               'Timestamp': timestamp,
               'EventType': 'DataDestruction',
               'ResourceType': event.get('resourceType'),
               'ResourceIds': event.get('resourceIds'),
               'RequestId': event.get('requestId'),
               'Requestor': event.get('requestor'),
               'ApprovedBy': event.get('approvedBy', []),
               'Reason': event.get('reason'),
               'Stage': event.get('stage', 'Unknown'),
               'Status': event.get('status', 'Unknown'),
               'Details': event.get('details', {}),
               'UserIdentity': {
                   'Type': 'AssumedRole',
                   'PrincipalId': identity['UserId'],
                   'Arn': identity['Arn'],
                   'AccountId': identity['Account']
               },
               'Signature': signature
           }
           
           # Store in DynamoDB
           table.put_item(Item=audit_record)
           
           # Log to CloudWatch
           logger.info(f"Destruction event logged: {event_id}")
           
           # For critical events, also     echo "Securely wiping function: $func"
     # Update code
     aws lambda update-function-code --function-name $func --zip-file fileb://empty-function.zip
     
     # Remove environment variables
     config=$(aws lambda get-function-configuration --function-name $func)
     if echo "$config" | grep -q "Environment"; then
       echo "Removing environment variables for function: $func"
       aws lambda update-function-configuration --function-name $func --environment "Variables={}"
     fi
   done
   ```

4. Delete Lambda functions:
   ```bash
   # Delete all Lambda functions
   for func in $(aws lambda list-functions --query "Functions[*].FunctionName" --output text); do
     echo "Deleting function: $func"
     aws lambda delete-function --function-name $func
   done
   ```

5. Delete Lambda versions and aliases:
   ```bash
   # For each function, delete all versions and aliases first
   for func in $(aws lambda list-functions --query "Functions[*].FunctionName" --output text); do
     # Delete all versions (except $LATEST which can't be deleted directly)
     for version in $(aws lambda list-versions-by-function --function-name $func --query "Versions[?Version!='$LATEST'].Version" --output text); do
       echo "Deleting version: $version of function: $func"
       aws lambda delete-function --function-name $func --qualifier $version
     done
     
     # Delete all aliases
     for alias in $(aws lambda list-aliases --function-name $func --query "Aliases[*].Name" --output text); do
       echo "Deleting alias: $alias of function: $func"
       aws lambda delete-alias --function-name $func --name $alias
     done
   done
   ```

6. Delete Lambda layers:
   ```bash
   # List and delete all layers and versions
   for layer in $(aws lambda list-layers --query "Layers[*].LayerName" --output text); do
     echo "Processing layer: $layer"
     for version in $(aws lambda list-layer-versions --layer-name $layer --query "LayerVersions[*].Version" --output text); do
       echo "Deleting layer version: $version of layer: $layer"
       aws lambda delete-layer-version --layer-name $layer --version-number $version
     done
   done
   ```

7. Verify deletion:
   ```bash
   # Verify no functions remain
   aws lambda list-functions --query "length(Functions)" --output text
   
   # Verify no layers remain or only empty layers
   aws lambda list-layers --query "length(Layers)" --output text
   ```

#### 5.2 Azure Functions Destruction

1. List all Function Apps:
   ```bash
   # List all function apps
   az functionapp list --query "[].{Name:name,ResourceGroup:resourceGroup,State:state}" --output table
   
   # Get details for each function app
   for app in $(az functionapp list --query "[].name" --output tsv); do
     echo "Function App: $app"
     echo "Functions:"
     az functionapp function list --name $app --resource-group $(az functionapp show --name $app --query resourceGroup --output tsv) --query "[].{Name:name}" --output table
     
     echo "Application settings:"
     az functionapp config appsettings list --name $app --resource-group $(az functionapp show --name $app --query resourceGroup --output tsv) --query "[].{Name:name,Value:value}" --output table
   done
   ```

2. Remove sensitive application settings:
   ```bash
   # For each function app, replace application settings with dummy values
   for app in $(az functionapp list --query "[].name" --output tsv); do
     rg=$(az functionapp show --name $app --query resourceGroup --output tsv)
     echo "Removing sensitive settings from Function App: $app"
     
     # Get all settings first
     settings=$(az functionapp config appsettings list --name $app --resource-group $rg --query "[].name" --output tsv)
     
     # Replace each setting with empty value or dummy
     for setting in $settings; do
       # Skip certain system settings
       if [[ $setting != WEBSITE_* ]] && [[ $setting != FUNCTIONS_* ]] && [[ $setting != AzureWebJobs* ]]; then
         echo "Overwriting setting: $setting"
         az functionapp config appsettings set --name $app --resource-group $rg --settings "$setting=WIPED_VALUE"
       fi
     done
   done
   ```

3. Replace function code with empty content:
   ```bash
   # This requires direct access to Kudu API or deployment methods
   # Below is an example using a simple HTTP trigger function
   
   # Create an empty function content
   mkdir -p empty-function/function
   cat > empty-function/host.json << EOF
   {
     "version": "2.0"
   }
   EOF
   
   cat > empty-function/function/function.json << EOF
   {
     "bindings": [
       {
         "authLevel": "anonymous",
         "type": "httpTrigger",
         "direction": "in",
         "name": "req"
       },
       {
         "type": "http",
         "direction": "out",
         "name": "res"
       }
     ]
   }
   EOF
   
   cat > empty-function/function/index.js << EOF
   module.exports = async function (context, req) {
     context.res = { status: 404 };
   }
   EOF
   
   # Create zip file
   cd empty-function
   zip -r ../empty-function.zip .
   cd ..
   
   # For each function app, deploy empty function
   for app in $(az functionapp list --query "[].name" --output tsv); do
     rg=$(az functionapp show --name $app --query resourceGroup --output tsv)
     echo "Replacing code in Function App: $app"
     
     # Deploy empty function
     az functionapp deployment source config-zip --resource-group $rg --name $app --src empty-function.zip
   done
   ```

4. Delete functions:
   ```bash
   # Delete each function from each function app
   for app in $(az functionapp list --query "[].name" --output tsv); do
     rg=$(az functionapp show --name $app --query resourceGroup --output tsv)
     
     for func in $(az functionapp function list --name $app --resource-group $rg --query "[].name" --output tsv); do
       echo "Deleting function: $func from app: $app"
       az functionapp function delete --name $app --resource-group $rg --function-name $func
     done
   done
   ```

5. Delete function apps:
   ```bash
   # Delete each function app
   for app in $(az functionapp list --query "[].name" --output tsv); do
     rg=$(az functionapp show --name $app --query resourceGroup --output tsv)
     echo "Deleting Function App: $app"
     az functionapp delete --name $app --resource-group $rg --yes
   done
   ```

6. Check for storage accounts and other dependencies:
   ```bash
   # List storage accounts
   az storage account list --query "[?tags.FunctionAppName!=null].{Name:name,ResourceGroup:resourceGroup,FunctionApp:tags.FunctionAppName}" --output table
   
   # Delete associated storage accounts
   for storage in $(az storage account list --query "[?tags.FunctionAppName!=null].name" --output tsv); do
     rg=$(az storage account show --name $storage --query resourceGroup --output tsv)
     echo "Deleting storage account: $storage"
     az storage account delete --name $storage --resource-group $rg --yes
   done
   ```

#### 5.3 AWS CloudWatch Logs Destruction

1. List log groups and streams:
   ```bash
   # List all log groups
   aws logs describe-log-groups --query "logGroups[*].{Name:logGroupName,Size:storedBytes,Retention:retentionInDays}" --output table
   
   # For large deployments, iterate through log groups
   aws logs describe-log-groups --query "logGroups[*].logGroupName" --output text | \
   while read log_group; do
     echo "Log Group: $log_group"
     echo "Log Streams:"
     aws logs describe-log-streams --log-group-name "$log_group" --query "logStreams[0:5].{Name:logStreamName,Size:storedBytes,CreationTime:creationTime}" --output table
     echo "..."
   done
   ```

2. Set short retention policies:
   ```bash
   # Set 1-day retention for all log groups
   aws logs describe-log-groups --query "logGroups[*].logGroupName" --output text | \
   while read log_group; do
     echo "Setting 1-day retention for log group: $log_group"
     aws logs put-retention-policy --log-group-name "$log_group" --retention-in-days 1
   done
   ```

3. Delete log events from log streams (if immediate deletion required):
   ```bash
   # For sensitive log groups, delete log events
   # This script processes one log group at a time - customize as needed
   LOG_GROUP_NAME="/aws/lambda/sensitive-function"
   
   # Get all log streams for this group
   aws logs describe-log-streams --log-group-name "$LOG_GROUP_NAME" --query "logStreams[*].logStreamName" --output text | \
   while read log_stream; do
     echo "Deleting events from log stream: $log_stream"
     
     # Get the most recent sequence token for this stream
     FIRST_EVENT=$(aws logs get-log-events --log-group-name "$LOG_GROUP_NAME" --log-stream-name "$log_stream" --limit 1 --start-from-head | jq -r '.events[0].timestamp')
     
     if [ -n "$FIRST_EVENT" ] && [ "$FIRST_EVENT" != "null" ]; then
       # Delete all events by setting start time to 0 and end time to the future
       aws logs delete-log-events --log-group-name "$LOG_GROUP_NAME" --log-stream-name "$log_stream" --start-time 0 --end-time $(($(date +%s) * 1000))
     fi
   done
   ```

4. Delete log groups:
   ```bash
   # Delete all log groups
   aws logs describe-log-groups --query "logGroups[*].logGroupName" --output text | \
   while read log_group; do
     echo "Deleting log group: $log_group"
     aws logs delete-log-group --log-group-name "$log_group"
   done
   ```

5. Delete CloudWatch metrics (if needed):
   ```bash
   # CloudWatch metrics can't be deleted directly, but you can delete alarms
   aws cloudwatch describe-alarms --query "MetricAlarms[*].AlarmName" --output text | \
   while read alarm; do
     echo "Deleting alarm: $alarm"
     aws cloudwatch delete-alarms --alarm-names "$alarm"
   done
   
   # Delete dashboards
   aws cloudwatch list-dashboards --query "DashboardEntries[*].DashboardName" --output text | \
   while read dashboard; do
     echo "Deleting dashboard: $dashboard"
     aws cloudwatch delete-dashboards --dashboard-names "$dashboard"
   done
   ```

#### 5.4 Azure Monitor Logs Destruction

1. List Log Analytics workspaces:
   ```bash
   # List all workspaces
   az monitor log-analytics workspace list --query "[].{Name:name,ResourceGroup:resourceGroup,Location:location,RetentionDays:retentionInDays}" --output table
   ```

2. List stored logs and set shorter retention:
   ```bash
   # For each workspace, set minimum retention
   for ws in $(az monitor log-analytics workspace list --query "[].name" --output tsv); do
     rg=$(az monitor log-analytics workspace show --workspace-name $ws --query resourceGroup --output tsv)
     echo "Setting minimum retention for workspace: $ws"
     
     # Set to minimum (30 days for most tiers)
     az monitor log-analytics workspace update --workspace-name $ws --resource-group $rg --retention-time 30
   done
   ```

3. Execute data purge requests (requires special permissions):
   ```bash
   # Create a purge request (example)
   # Note: This requires special permissions
   
   # First, get workspace ID
   WORKSPACE_NAME="my-workspace"
   RG=$(az monitor log-analytics workspace show --workspace-name $WORKSPACE_NAME --query resourceGroup --output tsv)
   WORKSPACE_ID=$(az monitor log-analytics workspace show --workspace-name $WORKSPACE_NAME --resource-group $RG --query customerId --output tsv)
   
   # Create purge request - requires subscription ID
   SUBSCRIPTION_ID=$(az account show --query id --output tsv)
   
   echo "Creating purge request for workspace: $WORKSPACE_NAME"
   
   # This requires REST API call with proper permissions
   # Sample request body (customize filters as needed)
   cat > purge-request.json << EOF
   {
     "table": "SecurityEvent",
     "filters": [
       {
         "column": "TimeGenerated",
         "operator": ">=",
         "value": "2023-01-01T00:00:00Z"
       },
       {
         "column": "TimeGenerated",
         "operator": "<",
         "value": "2023-06-01T00:00:00Z"
       }
     ]
   }
   EOF
   
   # Execute the purge request using REST API (requires proper authorization)
   az rest --method post \
     --uri "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourcegroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE_NAME/purge?api-version=2020-08-01" \
     --body @purge-request.json
   ```

4. Delete Azure Monitor diagnostic settings:
   ```bash
   # List diagnostic settings for a specific resource (e.g., virtual machine)
   RESOURCE_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/my-vm"
   
   az monitor diagnostic-settings list --resource $RESOURCE_ID --query "[].{Name:name}" --output table
   
   # Delete diagnostic settings
   for diag in $(az monitor diagnostic-settings list --resource $RESOURCE_ID --query "[].name" --output tsv); do
     echo "Deleting diagnostic setting: $diag for resource: $RESOURCE_ID"
     az monitor diagnostic-settings delete --name $diag --resource $RESOURCE_ID
   done
   ```

5. Delete Log Analytics workspaces:
   ```bash
   # Delete each workspace
   for ws in $(az monitor log-analytics workspace list --query "[].name" --output tsv); do
     rg=$(az monitor log-analytics workspace show --workspace-name $ws --query resourceGroup --output tsv)
     echo "Deleting workspace: $ws"
     az monitor log-analytics workspace delete --workspace-name $ws --resource-group $rg --yes
   done
   ```

---

## Part 5: Data Destruction Automation

### Section 1: Creating AWS Destruction Pipelines

#### 1.1 AWS Step Functions Destruction Workflow

Create a state machine that orchestrates the destruction process with proper verification and approvals:

1. Create a Step Functions definition file:
   ```json
   {
     "Comment": "Data Destruction State Machine",
     "StartAt": "ValidateRequest",
     "States": {
       "ValidateRequest": {
         "Type": "Task",
         "Resource": "arn:aws:lambda:REGION:ACCOUNT_ID:function:ValidateDestructionRequest",
         "Next": "ApprovalRequired",
         "Catch": [
           {
             "ErrorEquals": ["ValidationError"],
             "Next": "FailState"
           }
         ]
       },
       "ApprovalRequired": {
         "Type": "Choice",
         "Choices": [
           {
             "Variable": "$.requiresApproval",
             "BooleanEquals": true,
             "Next": "RequestApproval"
           }
         ],
         "Default": "BackupData"
       },
       "RequestApproval": {
         "Type": "Task",
         "Resource": "arn:aws:lambda:REGION:ACCOUNT_ID:function:RequestDestructionApproval",
         "Next": "WaitForApproval"
       },
       "WaitForApproval": {
         "Type": "Wait",
         "SecondsPath": "$.waitTime",
         "Next": "CheckApprovalStatus"
       },
       "CheckApprovalStatus": {
         "Type": "Task",
         "Resource": "arn:aws:lambda:REGION:ACCOUNT_ID:function:CheckDestructionApproval",
         "Next": "IsApproved"
       },
       "IsApproved": {
         "Type": "Choice",
         "Choices": [
           {
             "Variable": "$.approved",
             "BooleanEquals": true,
             "Next": "BackupData"
           },
           {
             "Variable": "$.waitForApproval",
             "BooleanEquals": true,
             "Next": "WaitForApproval"
           }
         ],
         "Default": "FailState"
       },
       "BackupData": {
         "Type": "Task",
         "Resource": "arn:aws:lambda:REGION:ACCOUNT_ID:function:BackupBeforeDestruction",
         "Next": "DisableAccess"
       },
       "DisableAccess": {
         "Type": "Task",
         "Resource": "arn:aws:lambda:REGION:ACCOUNT_ID:function:DisableDataAccess",
         "Next": "OverwriteData"
       },
       "OverwriteData": {
         "Type": "Task",
         "Resource": "arn:aws:lambda:REGION:ACCOUNT_ID:function:OverwriteDataWithRandom",
         "Next": "DeleteData"
       },
       "DeleteData": {
         "Type": "Task",
         "Resource": "arn:aws:lambda:REGION:ACCOUNT_ID:function:DeleteData",
         "Next": "VerifyDeletion"
       },
       "VerifyDeletion": {
         "Type": "Task",
         "Resource": "arn:aws:lambda:REGION:ACCOUNT_ID:function:VerifyDataDestruction",
         "Next": "GenerateCertificate"
       },
       "GenerateCertificate": {
         "Type": "Task",
         "Resource": "arn:aws:lambda:REGION:ACCOUNT_ID:function:GenerateDestructionCertificate",
         "End": true
       },
       "FailState": {
         "Type": "Fail",
         "Error": "DestructionError",
         "Cause": "Destruction process failed or was rejected"
       }
     }
   }
   ```

2. Implement Lambda functions for each step:

   Example for the validation function:
   ```python
   # validate_destruction_request.py
   import json
   import boto3
   import re
   
   def lambda_handler(event, context):
     """
     Validates a data destruction request
     
     Expected event structure:
     {
       "requestId": "unique-id",
       "resourceType": "s3|ebs|rds|dynamodb",
       "resourceIds": ["id1", "id2", "..."],
       "reason": "reason for destruction",
       "requestor": "user@example.com"
     }
     """
     required_fields = ["requestId", "resourceType", "resourceIds", "reason", "requestor"]
     
     # Check for required fields
     for field in required_fields:
       if field not in event or not event[field]:
         raise Exception(f"ValidationError: Missing required field: {field}")
     
     # Validate resource type
     valid_resource_types = ["s3", "ebs", "rds", "dynamodb", "lambda", "cloudwatch"]
     if event["resourceType"] not in valid_resource_types:
       raise Exception(f"ValidationError: Invalid resource type: {event['resourceType']}")
     
     # Validate email format
     email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}     -- First overwrite with random data
     SET @sql = CONCAT('UPDATE ', table_name, ' SET ');
     
     -- Get column information
     SET @sql_cols = (
       SELECT GROUP_CONCAT(
         CASE 
           WHEN DATA_TYPE IN ('varchar', 'char', 'text') THEN 
             CONCAT(COLUMN_NAME, ' = REPEAT(MD5(RAND()), ', 
                  CEILING(CHARACTER_MAXIMUM_LENGTH / 32), ')')
           WHEN DATA_TYPE IN ('int', 'bigint', 'smallint') THEN 
             CONCAT(COLUMN_NAME, ' = FLOOR(RAND() * 1000000)')
           WHEN DATA_TYPE = 'date' THEN 
             CONCAT(COLUMN_NAME, ' = DATE_ADD(''1970-01-01'', INTERVAL FLOOR(RAND() * 18250) DAY)')
           WHEN DATA_TYPE LIKE '%datetime%' THEN 
             CONCAT(COLUMN_NAME, ' = FROM_UNIXTIME(RAND() * 1000000000)')
           WHEN DATA_TYPE IN ('decimal', 'float', 'double') THEN 
             CONCAT(COLUMN_NAME, ' = RAND() * 10000')
           WHEN DATA_TYPE IN ('bit', 'boolean') THEN 
             CONCAT(COLUMN_NAME, ' = ROUND(RAND())')
           ELSE 
             CONCAT(COLUMN_NAME, ' = NULL')
         END
         SEPARATOR ', '
       )
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = table_name
       AND COLUMN_KEY != 'PRI'  -- Skip primary key columns
     );
     
     SET @full_sql = CONCAT(@sql, @sql_cols);
     PREPARE stmt FROM @full_sql;
     EXECUTE stmt;
     DEALLOCATE PREPARE stmt;
     
     -- Get row count
     SET @count_sql = CONCAT('SELECT COUNT(*) INTO @row_count FROM ', table_name);
     PREPARE stmt FROM @count_sql;
     EXECUTE stmt;
     DEALLOCATE PREPARE stmt;
     
     -- Repeat overwrite with zeros
     SET @sql_cols = (
       SELECT GROUP_CONCAT(
         CASE 
           WHEN DATA_TYPE IN ('varchar', 'char', 'text') THEN 
             CONCAT(COLUMN_NAME, ' = REPEAT(''0'', ', 
                  CASE WHEN CHARACTER_MAXIMUM_LENGTH IS NULL 
                       THEN 255 
                       ELSE CHARACTER_MAXIMUM_LENGTH END, ')')
           WHEN DATA_TYPE IN ('int', 'bigint', 'smallint') THEN 
             CONCAT(COLUMN_NAME, ' = 0')
           WHEN DATA_TYPE = 'date' THEN 
             CONCAT(COLUMN_NAME, ' = ''1970-01-01''')
           WHEN DATA_TYPE LIKE '%datetime%' THEN 
             CONCAT(COLUMN_NAME, ' = ''1970-01-01 00:00:00''')
           WHEN DATA_TYPE IN ('decimal', 'float', 'double') THEN 
             CONCAT(COLUMN_NAME, ' = 0')
           WHEN DATA_TYPE IN ('bit', 'boolean') THEN 
             CONCAT(COLUMN_NAME, ' = 0')
           ELSE 
             CONCAT(COLUMN_NAME, ' = NULL')
         END
         SEPARATOR ', '
       )
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = table_name
       AND COLUMN_KEY != 'PRI'  -- Skip primary key columns
     );
     
     SET @full_sql = CONCAT(@sql, @sql_cols);
     PREPARE stmt FROM @full_sql;
     EXECUTE stmt;
     DEALLOCATE PREPARE stmt;
     
     -- Delete all records
     SET @delete_sql = CONCAT('DELETE FROM ', table_name);
     PREPARE stmt FROM @delete_sql;
     EXECUTE stmt;
     DEALLOCATE PREPARE stmt;
     
     -- Finally drop the table
     SET @drop_sql = CONCAT('DROP TABLE ', table_name);
     PREPARE stmt FROM @drop_sql;
     EXECUTE stmt;
     DEALLOCATE PREPARE stmt;
     
     SELECT CONCAT('Securely deleted table ', table_name, ' with ', @row_count, ' rows') AS Result;
   END //
   DELIMITER ;
   ```

2. Execute the secure deletion for all tables:
   ```sql
   -- Get list of all tables and run secure deletion on each
   CREATE TEMPORARY TABLE tables_to_delete AS
   SELECT table_name 
   FROM information_schema.tables
   WHERE table_schema = DATABASE()
   AND table_type = 'BASE TABLE';
   
   -- Loop through tables
   DELIMITER //
   CREATE PROCEDURE delete_all_tables()
   BEGIN
     DECLARE done INT DEFAULT FALSE;
     DECLARE tbl_name VARCHAR(64);
     DECLARE cur CURSOR FOR SELECT table_name FROM tables_to_delete;
     DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
     
     OPEN cur;
     
     read_loop: LOOP
       FETCH cur INTO tbl_name;
       IF done THEN
         LEAVE read_loop;
       END IF;
       
       CALL secure_delete_table(tbl_name);
     END LOOP;
     
     CLOSE cur;
   END //
   DELIMITER ;
   
   -- Execute the procedure
   CALL delete_all_tables();
   
   -- Clean up
   DROP PROCEDURE delete_all_tables;
   DROP PROCEDURE secure_delete_table;
   DROP TEMPORARY TABLE tables_to_delete;
   ```

3. Azure SQL Database secure deletion:
   ```sql
   -- Example secure deletion stored procedure for Azure SQL
   CREATE PROCEDURE SecureDeleteTable
       @TableName NVARCHAR(128)
   AS
   BEGIN
       DECLARE @SQL NVARCHAR(MAX)
       DECLARE @ColumnList NVARCHAR(MAX) = ''
       DECLARE @RandomColumnList NVARCHAR(MAX) = ''
       DECLARE @ZeroColumnList NVARCHAR(MAX) = ''
       DECLARE @RowCount INT
       
       -- Get column information for updates
       SELECT @ColumnList = @ColumnList + ',' + QUOTENAME(c.name)
       FROM sys.columns c
       INNER JOIN sys.tables t ON c.object_id = t.object_id
       WHERE t.name = @TableName
       AND c.is_identity = 0  -- Skip identity columns
       
       -- Remove leading comma
       SET @ColumnList = STUFF(@ColumnList, 1, 1, '')
       
       -- Generate random data update statement
       SELECT @RandomColumnList = @RandomColumnList + ',' + 
           CASE 
               WHEN t.name LIKE '%char%' OR t.name LIKE 'nvarchar%' OR t.name LIKE 'varchar%' OR t.name LIKE '%text%'
                   THEN QUOTENAME(c.name) + ' = CONVERT(' + t.name + 
                        CASE WHEN c.max_length <> -1 
                             THEN '(' + CAST(c.max_length AS NVARCHAR) + ')' 
                             ELSE '(MAX)' END + 
                        ', CRYPT_GEN_RANDOM(' + 
                        CASE WHEN c.max_length <> -1 
                             THEN CAST(c.max_length AS NVARCHAR) 
                             ELSE '8000' END + '))'
               WHEN t.name LIKE '%int%' 
                   THEN QUOTENAME(c.name) + ' = ABS(CHECKSUM(NEWID()))'
               WHEN t.name LIKE '%date%' OR t.name LIKE '%time%'
                   THEN QUOTENAME(c.name) + ' = DATEADD(DAY, ABS(CHECKSUM(NEWID())) % 36500, ''1900-01-01'')'
               WHEN t.name LIKE '%decimal%' OR t.name LIKE '%numeric%' OR t.name LIKE 'float%' OR t.name = 'real'
                   THEN QUOTENAME(c.name) + ' = ABS(CHECKSUM(NEWID())) * 1.0 / ABS(CHECKSUM(NEWID()))'
               WHEN t.name = 'bit'
                   THEN QUOTENAME(c.name) + ' = CONVERT(BIT, ABS(CHECKSUM(NEWID())) % 2)'
               WHEN t.name IN ('binary', 'varbinary')
                   THEN QUOTENAME(c.name) + ' = CONVERT(' + t.name + 
                        CASE WHEN c.max_length <> -1 
                             THEN '(' + CAST(c.max_length AS NVARCHAR) + ')' 
                             ELSE '(MAX)' END + 
                        ', CRYPT_GEN_RANDOM(' + 
                        CASE WHEN c.max_length <> -1 
                             THEN CAST(c.max_length AS NVARCHAR) 
                             ELSE '8000' END + '))'
               ELSE QUOTENAME(c.name) + ' = NULL'
           END
       FROM sys.columns c
       INNER JOIN sys.tables t1 ON c.object_id = t1.object_id
       INNER JOIN sys.types t ON c.user_type_id = t.user_type_id
       WHERE t1.name = @TableName
       AND c.is_identity = 0  -- Skip identity columns
       
       -- Remove leading comma
       SET @RandomColumnList = STUFF(@RandomColumnList, 1, 1, '')
       
       -- Generate zero data update statement
       SELECT @ZeroColumnList = @ZeroColumnList + ',' + 
           CASE 
               WHEN t.name LIKE '%char%' OR t.name LIKE 'nvarchar%' OR t.name LIKE 'varchar%' OR t.name LIKE '%text%'
                   THEN QUOTENAME(c.name) + ' = CONVERT(' + t.name + 
                        CASE WHEN c.max_length <> -1 
                             THEN '(' + CAST(c.max_length AS NVARCHAR) + ')' 
                             ELSE '(MAX)' END + 
                        ', REPLICATE(''0'', ' + 
                        CASE WHEN c.max_length <> -1 
                             THEN CAST(c.max_length AS NVARCHAR) 
                             ELSE '8000' END + '))'
               WHEN t.name LIKE '%int%' 
                   THEN QUOTENAME(c.name) + ' = 0'
               WHEN t.name LIKE '%date%' OR t.name LIKE '%time%'
                   THEN QUOTENAME(c.name) + ' = ''1900-01-01'''
               WHEN t.name LIKE '%decimal%' OR t.name LIKE '%numeric%' OR t.name LIKE 'float%' OR t.name = 'real'
                   THEN QUOTENAME(c.name) + ' = 0'
               WHEN t.name = 'bit'
                   THEN QUOTENAME(c.name) + ' = 0'
               WHEN t.name IN ('binary', 'varbinary')
                   THEN QUOTENAME(c.name) + ' = CONVERT(' + t.name + 
                        CASE WHEN c.max_length <> -1 
                             THEN '(' + CAST(c.max_length AS NVARCHAR) + ')' 
                             ELSE '(MAX)' END + 
                        ', REPLICATE(CAST(0 AS BINARY(1)), ' + 
                        CASE WHEN c.max_length <> -1 
                             THEN CAST(c.max_length AS NVARCHAR) 
                             ELSE '8000' END + '))'
               ELSE QUOTENAME(c.name) + ' = NULL'
           END
       FROM sys.columns c
       INNER JOIN sys.tables t1 ON c.object_id = t1.object_id
       INNER JOIN sys.types t ON c.user_type_id = t.user_type_id
       WHERE t1.name = @TableName
       AND c.is_identity = 0  -- Skip identity columns
       
       -- Remove leading comma
       SET @ZeroColumnList = STUFF(@ZeroColumnList, 1, 1, '')
       
       -- Get row count
       SET @SQL = N'SELECT @RowCount = COUNT(*) FROM ' + QUOTENAME(@TableName)
       EXEC sp_executesql @SQL, N'@RowCount INT OUTPUT', @RowCount OUTPUT
       
       BEGIN TRY
           BEGIN TRANSACTION
           
           -- First overwrite with random data
           IF @RandomColumnList <> ''
           BEGIN
               SET @SQL = N'UPDATE ' + QUOTENAME(@TableName) + 
                          N' SET ' + @RandomColumnList
               EXEC sp_executesql @SQL
           END
           
           -- Then overwrite with zeros
           IF @ZeroColumnList <> ''
           BEGIN
               SET @SQL = N'UPDATE ' + QUOTENAME(@TableName) + 
                          N' SET ' + @ZeroColumnList
               EXEC sp_executesql @SQL
           END
           
           -- Delete all records
           SET @SQL = N'DELETE FROM ' + QUOTENAME(@TableName)
           EXEC sp_executesql @SQL
           
           -- Drop the table
           SET @SQL = N'DROP TABLE ' + QUOTENAME(@TableName)
           EXEC sp_executesql @SQL
           
           COMMIT TRANSACTION
           
           SELECT 'Securely deleted table ' + @TableName + ' with ' + 
                  CAST(@RowCount AS NVARCHAR(20)) + ' rows' AS Result
       END TRY
       BEGIN CATCH
           IF @@TRANCOUNT > 0
               ROLLBACK TRANSACTION
               
           DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE()
           DECLARE @ErrorSeverity INT = ERROR_SEVERITY()
           DECLARE @ErrorState INT = ERROR_STATE()
           
           RAISERROR(@ErrorMessage, @ErrorSeverity, @ErrorState)
       END CATCH
   END
   GO
   
   -- Execute for all tables
   CREATE PROCEDURE SecureDeleteAllTables
   AS
   BEGIN
       DECLARE @TableName NVARCHAR(128)
       DECLARE @SQL NVARCHAR(MAX)
       
       -- Create a temporary table to hold table names
       CREATE TABLE #TablesToDelete (TableName NVARCHAR(128))
       
       -- Get list of all tables
       INSERT INTO #TablesToDelete (TableName)
       SELECT name FROM sys.tables
       WHERE is_ms_shipped = 0  -- Exclude system tables
       
       -- Process each table
       WHILE EXISTS (SELECT 1 FROM #TablesToDelete)
       BEGIN
           SELECT TOP 1 @TableName = TableName FROM #TablesToDelete
           
           EXEC SecureDeleteTable @TableName
           
           DELETE FROM #TablesToDelete WHERE TableName = @TableName
       END
       
       -- Clean up
       DROP TABLE #TablesToDelete
   END
   GO
   
   -- Execute the procedure
   EXEC SecureDeleteAllTables
   GO
   
   -- Clean up
   DROP PROCEDURE SecureDeleteAllTables
   DROP PROCEDURE SecureDeleteTable
   GO
   ```

#### 4.2 AWS DynamoDB Secure Deletion

1. Create secure item overwriting function:
   ```javascript
   // Node.js script for securely overwriting DynamoDB items before deletion
   const AWS = require('aws-sdk');
   const crypto = require('crypto');
   const dynamodb = new AWS.DynamoDB();
   const docClient = new AWS.DynamoDB.DocumentClient();
   
   async function secureDeleteTable(tableName) {
     // Get table description to understand the schema
     const tableInfo = await dynamodb.describeTable({ TableName: tableName }).promise();
     const keySchema = tableInfo.Table.KeySchema;
     const primaryKey = keySchema.find(k => k.KeyType === 'HASH').AttributeName;
     const sortKey = keySchema.find(k => k.KeyType === 'RANGE')?.AttributeName;
     
     // Get attribute definitions to understand types
     const attrDefinitions = tableInfo.Table.AttributeDefinitions;
     const primaryKeyType = attrDefinitions.find(a => a.AttributeName === primaryKey).AttributeType;
     const sortKeyType = sortKey ? 
       attrDefinitions.find(a => a.AttributeName === sortKey)?.AttributeType : null;
     
     console.log(`Table: ${tableName}, PK: ${primaryKey}(${primaryKeyType}), SK: ${sortKey || 'none'}(${sortKeyType || 'n/a'})`);
     
     // Scan all items in the table
     let scanParams = { TableName: tableName };
     let itemCount = 0;
     let totalItems = 0;
     
     do {
       const scanResult = await docClient.scan(scanParams).promise();
       totalItems += scanResult.Items.length;
       
       // Process items in batches
       for (const item of scanResult.Items) {
         // Create key for this item
         const key = {};
         key[primaryKey] = item[primaryKey];
         if (sortKey) key[sortKey] = item[sortKey];
         
         // Get all attribute names from this item
         const attributeNames = Object.keys(item);
         
         // First overwrite - random data
         const randomItem = {};
         attributeNames.forEach(attr => {
           if (attr === primaryKey || attr === sortKey) {
             // Keep keys unchanged
             randomItem[attr] = item[attr];
           } else if (typeof item[attr] === 'string') {
             // Random string of same length
             randomItem[attr] = crypto.randomBytes(item[attr].length).toString('hex').substring(0, item[attr].length);
           } else if (typeof item[attr] === 'number') {
             // Random number
             randomItem[attr] = Math.floor(Math.random() * 1000000);
           } else if (typeof item[attr] === 'boolean') {
             // Random boolean
             randomItem[attr] = Math.random() >= 0.5;
           } else if (Buffer.isBuffer(item[attr])) {
             // Random buffer of same length
             randomItem[attr] = crypto.randomBytes(item[attr].length);
           } else if (Array.isArray(item[attr])) {
             // Random array of same length
             randomItem[attr] = Array(item[attr].length).fill().map(() => crypto.randomBytes(8).toString('hex'));
           } else if (typeof item[attr] === 'object' && item[attr] !== null) {
             // Random object with same structure
             randomItem[attr] = {};
             Object.keys(item[attr]).forEach(key => {
               randomItem[attr][key] = crypto.randomBytes(8).toString('hex');
             });
           }
         });
         
         // Update with random data
         await docClient.put({
           TableName: tableName,
           Item: randomItem
         }).promise();
         
         // Second overwrite - zeros/nulls
         const zeroItem = {};
         attributeNames.forEach(attr => {
           if (attr === primaryKey || attr === sortKey) {
             // Keep keys unchanged
             zeroItem[attr] = item[attr];
           } else if (typeof item[attr] === 'string') {
             // Zero string
             zeroItem[attr] = '0'.repeat(item[attr].length);
           } else if (typeof item[attr] === 'number') {
             // Zero
             zeroItem[attr] = 0;
           } else if (typeof item[attr] === 'boolean') {
             // False
             zeroItem[attr] = false;
           } else if (Buffer.isBuffer(item[attr])) {
             // Zero buffer
             zeroItem[attr] = Buffer.alloc(item[attr].length, 0);
           } else if (Array.isArray(item[attr])) {
             // Zero array
             zeroItem[attr] = Array(item[attr].length).fill('0');
           } else if (typeof item[attr] === 'object' && item[attr] !== null) {
             // Zero object
             zeroItem[attr] = {};
             Object.keys(item[attr]).forEach(key => {
               zeroItem[attr][key] = '0';
             });
           }
         });
         
         // Update with zero data
         await docClient.put({
           TableName: tableName,
           Item: zeroItem
         }).promise();
         
         // Finally delete the item
         await docClient.delete({
           TableName: tableName,
           Key: key
         }).promise();
         
         itemCount++;
         if (itemCount % 100 === 0) {
           console.log(`Processed ${itemCount} items...`);
         }
       }
       
       // Continue scanning if we have more items
       scanParams.ExclusiveStartKey = scanResult.LastEvaluatedKey;
     } while (scanParams.ExclusiveStartKey);
     
     console.log(`Securely deleted ${itemCount} items from table ${tableName}`);
     
     // Delete the table itself
     await dynamodb.deleteTable({ TableName: tableName }).promise();
     console.log(`Deleted table ${tableName}`);
     
     return { tableName, itemsDeleted: itemCount };
   }
   
   async function secureDeleteAllTables() {
     // List all tables
     const tables = await dynamodb.listTables({}).promise();
     console.log(`Found ${tables.TableNames.length} tables`);
     
     // Process each table
     for (const tableName of tables.TableNames) {
       try {
         console.log(`Starting secure deletion of table: ${tableName}`);
         const result = await secureDeleteTable(tableName);
         console.log(`Completed: ${result.itemsDeleted} items deleted from ${result.tableName}`);
       } catch (error) {
         console.error(`Error processing table ${tableName}: ${error.message}`);
       }
     }
   }
   
   // Execute
   secureDeleteAllTables().catch(err => console.error('Error:', err));
   ```

2. Azure Cosmos DB secure deletion:
   ```javascript
   // Node.js script for securely overwriting Cosmos DB items
   const { CosmosClient } = require('@azure/cosmos');
   const crypto = require('crypto');
   
   // Setup
   const endpoint = process.env.COSMOS_ENDPOINT;
   const key = process.env.COSMOS_KEY;
   const client = new CosmosClient({ endpoint, key });
   
   async function secureDeleteContainer(databaseId, containerId) {
     const database = client.database(databaseId);
     const container = database.container(containerId);
     
     // Get container metadata
     const containerInfo = await container.read();
     console.log(`Container: ${containerId}, Partition Key: ${containerInfo.resource.partitionKey.paths[0]}`);
     const partitionKeyPath = containerInfo.resource.partitionKey.paths[0].replace('/', '');
     
     // Query all items
     const querySpec = {
       query: "SELECT * FROM c"
     };
     
     const { resources: items } = await container.items.query(querySpec).fetchAll();
     console.log(`Found ${items.length} items in container ${containerId}`);
     
     let itemCount = 0;
     
     // Process each item
     for (const item of items) {
       const id = item.id;
       const partitionKey = item[partitionKeyPath];
       
       // Create overwrite item structure
       const attributeNames = Object.keys(item);
       
       // First overwrite - random data
       const randomItem = { id };
       attributeNames.forEach(attr => {
         if (attr === 'id' || attr === partitionKeyPath || attr === '_rid' || 
             attr === '_self' || attr === '_etag' || attr === '_attachments' || 
             attr === '_ts') {
           // Keep system properties and key fields unchanged
           randomItem[attr] = item[attr];
         } else if (typeof item[attr] === 'string') {
           randomItem[attr] = crypto.randomBytes(item[attr].length).toString('hex').substring(0, item[attr].length);
         } else if (typeof item[attr] === 'number') {
           randomItem[attr] = Math.floor(Math.random() * 1000000);
         } else if (typeof item[attr] === 'boolean') {
           randomItem[attr] = Math.random() >= 0.5;
         } else if (Array.isArray(item[attr])) {
           randomItem[attr] = Array(item[attr].length).fill().map(() => crypto.randomBytes(8).toString('hex'));
         } else if (typeof item[attr] === 'object' && item[attr] !== null) {
           randomItem[attr] = {};
           Object.keys(item[attr]).forEach(key => {
             randomItem[attr][key] = crypto.randomBytes(8).toString('hex');
           });
         }
       });
       
       // Update with random data
       await container.item(id, partitionKey).replace(randomItem);
       
       // Second overwrite - zeros/nulls
       const zeroItem = { id };
       attributeNames.forEach(attr => {
         if (attr === 'id' || attr === partitionKeyPath || attr === '_rid' || 
             attr === '_self' || attr === '_etag' || attr === '_attachments' || 
             attr === '_ts') {
           // Keep system properties and key fields unchanged
           zeroItem[attr] = item[attr];
         } else if (typeof item[attr] === 'string') {
           zeroItem[attr] = '0'.repeat(item[attr].length);
         } else if (typeof item[attr] === 'number') {
           zeroItem[attr] = 0;
         } else if (typeof item[attr] === 'boolean') {
           zeroItem[attr] = false;
         } else if (Array.isArray(item[attr])) {
           zeroItem[attr] = Array(item[attr].length).fill('0');
         } else if (typeof item[attr] === 'object' && item[attr] !== null) {
           zeroItem[attr] = {};
           Object.keys(item[attr]).forEach(key => {
             zeroItem[attr][key] = '0';
           });
         }
       });
       
       // Update with zero data
       await container.item(id, partitionKey).replace(zeroItem);
       
       // Finally delete the item
       await container.item(id, partitionKey).delete();
       
       itemCount++;
       if (itemCount % 100 === 0) {
         console.log(`Processed ${itemCount} items...`);
       }
     }
     
     console.log(`Securely deleted ${itemCount} items from container ${containerId}`);
     
     // Delete the container itself
     await container.delete();
     console.log(`Deleted container ${containerId}`);
     
     return { containerId, itemsDeleted: itemCount };
   }
   
   async function secureDeleteDatabase(databaseId) {
     const database = client.database(databaseId);
     
     // Get all containers
     const { resources: containers } = await database.containers.readAll().fetchAll();
     console.log(`Found ${containers.length} containers in database ${databaseId}`);
     
     // Process each container
     for (const container of containers) {
       try {
         console.log(`Starting secure deletion of container: ${container.id}`);
         const result = await secureDeleteContainer(databaseId, container.id);
         console.log(`Completed: ${result.itemsDeleted} items deleted from ${result.containerId}`);
       } catch (error) {
         console.error(`Error processing container ${container.id}: ${error.message}`);
       }
     }
     
     // Delete the database itself
     await database.delete();
     console.log(`Deleted database ${databaseId}`);
     
     return { databaseId, containersDeleted: containers.length };
   }
   
   async function secureDeleteAllDatabases() {
     // Get all databases
     const { resources: databases } = await client.databases.readAll().fetchAll();
     console.log(`Found ${databases.length} databases`);
     
     // Process each database
     for (const database of databases) {
       try {
         console.log(`Starting secure deletion of database: ${database.id}`);
         const result = await secureDeleteDatabase(database.id);
         console.log(`Completed: ${result.containersDeleted} containers deleted from ${result.databaseId}`);
       } catch (error) {
         console.error(`Error processing database ${database.id}: ${error.message}`);
       }
     }
   }
   
   // Execute
   secureDeleteAllDatabases().catch(err => console.error('Error:', err));
   ```

### Section 5: Specialized Service Destruction

#### 5.1 AWS Lambda Function and Layer Destruction

1. List Lambda functions and dependencies:
   ```bash
   # List all Lambda functions
   aws lambda list-functions --query "Functions[*].{Name:FunctionName,Runtime:Runtime,Role:Role}" --output table
   
   # Check for event source mappings
   for func in $(aws lambda list-functions --query "Functions[*].FunctionName" --output text); do
     echo "Function: $func"
     aws lambda list-event-source-mappings --function-name $func --query "EventSourceMappings[*].{UUID:UUID,Source:EventSourceArn,State:State}" --output table
   done
   
   # Check for environment variables
   for func in $(aws lambda list-functions --query "Functions[*].FunctionName" --output text); do
     echo "Function: $func"
     aws lambda get-function-configuration --function-name $func --query "Environment.Variables" --output json
   done
   
   # List all Lambda layers
   aws lambda list-layers --query "Layers[*].{Name:LayerName,Runtimes:LatestMatchingVersion.CompatibleRuntimes}" --output table
   ```

2. Remove event source mappings:
   ```bash
   # Remove event source mappings for each function
   for func in $(aws lambda list-functions --query "Functions[*].FunctionName" --output text); do
     for mapping in $(aws lambda list-event-source-mappings --function-name $func --query "EventSourceMappings[*].UUID" --output text); do
       echo "Deleting event source mapping: $mapping for function: $func"
       aws lambda delete-event-source-mapping --uuid $mapping
     done
   done
   ```

3. Securely delete function code and environment variables:
   ```bash
   # Create dummy empty function
   cat > empty-function.zip << EOF
   UEsDBBQAAAAIAG11jVbGTKRbHAAAABsAAAAJAAAAaW5kZXguanNLyvNLzygtyszPK9ZRUEopL8osUCgtS80pTtVRUCrOzM9TL0pNLVZwSixO9XDx8vP0UVBKzi/NK0ktAgBQSwECFAAUAAAACABtdY1WxkykWxwAAAAbAAAACQAAAAAAAAAAAAAAAAAAAAAAaW5kZXguanNQSwUGAAAAAAEAAQA3AAAAQwAAAAAA
   EOF
   
   # Update each function with empty code and no environment variables
   for func in $(aws lambda list-functions --query "Functions[*].FunctionName" --output text); do
     echo "Securely wiping function: $func"
     # Update code
     aws lambda update-function-code --function-name   # Get S3 deletion events
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObject \
     --start-time "$START_TIME" \
     --end-time "$END_TIME" \
     > s3_delete_events.json
   
   # Get EBS volume deletion events
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteVolume \
     --start-time "$START_TIME" \
     --end-time "$END_TIME" \
     > ebs_delete_events.json
   
   # Get RDS deletion events
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteDBInstance \
     --start-time "$START_TIME" \
     --end-time "$END_TIME" \
     > rds_delete_events.json
   
   # Get DynamoDB deletion events
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteTable \
     --start-time "$START_TIME" \
     --end-time "$END_TIME" \
     > dynamodb_delete_events.json
   
   # Generate summary report
   echo "AWS Deletion Audit Report: $(date)" > audit_summary.txt
   echo "Time Range: $START_TIME to $END_TIME" >> audit_summary.txt
   echo "-----------------------------------------" >> audit_summary.txt
   echo "S3 Object Deletions: $(jq '.Events | length' s3_delete_events.json)" >> audit_summary.txt
   echo "EBS Volume Deletions: $(jq '.Events | length' ebs_delete_events.json)" >> audit_summary.txt
   echo "RDS Instance Deletions: $(jq '.Events | length' rds_delete_events.json)" >> audit_summary.txt
   echo "DynamoDB Table Deletions: $(jq '.Events | length' dynamodb_delete_events.json)" >> audit_summary.txt
   
   # Create detailed CSV report
   echo "Timestamp,EventName,Username,ResourceType,ResourceName" > deletion_events.csv
   jq -r '.Events[] | [.EventTime, .EventName, .Username, .Resources[0].ResourceType, .Resources[0].ResourceName] | @csv' s3_delete_events.json >> deletion_events.csv
   jq -r '.Events[] | [.EventTime, .EventName, .Username, .Resources[0].ResourceType, .Resources[0].ResourceName] | @csv' ebs_delete_events.json >> deletion_events.csv
   jq -r '.Events[] | [.EventTime, .EventName, .Username, .Resources[0].ResourceType, .Resources[0].ResourceName] | @csv' rds_delete_events.json >> deletion_events.csv
   jq -r '.Events[] | [.EventTime, .EventName, .Username, .Resources[0].ResourceType, .Resources[0].ResourceName] | @csv' dynamodb_delete_events.json >> deletion_events.csv
   
   echo "Audit reports generated in $(pwd)"
   ```

2. Azure Activity Log Audit:
   ```bash
   # Create a temporary directory for audit files
   mkdir -p azure_audit/$(date +%Y%m%d)
   cd azure_audit/$(date +%Y%m%d)
   
   # Set time range for audit
   START_TIME=$(date -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)
   END_TIME=$(date +%Y-%m-%dT%H:%M:%SZ)
   
   # Get storage deletion events
   az monitor activity-log list \
     --start-time $START_TIME \
     --end-time $END_TIME \
     --filters "resourceProvider eq 'Microsoft.Storage'" \
     --query "[?contains(operationName.value, 'delete')].{Timestamp:eventTimestamp, Operation:operationName.value, Resource:resourceId, Caller:caller, Status:status.value}" \
     > storage_delete_events.json
   
   # Get compute deletion events
   az monitor activity-log list \
     --start-time $START_TIME \
     --end-time $END_TIME \
     --filters "resourceProvider eq 'Microsoft.Compute'" \
     --query "[?contains(operationName.value, 'delete')].{Timestamp:eventTimestamp, Operation:operationName.value, Resource:resourceId, Caller:caller, Status:status.value}" \
     > compute_delete_events.json
   
   # Get SQL deletion events
   az monitor activity-log list \
     --start-time $START_TIME \
     --end-time $END_TIME \
     --filters "resourceProvider eq 'Microsoft.Sql'" \
     --query "[?contains(operationName.value, 'delete')].{Timestamp:eventTimestamp, Operation:operationName.value, Resource:resourceId, Caller:caller, Status:status.value}" \
     > sql_delete_events.json
   
   # Get CosmosDB deletion events
   az monitor activity-log list \
     --start-time $START_TIME \
     --end-time $END_TIME \
     --filters "resourceProvider eq 'Microsoft.DocumentDB'" \
     --query "[?contains(operationName.value, 'delete')].{Timestamp:eventTimestamp, Operation:operationName.value, Resource:resourceId, Caller:caller, Status:status.value}" \
     > cosmosdb_delete_events.json
   
   # Generate summary report
   echo "Azure Deletion Audit Report: $(date)" > azure_audit_summary.txt
   echo "Time Range: $START_TIME to $END_TIME" >> azure_audit_summary.txt
   echo "-----------------------------------------" >> azure_audit_summary.txt
   echo "Storage Resource Deletions: $(jq '. | length' storage_delete_events.json)" >> azure_audit_summary.txt
   echo "Compute Resource Deletions: $(jq '. | length' compute_delete_events.json)" >> azure_audit_summary.txt
   echo "SQL Resource Deletions: $(jq '. | length' sql_delete_events.json)" >> azure_audit_summary.txt
   echo "CosmosDB Resource Deletions: $(jq '. | length' cosmosdb_delete_events.json)" >> azure_audit_summary.txt
   
   # Create detailed CSV report
   echo "Timestamp,Operation,Resource,Caller,Status" > azure_deletion_events.csv
   jq -r '.[] | [.Timestamp, .Operation, .Resource, .Caller, .Status] | @csv' storage_delete_events.json >> azure_deletion_events.csv
   jq -r '.[] | [.Timestamp, .Operation, .Resource, .Caller, .Status] | @csv' compute_delete_events.json >> azure_deletion_events.csv
   jq -r '.[] | [.Timestamp, .Operation, .Resource, .Caller, .Status] | @csv' sql_delete_events.json >> azure_deletion_events.csv
   jq -r '.[] | [.Timestamp, .Operation, .Resource, .Caller, .Status] | @csv' cosmosdb_delete_events.json >> azure_deletion_events.csv
   
   echo "Azure audit reports generated in $(pwd)"
   ```

3. Two-person verification checklist:
   ```
   DATA DESTRUCTION VERIFICATION CHECKLIST
   --------------------------------------
   
   Project: [Project Name]
   Date: [Current Date]
   Primary Verifier: [Name and Role]
   Secondary Verifier: [Name and Role]
   
   AWS Resources:
   [ ] S3 Buckets
     - Names: [List of bucket names]
     - Command used: aws s3 ls | grep [bucket-prefix]
     - Result: [No results found/Error]
     - CloudTrail events verified: [Yes/No]
   
   [ ] EBS Volumes
     - IDs: [List of volume IDs]
     - Command used: aws ec2 describe-volumes --volume-ids [volume-id]
     - Result: [No results found/Error]
     - CloudTrail events verified: [Yes/No]
   
   [ ] RDS Instances
     - Names: [List of instance names]
     - Command used: aws rds describe-db-instances --db-instance-identifier [instance-name]
     - Result: [No results found/Error]
     - CloudTrail events verified: [Yes/No]
   
   Azure Resources:
   [ ] Storage Accounts
     - Names: [List of account names]
     - Command used: az storage account show --name [account-name]
     - Result: [No results found/Error]
     - Activity logs verified: [Yes/No]
   
   [ ] Managed Disks
     - Names: [List of disk names]
     - Command used: az disk show --name [disk-name] --resource-group [resource-group]
     - Result: [No results found/Error]
     - Activity logs verified: [Yes/No]
   
   [ ] SQL Databases
     - Names: [List of database names]
     - Command used: az sql db show --name [db-name] --server [server-name] --resource-group [resource-group]
     - Result: [No results found/Error]
     - Activity logs verified: [Yes/No]
   
   Additional Checks:
   [ ] Access permissions revoked for all related resources
   [ ] Backup systems checked for residual data
   [ ] Dependent resources verified as deleted or updated
   [ ] Third-party systems notified of deletion as needed
   
   Exceptions and Issues:
   [Document any resources that could not be verified as deleted, any errors encountered, or any other issues]
   
   Certification:
   We certify that we have performed the verification steps above and confirm the successful destruction of the specified data and resources according to the organization's data destruction policy and applicable regulations.
   
   Primary Verifier Signature: ________________________ Date: ________
   
   Secondary Verifier Signature: ______________________ Date: ________
   ```

#### 1.4 Perform Data Discovery

1. AWS Macie for sensitive data discovery:
   ```bash
   # Create a Macie session
   aws macie2 enable-macie
   
   # Create a custom data identifier for any specific patterns
   aws macie2 create-custom-data-identifier \
     --name "Post-Deletion-Verification" \
     --regex "[Your-Specific-Pattern]" \
     --description "Pattern to verify complete data deletion"
   
   # Create and start a classification job
   aws macie2 create-classification-job \
     --job-type ONE_TIME \
     --name "Post-Deletion-Verification-$(date +%Y%m%d)" \
     --s3-job-definition "{\
       \"bucketDefinitions\": [\
         {\
           \"accountId\": \"$(aws sts get-caller-identity --query Account --output text)\",\
           \"buckets\": [\"bucket1\", \"bucket2\"]\
         }\
       ]\
     }" \
     --description "Verification scan after data destruction"
   ```

2. Azure Purview for data discovery:
   ```bash
   # List data sources in Purview
   az purview scan-datasource list \
     --account-name <purview-account-name> \
     --collection-name <collection-name>
   
   # Create a scan for verification
   az purview scan create-scan \
     --account-name <purview-account-name> \
     --collection-name <collection-name> \
     --data-source-name <data-source-name> \
     --scan-name "Post-Deletion-Verification-$(date +%Y%m%d)" \
     --kind AzureStorageAccount \
     --credential ... \
     --scope ... \
     --schedule-recurrence-type Once
   
   # Trigger the scan
   az purview scan run-scan \
     --account-name <purview-account-name> \
     --collection-name <collection-name> \
     --data-source-name <data-source-name> \
     --scan-name "Post-Deletion-Verification-$(date +%Y%m%d)"
   ```

3. Manual verification using CLI tools:
   ```bash
   # AWS S3 recursive ls
   aws s3 ls s3://<bucket-name>/ --recursive
   
   # AWS RDS snapshot check
   aws rds describe-db-snapshots \
     --query "DBSnapshots[?DBInstanceIdentifier=='<db-instance-name>']"
   
   # Azure blob storage check
   az storage blob list \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --output table \
     --auth-mode login
   
   # Azure SQL database restore check
   az sql db list-deleted \
     --resource-group <resource-group> \
     --server <server-name>
   ```

4. Document all findings:
   - Create a comprehensive report of any remaining data
   - Document reasons for exceptions
   - Plan remediation for any discovered data
   - Update destruction logs with findings

### Section 2: Legal and Compliance Holds

#### 2.1 Verify Legal Requirements

1. Legal hold verification checklist:
   ```
   LEGAL HOLD VERIFICATION CHECKLIST
   ---------------------------------
   
   Project: [Project Name]
   Date: [Current Date]
   Legal Representative: [Name and Role]
   
   1. Legal Hold Status Check:
      [ ] Reviewed active legal holds inventory
      [ ] Confirmed target data is NOT subject to any legal hold
      [ ] Obtained written confirmation from Legal Department
   
   2. Regulatory Compliance Check:
      [ ] Verified minimum retention periods for all data types
      [ ] Confirmed all retention periods have expired
      [ ] Identified applicable regulations:
          [ ] GDPR
          [ ] HIPAA
          [ ] PCI DSS
          [ ] SOX
          [ ] GLBA
          [ ] Other: _____________
      [ ] Verified destruction method complies with all regulations
   
   3. Contractual Obligations:
      [ ] Reviewed customer/vendor contracts related to the data
      [ ] Verified no contractual data retention requirements remain
      [ ] Obtained approval from contract management team
   
   4. Destruction Authorization:
      [ ] Destruction request reviewed and approved
      [ ] Appropriate management approval obtained
      [ ] Legal department approval obtained
      [ ] Compliance officer approval obtained
      [ ] Data owner approval obtained
   
   5. Documentation Requirements:
      [ ] Destruction certificate requirements identified
      [ ] Verification evidence requirements identified
      [ ] Audit trail requirements identified
      [ ] Records retention policy for destruction documentation identified
   
   Legal Department Approval:
   
   I certify that I have reviewed the legal and regulatory requirements applicable to the data proposed for destruction and confirm that:
   1. The data is not subject to any active legal hold
   2. All applicable retention periods have expired
   3. Destruction may proceed in accordance with the approved method
   
   Legal Representative Signature: ________________________ Date: ________
   
   Compliance Officer Signature: _________________________ Date: ________
   ```

2. Regulatory compliance matrix:
   ```
   DATA DESTRUCTION REGULATORY MATRIX
   ----------------------------------
   
   | Data Type | Regulation | Min. Retention | Destruction Method | Verification Required |
   |-----------|------------|----------------|-------------------|-----------------------|
   | PII       | GDPR       | Until purpose fulfilled | Secure deletion | Documentation required |
   | PHI       | HIPAA      | 6 years        | Cryptographic erasure | Destruction certificate |
   | Financial | SOX        | 7 years        | Secure deletion | Audit trail required |
   | Payment   | PCI DSS    | See policy     | Secure deletion | Quarterly validation |
   ```

3. Obtain legal approval template:
   ```
   LEGAL APPROVAL FOR DATA DESTRUCTION
   ----------------------------------
   
   I, [Legal Representative Name], in my capacity as [Title] at [Organization], 
   hereby authorize the destruction of the following data:
   
   Description: [Brief description of data]
   Classification: [Data classification level]
   Storage Location: [AWS/Azure details]
   Date Range: [Range of data to be destroyed]
   
   I confirm that:
   1. The data is not subject to any active litigation, investigation, or legal hold
   2. All applicable regulatory retention periods have expired
   3. All contractual obligations regarding this data have been fulfilled
   4. The proposed destruction method complies with all applicable regulations
   
   This approval is valid for 30 days from the date below.
   
   Signature: ________________________ Date: ________
   
   [Organization] Legal Department
   ```

#### 2.2 Implement Destruction Certificates

1. Generate detailed destruction certificate:
   ```
   CERTIFICATE OF DATA DESTRUCTION
   ------------------------------
   
   Certificate Number: [Unique ID]
   Date of Destruction: [Date]
   
   This is to certify that the following data has been permanently destroyed:
   
   Data Owner: [Department/Individual]
   Description of Data: [Detailed description]
   Classification Level: [Confidential/Restricted/Public]
   
   Data Location Details:
   - Cloud Service Provider(s): [AWS/Azure/Both]
   - Region(s): [List of regions]
   - Resource Types: [S3/EBS/RDS/Blob Storage/etc.]
   - Resource Identifiers: [List of specific resource IDs]
   
   Destruction Method:
   [ ] Logical deletion
   [ ] Secure overwrite (multiple passes)
   [ ] Cryptographic erasure
   [ ] Physical destruction (for hardware-based backups)
   
   Standards Compliance:
   [ ] NIST SP 800-88 Guidelines for Media Sanitization
   [ ] DoD 5220.22-M (3-pass overwrite)
   [ ] GDPR Article 17 (Right to erasure)
   [ ] HIPAA Security Rule
   [ ] PCI DSS Requirement 9.8 and 3.1
   [ ] Other: _____________
   
   Verification Method:
   [ ] System logs examination
   [ ] Cloud provider audit logs
   [ ] Data discovery scan using [tool]
   [ ] Two-person verification
   [ ] Third-party verification
   
   Destruction performed by:
   Name: [Name of primary person performing destruction]
   Title: [Job title]
   Signature: ________________________ Date: ________
   
   Witnessed/Verified by:
   Name: [Name of witness/verifier]
   Title: [Job title]
   Signature: ________________________ Date: ________
   
   Approved by:
   Name: [Name of approver]
   Title: [Job title - typically management or compliance officer]
   Signature: ________________________ Date: ________
   
   Attachments:
   [ ] System logs
   [ ] Cloud audit logs
   [ ] Verification screenshots
   [ ] Other evidence: _____________
   
   This certificate should be retained for a period of [retention period] years
   in accordance with [organization name]'s data destruction policy and applicable regulations.
   ```

2. Create destruction inventory log:
   ```
   DESTRUCTION INVENTORY LOG
   ------------------------
   
   Project: [Project Name]
   Period: [Start Date] to [End Date]
   
   | Item ID | Data Type | Resource ID | Cloud Service | Destruction Date | Certificate # | Verified By |
   |---------|-----------|-------------|--------------|------------------|--------------|------------|
   | 001     | Customer DB | rds-db-123 | AWS RDS      | 2023-06-15       | CERT-001     | J. Smith   |
   | 002     | Log Files   | bucket-xyz | AWS S3       | 2023-06-15       | CERT-002     | J. Smith   |
   | 003     | VM Disks    | disk-abc   | Azure        | 2023-06-16       | CERT-003     | A. Johnson |
   ```

3. Electronic destruction certificate system:
   - Implement a secure digital system for creating and storing certificates
   - Include digital signatures for all parties
   - Integrate with destruction workflow
   - Attach all evidence automatically
   - Apply retention policies automatically
   - Index for easy retrieval during audits

---

## Part 4: Advanced Techniques and Special Cases

### Section 1: Handling Encrypted Data

#### 1.1 Cryptographic Erasure

Cryptographic erasure involves destroying the encryption keys rather than the encrypted data itself, rendering the data unreadable.

1. Key management assessment:
   ```bash
   # For AWS KMS
   aws kms list-keys
   
   # For Azure Key Vault
   az keyvault key list --vault-name <keyvault-name>
   ```

2. Identify all services using the key:
   ```bash
   # AWS KMS key usage
   aws kms list-resource-tags --key-id <key-id>
   
   # AWS resources using the key (example for EBS)
   aws ec2 describe-volumes --filters "Name=encrypted,Values=true" \
     --query "Volumes[?KmsKeyId=='<key-arn>']"
   
   # Azure Key Vault key usage
   az keyvault key show --vault-name <keyvault-name> --name <key-name>
   ```

3. Document all systems dependent on the key:
   - Create a comprehensive inventory of all data encrypted with the key
   - Document business impact of key destruction
   - Ensure data is not needed before proceeding

4. For AWS KMS:
   ```bash
   # Disable the key
   aws kms disable-key --key-id <key-id>
   
   # Schedule key deletion (7-30 day waiting period)
   aws kms schedule-key-deletion --key-id <key-id> --pending-window-in-days 7
   
   # Monitor deletion status
   aws kms describe-key --key-id <key-id>
   ```

5. For Azure Key Vault:
   ```bash
   # Disable the key
   az keyvault key set-attributes --vault-name <keyvault-name> --name <key-name> --enabled false
   
   # Delete the key (soft delete)
   az keyvault key delete --vault-name <keyvault-name> --name <key-name>
   
   # If purge protection is not enabled, purge the key
   az keyvault key purge --vault-name <keyvault-name> --name <key-name>
   ```

6. Document the cryptographic erasure:
   - Create certificate specifically noting cryptographic erasure method
   - Document key identifiers and systems affected
   - Retain evidence of key destruction

#### 1.2 Handling Customer-Managed Keys (CMK)

1. AWS customer-managed keys:
   ```bash
   # Identify customer-managed keys
   aws kms list-keys --query "Keys[].KeyId" --output text | \
   while read key_id; do
     key_info=$(aws kms describe-key --key-id $key_id)
     key_manager=$(echo $key_info | jq -r '.KeyMetadata.KeyManager')
     if [ "$key_manager" == "CUSTOMER" ]; then
       echo "Customer-managed key: $key_id"
       echo $key_info | jq '.KeyMetadata'
     fi
   done
   ```

2. Azure customer-managed keys:
   ```bash
   # List all key vaults
   az keyvault list --query "[].name" --output tsv | \
   while read vault_name; do
     echo "Key Vault: $vault_name"
     # List keys in the vault
     az keyvault key list --vault-name $vault_name --query "[].{Name:name,Enabled:attributes.enabled}" --output table
   done
   ```

3. Coordinate with key custodians:
   - Identify key owners in the organization
   - Obtain approval for key destruction
   - Schedule key rotation if necessary before destruction
   - Document key custodian approval

4. Implement key destruction with proper oversight:
   - Require multiple approvals
   - Use split knowledge procedures if appropriate
   - Document each step with timestamps
   - Verify with key custodians after completion

### Section 2: Handling Replicated Data

#### 2.1 Cross-Region Replication

1. AWS S3 cross-region replication:
   ```bash
   # Check for cross-region replication
   aws s3api get-bucket-replication --bucket <bucket-name>
   
   # Disable replication
   aws s3api delete-bucket-replication --bucket <bucket-name>
   
   # List objects in destination bucket
   aws s3 ls s3://<destination-bucket>/ --recursive
   
   # Delete objects in destination bucket
   aws s3 rm s3://<destination-bucket>/ --recursive
   ```

2. Azure Storage replication:
   ```bash
   # Check account replication settings
   az storage account show \
     --name <storage-account-name> \
     --query "properties.secondaryLocation"
   
   # Modify to locally redundant storage
   az storage account update \
     --name <storage-account-name> \
     --resource-group <resource-group> \
     --sku Standard_LRS
   ```

3. AWS RDS read replicas:
   ```bash
   # List read replicas
   aws rds describe-db-instances \
     --query "DBInstances[?ReadReplicaSourceDBInstanceIdentifier!=null].{ReplicaID:DBInstanceIdentifier,Source:ReadReplicaSourceDBInstanceIdentifier}"
   
   # Delete each read replica
   aws rds delete-db-instance \
     --db-instance-identifier <replica-instance-id> \
     --skip-final-snapshot
   ```

4. Azure SQL Database geo-replication:
   ```bash
   # List geo-replicated databases
   az sql db replica list \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name>
   
   # Remove geo-replication link
   az sql db replica delete-link \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name> \
     --partner-server <partner-server-name> \
     --partner-database <partner-database-name>
   
   # Delete secondary database
   az sql db delete \
     --resource-group <secondary-resource-group> \
     --server <secondary-server-name> \
     --name <database-name> \
     --yes
   ```

#### 2.2 Cross-Account Replication

1. AWS cross-account S3 replication:
   ```bash
   # Identify any cross-account replication in source bucket
   aws s3api get-bucket-replication --bucket <source-bucket>
   
   # Use cross-account credentials to verify destination bucket
   # First assume role in destination account
   aws sts assume-role \
     --role-arn arn:aws:iam::<destination-account>:role/<cross-account-role> \
     --role-session-name DestructionVerification
   
   # Use temporary credentials to check destination bucket
   AWS_ACCESS_KEY_ID=<temp-access-key> \
   AWS_SECRET_ACCESS_KEY=<temp-secret-key> \
   AWS_SESSION_TOKEN=<temp-session-token> \
   aws s3 ls s3://<destination-bucket>/ --recursive
   
   # Delete data in destination bucket (with appropriate permissions)
   AWS_ACCESS_KEY_ID=<temp-access-key> \
   AWS_SECRET_ACCESS_KEY=<temp-secret-key> \
   AWS_SESSION_TOKEN=<temp-session-token> \
   aws s3 rm s3://<destination-bucket>/ --recursive
   ```

2. Azure cross-tenant replication:
   ```bash
   # Log in to the secondary tenant
   az login --tenant <secondary-tenant-id>
   
   # Check for replicated resources
   az storage account list --query "[].{Name:name,Location:location,ReplicationType:sku.name}"
   
   # Delete replicated data
   az storage blob delete-batch \
     --account-name <storage-account-name> \
     --source <container-name>
   
   # Switch back to primary tenant
   az login --tenant <primary-tenant-id>
   ```

3. Document all cross-account actions:
   - Create a separate certificate for cross-account data destruction
   - Document communication with other account owners
   - Verify destruction with account administrators
   - Include cross-account verification evidence

### Section 3: Handling Immutable Storage

#### 3.1 AWS S3 Object Lock

1. Check for Object Lock configuration:
   ```bash
   aws s3api get-object-lock-configuration --bucket <bucket-name>
   ```

2. List objects with retention periods:
   ```bash
   aws s3api list-objects-v2 --bucket <bucket-name> \
     --query "Contents[].{Key:Key}" --output text | \
   while read key; do
     retention=$(aws s3api get-object-retention --bucket <bucket-name> --key "$key" 2>/dev/null)
     if [ $? -eq 0 ]; then
       mode=$(echo $retention | jq -r '.Mode')
       until=$(echo $retention | jq -r '.RetainUntilDate')
       echo "Object: $key, Mode: $mode, RetainUntil: $until"
     fi
   done
   ```

3. Check for legal holds:
   ```bash
   aws s3api list-objects-v2 --bucket <bucket-name> \
     --query "Contents[].{Key:Key}" --output text | \
   while read key; do
     legal_hold=$(aws s3api get-object-legal-hold --bucket <bucket-name> --key "$key" 2>/dev/null)
     if [ $? -eq 0 ]; then
       status=$(echo $legal_hold | jq -r '.LegalHold.Status')
       echo "Object: $key, LegalHold: $status"
     fi
   done
   ```

4. Handle objects with legal holds:
   ```bash
   # Requires permissions and legal approval
   aws s3api put-object-legal-hold \
     --bucket <bucket-name> \
     --key <object-key> \
     --legal-hold Status=OFF
   ```

5. For governance mode retention:
   ```bash
   # Requires s3:BypassGovernanceRetention permission
   aws s3api delete-object \
     --bucket <bucket-name> \
     --key <object-key> \
     --bypass-governance-retention
   ```

6. For compliance mode retention:
   - Wait until retention period expires
   - Document objects that cannot be deleted due to retention periods
   - Schedule destruction for after retention period

#### 3.2 Azure Blob Immutable Storage

1. Check for immutability policies:
   ```bash
   az storage container immutability-policy show \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --auth-mode login
   ```

2. Check for legal holds:
   ```bash
   az storage container legal-hold show \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --tags "hold1,hold2" \
     --auth-mode login
   ```

3. Remove legal holds (requires permissions):
   ```bash
   az storage container legal-hold clear \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --tags "hold1,hold2" \
     --auth-mode login
   ```

4. For time-based retention:
   - Wait until retention period expires
   - Document containers that cannot be deleted due to policies
   - Schedule destruction for after retention period

5. For locked immutability policies:
   - Document that the data cannot be deleted until retention period expires
   - Include in exception report
   - Schedule follow-up for when retention period expires

### Section 4: Database Shredding

#### 4.1 AWS RDS Secure Deletion

1. Create a secure deletion stored procedure:
   ```sql
   -- Example secure deletion stored procedure for MySQL/MariaDB
   DELIMITER //
   CREATE PROCEDURE secure_delete_table(IN table_name VARCHAR(64))
   BEGIN
     DECLARE done INT DEFAULT FALSE;
     DECLARE i INT DEFAULT 0;
     DECLARE row_count INT;
     
     -- First overwrite with random data
     SET @sql = CONCAT('UPDATE ',# Comprehensive Data Destruction Guide: AWS and Microsoft Azure

## Introduction

This comprehensive guide provides detailed, step-by-step procedures for securely destroying data in Amazon Web Services (AWS) and Microsoft Azure environments. The procedures outlined here adhere to industry best practices and security standards to ensure complete and verifiable data destruction for compliance with regulations such as GDPR, HIPAA, PCI DSS, and organizational data protection policies.

---

## Part 1: AWS Data Destruction

### Section 1: AWS S3 Object and Bucket Destruction

#### 1.1 Understanding S3 Data Deletion Mechanics

Before initiating deletion procedures, understand how AWS S3 handles deletion:

- **Standard deletion**: Objects deleted through the console or API are not immediately removed and may be recoverable until permanent deletion occurs.
- **Versioning**: If enabled, deletion creates a delete marker rather than removing the object.
- **Multi-Factor Authentication (MFA) Delete**: Provides additional security for sensitive buckets.
- **Object Lock**: May prevent deletion until retention period expires.

#### 1.2 Preparing for S3 Data Destruction

1. **Inventory all S3 resources**:
   ```bash
   aws s3 ls
   ```

2. **Identify bucket versioning status**:
   ```bash
   aws s3api get-bucket-versioning --bucket bucket-name
   ```

3. **Check Object Lock configuration**:
   ```bash
   aws s3api get-object-lock-configuration --bucket bucket-name
   ```

4. **Identify cross-region replication**:
   ```bash
   aws s3api get-bucket-replication --bucket bucket-name
   ```

5. **Check lifecycle policies**:
   ```bash
   aws s3api get-bucket-lifecycle-configuration --bucket bucket-name
   ```

#### 1.3 Enable Versioning and Configure Lifecycle Policies

1. Sign in to the AWS Management Console
2. Navigate to Amazon S3
   - Click "Services" at the top of the screen
   - Under "Storage", select "S3"
3. Select the target bucket from the bucket list
4. Go to the "Properties" tab
   - Click on the "Properties" tab in the top navigation bar of the bucket detail page
5. Configure Versioning:
   - Scroll to the "Bucket Versioning" section
   - Click "Edit"
   - Select "Enable" radio button
   - Click "Save changes"
6. Configure lifecycle rules:
   - Navigate to the "Management" tab
   - Click "Create lifecycle rule"
   - Enter rule name (e.g., "Data-Destruction-Policy")
   - For scope, select:
     - "Apply to all objects in the bucket" OR
     - "Limit the scope to specific prefixes or tags" (then specify)
   - Expand "Lifecycle rule actions"
   - Check "Expire current versions of objects"
     - Set appropriate number of days (e.g., 1 day for immediate deletion)
   - Check "Delete expired delete markers or incomplete multipart uploads"
   - Check "Permanently delete noncurrent versions of objects"
     - Set appropriate number of days (e.g., 1 day for quick deletion)
   - Click "Create rule"
7. Verify the rule creation:
   - The new rule should appear in the lifecycle rules list
   - Status should show as "Enabled"

#### 1.4 Delete Individual Objects (Console Method)

1. Navigate to the target S3 bucket
   - Click on the bucket name in the S3 bucket list
2. Select objects to delete
   - Check the boxes next to the objects
   - For large numbers of objects, use the search functionality or filtering
3. Click "Delete" button in the top action bar
4. In the confirmation dialog:
   - Review the list of objects to be deleted
   - Type "permanently delete" in the confirmation field
   - Check "I acknowledge that this action will permanently delete the objects shown below."
5. Click "Delete objects" button
6. Monitor the deletion progress in the "Delete objects: status" dialog
7. Verify deletion by refreshing the object list

#### 1.5 Delete Individual Objects (AWS CLI Method)

1. For deleting a single object:
   ```bash
   aws s3 rm s3://bucket-name/path/to/object
   ```

2. For deleting multiple objects with a specific prefix:
   ```bash
   aws s3 rm s3://bucket-name/prefix/ --recursive
   ```

3. For deleting objects with a specific file extension:
   ```bash
   aws s3 rm s3://bucket-name --exclude "*" --include "*.txt" --recursive
   ```

4. For deleting all versions of objects (if versioning enabled):
   ```bash
   aws s3api list-object-versions --bucket bucket-name --prefix prefix/ | \
   jq -r '.Versions[] | .Key + " " + .VersionId' | \
   while read key version; do \
     aws s3api delete-object --bucket bucket-name --key "$key" --version-id "$version"; \
   done
   ```

5. For deleting delete markers (if versioning enabled):
   ```bash
   aws s3api list-object-versions --bucket bucket-name --prefix prefix/ | \
   jq -r '.DeleteMarkers[] | .Key + " " + .VersionId' | \
   while read key version; do \
     aws s3api delete-object --bucket bucket-name --key "$key" --version-id "$version"; \
   done
   ```

#### 1.6 Data Overwriting for Sensitive S3 Objects

For sensitive data, overwrite before deletion:

1. Create a zero-filled or random file locally:
   ```bash
   # Create 1MB file with zeros
   dd if=/dev/zero of=zeros.bin bs=1M count=1
   
   # Create 1MB file with random data
   dd if=/dev/urandom of=random.bin bs=1M count=1
   ```

2. Overwrite each sensitive object multiple times:
   ```bash
   # Overwrite with zeros (repeat 3 times for DoD-style wiping)
   for i in {1..3}; do
     aws s3 cp zeros.bin s3://bucket-name/path/to/sensitive-object
   done
   
   # Then delete
   aws s3 rm s3://bucket-name/path/to/sensitive-object
   ```

3. For automation with multiple objects, create a script:
   ```bash
   #!/bin/bash
   BUCKET="bucket-name"
   PREFIX="prefix/"
   
   # Create overwrite file
   dd if=/dev/urandom of=random.bin bs=1M count=1
   
   # Get all objects
   aws s3 ls s3://$BUCKET/$PREFIX --recursive | awk '{print $4}' > objects.txt
   
   # Overwrite each object 3 times
   while read object; do
     echo "Overwriting $object"
     for i in {1..3}; do
       aws s3 cp random.bin s3://$BUCKET/$object
     done
     # Delete the object
     aws s3 rm s3://$BUCKET/$object
   done < objects.txt
   ```

#### 1.7 Empty and Delete Bucket (Console Method)

1. Navigate to S3 in the AWS Management Console
2. Select the checkbox next to the bucket to delete
3. Click "Empty" button
4. In the confirmation dialog:
   - Type the bucket name to confirm
   - Check "I acknowledge that emptying this bucket will delete all objects and all object versions."
   - Click "Empty"
5. Wait for the emptying process to complete (this can take time for large buckets)
6. Once empty, select the bucket again
7. Click "Delete" button
8. In the confirmation dialog:
   - Type the bucket name to confirm
   - Click "Delete bucket"
9. Verify the bucket no longer appears in your bucket list

#### 1.8 Empty and Delete Bucket (AWS CLI Method)

1. Remove all objects and versions:
   ```bash
   # For non-versioned buckets
   aws s3 rm s3://bucket-name --recursive
   
   # For versioned buckets (more thorough)
   aws s3api delete-objects --bucket bucket-name \
     --delete "$(aws s3api list-object-versions \
                 --bucket bucket-name \
                 --output=json \
                 --query='{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"
   
   # Delete delete markers
   aws s3api delete-objects --bucket bucket-name \
     --delete "$(aws s3api list-object-versions \
                 --bucket bucket-name \
                 --output=json \
                 --query='{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}')"
   ```

2. Delete the bucket:
   ```bash
   aws s3api delete-bucket --bucket bucket-name
   ```

3. Verify bucket deletion:
   ```bash
   aws s3 ls | grep bucket-name
   ```

#### 1.9 Delete MFA-Protected Buckets

1. If MFA deletion is enabled, you need the MFA device serial number and current token:
   ```bash
   aws s3api delete-bucket --bucket bucket-name --mfa "arn:aws:iam::123456789012:mfa/user MFA-TOKEN"
   ```

2. To disable MFA Delete first (requires root or privileged IAM user):
   ```bash
   aws s3api put-bucket-versioning \
     --bucket bucket-name \
     --versioning-configuration Status=Suspended \
     --mfa "arn:aws:iam::123456789012:mfa/user MFA-TOKEN"
   ```

#### 1.10 S3 Data Destruction Verification

1. Verify bucket is no longer listed:
   ```bash
   aws s3 ls | grep bucket-name
   ```

2. Check CloudTrail logs for deletion events:
   ```bash
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObject \
     --start-time "2023-01-01T00:00:00Z" \
     --end-time "2023-01-02T00:00:00Z"
   ```

3. Document the deletion with timestamps, object counts, and verification method.

### Section 2: AWS EBS Volume Destruction

#### 2.1 Understanding EBS Volume Deletion

- Deleting an EBS volume permanently removes all data
- AWS performs block-level wiping before reallocating storage
- Volume must be detached from instances before deletion
- Snapshot dependencies should be considered
- Encrypted volumes provide additional security (cryptographic erasure)

#### 2.2 Preliminary Steps

1. Identify EBS volumes:
   ```bash
   aws ec2 describe-volumes --query "Volumes[*].{ID:VolumeId,State:State,Size:Size,Type:VolumeType,InstanceId:Attachments[0].InstanceId,Device:Attachments[0].Device}"
   ```

2. Identify volumes to be destroyed:
   ```bash
   # Volumes attached to a specific instance
   aws ec2 describe-volumes --filters "Name=attachment.instance-id,Values=i-1234567890abcdef0" --query "Volumes[*].{ID:VolumeId,Size:Size,Type:VolumeType,Device:Attachments[0].Device}"
   
   # Volumes with specific tag
   aws ec2 describe-volumes --filters "Name=tag:Environment,Values=Production" --query "Volumes[*].{ID:VolumeId,State:State,Size:Size}"
   ```

3. Check for snapshot dependencies:
   ```bash
   aws ec2 describe-snapshots --filters "Name=volume-id,Values=vol-1234567890abcdef0" --query "Snapshots[*].{ID:SnapshotId,StartTime:StartTime,Description:Description}"
   ```

#### 2.3 Create Snapshot (for backup if needed)

1. Go to EC2 dashboard in AWS Management Console
   - Click "Services" at the top
   - Under "Compute", select "EC2"
2. In the left navigation pane, click "Volumes" under "Elastic Block Store"
3. Select the target volume by clicking the checkbox next to it
4. Click "Actions" dropdown
5. Select "Create Snapshot"
6. In the "Create Snapshot" dialog:
   - Provide a descriptive name: "Final-Backup-[Volume-ID]-[Date]"
   - Add a detailed description including reason for backup, date, and volume details
   - Add tags (optional but recommended):
     - Key: "Purpose", Value: "Final Backup"
     - Key: "DeleteAfter", Value: "[retention date]"
   - Click "Create Snapshot"
7. Note the snapshot ID for future reference
8. Monitor snapshot creation progress:
   - Go to "Snapshots" in the left navigation pane
   - Find your snapshot in the list
   - Wait for "Status" to change from "pending" to "completed"

#### 2.4 Data Overwriting for Sensitive Volumes (Optional)

For volumes containing sensitive data:

1. Create a temporary EC2 instance:
   ```bash
   aws ec2 run-instances \
     --image-id ami-12345678 \
     --instance-type t3.micro \
     --key-name MyKeyPair \
     --security-group-ids sg-12345678 \
     --subnet-id subnet-12345678 \
     --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=DataWiper}]'
   ```

2. Attach the volume to wipe:
   ```bash
   aws ec2 attach-volume \
     --volume-id vol-1234567890abcdef0 \
     --instance-id i-1234567890abcdef0 \
     --device /dev/sdf
   ```

3. SSH into the instance and overwrite the volume:
   ```bash
   # Login to instance
   ssh -i MyKeyPair.pem ec2-user@instance-public-ip
   
   # Identify the attached volume
   lsblk
   
   # Overwrite with zeros (DoD 5220.22-M single pass)
   sudo dd if=/dev/zero of=/dev/nvme1n1 bs=1M status=progress
   
   # For more secure wiping (DoD 5220.22-M three-pass):
   # Pass 1: All zeros
   sudo dd if=/dev/zero of=/dev/nvme1n1 bs=1M status=progress
   
   # Pass 2: All ones
   sudo dd if=/dev/one of=/dev/nvme1n1 bs=1M status=progress
   # Note: Create /dev/one first: sudo sh -c 'tr "\000" "\377" < /dev/zero > /dev/one' &
   
   # Pass 3: Random data
   sudo dd if=/dev/urandom of=/dev/nvme1n1 bs=1M status=progress
   ```

4. Detach volume after wiping:
   ```bash
   aws ec2 detach-volume --volume-id vol-1234567890abcdef0
   ```

5. Terminate temporary instance:
   ```bash
   aws ec2 terminate-instances --instance-ids i-1234567890abcdef0
   ```

#### 2.5 Detach Volume

1. Using AWS Management Console:
   - Go to EC2 dashboard
   - Click "Volumes" in the left navigation pane
   - Select the volume to detach
   - Click "Actions" > "Detach Volume"
   - In the confirmation dialog, click "Yes, Detach"
   - Monitor "State" until it changes from "detaching" to "available"

2. Using AWS CLI:
   ```bash
   # Check if volume is attached
   aws ec2 describe-volumes --volume-ids vol-1234567890abcdef0 --query "Volumes[0].Attachments"
   
   # Force detach if necessary (use with caution)
   aws ec2 detach-volume --volume-id vol-1234567890abcdef0 --force
   
   # Standard detach
   aws ec2 detach-volume --volume-id vol-1234567890abcdef0
   
   # Verify detachment
   aws ec2 describe-volumes --volume-ids vol-1234567890abcdef0 --query "Volumes[0].State"
   ```

3. Wait until the volume state is "available" before proceeding:
   ```bash
   aws ec2 wait volume-available --volume-ids vol-1234567890abcdef0
   ```

#### 2.6 Delete Volume

1. Using AWS Management Console:
   - Ensure volume state is "available"
   - Select the volume
   - Click "Actions" > "Delete Volume"
   - In the confirmation dialog, click "Yes, Delete"
   - Monitor until the volume disappears from the volume list

2. Using AWS CLI:
   ```bash
   # Delete volume
   aws ec2 delete-volume --volume-id vol-1234567890abcdef0
   
   # Verify deletion
   aws ec2 describe-volumes --volume-ids vol-1234567890abcdef0
   # Should return an error indicating the volume does not exist
   ```

3. For batch deletion of multiple volumes:
   ```bash
   # Get all available volumes
   VOLUMES=$(aws ec2 describe-volumes --filters "Name=status,Values=available" --query "Volumes[*].VolumeId" --output text)
   
   # Delete each volume
   for vol in $VOLUMES; do
     echo "Deleting volume: $vol"
     aws ec2 delete-volume --volume-id $vol
   done
   ```

#### 2.7 Clean Snapshots

1. Using AWS Management Console:
   - Go to EC2 dashboard
   - Click "Snapshots" in the left navigation pane
   - Use filters to identify snapshots of the deleted volume
   - Select snapshots to delete
   - Click "Actions" > "Delete Snapshot"
   - In the confirmation dialog, click "Yes, Delete"

2. Using AWS CLI:
   ```bash
   # List snapshots for a specific volume
   aws ec2 describe-snapshots --filters "Name=volume-id,Values=vol-1234567890abcdef0" --query "Snapshots[*].SnapshotId"
   
   # Delete a specific snapshot
   aws ec2 delete-snapshot --snapshot-id snap-1234567890abcdef0
   
   # Delete all snapshots for a volume
   SNAPS=$(aws ec2 describe-snapshots --filters "Name=volume-id,Values=vol-1234567890abcdef0" --query "Snapshots[*].SnapshotId" --output text)
   for snap in $SNAPS; do
     echo "Deleting snapshot: $snap"
     aws ec2 delete-snapshot --snapshot-id $snap
   done
   ```

#### 2.8 EBS Data Destruction Verification

1. Verify volume no longer exists:
   ```bash
   aws ec2 describe-volumes --volume-ids vol-1234567890abcdef0
   # Should return an error
   ```

2. Check CloudTrail for deletion events:
   ```bash
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=ResourceName,AttributeValue=vol-1234567890abcdef0
   ```

3. Document the deletion with timestamps and verification method.

### Section 3: AWS RDS Database Destruction

#### 3.1 Understanding RDS Deletion Implications

- RDS deletion removes the database instance and, optionally, automated backups
- Final snapshots can be created for archival purposes
- Multi-AZ deployments are fully removed
- Parameter groups and option groups are not automatically deleted
- Custom subnet groups are not automatically deleted
- Deletion protection might prevent immediate deletion

#### 3.2 Preliminary RDS Assessment

1. Identify all RDS instances:
   ```bash
   aws rds describe-db-instances --query "DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier,Engine:Engine,Status:DBInstanceStatus,MultiAZ:MultiAZ,DeletionProtection:DeletionProtection}"
   ```

2. Check for deletion protection:
   ```bash
   aws rds describe-db-instances --db-instance-identifier database-name --query "DBInstances[0].DeletionProtection"
   ```

3. Identify read replicas:
   ```bash
   aws rds describe-db-instances --query "DBInstances[?ReadReplicaSourceDBInstanceIdentifier!=null].{ReplicaID:DBInstanceIdentifier,Source:ReadReplicaSourceDBInstanceIdentifier}"
   ```

4. Check automated backup retention:
   ```bash
   aws rds describe-db-instances --db-instance-identifier database-name --query "DBInstances[0].BackupRetentionPeriod"
   ```

#### 3.3 Create Final Backup

1. Using AWS Management Console:
   - Go to RDS dashboard
   - Click "Databases" in the left navigation pane
   - Select the database instance
   - Click "Actions" > "Take snapshot"
   - Provide a snapshot identifier: "final-snapshot-[db-name]-[date]"
   - Add a description detailing the purpose of the snapshot
   - Click "Take Snapshot"
   - Monitor snapshot creation in the "Snapshots" section

2. Using AWS CLI:
   ```bash
   # Create manual snapshot
   aws rds create-db-snapshot \
     --db-instance-identifier database-name \
     --db-snapshot-identifier final-snapshot-database-name-20230101 \
     --tags Key=Purpose,Value=FinalBackup
   
   # Monitor snapshot creation
   aws rds describe-db-snapshots \
     --db-snapshot-identifier final-snapshot-database-name-20230101 \
     --query "DBSnapshots[0].Status"
   
   # Wait for snapshot to complete
   aws rds wait db-snapshot-available \
     --db-snapshot-identifier final-snapshot-database-name-20230101
   ```

#### 3.4 Export Database for Long-term Archival (Optional)

1. For critical data, export to S3:
   ```bash
   aws rds start-export-task \
     --export-task-identifier export-database-name-20230101 \
     --source-arn arn:aws:rds:region:account-id:snapshot:final-snapshot-database-name-20230101 \
     --s3-bucket-name export-bucket \
     --iam-role-arn arn:aws:iam::account-id:role/RDSExportRole \
     --kms-key-id arn:aws:kms:region:account-id:key/key-id
   ```

2. Monitor export progress:
   ```bash
   aws rds describe-export-tasks \
     --export-task-identifier export-database-name-20230101
   ```

#### 3.5 Remove Read Replicas First

Read replicas must be deleted before the source instance:

1. Identify all read replicas:
   ```bash
   aws rds describe-db-instances \
     --query "DBInstances[?ReadReplicaSourceDBInstanceIdentifier=='database-name'].DBInstanceIdentifier"
   ```

2. Delete each read replica:
   ```bash
   # Disable deletion protection if enabled
   aws rds modify-db-instance \
     --db-instance-identifier replica-name \
     --no-deletion-protection \
     --apply-immediately
   
   # Delete replica without final snapshot
   aws rds delete-db-instance \
     --db-instance-identifier replica-name \
     --skip-final-snapshot
   
   # Wait for deletion to complete
   aws rds wait db-instance-deleted \
     --db-instance-identifier replica-name
   ```

#### 3.6 Disable Deletion Protection

1. Using AWS Management Console:
   - Go to RDS dashboard
   - Select the database instance
   - Click "Modify"
   - Scroll to "Deletion protection"
   - Uncheck the "Enable deletion protection" checkbox
   - Under "Scheduling of modifications", select "Apply immediately"
   - Click "Continue" 
   - Review the changes
   - Click "Modify DB Instance"
   - Wait for the modification to complete

2. Using AWS CLI:
   ```bash
   # Disable deletion protection
   aws rds modify-db-instance \
     --db-instance-identifier database-name \
     --no-deletion-protection \
     --apply-immediately
   
   # Verify deletion protection is disabled
   aws rds describe-db-instances \
     --db-instance-identifier database-name \
     --query "DBInstances[0].DeletionProtection"
   
   # Wait for modification to complete
   aws rds wait db-instance-available \
     --db-instance-identifier database-name
   ```

#### 3.7 Delete Database Instance

1. Using AWS Management Console:
   - Go to RDS dashboard
   - Select the database instance
   - Click "Actions" > "Delete"
   - In the deletion dialog:
     - Choose whether to create a final snapshot
     - If creating a final snapshot, provide a snapshot name
     - Enter the database name to confirm deletion
     - Select "Delete automated backups" (if you want all backups removed)
     - Click "Delete"
   - Monitor the deletion process in the database list

2. Using AWS CLI:
   ```bash
   # Delete with final snapshot
   aws rds delete-db-instance \
     --db-instance-identifier database-name \
     --final-db-snapshot-identifier final-deletion-snapshot-database-name-20230101
   
   # Delete without final snapshot (complete removal)
   aws rds delete-db-instance \
     --db-instance-identifier database-name \
     --skip-final-snapshot
   ```

3. Wait for deletion to complete:
   ```bash
   aws rds wait db-instance-deleted \
     --db-instance-identifier database-name
   ```

#### 3.8 Delete Automated Backups

1. Using AWS Management Console:
   - Go to RDS dashboard
   - Click "Automated backups" in the left navigation pane
   - Click the "Retained" tab to see automated backups
   - Select backups associated with the deleted database
   - Click "Delete"
   - Confirm deletion

2. Using AWS CLI:
   ```bash
   # List retained automated backups
   aws rds describe-db-instance-automated-backups \
     --query "DBInstanceAutomatedBackups[?DBInstanceIdentifier=='database-name']"
   
   # Delete specific automated backups
   aws rds delete-db-instance-automated-backups \
     --dbi-resource-id dbinstance-resource-id
   ```

#### 3.9 Delete Parameter Groups and Option Groups (Optional)

1. Delete custom parameter groups:
   ```bash
   # List parameter groups
   aws rds describe-db-parameter-groups \
     --query "DBParameterGroups[?DBParameterGroupName!='default*']"
   
   # Delete parameter group
   aws rds delete-db-parameter-group \
     --db-parameter-group-name custom-parameter-group-name
   ```

2. Delete custom option groups:
   ```bash
   # List option groups
   aws rds describe-option-groups \
     --query "OptionGroups[?OptionGroupName!='default*']"
   
   # Delete option group
   aws rds delete-option-group \
     --option-group-name custom-option-group-name
   ```

#### 3.10 Delete DB Subnet Groups (Optional)

```bash
# List subnet groups
aws rds describe-db-subnet-groups \
  --query "DBSubnetGroups[?DBSubnetGroupName!='default']"

# Delete subnet group
aws rds delete-db-subnet-group \
  --db-subnet-group-name custom-subnet-group-name
```

#### 3.11 RDS Data Destruction Verification

1. Verify instance no longer exists:
   ```bash
   aws rds describe-db-instances \
     --db-instance-identifier database-name
   # Should return an error
   ```

2. Verify automated backups are removed:
   ```bash
   aws rds describe-db-instance-automated-backups \
     --query "DBInstanceAutomatedBackups[?DBInstanceIdentifier=='database-name']"
   # Should return empty list
   ```

3. Check CloudTrail for deletion events:
   ```bash
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=ResourceName,AttributeValue=database-name
   ```

4. Document the deletion with timestamps and verification method.

---

## Part 2: Microsoft Azure Data Destruction

### Section 1: Azure Blob Storage Destruction

#### 1.1 Understanding Azure Blob Storage Deletion

- By default, deleted blobs can be recovered within the retention period
- Soft delete feature allows recovery of accidentally deleted data
- Blob versions and snapshots must be explicitly removed
- Legal holds and immutable storage policies may prevent deletion
- Container deletion does not immediately delete blobs if soft delete is enabled

#### 1.2 Preliminary Assessment

1. Install the latest Azure CLI:
   ```bash
   # For Linux
   curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
   
   # For Windows (PowerShell)
   Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi
   Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'
   ```

2. Login to Azure:
   ```bash
   az login
   ```

3. Identify storage accounts:
   ```bash
   az storage account list --output table
   ```

4. Check soft delete settings:
   ```bash
   az storage blob service-properties show \
     --account-name <storage-account-name> \
     --query deleteRetentionPolicy
   ```

5. Check for legal holds or immutable policies:
   ```bash
   az storage container immutability-policy show \
     --account-name <storage-account-name> \
     --container-name <container-name>
   ```

#### 1.3 Enable Soft Delete and Configure Lifecycle Management

1. Using Azure Portal:
   - Sign in to the Azure Portal (https://portal.azure.com)
   - Navigate to your Storage Account
     - Click "All resources" or search for your storage account
     - Click on your storage account name
   - Under "Blob service" in the left menu, click "Data protection"
   - In the "Soft delete" section:
     - Enable "Soft delete for blobs" by checking the box
     - Set retention period (1-365 days)
     - Click "Save"
   - Go to "Lifecycle management" under "Blob service"
   - Click "+ Add a rule"
   - Provide rule details:
     - Name: "Data-Destruction-Policy"
     - Rule scope: Select "Apply rule to all blobs in storage account" or limit to containers
   - Set blob base conditions:
     - Check "Delete blob" under "Actions"
     - Set "Days after last modification" to appropriate value (e.g., 1 day)
   - Add additional settings for blob snapshots:
     - Check "Delete snapshot"
     - Set appropriate days value
   - Add additional settings for blob versions:
     - Check "Delete version"
     - Set appropriate days value
   - Click "Add" to save the rule

2. Using Azure CLI:
   ```bash
   # Enable soft delete with 7-day retention
   az storage blob service-properties update \
     --account-name <storage-account-name> \
     --enable-delete-retention true \
     --delete-retention-days 7
   
   # Create lifecycle management rule
   az storage account management-policy create \
     --account-name <storage-account-name> \
     --policy @policy.json
   ```

   Example `policy.json`:
   ```json
   {
     "rules": [
       {
         "enabled": true,
         "name": "Data-Destruction-Policy",
         "type": "Lifecycle",
         "definition": {
           "actions": {
             "baseBlob": {
               "delete": {
                 "daysAfterModificationGreaterThan": 1
               }
             },
             "snapshot": {
               "delete": {
                 "daysAfterCreationGreaterThan": 1
               }
             },
             "version": {
               "delete": {
                 "daysAfterCreationGreaterThan": 1
               }
             }
           },
           "filters": {
             "blobTypes": ["blockBlob"]
           }
         }
       }
     ]
   }
   ```

#### 1.4 Delete Individual Blobs (Portal Method)

1. Navigate to the Storage Account
   - Sign in to the Azure Portal
   - Search for "Storage accounts" in the search bar
   - Select your storage account from the list
2. Go to "Containers"
   - In the left menu, click "Containers" under "Data storage"
3. Select the container containing target blobs
   - Click on the container name to open it
4. Browse and select the blob(s) to delete
   - Check the boxes next to the blobs you want to delete
   - For large containers, use the filter and search functions
5. Click "Delete" in the top menu
6. In the confirmation dialog:
   - Review the selected blobs
   - Check "Permanently delete blobs that are under retention policy or legal hold" if you want to override soft delete
   - Click "Delete"
7. Monitor the delete operation in the notifications area
8. Refresh the blob list to verify deletion

#### 1.5 Delete Individual Blobs (Azure CLI)

1. Delete a single blob:
   ```bash
   az storage blob delete \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --name <blob-name> \
     --auth-mode login
   ```

2. Delete multiple blobs with prefix:
   ```bash
   az storage blob delete-batch \
     --account-name <storage-account-name> \
     --source <container-name> \
     --pattern "<prefix>*" \
     --auth-mode login
   ```

3. Delete all blobs in a container:
   ```bash
   az storage blob delete-batch \
     --account-name <storage-account-name> \
     --source <container-name> \
     --auth-mode login
   ```

4. Delete blob snapshots:
   ```bash
   # Delete a specific snapshot
   az storage blob delete \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --name <blob-name> \
     --snapshot <snapshot-timestamp> \
     --auth-mode login
   
   # Delete all snapshots for a blob
   az storage blob delete \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --name <blob-name> \
     --delete-snapshots only \
     --auth-mode login
   ```

5. Delete blob versions:
   ```bash
   # List versions
   az storage blob list \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --include v \
     --query "[?name=='<blob-name>']" \
     --auth-mode login
   
   # Delete specific version
   az storage blob delete \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --name <blob-name> \
     --version-id <version-id> \
     --auth-mode login
   ```

#### 1.6 Data Overwriting for Sensitive Blobs

For sensitive data, overwrite before deletion:

1. Create a zero or random file locally:
   ```bash
   # Create 1MB file with zeros
   dd if=/dev/zero of=zeros.bin bs=1M count=1
   
   # Create 1MB file with random data
   dd if=/dev/urandom of=random.bin bs=1M count=1
   ```

2. Overwrite each sensitive blob multiple times:
   ```bash
   # Get blob size first
   blob_size=$(az storage blob show \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --name <blob-name> \
     --query properties.contentLength \
     --output tsv \
     --auth-mode login)
   
   # Create appropriate size overwrite file
   dd if=/dev/urandom of=random.bin bs=1M count=$((($blob_size/1024/1024)+1))
   
   # Overwrite blob multiple times (DoD 5220.22-M style)
   for i in {1..3}; do
     az storage blob upload \
       --account-name <storage-account-name> \
       --container-name <container-name> \
       --name <blob-name> \
       --file random.bin \
       --overwrite \
       --auth-mode login
   done
   
   # Delete the overwritten blob
   az storage blob delete \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --name <blob-name> \
     --auth-mode login
   ```

3. For automation with multiple blobs:
   ```bash
   #!/bin/bash
   STORAGE_ACCOUNT="<storage-account-name>"
   CONTAINER="<container-name>"
   PREFIX="<prefix>"
   
   # List all blobs with prefix
   blobs=$(az storage blob list \
     --account-name $STORAGE_ACCOUNT \
     --container-name $CONTAINER \
     --prefix $PREFIX \
     --query "[].name" \
     --output tsv \
     --auth-mode login)
   
   # Create overwrite file
   dd if=/dev/urandom of=random.bin bs=1M count=10
   
   # Overwrite each blob
   for blob in $blobs; do
     echo "Overwriting $blob"
     for i in {1..3}; do
       az storage blob upload \
         --account-name $STORAGE_ACCOUNT \
         --container-name $CONTAINER \
         --name "$blob" \
         --file random.bin \
         --overwrite \
         --auth-mode login
     done
     
     # Delete the overwritten blob
     az storage blob delete \
       --account-name $STORAGE_ACCOUNT \
       --container-name $CONTAINER \
       --name "$blob" \
       --auth-mode login
   done
   ```

#### 1.7 Delete Container (Portal Method)

1. Navigate to Storage Account in Azure Portal
   - Sign in to the Azure Portal
   - Go to your storage account
2. Go to "Containers"
   - Click "Containers" in the left menu
3. Select the container(s) to delete
   - Check the box next to each container
4. Click "Delete" in the top menu
5. In the confirmation dialog:
   - Confirm you want to delete the container(s)
   - Click "Delete"
6. Monitor the deletion in the notifications area
7. Refresh the container list to verify deletion

#### 1.8 Delete Container (Azure CLI)

1. Delete a single container:
   ```bash
   az storage container delete \
     --account-name <storage-account-name> \
     --name <container-name> \
     --auth-mode login
   ```

2. For multiple containers:
   ```bash
   # List containers with a specific prefix
   containers=$(az storage container list \
     --account-name <storage-account-name> \
     --prefix <prefix> \
     --query "[].name" \
     --output tsv \
     --auth-mode login)
   
   # Delete each container
   for container in $containers; do
     echo "Deleting container: $container"
     az storage container delete \
       --account-name <storage-account-name> \
       --name "$container" \
       --auth-mode login
   done
   ```

#### 1.9 Purge Soft-Deleted Data

1. List soft-deleted blobs:
   ```bash
   az storage blob list \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --include d \
     --auth-mode login
   ```

2. Restore a soft-deleted blob (if needed):
   ```bash
   az storage blob undelete \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --name <blob-name> \
     --auth-mode login
   ```

3. For immediate purge of soft-deleted blobs (requires special permissions):
   ```bash
   # This is an example using Azure Storage REST API via curl
   # Note: Requires appropriate authorization headers
   
   curl -X DELETE "https://<storage-account>.blob.core.windows.net/<container>/<blob>?comp=expiry" \
     -H "Authorization: Bearer <token>" \
     -H "x-ms-version: 2020-04-08"
   ```

4. Wait for the retention period to expire for automatic purging

5. For soft-deleted containers:
   ```bash
   # List deleted containers
   az storage container list-deleted \
     --account-name <storage-account-name> \
     --auth-mode login
   
   # Restore a container if needed
   az storage container restore \
     --account-name <storage-account-name> \
     --name <container-name> \
     --deleted-version <version-id> \
     --auth-mode login
   ```

#### 1.10 Blob Storage Destruction Verification

1. Verify blobs are no longer listed:
   ```bash
   az storage blob list \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --prefix <prefix> \
     --auth-mode login
   ```

2. Check for soft-deleted blobs:
   ```bash
   az storage blob list \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --include d \
     --auth-mode login
   ```

3. Verify containers are no longer listed:
   ```bash
   az storage container list \
     --account-name <storage-account-name> \
     --prefix <prefix> \
     --auth-mode login
   ```

4. Check Azure Activity Log for deletion operations:
   ```bash
   az monitor activity-log list \
     --resource-group <resource-group> \
     --start-time <start-time> \
     --filters "resourceProvider eq 'Microsoft.Storage'"
   ```

5. Document the deletion with timestamps and verification method.

### Section 2: Azure Managed Disk Destruction

#### 2.1 Understanding Azure Disk Deletion

- Managed disks are stored as page blobs in Microsoft-managed storage accounts
- Deleted disks are retained in soft-deleted state for default period
- Snapshots and images must be deleted separately
- Azure does not guarantee immediate data sanitization after deletion
- Encryption provides cryptographic erasure protection

#### 2.2 Preliminary Assessment

1. List all managed disks:
   ```bash
   az disk list --output table
   ```

2. Check for disk attachments:
   ```bash
   az disk list --query "[?managedBy!=null].{Name:name, AttachedTo:managedBy}" --output table
   ```

3. Check for disk encryption:
   ```bash
   az disk list --query "[].{Name:name, EncryptionType:encryption.type}" --output table
   ```

4. Check for snapshots and images:
   ```bash
   # List snapshots
   az snapshot list --output table
   
   # List images
   az image list --output table
   ```

#### 2.3 Create Snapshot (if needed)

1. Using Azure Portal:
   - Sign in to the Azure Portal
   - Navigate to "Disks" (search in the top search bar)
   - Select the target disk
   - Click "Create snapshot" from the top menu
   - Provide snapshot details:
     - Name: "Final-Backup-[Disk-Name]-[Date]"
     - Resource group: Select appropriate resource group
     - Account type: Select storage redundancy option
     - Add appropriate tags for tracking
   - Click "Create"
   - Monitor the snapshot creation process in the notifications area

2. Using Azure CLI:
   ```bash
   # Create snapshot
   az snapshot create \
     --resource-group <resource-group> \
     --name "Final-Backup-<disk-name>-$(date +%Y%m%d)" \
     --source <disk-id> \
     --tags "Purpose=FinalBackup" "DeleteAfter=$(date -d '+30 days' +%Y-%m-%d)"
   
   # Monitor creation
   az snapshot show \
     --resource-group <resource-group> \
     --name "Final-Backup-<disk-name>-$(date +%Y%m%d)" \
     --query "provisioningState"
   ```

#### 2.4 Secure Erase for Confidential Data

For disks containing sensitive data:

1. Enable encryption if not already enabled:
   ```bash
   # Check encryption status
   az disk show \
     --resource-group <resource-group> \
     --name <disk-name> \
     --query "encryption"
   
   # Enable encryption with platform-managed key
   az disk update \
     --resource-group <resource-group> \
     --name <disk-name> \
     --encryption-type EncryptionAtRestWithPlatformKey
   ```

2. For customer-managed keys, rotate the key before deletion:
   ```bash
   # Update disk to use a new key
   az disk update \
     --resource-group <resource-group> \
     --name <disk-name> \
     --encryption-type EncryptionAtRestWithCustomerKey \
     --key-url "https://<keyvault-name>.vault.azure.net/keys/<new-key-name>/<new-key-version>"
   ```

3. For VM-attached disks requiring data wipe:
   ```bash
   # SSH into the VM and securely wipe the disk
   # Example for Linux using shred (replace /dev/sdX with actual device)
   sudo shred -vzn 3 /dev/sdX
   
   # Example for Windows using PowerShell and cipher (run inside VM)
   cipher /w:C:
   ```

#### 2.5 Detach Disk from VM

1. Using Azure Portal:
   - Sign in to the Azure Portal
   - Search for and select "Virtual machines"
   - Click on the VM using the disk
   - Under "Settings", click "Disks"
   - Find the data disk in the list
   - Click the "Detach" icon (X) at the far right
   - Click "Save" at the top
   - Monitor the operation in the notifications area

2. Using Azure CLI:
   ```bash
   # Identify the VM and attached disks
   az vm disk list \
     --resource-group <resource-group> \
     --vm-name <vm-name> \
     --query "[].{Name:name, Lun:lun}" \
     --output table
   
   # Detach disk by LUN
   az vm disk detach \
     --resource-group <resource-group> \
     --vm-name <vm-name> \
     --lun <lun-number>
   
   # Verify detachment
   az vm disk list \
     --resource-group <resource-group> \
     --vm-name <vm-name> \
     --output table
   ```

3. For PowerShell:
   ```powershell
   # Detach disk
   $vm = Get-AzVM -ResourceGroupName <resource-group> -Name <vm-name>
   Remove-AzVMDataDisk -VM $vm -Name <disk-name>
   Update-AzVM -ResourceGroupName <resource-group> -VM $vm
   ```

4. Wait for the detach operation to complete:
   ```bash
   # Check disk status
   az disk show \
     --resource-group <resource-group> \
     --name <disk-name> \
     --query managedBy
   # Should return null when detached
   ```

#### 2.6 Delete the Disk

1. Using Azure Portal:
   - Navigate to "Disks" in the Azure Portal
   - Select the disk(s) to delete
   - Click "Delete" from the top menu
   - In the confirmation dialog, type "yes" to confirm
   - Click "Delete"
   - Monitor the deletion in the notifications area

2. Using Azure CLI:
   ```bash
   # Delete a single disk
   az disk delete \
     --resource-group <resource-group> \
     --name <disk-name> \
     --yes
   
   # Delete multiple disks
   disks=$(az disk list \
     --resource-group <resource-group> \
     --query "[?tags.Environment=='Development'].id" \
     --output tsv)
   
   for disk in $disks; do
     echo "Deleting disk: $disk"
     az disk delete --ids $disk --yes
   done
   ```

3. For PowerShell:
   ```powershell
   # Delete disk
   Remove-AzDisk -ResourceGroupName <resource-group> -DiskName <disk-name> -Force
   ```

4. Verify deletion:
   ```bash
   az disk show \
     --resource-group <resource-group> \
     --name <disk-name>
   # Should return an error indicating the disk doesn't exist
   ```

#### 2.7 Delete Associated Snapshots and Images

1. Delete associated snapshots:
   ```bash
   # Find snapshots for the disk
   az snapshot list \
     --query "[?contains(name, '<disk-name>')].{Name:name, ResourceGroup:resourceGroup}" \
     --output table
   
   # Delete each snapshot
   az snapshot delete \
     --resource-group <resource-group> \
     --name <snapshot-name> \
     --yes
   ```

2. Delete associated images:
   ```bash
   # Find images potentially using the disk
   az image list \
     --query "[?contains(name, '<disk-name>')].{Name:name, ResourceGroup:resourceGroup}" \
     --output table
   
   # Delete each image
   az image delete \
     --resource-group <resource-group> \
     --name <image-name>
   ```

#### 2.8 Disk Destruction Verification

1. Verify disk no longer exists:
   ```bash
   az disk show \
     --resource-group <resource-group> \
     --name <disk-name>
   # Should return an error
   ```

2. Check Azure Activity Log for deletion operations:
   ```bash
   az monitor activity-log list \
     --resource-group <resource-group> \
     --start-time <start-time> \
     --filters "resourceProvider eq 'Microsoft.Compute'" "resourceType eq 'disks'"
   ```

3. Document the deletion with timestamps and verification method.

### Section 3: Azure SQL Database Destruction

#### 3.1 Understanding SQL Database Deletion

- SQL database deletion removes the database permanently after retention period
- Automated backups are retained according to backup retention settings
- Point-in-time restores are available during retention period
- Long-term backups must be handled separately
- Geo-replicated databases must be handled separately

#### 3.2 Preliminary Assessment

1. List all SQL servers and databases:
   ```bash
   # List servers
   az sql server list --output table
   
   # List databases for a server
   az sql db list \
     --resource-group <resource-group> \
     --server <server-name> \
     --output table
   ```

2. Check for replicas and failover groups:
   ```bash
   # Check for geo-replicated databases
   az sql db replica list \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name>
   
   # Check for failover groups
   az sql failover-group list \
     --resource-group <resource-group> \
     --server <server-name>
   ```

3. Check backup retention settings:
   ```bash
   az sql db show \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <database-name> \
     --query "backupRetentionDays"
   ```

4. Check for long-term retention backups:
   ```bash
   az sql db ltr-backup list \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name> \
     --only-latest-per-database
   ```

#### 3.3 Create Final Backup (if needed)

1. Using Azure Portal:
   - Sign in to the Azure Portal
   - Navigate to the SQL database
     - Search for "SQL databases" in the top search bar
     - Select your database from the list
   - Click "Export" in the top menu
   - Configure export settings:
     - Storage account: Select target storage account
     - Container: Select or create a container
     - Database file type: Select appropriate format (BACPAC recommended)
     - Add appropriate login credentials
   - Click "OK" to start the export
   - Monitor the export operation in the notifications area

2. Using Azure CLI:
   ```bash
   # Create a storage container for the backup
   az storage container create \
     --account-name <storage-account-name> \
     --name "final-backups" \
     --auth-mode login
   
   # Generate SAS token for the storage account
   sas=$(az storage account generate-sas \
     --account-name <storage-account-name> \
     --permissions rw \
     --expiry $(date -d "+1 day" +%Y-%m-%dT%H:%MZ) \
     --resource-types co \
     --services b \
     --https-only \
     --output tsv)
   
   # Export database to BACPAC
   az sql db export \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <database-name> \
     --admin-user <admin-username> \
     --admin-password <admin-password> \
     --storage-key-type SharedAccessKey \
     --storage-key "$sas" \
     --storage-uri "https://<storage-account-name>.blob.core.windows.net/final-backups/<database-name>-final-$(date +%Y%m%d).bacpac"
   ```

3. For PowerShell:
   ```powershell
   # Export database
   $storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName <resource-group> -Name <storage-account-name>)[0].Value
   $bcpArgs = New-Object Microsoft.Azure.Commands.Sql.Database.Model.DatabaseExportBacpacProperties
   $bcpArgs.StorageKeyType = "StorageAccessKey"
   $bcpArgs.StorageKey = $storageAccountKey
   $bcpArgs.StorageUri = "https://<storage-account-name>.blob.core.windows.net/final-backups/<database-name>-final-$(Get-Date -Format 'yyyyMMdd').bacpac"
   $bcpArgs.AdministratorLogin = "<admin-username>"
   $bcpArgs.AdministratorLoginPassword = (ConvertTo-SecureString -String "<admin-password>" -AsPlainText -Force)
   
   $exportRequest = New-AzSqlDatabaseExport -ResourceGroupName <resource-group> -ServerName <server-name> -DatabaseName <database-name> -DatabaseExportBacpacProperties $bcpArgs
   
   # Check status
   Get-AzSqlDatabaseImportExportStatus -OperationStatusLink $exportRequest.OperationStatusLink
   ```

#### 3.4 Handle Geo-Replicas and Failover Groups

1. Remove database from failover group:
   ```bash
   # List databases in failover group
   az sql failover-group show \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <failover-group-name> \
     --query "databases"
   
   # Remove database from failover group
   az sql failover-group update \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <failover-group-name> \
     --remove-db <database-name>
   ```

2. Delete geo-replicated databases:
   ```bash
   # List replicas
   az sql db replica list \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name>
   
   # Delete each secondary replica
   az sql db delete \
     --resource-group <secondary-resource-group> \
     --server <secondary-server-name> \
     --name <database-name> \
     --yes
   ```

#### 3.5 Delete Long-Term Retention Backups

1. List long-term retention backups:
   ```bash
   # Get all LTR backups for the database
   az sql db ltr-backup list \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name> \
     --output table
   ```

2. Delete specific LTR backup:
   ```bash
   az sql db ltr-backup delete \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name> \
     --backup-name <backup-name> \
     --yes
   ```

3. Delete all LTR backups for a database:
   ```bash
   # Get list of backups
   backups=$(az sql db ltr-backup list \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name> \
     --query "[].{Name:name}" \
     --output tsv)
   
   # Delete each backup
   for backup in $backups; do
     echo "Deleting LTR backup: $backup"
     az sql db ltr-backup delete \
       --resource-group <resource-group> \
       --server <server-name> \
       --database <database-name> \
       --backup-name $backup \
       --yes
   done
   ```

#### 3.6 Delete Database

1. Using Azure Portal:
   - Sign in to the Azure Portal
   - Navigate to SQL databases
   - Select the database to delete
   - Click "Delete" from the top menu
   - In the confirmation dialog:
     - Read the warning about deletion
     - Type the database name to confirm
     - Click "Delete"
   - Monitor the deletion in the notifications area

2. Using Azure CLI:
   ```bash
   # Delete database
   az sql db delete \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <database-name> \
     --yes
   ```

3. For PowerShell:
   ```powershell
   # Delete database
   Remove-AzSqlDatabase -ResourceGroupName <resource-group> -ServerName <server-name> -DatabaseName <database-name> -Force
   ```

4. Verify deletion:
   ```bash
   az sql db show \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <database-name>
   # Should return an error indicating the database doesn't exist
   ```

#### 3.7 Delete Elastic Pools (if applicable)

1. Check if there are any remaining databases in the elastic pool:
   ```bash
   az sql elastic-pool list-dbs \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <pool-name>
   ```

2. Delete the elastic pool if it's empty:
   ```bash
   az sql elastic-pool delete \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <pool-name> \
     --yes
   ```

#### 3.8 Delete SQL Server (if no longer needed)

1. Check for remaining databases:
   ```bash
   az sql db list \
     --resource-group <resource-group> \
     --server <server-name> \
     --output table
   ```

2. Delete the server:
   ```bash
   az sql server delete \
     --resource-group <resource-group> \
     --name <server-name> \
     --yes
   ```

#### 3.9 SQL Database Destruction Verification

1. Verify database no longer exists:
   ```bash
   az sql db show \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <database-name>
   # Should return an error
   ```

2. Verify no restorable backups exist:
   ```bash
   # Check for restorable deleted databases
   az sql db list-deleted \
     --resource-group <resource-group> \
     --server <server-name>
   
   # Check for LTR backups
   az sql db ltr-backup list \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name>
   ```

3. Check Azure Activity Log for deletion operations:
   ```bash
   az monitor activity-log list \
     --resource-group <resource-group> \
     --start-time <start-time> \
     --filters "resourceProvider eq 'Microsoft.Sql'"
   ```

4. Document the deletion with timestamps and verification method.

### Section 4: Azure Cosmos DB Destruction

#### 4.1 Understanding Cosmos DB Deletion

- Cosmos DB data can exist at multiple levels: account, database, container, items
- Backups may exist depending on backup policy configuration
- Continuous backup mode enables point-in-time restoration
- Multi-region deployments replicate data to all configured regions
- Soft delete features may retain deleted items

#### 4.2 Preliminary Assessment

1. List all Cosmos DB accounts:
   ```bash
   az cosmosdb list --output table
   ```

2. List databases in an account:
   ```bash
   az cosmosdb sql database list \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --output table
   ```

3. List containers in a database:
   ```bash
   az cosmosdb sql container list \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --database-name <database-name> \
     --output table
   ```

4. Check backup policy:
   ```bash
   az cosmosdb show \
     --resource-group <resource-group> \
     --name <account-name> \
     --query "backupPolicy"
   ```

5. Check consistency level and replication configuration:
   ```bash
   az cosmosdb show \
     --resource-group <resource-group> \
     --name <account-name> \
     --query "{Consistency:consistencyPolicy.defaultConsistencyLevel, Regions:locations}"
   ```

#### 4.3 Export Data (if needed)

1. Using Data Migration Tool:
   - Download the Cosmos DB Data Migration Tool
   - Configure source connection to Cosmos DB account
   - Configure target connection to file or other storage
   - Execute the export

2. Using Azure Portal Data Explorer:
   - Sign in to the Azure Portal
   - Navigate to your Cosmos DB account
   - Click "Data Explorer" in the left menu
   - Select the database and container
   - Click "Export" in the top menu
   - Configure the export settings
   - Start the export operation

3. Using Azure CLI and custom script:
   ```bash
   # Example script to export using the CosmosDB REST API
   # Requires jq for JSON processing
   
   # Set variables
   ACCOUNT_NAME="<account-name>"
   DATABASE_NAME="<database-name>"
   CONTAINER_NAME="<container-name>"
   RESOURCE_GROUP="<resource-group>"
   OUTPUT_FILE="${DATABASE_NAME}-${CONTAINER_NAME}-export.json"
   
   # Get master key
   MASTER_KEY=$(az cosmosdb keys list \
     --resource-group $RESOURCE_GROUP \
     --name $ACCOUNT_NAME \
     --type keys \
     --query primaryMasterKey \
     --output tsv)
   
   # Get endpoint
   ENDPOINT=$(az cosmosdb show \
     --resource-group $RESOURCE_GROUP \
     --name $ACCOUNT_NAME \
     --query documentEndpoint \
     --output tsv)
   
   # Create a date for the authorization header
   DATE=$(date -u "+%a, %d %b %Y %H:%M:%S GMT")
   
   # Set up continuation token variable
   CONTINUATION=""
   
   # Loop until all documents are exported
   echo "[" > $OUTPUT_FILE
   FIRST=true
   
   while true; do
     # Build the authorization token
     VERB="GET"
     RESOURCE_TYPE="docs"
     RESOURCE_LINK="dbs/${DATABASE_NAME}/colls/${CONTAINER_NAME}"
     
     # Create the authorization signature
     SIGNATURE="$(echo -en "${VERB}\n${RESOURCE_TYPE}\n${RESOURCE_LINK}\n${DATE}\n\n" | \
                  openssl dgst -sha256 -mac HMAC -macopt "key:$MASTER_KEY" -binary | \
                  base64)"
     
     # URL encode the signature
     ENCODED_SIGNATURE=$(echo $SIGNATURE | sed 's/+/%2B/g' | sed 's/\//%2F/g' | sed 's/=/%3D/g')
     
     # Build the authorization header
     AUTH_HEADER="type=master&ver=1.0&sig=${ENCODED_SIGNATURE}"
     
     # Build the URL
     URL="${ENDPOINT}${RESOURCE_LINK}/docs"
     
     # Add continuation token if available
     CONT_HEADER=""
     if [ ! -z "$CONTINUATION" ]; then
       CONT_HEADER="-H 'x-ms-continuation:$CONTINUATION'"
     fi
     
     # Make the request
     RESPONSE=$(curl -s -X GET "$URL" \
       -H "Authorization: $AUTH_HEADER" \
       -H "x-ms-date: $DATE" \
       -H "x-ms-version: 2018-12-31" \
       $CONT_HEADER)
     
     # Extract documents
     DOCS=$(echo $RESPONSE | jq -c '.Documents[]')
     
     # Write to file
     for DOC in $DOCS; do
       if [ "$FIRST" = true ]; then
         FIRST=false
       else
         echo "," >> $OUTPUT_FILE
       fi
       echo "$DOC" >> $OUTPUT_FILE
     done
     
     # Get continuation token
     CONTINUATION=$(echo $RESPONSE | jq -r '."x-ms-continuation"')
     
     # Exit if no continuation token
     if [ "$CONTINUATION" = "null" ] || [ -z "$CONTINUATION" ]; then
       break
     fi
   done
   
   echo "]" >> $OUTPUT_FILE
   echo "Export completed to $OUTPUT_FILE"
   ```

#### 4.4 Delete Items (Data Level)

For selective data deletion:

1. Using Azure Portal Data Explorer:
   - Navigate to the Cosmos DB account in Azure Portal
   - Click "Data Explorer" in the left menu
   - Browse to the database and container
   - Use the query editor to find items to delete
   - Select items and click "Delete" in the top menu
   - Confirm deletion

2. Using Azure CLI and SDK:
   ```python
   # Python script for batch deletion of items
   from azure.cosmos import CosmosClient, PartitionKey
   import os
   
   # Set up credentials
   endpoint = "https://<account-name>.documents.azure.com:443/"
   key = "<master-key>"
   
   # Initialize client
   client = CosmosClient(endpoint, key)
   
   # Get reference to database and container
   database = client.get_database_client("<database-name>")
   container = database.get_container_client("<container-name>")
   
   # Query for items to delete (customize as needed)
   query = "SELECT c.id, c.<partition-key-path> FROM c WHERE c.status = 'Archived'"
   
   # Delete each item
   items_deleted = 0
   for item in container.query_items(query=query, enable_cross_partition_query=True):
     partition_key_value = item["<partition-key-path>"]
     container.delete_item(item=item["id"], partition_key=partition_key_value)
     items_deleted += 1
     if items_deleted % 100 == 0:
       print(f"Deleted {items_deleted} items...")
   
   print(f"Total items deleted: {items_deleted}")
   ```

3. To delete all items while preserving the container:
   ```bash
   # Bash script to delete all items using the Cosmos DB REST API
   
   # Set variables
   ACCOUNT_NAME="<account-name>"
   DATABASE_NAME="<database-name>"
   CONTAINER_NAME="<container-name>"
   RESOURCE_GROUP="<resource-group>"
   PARTITION_KEY_NAME="<partition-key-name>"
   
   # Get master key
   MASTER_KEY=$(az cosmosdb keys list \
     --resource-group $RESOURCE_GROUP \
     --name $ACCOUNT_NAME \
     --type keys \
     --query primaryMasterKey \
     --output tsv)
   
   # Get endpoint
   ENDPOINT=$(az cosmosdb show \
     --resource-group $RESOURCE_GROUP \
     --name $ACCOUNT_NAME \
     --query documentEndpoint \
     --output tsv)
   
   # First, query for all document IDs and partition keys
   echo "Querying for all documents..."
   
   # Execute query to get IDs and partition keys (assuming a simple partition key structure)
   # Save query results to a temporary file
   az cosmosdb sql query \
     --resource-group $RESOURCE_GROUP \
     --account-name $ACCOUNT_NAME \
     --database-name $DATABASE_NAME \
     --container-name $CONTAINER_NAME \
     --query "SELECT c.id, c.$PARTITION_KEY_NAME FROM c" \
     > documents.json
   
   # Delete each document
   echo "Starting deletion process..."
   TOTAL=$(jq '.[] | length' documents.json)
   COUNTER=0
   
   cat documents.json | jq -c '.[]' | while read -r doc; do
     ID=$(echo $doc | jq -r '.id')
     PARTITION_KEY=$(echo $doc | jq -r ".$PARTITION_KEY_NAME")
     
     # Delete the document
     az cosmosdb sql delete \
       --resource-group $RESOURCE_GROUP \
       --account-name $ACCOUNT_NAME \
       --database-name $DATABASE_NAME \
       --container-name $CONTAINER_NAME \
       --item-id $ID \
       --partition-key $PARTITION_KEY
     
     COUNTER=$((COUNTER+1))
     if [ $((COUNTER % 100)) -eq 0 ]; then
       echo "Deleted $COUNTER of $TOTAL documents..."
     fi
   done
   
   echo "Deletion complete. Deleted $COUNTER documents."
   rm documents.json
   ```

#### 4.5 Delete Collections/Containers

1. Using Azure Portal:
   - Navigate to the Cosmos DB account
   - Click "Data Explorer" in the left menu
   - Expand the database containing your container
   - Right-click on the container
   - Select "Delete Container"
   - Type the container name to confirm
   - Click "OK"

2. Using Azure CLI:
   ```bash
   # Delete a SQL API container
   az cosmosdb sql container delete \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --database-name <database-name> \
     --name <container-name> \
     --yes
   
   # For other APIs (MongoDB, Cassandra, Gremlin, Table)
   # Use the corresponding command, e.g., for MongoDB:
   az cosmosdb mongodb collection delete \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --database-name <database-name> \
     --name <collection-name> \
     --yes
   ```

3. Batch delete all containers in a database:
   ```bash
   # List all containers
   containers=$(az cosmosdb sql container list \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --database-name <database-name> \
     --query "[].name" \
     --output tsv)
   
   # Delete each container
   for container in $containers; do
     echo "Deleting container: $container"
     az cosmosdb sql container delete \
       --resource-group <resource-group> \
       --account-name <account-name> \
       --database-name <database-name> \
       --name "$container" \
       --yes
   done
   ```

#### 4.6 Delete Database

1. Using Azure Portal:
   - Navigate to the Cosmos DB account
   - Click "Data Explorer" in the left menu
   - Right-click on the database
   - Select "Delete Database"
   - Type the database name to confirm
   - Click "OK"

2. Using Azure CLI:
   ```bash
   # Delete a SQL API database
   az cosmosdb sql database delete \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --name <database-name> \
     --yes
   
   # For other APIs (MongoDB, Cassandra, Gremlin, Table)
   # Use the corresponding command, e.g., for MongoDB:
   az cosmosdb mongodb database delete \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --name <database-name> \
     --yes
   ```

3. Batch delete all databases in an account:
   ```bash
   # List all databases
   databases=$(az cosmosdb sql database list \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --query "[].name" \
     --output tsv)
   
   # Delete each database
   for db in $databases; do
     echo "Deleting database: $db"
     az cosmosdb sql database delete \
       --resource-group <resource-group> \
       --account-name <account-name> \
       --name "$db" \
       --yes
   done
   ```

#### 4.7 Delete Cosmos DB Account

1. Using Azure Portal:
   - Navigate to "Azure Cosmos DB accounts" in the portal
   - Select the account you want to delete
   - Click "Delete" from the top menu
   - In the confirmation dialog:
     - Type the account name to confirm
     - Click "Delete"
   - Monitor the deletion process in the notifications area

2. Using Azure CLI:
   ```bash
   # Delete Cosmos DB account
   az cosmosdb delete \
     --resource-group <resource-group> \
     --name <account-name> \
     --yes
   ```

3. For PowerShell:
   ```powershell
   # Delete Cosmos DB account
   Remove-AzCosmosDBAccount -ResourceGroupName <resource-group> -Name <account-name> -Force
   ```

4. Verify deletion:
   ```bash
   az cosmosdb show \
     --resource-group <resource-group> \
     --name <account-name>
   # Should return an error indicating the account doesn't exist
   ```

#### 4.8 Cosmos DB Destruction Verification

1. Verify account no longer exists:
   ```bash
   az cosmosdb show \
     --resource-group <resource-group> \
     --name <account-name>
   # Should return an error
   ```

2. Check for any backup resources:
   ```bash
   # Check for any backup vaults containing Cosmos DB backups
   az backup vault list \
     --resource-group <resource-group>
   ```

3. Check Azure Activity Log for deletion operations:
   ```bash
   az monitor activity-log list \
     --resource-group <resource-group> \
     --start-time <start-time> \
     --filters "resourceProvider eq 'Microsoft.DocumentDB'"
   ```

4. Document the deletion with timestamps and verification method.

### Section 5: Azure Data Factory Pipelines for Secure Data Destruction

#### 5.1 Understanding Data Factory for Destruction

- Azure Data Factory can automate and orchestrate complex data destruction workflows
- Can handle multi-step processes across various data stores
- Provides logging and monitoring capabilities
- Enables scheduled or triggered destruction processes
- Can implement data overwriting before deletion

#### 5.2 Creating a Data Destruction Pipeline

1. Sign in to the Azure Portal
2. Navigate to your Azure Data Factory instance
   - Search for "Data factories" in the search bar
   - Select your Data Factory or create a new one
3. Click "Author & Monitor" to open the ADF studio
4. Create a new pipeline:
   - Click "+" and select "Pipeline"
   - Name it "Data-Destruction-Pipeline"
   - Add a description detailing its purpose

#### 5.3 Configure Pipeline Variables

1. Click on the pipeline canvas background
2. Go to "Variables" tab and add the following:
   - `DataStorageType`: String, default: "BlobStorage"
   - `ContainerName`: String
   - `AccountName`: String
   - `ResourceGroup`: String
   - `ConfirmDestruction`: Boolean, default: false

#### 5.4 Add Validation Activities

1. Add a "Set variable" activity:
   - Name it "ValidateDestructionRequest"
   - Variable: "ConfirmDestruction"
   - Value: `@pipeline().parameters.confirmDestruction`

2. Add an "If Condition" activity:
   - Name it "CheckDestructionConfirmation"
   - Expression: `@variables('ConfirmDestruction')`
   - Connect from the previous activity

3. In the "True" path, continue with destruction activities
4. In the "False" path, add a "Fail" activity:
   - Name it "AbortDestruction"
   - Error message: "Destruction not confirmed. Process aborted."
   - Error code: "USER_ABORT"

#### 5.5 Add Data Overwrite Step (for sensitive data)

In the "True" path of the condition:

1. Add a "ForEach" activity:
   - Name it "IterateThroughStorageLocations"
   - Configure the "Items" field with your data location list

2. Inside the ForEach, add a "Copy" activity:
   - Name it "OverwriteWithRandomData"
   - Source: Configure "Data Generator" as source type
     - Number of rows: 1000
     - Column pattern:
       - Name: "data"
       - Pattern: Random
       - Length: 1024
   - Sink: Configure your data store (Blob, SQL, etc.)
   - Enable "Preserve settings"

3. Add another "Copy" activity after the overwrite:
   - Name it "OverwriteWithZeros"
   - Similar configuration but set pattern to constant zeros
   - Connect from the previous activity

#### 5.6 Add Deletion Activities

After the overwrite steps, add the appropriate deletion activities:

1. For Blob Storage:
   - Add an "Azure Blob Delete" activity:
     - Name it "DeleteBlobData"
     - Connect from the overwrite activity
     - Configure connection to your storage account
     - Blob path: `@item().path`

2. For SQL Database:
   - Add a "Stored Procedure" activity:
     - Name it "ExecuteSQLDeletion"
     - Configure connection to your SQL server
     - Stored procedure name: (a procedure that truncates/drops tables)
     - Parameters: Pass relevant parameters

3. For Cosmos DB:
   - Add an "Azure Cosmos DB" activity:
     - Name it "DeleteCosmosData"
     - Configure connection to your Cosmos DB account
     - Operation: "DeleteCollection"
     - Parameters: Pass database and collection names

#### 5.7 Add Logging and Notification

1. Add a "Web" activity for logging:
   - Name it "LogDeletionActivity"
   - URL: Your logging endpoint
   - Method: POST
   - Body: JSON containing deletion details
   - Connect from deletion activities

2. Add an "Azure Function" activity for notification:
   - Name it "SendNotification"
   - Function name: (a function that sends notifications)
   - Parameters: Pass deletion details
   - Connect from logging activity

#### 5.8 Execute and Monitor

1. Validate the pipeline:
   - Click "Validate" in the toolbar
   - Address any validation errors

2. Publish changes:
   - Click "Publish all" to save the pipeline

3. Execute the pipeline:
   - Click "Add trigger" > "Trigger now"
   - Enter required parameters
   - Confirm pipeline execution

4. Monitor execution:
   - Go to the "Monitor" tab
   - Select your pipeline run
   - View detailed execution information
   - Check activity outputs and logs

#### 5.9 Create Reusable Pipeline Template

For repeatable destruction operations:

1. Export the pipeline as a template:
   - Click on the pipeline
   - Click "Export template"
   - Save the ARM template

2. Create a script to deploy and execute:
   ```bash
   # Deploy pipeline template
   az deployment group create \
     --resource-group <resource-group> \
     --template-file destruction-pipeline-template.json \
     --parameters @parameters.json
   
   # Execute pipeline with parameters
   az datafactory pipeline create-run \
     --resource-group <resource-group> \
     --factory-name <data-factory-name> \
     --pipeline-name Data-Destruction-Pipeline \
     --parameters "{ \"dataStorageType\": \"BlobStorage\", \"containerName\": \"<container-name>\", \"confirmDestruction\": true }"
   ```

### Section 6: Azure Key Vault Destruction (for Encrypted Data)

#### 6.1 Understanding Key Vault Deletion Impact

- Deleting keys in Key Vault renders encrypted data inaccessible (cryptographic erasure)
- Soft delete feature retains deleted keys for recovery period
- Purge protection may prevent immediate permanent deletion
- Key rotation creates new key versions but doesn't delete old versions by default
- Access policies and RBAC control who can delete keys

#### 6.2 Preliminary Assessment

1. List all Key Vaults:
   ```bash
   az keyvault list --output table
   ```

2. Check soft delete and purge protection settings:
   ```bash
   az keyvault show \
     --name <keyvault-name> \
     --query "{SoftDelete:properties.enableSoftDelete, PurgeProtection:properties.enablePurgeProtection}"
   ```

3. List keys and secrets:
   ```bash
   # List keys
   az keyvault key list \
     --vault-name <keyvault-name> \
     --output table
   
   # List secrets
   az keyvault secret list \
     --vault-name <keyvault-name> \
     --output table
   ```

4. Check for key usage:
   ```bash
   # Example: Check for disk encryption using this key vault
   az disk list \
     --query "[?encryption.type=='EncryptionAtRestWithCustomerKey'].{Name:name, KeyUrl:encryption.diskEncryptionSetId}" \
     --output table
   ```

#### 6.3 Identify Keys and Secrets

1. Catalog all keys with purpose:
   ```bash
   # List all keys with details
   az keyvault key list \
     --vault-name <keyvault-name> \
     --query "[].{Name:name, Enabled:attributes.enabled, Created:attributes.created, Updated:attributes.updated}" \
     --output table
   ```

2. Catalog all secrets with purpose:
   ```bash
   # List all secrets with details
   az keyvault secret list \
     --vault-name <keyvault-name> \
     --query "[].{Name:name, Enabled:attributes.enabled, Created:attributes.created, Updated:attributes.updated}" \
     --output table
   ```

3. Document each key's usage:
   - Create a spreadsheet or document listing each key
   - Identify which systems/data rely on each key
   - Determine impact of key deletion
   - Note any dependencies between keys

#### 6.4 Disable Keys and Secrets

1. Using Azure Portal:
   - Navigate to your Key Vault
   - Select "Keys" or "Secrets" in the left menu
   - Click on the key/secret you want to disable
   - Click on the current version
   - Click "Disable" at the top
   - Confirm the action

2. Using Azure CLI:
   ```bash
   # Disable a key
   az keyvault key set-attributes \
     --vault-name <keyvault-name> \
     --name <key-name> \
     --enabled false
   
   # Disable a secret
   az keyvault secret set-attributes \
     --vault-name <keyvault-name> \
     --name <secret-name> \
     --enabled false
   ```

3. Batch disable all keys:
   ```bash
   # Get all keys
   keys=$(az keyvault key list \
     --vault-name <keyvault-name> \
     --query "[].name" \
     --output tsv)
   
   # Disable each key
   for key in $keys; do
     echo "Disabling key: $key"
     az keyvault key set-attributes \
       --vault-name <keyvault-name> \
       --name "$key" \
       --enabled false
   done
   ```

4. Batch disable all secrets:
   ```bash
   # Get all secrets
   secrets=$(az keyvault secret list \
     --vault-name <keyvault-name> \
     --query "[].name" \
     --output tsv)
   
   # Disable each secret
   for secret in $secrets; do
     echo "Disabling secret: $secret"
     az keyvault secret set-attributes \
       --vault-name <keyvault-name> \
       --name "$secret" \
       --enabled false
   done
   ```

#### 6.5 Delete Keys and Secrets

1. Using Azure Portal:
   - Navigate to your Key Vault
   - Select "Keys" or "Secrets" in the left menu
   - Select the key/secret to delete
   - Click "Delete" at the top
   - Confirm the deletion
   - Note: This performs a soft delete if enabled

2. Using Azure CLI:
   ```bash
   # Delete a key (soft delete)
   az keyvault key delete \
     --vault-name <keyvault-name> \
     --name <key-name>
   
   # Delete a secret (soft delete)
   az keyvault secret delete \
     --vault-name <keyvault-name> \
     --name <secret-name>
   ```

3. Batch delete all keys:
   ```bash
   # Get all keys
   keys=$(az keyvault key list \
     --vault-name <keyvault-name> \
     --query "[].name" \
     --output tsv)
   
   # Delete each key
   for key in $keys; do
     echo "Deleting key: $key"
     az keyvault key delete \
       --vault-name <keyvault-name> \
       --name "$key"
   done
   ```

4. Batch delete all secrets:
   ```bash
   # Get all secrets
   secrets=$(az keyvault secret list \
     --vault-name <keyvault-name> \
     --query "[].name" \
     --output tsv)
   
   # Delete each secret
   for secret in $secrets; do
     echo "Deleting secret: $secret"
     az keyvault secret delete \
       --vault-name <keyvault-name> \
       --name "$secret"
   done
   ```

#### 6.6 Purge Deleted Keys and Secrets

If purge protection is not enabled:

1. Using Azure Portal:
   - Navigate to your Key Vault
   - Select "Keys" or "Secrets" in the left menu
   - Click "Manage deleted keys" or "Manage deleted secrets"
   - Select the deleted key/secret
   - Click "Purge" to permanently delete it

2. Using Azure CLI:
   ```bash
   # List deleted keys
   az keyvault key list-deleted \
     --vault-name <keyvault-name> \
     --output table
   
   # Purge a deleted key
   az keyvault key purge \
     --vault-name <keyvault-name> \
     --name <key-name>
   
   # List deleted secrets
   az keyvault secret list-deleted \
     --vault-name <keyvault-name> \
     --output table
   
   # Purge a deleted secret
   az keyvault secret purge \
     --vault-name <keyvault-name> \
     --name <secret-name>
   ```

3. Batch purge all deleted keys:
   ```bash
   # Get all deleted keys
   deleted_keys=$(az keyvault key list-deleted \
     --vault-name <keyvault-name> \
     --query "[].name" \
     --output tsv)
   
   # Purge each deleted key
   for key in $deleted_keys; do
     echo "Purging key: $key"
     az keyvault key purge \
       --vault-name <keyvault-name> \
       --name "$key"
   done
   ```

4. Batch purge all deleted secrets:
   ```bash
   # Get all deleted secrets
   deleted_secrets=$(az keyvault secret list-deleted \
     --vault-name <keyvault-name> \
     --query "[].name" \
     --output tsv)
   
   # Purge each deleted secret
   for secret in $deleted_secrets; do
     echo "Purging secret: $secret"
     az keyvault secret purge \
       --vault-name <keyvault-name> \
       --name "$secret"
   done
   ```

#### 6.7 Delete the Key Vault

1. Using Azure Portal:
   - Navigate to your Key Vault
   - Click "Delete" in the top menu
   - Type the vault name to confirm
   - Click "Delete"
   - Note: This performs a soft delete if enabled

2. Using Azure CLI:
   ```bash
   # Delete the key vault (soft delete)
   az keyvault delete \
     --name <keyvault-name> \
     --resource-group <resource-group>
   ```

3. Purge the deleted Key Vault (if purge protection is not enabled):
   ```bash
   # List deleted vaults
   az keyvault list-deleted --output table
   
   # Purge a deleted vault
   az keyvault purge --name <keyvault-name>
   ```

#### 6.8 Key Vault Destruction Verification

1. Verify keys no longer exist:
   ```bash
   az keyvault key show \
     --vault-name <keyvault-name> \
     --name <key-name>
   # Should return an error
   ```

2. Verify secrets no longer exist:
   ```bash
   az keyvault secret show \
     --vault-name <keyvault-name> \
     --name <secret-name>
   # Should return an error
   ```

3. Verify vault no longer exists:
   ```bash
   az keyvault show \
     --name <keyvault-name>
   # Should return an error
   ```

4. Check for deleted but not purged resources:
   ```bash
   # Check for deleted keys
   az keyvault key list-deleted \
     --vault-name <keyvault-name>
   
   # Check for deleted secrets
   az keyvault secret list-deleted \
     --vault-name <keyvault-name>
   
   # Check for deleted vaults
   az keyvault list-deleted
   ```

5. Check Azure Activity Log for deletion operations:
   ```bash
   az monitor activity-log list \
     --resource-group <resource-group> \
     --start-time <start-time> \
     --filters "resourceProvider eq 'Microsoft.KeyVault'"
   ```

6. Document the deletion with timestamps and verification method.

---

## Part 3: Cross-Platform Considerations

### Section 1: Compliance Verification

#### 1.1 Understanding Compliance Requirements

- Different regulations have specific data destruction requirements:
  - GDPR: Right to erasure (Article 17)
  - HIPAA: Media sanitization requirements
  - PCI DSS: Secure deletion of cardholder data
  - SOC 2: Data disposal procedures
  - NIST SP 800-88: Media sanitization guidelines
- Organization-specific policies may require additional steps
- Verification and documentation are essential for compliance
- Chain of custody should be maintained
- Third-party verification may be required

#### 1.2 Document Destruction Process

1. Create a Data Destruction Log:
   - Date and time of destruction
   - Description of data destroyed
   - Data classification level
   - Location of data (cloud provider, region, resource ID)
   - Destruction method used
   - Personnel performing destruction
   - Verification method
   - Approvals received

2. Data Destruction Log Template:
   ```
   Data Destruction Log
   -------------------
   
   Organization: [Organization Name]
   Project/System: [Project/System Name]
   
   Destruction Details:
   - Request Date: [Date request received]
   - Approval Date: [Date approved]
   - Execution Date: [Date destruction performed]
   - Completion Date: [Date verification completed]
   
   Data Details:
   - Description: [Brief description of data]
   - Classification: [Confidential/Restricted/Public]
   - Format: [Database/Files/Documents/etc.]
   - Volume: [Size or record count]
   - Retention Period: [Required retention period]
   - Retention End Date: [Date retention period ended]
   
   Location Details:
   - Cloud Provider: [AWS/Azure/Both]
   - Regions: [List of regions]
   - Resource IDs: [List of resource IDs]
   
   Destruction Method:
   - Technique Used: [Deletion/Overwrite/Encryption/etc.]
   - Tools Used: [List of tools/commands]
   - Standards Followed: [NIST SP 800-88/DoD 5220.22-M/etc.]
   
   Personnel:
   - Requestor: [Name and role]
   - Approver: [Name and role]
   - Executor: [Name and role]
   - Verifier: [Name and role]
   
   Verification:
   - Method: [Audit logs/Manual inspection/etc.]
   - Results: [Pass/Fail/Partial]
   - Evidence: [Reference to attached evidence]
   - Exceptions: [Any data that couldn't be destroyed]
   
   Additional Notes:
   [Any relevant information]
   
   Signatures:
   
   Executor: ________________________ Date: ________
   
   Verifier: ________________________ Date: ________
   
   Compliance Officer: ______________ Date: ________
   ```

3. Include detailed technical logs:
   - Command outputs
   - Screenshots of console operations
   - Error messages and resolutions
   - Timestamps of each action

4. Maintain documentation for the required retention period:
   - Store securely with access controls
   - Encrypt if containing sensitive information
   - Include in backup systems
   - Apply appropriate retention policies

#### 1.3 Run Audit Reports

1. AWS CloudTrail Audit:
   ```bash
   # Create a temporary directory for audit files
   mkdir -p audit/$(date +%Y%m%d)
   cd audit/$(date +%Y%m%d)
   
   # Set time range for audit
   START_TIME="$(date -d '7 days ago' --iso-8601=seconds)"
   END_TIME="$(date --iso-8601=seconds)"
   
   # Get S3 deletion events
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObject \
     --start-time "$START_TIME" \
     --end-time "$END_TIME" \
     if not re.match(email_regex, event["requestor"]):
       raise Exception(f"ValidationError: Invalid email format: {event['requestor']}")
     
     # Check if resources exist
     if event["resourceType"] == "s3":
       s3 = boto3.client('s3')
       for bucket in event["resourceIds"]:
         try:
           s3.head_bucket(Bucket=bucket)
         except Exception as e:
           raise Exception(f"ValidationError: Bucket does not exist or no permission: {bucket}")
     
     # Add similar checks for other resource types
     
     # Set approval requirements
     # Rule: Resources with size > 1GB require approval
     requires_approval = False
     
     if event["resourceType"] == "s3":
       s3 = boto3.client('s3')
       total_size = 0
       for bucket in event["resourceIds"]:
         response = s3.list_objects_v2(Bucket=bucket)
         if "Contents" in response:
           bucket_size = sum(obj["Size"] for obj in response["Contents"])
           total_size += bucket_size
       
       requires_approval = total_size > 1_000_000_000  # 1GB
     
     # Add similar size checks for other resource types
     
     # Return the validation result with approval flag
     return {
       "requestId": event["requestId"],
       "resourceType": event["resourceType"],
       "resourceIds": event["resourceIds"],
       "reason": event["reason"],
       "requestor": event["requestor"],
       "requiresApproval": requires_approval,
       "waitTime": 3600,  # Default wait time for approval (1 hour)
       "validationTime": context.invoked_function_arn
     }
   ```

3. Deploy the workflow using AWS CloudFormation:
   ```yaml
   AWSTemplateFormatVersion: '2010-09-09'
   Description: 'Data Destruction Automation Workflow'
   
   Resources:
     DataDestructionStateMachine:
       Type: AWS::StepFunctions::StateMachine
       Properties:
         StateMachineName: DataDestructionWorkflow
         RoleArn: !GetAtt DataDestructionRole.Arn
         DefinitionString: !Sub |
           {
             "Comment": "Data Destruction State Machine",
             "StartAt": "ValidateRequest",
             # Full state machine definition here
           }
     
     ValidateDestructionRequestFunction:
       Type: AWS::Lambda::Function
       Properties:
         Handler: validate_destruction_request.lambda_handler
         Role: !GetAtt LambdaExecutionRole.Arn
         Code:
           ZipFile: |
             # Function code here
         Runtime: python3.9
         Timeout: 60
     
     # Additional function definitions here
     
     DataDestructionRole:
       Type: AWS::IAM::Role
       Properties:
         AssumeRolePolicyDocument:
           Version: '2012-10-17'
           Statement:
             - Effect: Allow
               Principal:
                 Service: states.amazonaws.com
               Action: sts:AssumeRole
         ManagedPolicyArns:
           - arn:aws:iam::aws:policy/service-role/AWSLambdaRole
     
     LambdaExecutionRole:
       Type: AWS::IAM::Role
       Properties:
         AssumeRolePolicyDocument:
           Version: '2012-10-17'
           Statement:
             - Effect: Allow
               Principal:
                 Service: lambda.amazonaws.com
               Action: sts:AssumeRole
         ManagedPolicyArns:
           - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
         Policies:
           - PolicyName: DestructionPermissions
             PolicyDocument:
               Version: '2012-10-17'
               Statement:
                 - Effect: Allow
                   Action:
                     - s3:*
                     - ec2:*
                     - rds:*
                     - dynamodb:*
                     - lambda:*
                     - logs:*
                   Resource: '*'
   
   Outputs:
     StateMachineArn:
       Description: ARN of the Data Destruction State Machine
       Value: !Ref DataDestructionStateMachine
   ```

### Section 2: Creating Azure Destruction Pipelines

#### 2.1 Azure Logic Apps Destruction Workflow

Create a Logic App that orchestrates the data destruction process:

1. Create a Logic App definition:
   ```json
   {
     "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
     "contentVersion": "1.0.0.0",
     "parameters": {
       "logicAppName": {
         "type": "string",
         "defaultValue": "DataDestructionWorkflow"
       },
       "location": {
         "type": "string",
         "defaultValue": "[resourceGroup().location]"
       },
       "approverEmail": {
         "type": "string",
         "defaultValue": "approver@example.com"
       }
     },
     "resources": [
       {
         "type": "Microsoft.Logic/workflows",
         "apiVersion": "2019-05-01",
         "name": "[parameters('logicAppName')]",
         "location": "[parameters('location')]",
         "properties": {
           "state": "Enabled",
           "definition": {
             "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
             "contentVersion": "1.0.0.0",
             "parameters": {
               "approverEmail": {
                 "type": "string",
                 "defaultValue": "[parameters('approverEmail')]"
               }
             },
             "triggers": {
               "manual": {
                 "type": "Request",
                 "kind": "Http",
                 "inputs": {
                   "schema": {
                     "type": "object",
                     "properties": {
                       "requestId": {
                         "type": "string"
                       },
                       "resourceType": {
                         "type": "string"
                       },
                       "resourceIds": {
                         "type": "array",
                         "items": {
                           "type": "string"
                         }
                       },
                       "reason": {
                         "type": "string"
                       },
                       "requestor": {
                         "type": "string"
                       }
                     },
                     "required": [
                       "requestId",
                       "resourceType",
                       "resourceIds",
                       "reason",
                       "requestor"
                     ]
                   }
                 }
               }
             },
             "actions": {
               "ValidateRequest": {
                 "type": "Function",
                 "inputs": {
                   "function": {
                     "id": "[resourceId('Microsoft.Web/sites/functions', 'DestructionFunctions', 'ValidateDestructionRequest')]"
                   },
                   "body": "@triggerBody()"
                 },
                 "runAfter": {}
               },
               "CheckIfApprovalRequired": {
                 "type": "If",
                 "expression": "@body('ValidateRequest').requiresApproval",
                 "actions": {
                   "SendApprovalEmail": {
                     "type": "ApiConnection",
                     "inputs": {
                       "host": {
                         "connection": {
                           "name": "@parameters('$connections')['office365']['connectionId']"
                         }
                       },
                       "method": "post",
                       "body": {
                         "To": "@parameters('approverEmail')",
                         "Subject": "Data Destruction Approval Required: @{triggerBody().requestId}",
                         "Body": "<p>A data destruction request requires your approval:</p><p>Request ID: @{triggerBody().requestId}</p><p>Resource Type: @{triggerBody().resourceType}</p><p>Resources: @{join(triggerBody().resourceIds, ', ')}</p><p>Reason: @{triggerBody().reason}</p><p>Requestor: @{triggerBody().requestor}</p><p>Please approve or reject:</p><p><a href=\"@{body('ValidateRequest').approvalUrl}\">Approve</a> | <a href=\"@{body('ValidateRequest').rejectUrl}\">Reject</a></p>"
                       },
                       "path": "/v2/Mail"
                     },
                     "runAfter": {}
                   },
                   "WaitForApproval": {
                     "type": "ApiConnection",
                     "inputs": {
                       "host": {
                         "connection": {
                           "name": "@parameters('$connections')['http']['connectionId']"
                         }
                       },
                       "method": "get",
                       "uri": "@body('ValidateRequest').approvalStatusUrl",
                       "queries": {
                         "requestId": "@triggerBody().requestId"
                       }
                     },
                     "runAfter": {
                       "SendApprovalEmail": [
                         "Succeeded"
                       ]
                     }
                   },
                   "CheckApprovalStatus": {
                     "type": "If",
                     "expression": "@body('WaitForApproval').approved",
                     "actions": {},
                     "else": {
                       "actions": {
                         "TerminateRejected": {
                           "type": "Terminate",
                           "inputs": {
                             "runStatus": "Failed",
                             "runError": {
                               "code": "Rejected",
                               "message": "Destruction request was rejected by approver."
                             }
                           },
                           "runAfter": {}
                         }
                       }
                     },
                     "runAfter": {
                       "WaitForApproval": [
                         "Succeeded"
                       ]
                     }
                   }
                 },
                 "else": {
                   "actions": {}
                 },
                 "runAfter": {
                   "ValidateRequest": [
                     "Succeeded"
                   ]
                 }
               },
               "BackupData": {
                 "type": "Function",
                 "inputs": {
                   "function": {
                     "id": "[resourceId('Microsoft.Web/sites/functions', 'DestructionFunctions', 'BackupBeforeDestruction')]"
                   },
                   "body": {
                     "requestId": "@triggerBody().requestId",
                     "resourceType": "@triggerBody().resourceType",
                     "resourceIds": "@triggerBody().resourceIds"
                   }
                 },
                 "runAfter": {
                   "CheckIfApprovalRequired": [
                     "Succeeded"
                   ]
                 }
               },
               "DisableAccess": {
                 "type": "Function",
                 "inputs": {
                   "function": {
                     "id": "[resourceId('Microsoft.Web/sites/functions', 'DestructionFunctions', 'DisableDataAccess')]"
                   },
                   "body": {
                     "requestId": "@triggerBody().requestId",
                     "resourceType": "@triggerBody().resourceType",
                     "resourceIds":     -- First overwrite with random data
     SET @sql = CONCAT('UPDATE ', table_name, ' SET ');
     
     -- Get column information
     SET @sql_cols = (
       SELECT GROUP_CONCAT(
         CASE 
           WHEN DATA_TYPE IN ('varchar', 'char', 'text') THEN 
             CONCAT(COLUMN_NAME, ' = REPEAT(MD5(RAND()), ', 
                  CEILING(CHARACTER_MAXIMUM_LENGTH / 32), ')')
           WHEN DATA_TYPE IN ('int', 'bigint', 'smallint') THEN 
             CONCAT(COLUMN_NAME, ' = FLOOR(RAND() * 1000000)')
           WHEN DATA_TYPE = 'date' THEN 
             CONCAT(COLUMN_NAME, ' = DATE_ADD(''1970-01-01'', INTERVAL FLOOR(RAND() * 18250) DAY)')
           WHEN DATA_TYPE LIKE '%datetime%' THEN 
             CONCAT(COLUMN_NAME, ' = FROM_UNIXTIME(RAND() * 1000000000)')
           WHEN DATA_TYPE IN ('decimal', 'float', 'double') THEN 
             CONCAT(COLUMN_NAME, ' = RAND() * 10000')
           WHEN DATA_TYPE IN ('bit', 'boolean') THEN 
             CONCAT(COLUMN_NAME, ' = ROUND(RAND())')
           ELSE 
             CONCAT(COLUMN_NAME, ' = NULL')
         END
         SEPARATOR ', '
       )
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = table_name
       AND COLUMN_KEY != 'PRI'  -- Skip primary key columns
     );
     
     SET @full_sql = CONCAT(@sql, @sql_cols);
     PREPARE stmt FROM @full_sql;
     EXECUTE stmt;
     DEALLOCATE PREPARE stmt;
     
     -- Get row count
     SET @count_sql = CONCAT('SELECT COUNT(*) INTO @row_count FROM ', table_name);
     PREPARE stmt FROM @count_sql;
     EXECUTE stmt;
     DEALLOCATE PREPARE stmt;
     
     -- Repeat overwrite with zeros
     SET @sql_cols = (
       SELECT GROUP_CONCAT(
         CASE 
           WHEN DATA_TYPE IN ('varchar', 'char', 'text') THEN 
             CONCAT(COLUMN_NAME, ' = REPEAT(''0'', ', 
                  CASE WHEN CHARACTER_MAXIMUM_LENGTH IS NULL 
                       THEN 255 
                       ELSE CHARACTER_MAXIMUM_LENGTH END, ')')
           WHEN DATA_TYPE IN ('int', 'bigint', 'smallint') THEN 
             CONCAT(COLUMN_NAME, ' = 0')
           WHEN DATA_TYPE = 'date' THEN 
             CONCAT(COLUMN_NAME, ' = ''1970-01-01''')
           WHEN DATA_TYPE LIKE '%datetime%' THEN 
             CONCAT(COLUMN_NAME, ' = ''1970-01-01 00:00:00''')
           WHEN DATA_TYPE IN ('decimal', 'float', 'double') THEN 
             CONCAT(COLUMN_NAME, ' = 0')
           WHEN DATA_TYPE IN ('bit', 'boolean') THEN 
             CONCAT(COLUMN_NAME, ' = 0')
           ELSE 
             CONCAT(COLUMN_NAME, ' = NULL')
         END
         SEPARATOR ', '
       )
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = table_name
       AND COLUMN_KEY != 'PRI'  -- Skip primary key columns
     );
     
     SET @full_sql = CONCAT(@sql, @sql_cols);
     PREPARE stmt FROM @full_sql;
     EXECUTE stmt;
     DEALLOCATE PREPARE stmt;
     
     -- Delete all records
     SET @delete_sql = CONCAT('DELETE FROM ', table_name);
     PREPARE stmt FROM @delete_sql;
     EXECUTE stmt;
     DEALLOCATE PREPARE stmt;
     
     -- Finally drop the table
     SET @drop_sql = CONCAT('DROP TABLE ', table_name);
     PREPARE stmt FROM @drop_sql;
     EXECUTE stmt;
     DEALLOCATE PREPARE stmt;
     
     SELECT CONCAT('Securely deleted table ', table_name, ' with ', @row_count, ' rows') AS Result;
   END //
   DELIMITER ;
   ```

2. Execute the secure deletion for all tables:
   ```sql
   -- Get list of all tables and run secure deletion on each
   CREATE TEMPORARY TABLE tables_to_delete AS
   SELECT table_name 
   FROM information_schema.tables
   WHERE table_schema = DATABASE()
   AND table_type = 'BASE TABLE';
   
   -- Loop through tables
   DELIMITER //
   CREATE PROCEDURE delete_all_tables()
   BEGIN
     DECLARE done INT DEFAULT FALSE;
     DECLARE tbl_name VARCHAR(64);
     DECLARE cur CURSOR FOR SELECT table_name FROM tables_to_delete;
     DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
     
     OPEN cur;
     
     read_loop: LOOP
       FETCH cur INTO tbl_name;
       IF done THEN
         LEAVE read_loop;
       END IF;
       
       CALL secure_delete_table(tbl_name);
     END LOOP;
     
     CLOSE cur;
   END //
   DELIMITER ;
   
   -- Execute the procedure
   CALL delete_all_tables();
   
   -- Clean up
   DROP PROCEDURE delete_all_tables;
   DROP PROCEDURE secure_delete_table;
   DROP TEMPORARY TABLE tables_to_delete;
   ```

3. Azure SQL Database secure deletion:
   ```sql
   -- Example secure deletion stored procedure for Azure SQL
   CREATE PROCEDURE SecureDeleteTable
       @TableName NVARCHAR(128)
   AS
   BEGIN
       DECLARE @SQL NVARCHAR(MAX)
       DECLARE @ColumnList NVARCHAR(MAX) = ''
       DECLARE @RandomColumnList NVARCHAR(MAX) = ''
       DECLARE @ZeroColumnList NVARCHAR(MAX) = ''
       DECLARE @RowCount INT
       
       -- Get column information for updates
       SELECT @ColumnList = @ColumnList + ',' + QUOTENAME(c.name)
       FROM sys.columns c
       INNER JOIN sys.tables t ON c.object_id = t.object_id
       WHERE t.name = @TableName
       AND c.is_identity = 0  -- Skip identity columns
       
       -- Remove leading comma
       SET @ColumnList = STUFF(@ColumnList, 1, 1, '')
       
       -- Generate random data update statement
       SELECT @RandomColumnList = @RandomColumnList + ',' + 
           CASE 
               WHEN t.name LIKE '%char%' OR t.name LIKE 'nvarchar%' OR t.name LIKE 'varchar%' OR t.name LIKE '%text%'
                   THEN QUOTENAME(c.name) + ' = CONVERT(' + t.name + 
                        CASE WHEN c.max_length <> -1 
                             THEN '(' + CAST(c.max_length AS NVARCHAR) + ')' 
                             ELSE '(MAX)' END + 
                        ', CRYPT_GEN_RANDOM(' + 
                        CASE WHEN c.max_length <> -1 
                             THEN CAST(c.max_length AS NVARCHAR) 
                             ELSE '8000' END + '))'
               WHEN t.name LIKE '%int%' 
                   THEN QUOTENAME(c.name) + ' = ABS(CHECKSUM(NEWID()))'
               WHEN t.name LIKE '%date%' OR t.name LIKE '%time%'
                   THEN QUOTENAME(c.name) + ' = DATEADD(DAY, ABS(CHECKSUM(NEWID())) % 36500, ''1900-01-01'')'
               WHEN t.name LIKE '%decimal%' OR t.name LIKE '%numeric%' OR t.name LIKE 'float%' OR t.name = 'real'
                   THEN QUOTENAME(c.name) + ' = ABS(CHECKSUM(NEWID())) * 1.0 / ABS(CHECKSUM(NEWID()))'
               WHEN t.name = 'bit'
                   THEN QUOTENAME(c.name) + ' = CONVERT(BIT, ABS(CHECKSUM(NEWID())) % 2)'
               WHEN t.name IN ('binary', 'varbinary')
                   THEN QUOTENAME(c.name) + ' = CONVERT(' + t.name + 
                        CASE WHEN c.max_length <> -1 
                             THEN '(' + CAST(c.max_length AS NVARCHAR) + ')' 
                             ELSE '(MAX)' END + 
                        ', CRYPT_GEN_RANDOM(' + 
                        CASE WHEN c.max_length <> -1 
                             THEN CAST(c.max_length AS NVARCHAR) 
                             ELSE '8000' END + '))'
               ELSE QUOTENAME(c.name) + ' = NULL'
           END
       FROM sys.columns c
       INNER JOIN sys.tables t1 ON c.object_id = t1.object_id
       INNER JOIN sys.types t ON c.user_type_id = t.user_type_id
       WHERE t1.name = @TableName
       AND c.is_identity = 0  -- Skip identity columns
       
       -- Remove leading comma
       SET @RandomColumnList = STUFF(@RandomColumnList, 1, 1, '')
       
       -- Generate zero data update statement
       SELECT @ZeroColumnList = @ZeroColumnList + ',' + 
           CASE 
               WHEN t.name LIKE '%char%' OR t.name LIKE 'nvarchar%' OR t.name LIKE 'varchar%' OR t.name LIKE '%text%'
                   THEN QUOTENAME(c.name) + ' = CONVERT(' + t.name + 
                        CASE WHEN c.max_length <> -1 
                             THEN '(' + CAST(c.max_length AS NVARCHAR) + ')' 
                             ELSE '(MAX)' END + 
                        ', REPLICATE(''0'', ' + 
                        CASE WHEN c.max_length <> -1 
                             THEN CAST(c.max_length AS NVARCHAR) 
                             ELSE '8000' END + '))'
               WHEN t.name LIKE '%int%' 
                   THEN QUOTENAME(c.name) + ' = 0'
               WHEN t.name LIKE '%date%' OR t.name LIKE '%time%'
                   THEN QUOTENAME(c.name) + ' = ''1900-01-01'''
               WHEN t.name LIKE '%decimal%' OR t.name LIKE '%numeric%' OR t.name LIKE 'float%' OR t.name = 'real'
                   THEN QUOTENAME(c.name) + ' = 0'
               WHEN t.name = 'bit'
                   THEN QUOTENAME(c.name) + ' = 0'
               WHEN t.name IN ('binary', 'varbinary')
                   THEN QUOTENAME(c.name) + ' = CONVERT(' + t.name + 
                        CASE WHEN c.max_length <> -1 
                             THEN '(' + CAST(c.max_length AS NVARCHAR) + ')' 
                             ELSE '(MAX)' END + 
                        ', REPLICATE(CAST(0 AS BINARY(1)), ' + 
                        CASE WHEN c.max_length <> -1 
                             THEN CAST(c.max_length AS NVARCHAR) 
                             ELSE '8000' END + '))'
               ELSE QUOTENAME(c.name) + ' = NULL'
           END
       FROM sys.columns c
       INNER JOIN sys.tables t1 ON c.object_id = t1.object_id
       INNER JOIN sys.types t ON c.user_type_id = t.user_type_id
       WHERE t1.name = @TableName
       AND c.is_identity = 0  -- Skip identity columns
       
       -- Remove leading comma
       SET @ZeroColumnList = STUFF(@ZeroColumnList, 1, 1, '')
       
       -- Get row count
       SET @SQL = N'SELECT @RowCount = COUNT(*) FROM ' + QUOTENAME(@TableName)
       EXEC sp_executesql @SQL, N'@RowCount INT OUTPUT', @RowCount OUTPUT
       
       BEGIN TRY
           BEGIN TRANSACTION
           
           -- First overwrite with random data
           IF @RandomColumnList <> ''
           BEGIN
               SET @SQL = N'UPDATE ' + QUOTENAME(@TableName) + 
                          N' SET ' + @RandomColumnList
               EXEC sp_executesql @SQL
           END
           
           -- Then overwrite with zeros
           IF @ZeroColumnList <> ''
           BEGIN
               SET @SQL = N'UPDATE ' + QUOTENAME(@TableName) + 
                          N' SET ' + @ZeroColumnList
               EXEC sp_executesql @SQL
           END
           
           -- Delete all records
           SET @SQL = N'DELETE FROM ' + QUOTENAME(@TableName)
           EXEC sp_executesql @SQL
           
           -- Drop the table
           SET @SQL = N'DROP TABLE ' + QUOTENAME(@TableName)
           EXEC sp_executesql @SQL
           
           COMMIT TRANSACTION
           
           SELECT 'Securely deleted table ' + @TableName + ' with ' + 
                  CAST(@RowCount AS NVARCHAR(20)) + ' rows' AS Result
       END TRY
       BEGIN CATCH
           IF @@TRANCOUNT > 0
               ROLLBACK TRANSACTION
               
           DECLARE @ErrorMessage NVARCHAR(4000) = ERROR_MESSAGE()
           DECLARE @ErrorSeverity INT = ERROR_SEVERITY()
           DECLARE @ErrorState INT = ERROR_STATE()
           
           RAISERROR(@ErrorMessage, @ErrorSeverity, @ErrorState)
       END CATCH
   END
   GO
   
   -- Execute for all tables
   CREATE PROCEDURE SecureDeleteAllTables
   AS
   BEGIN
       DECLARE @TableName NVARCHAR(128)
       DECLARE @SQL NVARCHAR(MAX)
       
       -- Create a temporary table to hold table names
       CREATE TABLE #TablesToDelete (TableName NVARCHAR(128))
       
       -- Get list of all tables
       INSERT INTO #TablesToDelete (TableName)
       SELECT name FROM sys.tables
       WHERE is_ms_shipped = 0  -- Exclude system tables
       
       -- Process each table
       WHILE EXISTS (SELECT 1 FROM #TablesToDelete)
       BEGIN
           SELECT TOP 1 @TableName = TableName FROM #TablesToDelete
           
           EXEC SecureDeleteTable @TableName
           
           DELETE FROM #TablesToDelete WHERE TableName = @TableName
       END
       
       -- Clean up
       DROP TABLE #TablesToDelete
   END
   GO
   
   -- Execute the procedure
   EXEC SecureDeleteAllTables
   GO
   
   -- Clean up
   DROP PROCEDURE SecureDeleteAllTables
   DROP PROCEDURE SecureDeleteTable
   GO
   ```

#### 4.2 AWS DynamoDB Secure Deletion

1. Create secure item overwriting function:
   ```javascript
   // Node.js script for securely overwriting DynamoDB items before deletion
   const AWS = require('aws-sdk');
   const crypto = require('crypto');
   const dynamodb = new AWS.DynamoDB();
   const docClient = new AWS.DynamoDB.DocumentClient();
   
   async function secureDeleteTable(tableName) {
     // Get table description to understand the schema
     const tableInfo = await dynamodb.describeTable({ TableName: tableName }).promise();
     const keySchema = tableInfo.Table.KeySchema;
     const primaryKey = keySchema.find(k => k.KeyType === 'HASH').AttributeName;
     const sortKey = keySchema.find(k => k.KeyType === 'RANGE')?.AttributeName;
     
     // Get attribute definitions to understand types
     const attrDefinitions = tableInfo.Table.AttributeDefinitions;
     const primaryKeyType = attrDefinitions.find(a => a.AttributeName === primaryKey).AttributeType;
     const sortKeyType = sortKey ? 
       attrDefinitions.find(a => a.AttributeName === sortKey)?.AttributeType : null;
     
     console.log(`Table: ${tableName}, PK: ${primaryKey}(${primaryKeyType}), SK: ${sortKey || 'none'}(${sortKeyType || 'n/a'})`);
     
     // Scan all items in the table
     let scanParams = { TableName: tableName };
     let itemCount = 0;
     let totalItems = 0;
     
     do {
       const scanResult = await docClient.scan(scanParams).promise();
       totalItems += scanResult.Items.length;
       
       // Process items in batches
       for (const item of scanResult.Items) {
         // Create key for this item
         const key = {};
         key[primaryKey] = item[primaryKey];
         if (sortKey) key[sortKey] = item[sortKey];
         
         // Get all attribute names from this item
         const attributeNames = Object.keys(item);
         
         // First overwrite - random data
         const randomItem = {};
         attributeNames.forEach(attr => {
           if (attr === primaryKey || attr === sortKey) {
             // Keep keys unchanged
             randomItem[attr] = item[attr];
           } else if (typeof item[attr] === 'string') {
             // Random string of same length
             randomItem[attr] = crypto.randomBytes(item[attr].length).toString('hex').substring(0, item[attr].length);
           } else if (typeof item[attr] === 'number') {
             // Random number
             randomItem[attr] = Math.floor(Math.random() * 1000000);
           } else if (typeof item[attr] === 'boolean') {
             // Random boolean
             randomItem[attr] = Math.random() >= 0.5;
           } else if (Buffer.isBuffer(item[attr])) {
             // Random buffer of same length
             randomItem[attr] = crypto.randomBytes(item[attr].length);
           } else if (Array.isArray(item[attr])) {
             // Random array of same length
             randomItem[attr] = Array(item[attr].length).fill().map(() => crypto.randomBytes(8).toString('hex'));
           } else if (typeof item[attr] === 'object' && item[attr] !== null) {
             // Random object with same structure
             randomItem[attr] = {};
             Object.keys(item[attr]).forEach(key => {
               randomItem[attr][key] = crypto.randomBytes(8).toString('hex');
             });
           }
         });
         
         // Update with random data
         await docClient.put({
           TableName: tableName,
           Item: randomItem
         }).promise();
         
         // Second overwrite - zeros/nulls
         const zeroItem = {};
         attributeNames.forEach(attr => {
           if (attr === primaryKey || attr === sortKey) {
             // Keep keys unchanged
             zeroItem[attr] = item[attr];
           } else if (typeof item[attr] === 'string') {
             // Zero string
             zeroItem[attr] = '0'.repeat(item[attr].length);
           } else if (typeof item[attr] === 'number') {
             // Zero
             zeroItem[attr] = 0;
           } else if (typeof item[attr] === 'boolean') {
             // False
             zeroItem[attr] = false;
           } else if (Buffer.isBuffer(item[attr])) {
             // Zero buffer
             zeroItem[attr] = Buffer.alloc(item[attr].length, 0);
           } else if (Array.isArray(item[attr])) {
             // Zero array
             zeroItem[attr] = Array(item[attr].length).fill('0');
           } else if (typeof item[attr] === 'object' && item[attr] !== null) {
             // Zero object
             zeroItem[attr] = {};
             Object.keys(item[attr]).forEach(key => {
               zeroItem[attr][key] = '0';
             });
           }
         });
         
         // Update with zero data
         await docClient.put({
           TableName: tableName,
           Item: zeroItem
         }).promise();
         
         // Finally delete the item
         await docClient.delete({
           TableName: tableName,
           Key: key
         }).promise();
         
         itemCount++;
         if (itemCount % 100 === 0) {
           console.log(`Processed ${itemCount} items...`);
         }
       }
       
       // Continue scanning if we have more items
       scanParams.ExclusiveStartKey = scanResult.LastEvaluatedKey;
     } while (scanParams.ExclusiveStartKey);
     
     console.log(`Securely deleted ${itemCount} items from table ${tableName}`);
     
     // Delete the table itself
     await dynamodb.deleteTable({ TableName: tableName }).promise();
     console.log(`Deleted table ${tableName}`);
     
     return { tableName, itemsDeleted: itemCount };
   }
   
   async function secureDeleteAllTables() {
     // List all tables
     const tables = await dynamodb.listTables({}).promise();
     console.log(`Found ${tables.TableNames.length} tables`);
     
     // Process each table
     for (const tableName of tables.TableNames) {
       try {
         console.log(`Starting secure deletion of table: ${tableName}`);
         const result = await secureDeleteTable(tableName);
         console.log(`Completed: ${result.itemsDeleted} items deleted from ${result.tableName}`);
       } catch (error) {
         console.error(`Error processing table ${tableName}: ${error.message}`);
       }
     }
   }
   
   // Execute
   secureDeleteAllTables().catch(err => console.error('Error:', err));
   ```

2. Azure Cosmos DB secure deletion:
   ```javascript
   // Node.js script for securely overwriting Cosmos DB items
   const { CosmosClient } = require('@azure/cosmos');
   const crypto = require('crypto');
   
   // Setup
   const endpoint = process.env.COSMOS_ENDPOINT;
   const key = process.env.COSMOS_KEY;
   const client = new CosmosClient({ endpoint, key });
   
   async function secureDeleteContainer(databaseId, containerId) {
     const database = client.database(databaseId);
     const container = database.container(containerId);
     
     // Get container metadata
     const containerInfo = await container.read();
     console.log(`Container: ${containerId}, Partition Key: ${containerInfo.resource.partitionKey.paths[0]}`);
     const partitionKeyPath = containerInfo.resource.partitionKey.paths[0].replace('/', '');
     
     // Query all items
     const querySpec = {
       query: "SELECT * FROM c"
     };
     
     const { resources: items } = await container.items.query(querySpec).fetchAll();
     console.log(`Found ${items.length} items in container ${containerId}`);
     
     let itemCount = 0;
     
     // Process each item
     for (const item of items) {
       const id = item.id;
       const partitionKey = item[partitionKeyPath];
       
       // Create overwrite item structure
       const attributeNames = Object.keys(item);
       
       // First overwrite - random data
       const randomItem = { id };
       attributeNames.forEach(attr => {
         if (attr === 'id' || attr === partitionKeyPath || attr === '_rid' || 
             attr === '_self' || attr === '_etag' || attr === '_attachments' || 
             attr === '_ts') {
           // Keep system properties and key fields unchanged
           randomItem[attr] = item[attr];
         } else if (typeof item[attr] === 'string') {
           randomItem[attr] = crypto.randomBytes(item[attr].length).toString('hex').substring(0, item[attr].length);
         } else if (typeof item[attr] === 'number') {
           randomItem[attr] = Math.floor(Math.random() * 1000000);
         } else if (typeof item[attr] === 'boolean') {
           randomItem[attr] = Math.random() >= 0.5;
         } else if (Array.isArray(item[attr])) {
           randomItem[attr] = Array(item[attr].length).fill().map(() => crypto.randomBytes(8).toString('hex'));
         } else if (typeof item[attr] === 'object' && item[attr] !== null) {
           randomItem[attr] = {};
           Object.keys(item[attr]).forEach(key => {
             randomItem[attr][key] = crypto.randomBytes(8).toString('hex');
           });
         }
       });
       
       // Update with random data
       await container.item(id, partitionKey).replace(randomItem);
       
       // Second overwrite - zeros/nulls
       const zeroItem = { id };
       attributeNames.forEach(attr => {
         if (attr === 'id' || attr === partitionKeyPath || attr === '_rid' || 
             attr === '_self' || attr === '_etag' || attr === '_attachments' || 
             attr === '_ts') {
           // Keep system properties and key fields unchanged
           zeroItem[attr] = item[attr];
         } else if (typeof item[attr] === 'string') {
           zeroItem[attr] = '0'.repeat(item[attr].length);
         } else if (typeof item[attr] === 'number') {
           zeroItem[attr] = 0;
         } else if (typeof item[attr] === 'boolean') {
           zeroItem[attr] = false;
         } else if (Array.isArray(item[attr])) {
           zeroItem[attr] = Array(item[attr].length).fill('0');
         } else if (typeof item[attr] === 'object' && item[attr] !== null) {
           zeroItem[attr] = {};
           Object.keys(item[attr]).forEach(key => {
             zeroItem[attr][key] = '0';
           });
         }
       });
       
       // Update with zero data
       await container.item(id, partitionKey).replace(zeroItem);
       
       // Finally delete the item
       await container.item(id, partitionKey).delete();
       
       itemCount++;
       if (itemCount % 100 === 0) {
         console.log(`Processed ${itemCount} items...`);
       }
     }
     
     console.log(`Securely deleted ${itemCount} items from container ${containerId}`);
     
     // Delete the container itself
     await container.delete();
     console.log(`Deleted container ${containerId}`);
     
     return { containerId, itemsDeleted: itemCount };
   }
   
   async function secureDeleteDatabase(databaseId) {
     const database = client.database(databaseId);
     
     // Get all containers
     const { resources: containers } = await database.containers.readAll().fetchAll();
     console.log(`Found ${containers.length} containers in database ${databaseId}`);
     
     // Process each container
     for (const container of containers) {
       try {
         console.log(`Starting secure deletion of container: ${container.id}`);
         const result = await secureDeleteContainer(databaseId, container.id);
         console.log(`Completed: ${result.itemsDeleted} items deleted from ${result.containerId}`);
       } catch (error) {
         console.error(`Error processing container ${container.id}: ${error.message}`);
       }
     }
     
     // Delete the database itself
     await database.delete();
     console.log(`Deleted database ${databaseId}`);
     
     return { databaseId, containersDeleted: containers.length };
   }
   
   async function secureDeleteAllDatabases() {
     // Get all databases
     const { resources: databases } = await client.databases.readAll().fetchAll();
     console.log(`Found ${databases.length} databases`);
     
     // Process each database
     for (const database of databases) {
       try {
         console.log(`Starting secure deletion of database: ${database.id}`);
         const result = await secureDeleteDatabase(database.id);
         console.log(`Completed: ${result.containersDeleted} containers deleted from ${result.databaseId}`);
       } catch (error) {
         console.error(`Error processing database ${database.id}: ${error.message}`);
       }
     }
   }
   
   // Execute
   secureDeleteAllDatabases().catch(err => console.error('Error:', err));
   ```

### Section 5: Specialized Service Destruction

#### 5.1 AWS Lambda Function and Layer Destruction

1. List Lambda functions and dependencies:
   ```bash
   # List all Lambda functions
   aws lambda list-functions --query "Functions[*].{Name:FunctionName,Runtime:Runtime,Role:Role}" --output table
   
   # Check for event source mappings
   for func in $(aws lambda list-functions --query "Functions[*].FunctionName" --output text); do
     echo "Function: $func"
     aws lambda list-event-source-mappings --function-name $func --query "EventSourceMappings[*].{UUID:UUID,Source:EventSourceArn,State:State}" --output table
   done
   
   # Check for environment variables
   for func in $(aws lambda list-functions --query "Functions[*].FunctionName" --output text); do
     echo "Function: $func"
     aws lambda get-function-configuration --function-name $func --query "Environment.Variables" --output json
   done
   
   # List all Lambda layers
   aws lambda list-layers --query "Layers[*].{Name:LayerName,Runtimes:LatestMatchingVersion.CompatibleRuntimes}" --output table
   ```

2. Remove event source mappings:
   ```bash
   # Remove event source mappings for each function
   for func in $(aws lambda list-functions --query "Functions[*].FunctionName" --output text); do
     for mapping in $(aws lambda list-event-source-mappings --function-name $func --query "EventSourceMappings[*].UUID" --output text); do
       echo "Deleting event source mapping: $mapping for function: $func"
       aws lambda delete-event-source-mapping --uuid $mapping
     done
   done
   ```

3. Securely delete function code and environment variables:
   ```bash
   # Create dummy empty function
   cat > empty-function.zip << EOF
   UEsDBBQAAAAIAG11jVbGTKRbHAAAABsAAAAJAAAAaW5kZXguanNLyvNLzygtyszPK9ZRUEopL8osUCgtS80pTtVRUCrOzM9TL0pNLVZwSixO9XDx8vP0UVBKzi/NK0ktAgBQSwECFAAUAAAACABtdY1WxkykWxwAAAAbAAAACQAAAAAAAAAAAAAAAAAAAAAAaW5kZXguanNQSwUGAAAAAAEAAQA3AAAAQwAAAAAA
   EOF
   
   # Update each function with empty code and no environment variables
   for func in $(aws lambda list-functions --query "Functions[*].FunctionName" --output text); do
     echo "Securely wiping function: $func"
     # Update code
     aws lambda update-function-code --function-name   # Get S3 deletion events
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObject \
     --start-time "$START_TIME" \
     --end-time "$END_TIME" \
     > s3_delete_events.json
   
   # Get EBS volume deletion events
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteVolume \
     --start-time "$START_TIME" \
     --end-time "$END_TIME" \
     > ebs_delete_events.json
   
   # Get RDS deletion events
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteDBInstance \
     --start-time "$START_TIME" \
     --end-time "$END_TIME" \
     > rds_delete_events.json
   
   # Get DynamoDB deletion events
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteTable \
     --start-time "$START_TIME" \
     --end-time "$END_TIME" \
     > dynamodb_delete_events.json
   
   # Generate summary report
   echo "AWS Deletion Audit Report: $(date)" > audit_summary.txt
   echo "Time Range: $START_TIME to $END_TIME" >> audit_summary.txt
   echo "-----------------------------------------" >> audit_summary.txt
   echo "S3 Object Deletions: $(jq '.Events | length' s3_delete_events.json)" >> audit_summary.txt
   echo "EBS Volume Deletions: $(jq '.Events | length' ebs_delete_events.json)" >> audit_summary.txt
   echo "RDS Instance Deletions: $(jq '.Events | length' rds_delete_events.json)" >> audit_summary.txt
   echo "DynamoDB Table Deletions: $(jq '.Events | length' dynamodb_delete_events.json)" >> audit_summary.txt
   
   # Create detailed CSV report
   echo "Timestamp,EventName,Username,ResourceType,ResourceName" > deletion_events.csv
   jq -r '.Events[] | [.EventTime, .EventName, .Username, .Resources[0].ResourceType, .Resources[0].ResourceName] | @csv' s3_delete_events.json >> deletion_events.csv
   jq -r '.Events[] | [.EventTime, .EventName, .Username, .Resources[0].ResourceType, .Resources[0].ResourceName] | @csv' ebs_delete_events.json >> deletion_events.csv
   jq -r '.Events[] | [.EventTime, .EventName, .Username, .Resources[0].ResourceType, .Resources[0].ResourceName] | @csv' rds_delete_events.json >> deletion_events.csv
   jq -r '.Events[] | [.EventTime, .EventName, .Username, .Resources[0].ResourceType, .Resources[0].ResourceName] | @csv' dynamodb_delete_events.json >> deletion_events.csv
   
   echo "Audit reports generated in $(pwd)"
   ```

2. Azure Activity Log Audit:
   ```bash
   # Create a temporary directory for audit files
   mkdir -p azure_audit/$(date +%Y%m%d)
   cd azure_audit/$(date +%Y%m%d)
   
   # Set time range for audit
   START_TIME=$(date -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)
   END_TIME=$(date +%Y-%m-%dT%H:%M:%SZ)
   
   # Get storage deletion events
   az monitor activity-log list \
     --start-time $START_TIME \
     --end-time $END_TIME \
     --filters "resourceProvider eq 'Microsoft.Storage'" \
     --query "[?contains(operationName.value, 'delete')].{Timestamp:eventTimestamp, Operation:operationName.value, Resource:resourceId, Caller:caller, Status:status.value}" \
     > storage_delete_events.json
   
   # Get compute deletion events
   az monitor activity-log list \
     --start-time $START_TIME \
     --end-time $END_TIME \
     --filters "resourceProvider eq 'Microsoft.Compute'" \
     --query "[?contains(operationName.value, 'delete')].{Timestamp:eventTimestamp, Operation:operationName.value, Resource:resourceId, Caller:caller, Status:status.value}" \
     > compute_delete_events.json
   
   # Get SQL deletion events
   az monitor activity-log list \
     --start-time $START_TIME \
     --end-time $END_TIME \
     --filters "resourceProvider eq 'Microsoft.Sql'" \
     --query "[?contains(operationName.value, 'delete')].{Timestamp:eventTimestamp, Operation:operationName.value, Resource:resourceId, Caller:caller, Status:status.value}" \
     > sql_delete_events.json
   
   # Get CosmosDB deletion events
   az monitor activity-log list \
     --start-time $START_TIME \
     --end-time $END_TIME \
     --filters "resourceProvider eq 'Microsoft.DocumentDB'" \
     --query "[?contains(operationName.value, 'delete')].{Timestamp:eventTimestamp, Operation:operationName.value, Resource:resourceId, Caller:caller, Status:status.value}" \
     > cosmosdb_delete_events.json
   
   # Generate summary report
   echo "Azure Deletion Audit Report: $(date)" > azure_audit_summary.txt
   echo "Time Range: $START_TIME to $END_TIME" >> azure_audit_summary.txt
   echo "-----------------------------------------" >> azure_audit_summary.txt
   echo "Storage Resource Deletions: $(jq '. | length' storage_delete_events.json)" >> azure_audit_summary.txt
   echo "Compute Resource Deletions: $(jq '. | length' compute_delete_events.json)" >> azure_audit_summary.txt
   echo "SQL Resource Deletions: $(jq '. | length' sql_delete_events.json)" >> azure_audit_summary.txt
   echo "CosmosDB Resource Deletions: $(jq '. | length' cosmosdb_delete_events.json)" >> azure_audit_summary.txt
   
   # Create detailed CSV report
   echo "Timestamp,Operation,Resource,Caller,Status" > azure_deletion_events.csv
   jq -r '.[] | [.Timestamp, .Operation, .Resource, .Caller, .Status] | @csv' storage_delete_events.json >> azure_deletion_events.csv
   jq -r '.[] | [.Timestamp, .Operation, .Resource, .Caller, .Status] | @csv' compute_delete_events.json >> azure_deletion_events.csv
   jq -r '.[] | [.Timestamp, .Operation, .Resource, .Caller, .Status] | @csv' sql_delete_events.json >> azure_deletion_events.csv
   jq -r '.[] | [.Timestamp, .Operation, .Resource, .Caller, .Status] | @csv' cosmosdb_delete_events.json >> azure_deletion_events.csv
   
   echo "Azure audit reports generated in $(pwd)"
   ```

3. Two-person verification checklist:
   ```
   DATA DESTRUCTION VERIFICATION CHECKLIST
   --------------------------------------
   
   Project: [Project Name]
   Date: [Current Date]
   Primary Verifier: [Name and Role]
   Secondary Verifier: [Name and Role]
   
   AWS Resources:
   [ ] S3 Buckets
     - Names: [List of bucket names]
     - Command used: aws s3 ls | grep [bucket-prefix]
     - Result: [No results found/Error]
     - CloudTrail events verified: [Yes/No]
   
   [ ] EBS Volumes
     - IDs: [List of volume IDs]
     - Command used: aws ec2 describe-volumes --volume-ids [volume-id]
     - Result: [No results found/Error]
     - CloudTrail events verified: [Yes/No]
   
   [ ] RDS Instances
     - Names: [List of instance names]
     - Command used: aws rds describe-db-instances --db-instance-identifier [instance-name]
     - Result: [No results found/Error]
     - CloudTrail events verified: [Yes/No]
   
   Azure Resources:
   [ ] Storage Accounts
     - Names: [List of account names]
     - Command used: az storage account show --name [account-name]
     - Result: [No results found/Error]
     - Activity logs verified: [Yes/No]
   
   [ ] Managed Disks
     - Names: [List of disk names]
     - Command used: az disk show --name [disk-name] --resource-group [resource-group]
     - Result: [No results found/Error]
     - Activity logs verified: [Yes/No]
   
   [ ] SQL Databases
     - Names: [List of database names]
     - Command used: az sql db show --name [db-name] --server [server-name] --resource-group [resource-group]
     - Result: [No results found/Error]
     - Activity logs verified: [Yes/No]
   
   Additional Checks:
   [ ] Access permissions revoked for all related resources
   [ ] Backup systems checked for residual data
   [ ] Dependent resources verified as deleted or updated
   [ ] Third-party systems notified of deletion as needed
   
   Exceptions and Issues:
   [Document any resources that could not be verified as deleted, any errors encountered, or any other issues]
   
   Certification:
   We certify that we have performed the verification steps above and confirm the successful destruction of the specified data and resources according to the organization's data destruction policy and applicable regulations.
   
   Primary Verifier Signature: ________________________ Date: ________
   
   Secondary Verifier Signature: ______________________ Date: ________
   ```

#### 1.4 Perform Data Discovery

1. AWS Macie for sensitive data discovery:
   ```bash
   # Create a Macie session
   aws macie2 enable-macie
   
   # Create a custom data identifier for any specific patterns
   aws macie2 create-custom-data-identifier \
     --name "Post-Deletion-Verification" \
     --regex "[Your-Specific-Pattern]" \
     --description "Pattern to verify complete data deletion"
   
   # Create and start a classification job
   aws macie2 create-classification-job \
     --job-type ONE_TIME \
     --name "Post-Deletion-Verification-$(date +%Y%m%d)" \
     --s3-job-definition "{\
       \"bucketDefinitions\": [\
         {\
           \"accountId\": \"$(aws sts get-caller-identity --query Account --output text)\",\
           \"buckets\": [\"bucket1\", \"bucket2\"]\
         }\
       ]\
     }" \
     --description "Verification scan after data destruction"
   ```

2. Azure Purview for data discovery:
   ```bash
   # List data sources in Purview
   az purview scan-datasource list \
     --account-name <purview-account-name> \
     --collection-name <collection-name>
   
   # Create a scan for verification
   az purview scan create-scan \
     --account-name <purview-account-name> \
     --collection-name <collection-name> \
     --data-source-name <data-source-name> \
     --scan-name "Post-Deletion-Verification-$(date +%Y%m%d)" \
     --kind AzureStorageAccount \
     --credential ... \
     --scope ... \
     --schedule-recurrence-type Once
   
   # Trigger the scan
   az purview scan run-scan \
     --account-name <purview-account-name> \
     --collection-name <collection-name> \
     --data-source-name <data-source-name> \
     --scan-name "Post-Deletion-Verification-$(date +%Y%m%d)"
   ```

3. Manual verification using CLI tools:
   ```bash
   # AWS S3 recursive ls
   aws s3 ls s3://<bucket-name>/ --recursive
   
   # AWS RDS snapshot check
   aws rds describe-db-snapshots \
     --query "DBSnapshots[?DBInstanceIdentifier=='<db-instance-name>']"
   
   # Azure blob storage check
   az storage blob list \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --output table \
     --auth-mode login
   
   # Azure SQL database restore check
   az sql db list-deleted \
     --resource-group <resource-group> \
     --server <server-name>
   ```

4. Document all findings:
   - Create a comprehensive report of any remaining data
   - Document reasons for exceptions
   - Plan remediation for any discovered data
   - Update destruction logs with findings

### Section 2: Legal and Compliance Holds

#### 2.1 Verify Legal Requirements

1. Legal hold verification checklist:
   ```
   LEGAL HOLD VERIFICATION CHECKLIST
   ---------------------------------
   
   Project: [Project Name]
   Date: [Current Date]
   Legal Representative: [Name and Role]
   
   1. Legal Hold Status Check:
      [ ] Reviewed active legal holds inventory
      [ ] Confirmed target data is NOT subject to any legal hold
      [ ] Obtained written confirmation from Legal Department
   
   2. Regulatory Compliance Check:
      [ ] Verified minimum retention periods for all data types
      [ ] Confirmed all retention periods have expired
      [ ] Identified applicable regulations:
          [ ] GDPR
          [ ] HIPAA
          [ ] PCI DSS
          [ ] SOX
          [ ] GLBA
          [ ] Other: _____________
      [ ] Verified destruction method complies with all regulations
   
   3. Contractual Obligations:
      [ ] Reviewed customer/vendor contracts related to the data
      [ ] Verified no contractual data retention requirements remain
      [ ] Obtained approval from contract management team
   
   4. Destruction Authorization:
      [ ] Destruction request reviewed and approved
      [ ] Appropriate management approval obtained
      [ ] Legal department approval obtained
      [ ] Compliance officer approval obtained
      [ ] Data owner approval obtained
   
   5. Documentation Requirements:
      [ ] Destruction certificate requirements identified
      [ ] Verification evidence requirements identified
      [ ] Audit trail requirements identified
      [ ] Records retention policy for destruction documentation identified
   
   Legal Department Approval:
   
   I certify that I have reviewed the legal and regulatory requirements applicable to the data proposed for destruction and confirm that:
   1. The data is not subject to any active legal hold
   2. All applicable retention periods have expired
   3. Destruction may proceed in accordance with the approved method
   
   Legal Representative Signature: ________________________ Date: ________
   
   Compliance Officer Signature: _________________________ Date: ________
   ```

2. Regulatory compliance matrix:
   ```
   DATA DESTRUCTION REGULATORY MATRIX
   ----------------------------------
   
   | Data Type | Regulation | Min. Retention | Destruction Method | Verification Required |
   |-----------|------------|----------------|-------------------|-----------------------|
   | PII       | GDPR       | Until purpose fulfilled | Secure deletion | Documentation required |
   | PHI       | HIPAA      | 6 years        | Cryptographic erasure | Destruction certificate |
   | Financial | SOX        | 7 years        | Secure deletion | Audit trail required |
   | Payment   | PCI DSS    | See policy     | Secure deletion | Quarterly validation |
   ```

3. Obtain legal approval template:
   ```
   LEGAL APPROVAL FOR DATA DESTRUCTION
   ----------------------------------
   
   I, [Legal Representative Name], in my capacity as [Title] at [Organization], 
   hereby authorize the destruction of the following data:
   
   Description: [Brief description of data]
   Classification: [Data classification level]
   Storage Location: [AWS/Azure details]
   Date Range: [Range of data to be destroyed]
   
   I confirm that:
   1. The data is not subject to any active litigation, investigation, or legal hold
   2. All applicable regulatory retention periods have expired
   3. All contractual obligations regarding this data have been fulfilled
   4. The proposed destruction method complies with all applicable regulations
   
   This approval is valid for 30 days from the date below.
   
   Signature: ________________________ Date: ________
   
   [Organization] Legal Department
   ```

#### 2.2 Implement Destruction Certificates

1. Generate detailed destruction certificate:
   ```
   CERTIFICATE OF DATA DESTRUCTION
   ------------------------------
   
   Certificate Number: [Unique ID]
   Date of Destruction: [Date]
   
   This is to certify that the following data has been permanently destroyed:
   
   Data Owner: [Department/Individual]
   Description of Data: [Detailed description]
   Classification Level: [Confidential/Restricted/Public]
   
   Data Location Details:
   - Cloud Service Provider(s): [AWS/Azure/Both]
   - Region(s): [List of regions]
   - Resource Types: [S3/EBS/RDS/Blob Storage/etc.]
   - Resource Identifiers: [List of specific resource IDs]
   
   Destruction Method:
   [ ] Logical deletion
   [ ] Secure overwrite (multiple passes)
   [ ] Cryptographic erasure
   [ ] Physical destruction (for hardware-based backups)
   
   Standards Compliance:
   [ ] NIST SP 800-88 Guidelines for Media Sanitization
   [ ] DoD 5220.22-M (3-pass overwrite)
   [ ] GDPR Article 17 (Right to erasure)
   [ ] HIPAA Security Rule
   [ ] PCI DSS Requirement 9.8 and 3.1
   [ ] Other: _____________
   
   Verification Method:
   [ ] System logs examination
   [ ] Cloud provider audit logs
   [ ] Data discovery scan using [tool]
   [ ] Two-person verification
   [ ] Third-party verification
   
   Destruction performed by:
   Name: [Name of primary person performing destruction]
   Title: [Job title]
   Signature: ________________________ Date: ________
   
   Witnessed/Verified by:
   Name: [Name of witness/verifier]
   Title: [Job title]
   Signature: ________________________ Date: ________
   
   Approved by:
   Name: [Name of approver]
   Title: [Job title - typically management or compliance officer]
   Signature: ________________________ Date: ________
   
   Attachments:
   [ ] System logs
   [ ] Cloud audit logs
   [ ] Verification screenshots
   [ ] Other evidence: _____________
   
   This certificate should be retained for a period of [retention period] years
   in accordance with [organization name]'s data destruction policy and applicable regulations.
   ```

2. Create destruction inventory log:
   ```
   DESTRUCTION INVENTORY LOG
   ------------------------
   
   Project: [Project Name]
   Period: [Start Date] to [End Date]
   
   | Item ID | Data Type | Resource ID | Cloud Service | Destruction Date | Certificate # | Verified By |
   |---------|-----------|-------------|--------------|------------------|--------------|------------|
   | 001     | Customer DB | rds-db-123 | AWS RDS      | 2023-06-15       | CERT-001     | J. Smith   |
   | 002     | Log Files   | bucket-xyz | AWS S3       | 2023-06-15       | CERT-002     | J. Smith   |
   | 003     | VM Disks    | disk-abc   | Azure        | 2023-06-16       | CERT-003     | A. Johnson |
   ```

3. Electronic destruction certificate system:
   - Implement a secure digital system for creating and storing certificates
   - Include digital signatures for all parties
   - Integrate with destruction workflow
   - Attach all evidence automatically
   - Apply retention policies automatically
   - Index for easy retrieval during audits

---

## Part 4: Advanced Techniques and Special Cases

### Section 1: Handling Encrypted Data

#### 1.1 Cryptographic Erasure

Cryptographic erasure involves destroying the encryption keys rather than the encrypted data itself, rendering the data unreadable.

1. Key management assessment:
   ```bash
   # For AWS KMS
   aws kms list-keys
   
   # For Azure Key Vault
   az keyvault key list --vault-name <keyvault-name>
   ```

2. Identify all services using the key:
   ```bash
   # AWS KMS key usage
   aws kms list-resource-tags --key-id <key-id>
   
   # AWS resources using the key (example for EBS)
   aws ec2 describe-volumes --filters "Name=encrypted,Values=true" \
     --query "Volumes[?KmsKeyId=='<key-arn>']"
   
   # Azure Key Vault key usage
   az keyvault key show --vault-name <keyvault-name> --name <key-name>
   ```

3. Document all systems dependent on the key:
   - Create a comprehensive inventory of all data encrypted with the key
   - Document business impact of key destruction
   - Ensure data is not needed before proceeding

4. For AWS KMS:
   ```bash
   # Disable the key
   aws kms disable-key --key-id <key-id>
   
   # Schedule key deletion (7-30 day waiting period)
   aws kms schedule-key-deletion --key-id <key-id> --pending-window-in-days 7
   
   # Monitor deletion status
   aws kms describe-key --key-id <key-id>
   ```

5. For Azure Key Vault:
   ```bash
   # Disable the key
   az keyvault key set-attributes --vault-name <keyvault-name> --name <key-name> --enabled false
   
   # Delete the key (soft delete)
   az keyvault key delete --vault-name <keyvault-name> --name <key-name>
   
   # If purge protection is not enabled, purge the key
   az keyvault key purge --vault-name <keyvault-name> --name <key-name>
   ```

6. Document the cryptographic erasure:
   - Create certificate specifically noting cryptographic erasure method
   - Document key identifiers and systems affected
   - Retain evidence of key destruction

#### 1.2 Handling Customer-Managed Keys (CMK)

1. AWS customer-managed keys:
   ```bash
   # Identify customer-managed keys
   aws kms list-keys --query "Keys[].KeyId" --output text | \
   while read key_id; do
     key_info=$(aws kms describe-key --key-id $key_id)
     key_manager=$(echo $key_info | jq -r '.KeyMetadata.KeyManager')
     if [ "$key_manager" == "CUSTOMER" ]; then
       echo "Customer-managed key: $key_id"
       echo $key_info | jq '.KeyMetadata'
     fi
   done
   ```

2. Azure customer-managed keys:
   ```bash
   # List all key vaults
   az keyvault list --query "[].name" --output tsv | \
   while read vault_name; do
     echo "Key Vault: $vault_name"
     # List keys in the vault
     az keyvault key list --vault-name $vault_name --query "[].{Name:name,Enabled:attributes.enabled}" --output table
   done
   ```

3. Coordinate with key custodians:
   - Identify key owners in the organization
   - Obtain approval for key destruction
   - Schedule key rotation if necessary before destruction
   - Document key custodian approval

4. Implement key destruction with proper oversight:
   - Require multiple approvals
   - Use split knowledge procedures if appropriate
   - Document each step with timestamps
   - Verify with key custodians after completion

### Section 2: Handling Replicated Data

#### 2.1 Cross-Region Replication

1. AWS S3 cross-region replication:
   ```bash
   # Check for cross-region replication
   aws s3api get-bucket-replication --bucket <bucket-name>
   
   # Disable replication
   aws s3api delete-bucket-replication --bucket <bucket-name>
   
   # List objects in destination bucket
   aws s3 ls s3://<destination-bucket>/ --recursive
   
   # Delete objects in destination bucket
   aws s3 rm s3://<destination-bucket>/ --recursive
   ```

2. Azure Storage replication:
   ```bash
   # Check account replication settings
   az storage account show \
     --name <storage-account-name> \
     --query "properties.secondaryLocation"
   
   # Modify to locally redundant storage
   az storage account update \
     --name <storage-account-name> \
     --resource-group <resource-group> \
     --sku Standard_LRS
   ```

3. AWS RDS read replicas:
   ```bash
   # List read replicas
   aws rds describe-db-instances \
     --query "DBInstances[?ReadReplicaSourceDBInstanceIdentifier!=null].{ReplicaID:DBInstanceIdentifier,Source:ReadReplicaSourceDBInstanceIdentifier}"
   
   # Delete each read replica
   aws rds delete-db-instance \
     --db-instance-identifier <replica-instance-id> \
     --skip-final-snapshot
   ```

4. Azure SQL Database geo-replication:
   ```bash
   # List geo-replicated databases
   az sql db replica list \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name>
   
   # Remove geo-replication link
   az sql db replica delete-link \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name> \
     --partner-server <partner-server-name> \
     --partner-database <partner-database-name>
   
   # Delete secondary database
   az sql db delete \
     --resource-group <secondary-resource-group> \
     --server <secondary-server-name> \
     --name <database-name> \
     --yes
   ```

#### 2.2 Cross-Account Replication

1. AWS cross-account S3 replication:
   ```bash
   # Identify any cross-account replication in source bucket
   aws s3api get-bucket-replication --bucket <source-bucket>
   
   # Use cross-account credentials to verify destination bucket
   # First assume role in destination account
   aws sts assume-role \
     --role-arn arn:aws:iam::<destination-account>:role/<cross-account-role> \
     --role-session-name DestructionVerification
   
   # Use temporary credentials to check destination bucket
   AWS_ACCESS_KEY_ID=<temp-access-key> \
   AWS_SECRET_ACCESS_KEY=<temp-secret-key> \
   AWS_SESSION_TOKEN=<temp-session-token> \
   aws s3 ls s3://<destination-bucket>/ --recursive
   
   # Delete data in destination bucket (with appropriate permissions)
   AWS_ACCESS_KEY_ID=<temp-access-key> \
   AWS_SECRET_ACCESS_KEY=<temp-secret-key> \
   AWS_SESSION_TOKEN=<temp-session-token> \
   aws s3 rm s3://<destination-bucket>/ --recursive
   ```

2. Azure cross-tenant replication:
   ```bash
   # Log in to the secondary tenant
   az login --tenant <secondary-tenant-id>
   
   # Check for replicated resources
   az storage account list --query "[].{Name:name,Location:location,ReplicationType:sku.name}"
   
   # Delete replicated data
   az storage blob delete-batch \
     --account-name <storage-account-name> \
     --source <container-name>
   
   # Switch back to primary tenant
   az login --tenant <primary-tenant-id>
   ```

3. Document all cross-account actions:
   - Create a separate certificate for cross-account data destruction
   - Document communication with other account owners
   - Verify destruction with account administrators
   - Include cross-account verification evidence

### Section 3: Handling Immutable Storage

#### 3.1 AWS S3 Object Lock

1. Check for Object Lock configuration:
   ```bash
   aws s3api get-object-lock-configuration --bucket <bucket-name>
   ```

2. List objects with retention periods:
   ```bash
   aws s3api list-objects-v2 --bucket <bucket-name> \
     --query "Contents[].{Key:Key}" --output text | \
   while read key; do
     retention=$(aws s3api get-object-retention --bucket <bucket-name> --key "$key" 2>/dev/null)
     if [ $? -eq 0 ]; then
       mode=$(echo $retention | jq -r '.Mode')
       until=$(echo $retention | jq -r '.RetainUntilDate')
       echo "Object: $key, Mode: $mode, RetainUntil: $until"
     fi
   done
   ```

3. Check for legal holds:
   ```bash
   aws s3api list-objects-v2 --bucket <bucket-name> \
     --query "Contents[].{Key:Key}" --output text | \
   while read key; do
     legal_hold=$(aws s3api get-object-legal-hold --bucket <bucket-name> --key "$key" 2>/dev/null)
     if [ $? -eq 0 ]; then
       status=$(echo $legal_hold | jq -r '.LegalHold.Status')
       echo "Object: $key, LegalHold: $status"
     fi
   done
   ```

4. Handle objects with legal holds:
   ```bash
   # Requires permissions and legal approval
   aws s3api put-object-legal-hold \
     --bucket <bucket-name> \
     --key <object-key> \
     --legal-hold Status=OFF
   ```

5. For governance mode retention:
   ```bash
   # Requires s3:BypassGovernanceRetention permission
   aws s3api delete-object \
     --bucket <bucket-name> \
     --key <object-key> \
     --bypass-governance-retention
   ```

6. For compliance mode retention:
   - Wait until retention period expires
   - Document objects that cannot be deleted due to retention periods
   - Schedule destruction for after retention period

#### 3.2 Azure Blob Immutable Storage

1. Check for immutability policies:
   ```bash
   az storage container immutability-policy show \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --auth-mode login
   ```

2. Check for legal holds:
   ```bash
   az storage container legal-hold show \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --tags "hold1,hold2" \
     --auth-mode login
   ```

3. Remove legal holds (requires permissions):
   ```bash
   az storage container legal-hold clear \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --tags "hold1,hold2" \
     --auth-mode login
   ```

4. For time-based retention:
   - Wait until retention period expires
   - Document containers that cannot be deleted due to policies
   - Schedule destruction for after retention period

5. For locked immutability policies:
   - Document that the data cannot be deleted until retention period expires
   - Include in exception report
   - Schedule follow-up for when retention period expires

### Section 4: Database Shredding

#### 4.1 AWS RDS Secure Deletion

1. Create a secure deletion stored procedure:
   ```sql
   -- Example secure deletion stored procedure for MySQL/MariaDB
   DELIMITER //
   CREATE PROCEDURE secure_delete_table(IN table_name VARCHAR(64))
   BEGIN
     DECLARE done INT DEFAULT FALSE;
     DECLARE i INT DEFAULT 0;
     DECLARE row_count INT;
     
     -- First overwrite with random data
     SET @sql = CONCAT('UPDATE ',# Comprehensive Data Destruction Guide: AWS and Microsoft Azure

## Introduction

This comprehensive guide provides detailed, step-by-step procedures for securely destroying data in Amazon Web Services (AWS) and Microsoft Azure environments. The procedures outlined here adhere to industry best practices and security standards to ensure complete and verifiable data destruction for compliance with regulations such as GDPR, HIPAA, PCI DSS, and organizational data protection policies.

---

## Part 1: AWS Data Destruction

### Section 1: AWS S3 Object and Bucket Destruction

#### 1.1 Understanding S3 Data Deletion Mechanics

Before initiating deletion procedures, understand how AWS S3 handles deletion:

- **Standard deletion**: Objects deleted through the console or API are not immediately removed and may be recoverable until permanent deletion occurs.
- **Versioning**: If enabled, deletion creates a delete marker rather than removing the object.
- **Multi-Factor Authentication (MFA) Delete**: Provides additional security for sensitive buckets.
- **Object Lock**: May prevent deletion until retention period expires.

#### 1.2 Preparing for S3 Data Destruction

1. **Inventory all S3 resources**:
   ```bash
   aws s3 ls
   ```

2. **Identify bucket versioning status**:
   ```bash
   aws s3api get-bucket-versioning --bucket bucket-name
   ```

3. **Check Object Lock configuration**:
   ```bash
   aws s3api get-object-lock-configuration --bucket bucket-name
   ```

4. **Identify cross-region replication**:
   ```bash
   aws s3api get-bucket-replication --bucket bucket-name
   ```

5. **Check lifecycle policies**:
   ```bash
   aws s3api get-bucket-lifecycle-configuration --bucket bucket-name
   ```

#### 1.3 Enable Versioning and Configure Lifecycle Policies

1. Sign in to the AWS Management Console
2. Navigate to Amazon S3
   - Click "Services" at the top of the screen
   - Under "Storage", select "S3"
3. Select the target bucket from the bucket list
4. Go to the "Properties" tab
   - Click on the "Properties" tab in the top navigation bar of the bucket detail page
5. Configure Versioning:
   - Scroll to the "Bucket Versioning" section
   - Click "Edit"
   - Select "Enable" radio button
   - Click "Save changes"
6. Configure lifecycle rules:
   - Navigate to the "Management" tab
   - Click "Create lifecycle rule"
   - Enter rule name (e.g., "Data-Destruction-Policy")
   - For scope, select:
     - "Apply to all objects in the bucket" OR
     - "Limit the scope to specific prefixes or tags" (then specify)
   - Expand "Lifecycle rule actions"
   - Check "Expire current versions of objects"
     - Set appropriate number of days (e.g., 1 day for immediate deletion)
   - Check "Delete expired delete markers or incomplete multipart uploads"
   - Check "Permanently delete noncurrent versions of objects"
     - Set appropriate number of days (e.g., 1 day for quick deletion)
   - Click "Create rule"
7. Verify the rule creation:
   - The new rule should appear in the lifecycle rules list
   - Status should show as "Enabled"

#### 1.4 Delete Individual Objects (Console Method)

1. Navigate to the target S3 bucket
   - Click on the bucket name in the S3 bucket list
2. Select objects to delete
   - Check the boxes next to the objects
   - For large numbers of objects, use the search functionality or filtering
3. Click "Delete" button in the top action bar
4. In the confirmation dialog:
   - Review the list of objects to be deleted
   - Type "permanently delete" in the confirmation field
   - Check "I acknowledge that this action will permanently delete the objects shown below."
5. Click "Delete objects" button
6. Monitor the deletion progress in the "Delete objects: status" dialog
7. Verify deletion by refreshing the object list

#### 1.5 Delete Individual Objects (AWS CLI Method)

1. For deleting a single object:
   ```bash
   aws s3 rm s3://bucket-name/path/to/object
   ```

2. For deleting multiple objects with a specific prefix:
   ```bash
   aws s3 rm s3://bucket-name/prefix/ --recursive
   ```

3. For deleting objects with a specific file extension:
   ```bash
   aws s3 rm s3://bucket-name --exclude "*" --include "*.txt" --recursive
   ```

4. For deleting all versions of objects (if versioning enabled):
   ```bash
   aws s3api list-object-versions --bucket bucket-name --prefix prefix/ | \
   jq -r '.Versions[] | .Key + " " + .VersionId' | \
   while read key version; do \
     aws s3api delete-object --bucket bucket-name --key "$key" --version-id "$version"; \
   done
   ```

5. For deleting delete markers (if versioning enabled):
   ```bash
   aws s3api list-object-versions --bucket bucket-name --prefix prefix/ | \
   jq -r '.DeleteMarkers[] | .Key + " " + .VersionId' | \
   while read key version; do \
     aws s3api delete-object --bucket bucket-name --key "$key" --version-id "$version"; \
   done
   ```

#### 1.6 Data Overwriting for Sensitive S3 Objects

For sensitive data, overwrite before deletion:

1. Create a zero-filled or random file locally:
   ```bash
   # Create 1MB file with zeros
   dd if=/dev/zero of=zeros.bin bs=1M count=1
   
   # Create 1MB file with random data
   dd if=/dev/urandom of=random.bin bs=1M count=1
   ```

2. Overwrite each sensitive object multiple times:
   ```bash
   # Overwrite with zeros (repeat 3 times for DoD-style wiping)
   for i in {1..3}; do
     aws s3 cp zeros.bin s3://bucket-name/path/to/sensitive-object
   done
   
   # Then delete
   aws s3 rm s3://bucket-name/path/to/sensitive-object
   ```

3. For automation with multiple objects, create a script:
   ```bash
   #!/bin/bash
   BUCKET="bucket-name"
   PREFIX="prefix/"
   
   # Create overwrite file
   dd if=/dev/urandom of=random.bin bs=1M count=1
   
   # Get all objects
   aws s3 ls s3://$BUCKET/$PREFIX --recursive | awk '{print $4}' > objects.txt
   
   # Overwrite each object 3 times
   while read object; do
     echo "Overwriting $object"
     for i in {1..3}; do
       aws s3 cp random.bin s3://$BUCKET/$object
     done
     # Delete the object
     aws s3 rm s3://$BUCKET/$object
   done < objects.txt
   ```

#### 1.7 Empty and Delete Bucket (Console Method)

1. Navigate to S3 in the AWS Management Console
2. Select the checkbox next to the bucket to delete
3. Click "Empty" button
4. In the confirmation dialog:
   - Type the bucket name to confirm
   - Check "I acknowledge that emptying this bucket will delete all objects and all object versions."
   - Click "Empty"
5. Wait for the emptying process to complete (this can take time for large buckets)
6. Once empty, select the bucket again
7. Click "Delete" button
8. In the confirmation dialog:
   - Type the bucket name to confirm
   - Click "Delete bucket"
9. Verify the bucket no longer appears in your bucket list

#### 1.8 Empty and Delete Bucket (AWS CLI Method)

1. Remove all objects and versions:
   ```bash
   # For non-versioned buckets
   aws s3 rm s3://bucket-name --recursive
   
   # For versioned buckets (more thorough)
   aws s3api delete-objects --bucket bucket-name \
     --delete "$(aws s3api list-object-versions \
                 --bucket bucket-name \
                 --output=json \
                 --query='{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"
   
   # Delete delete markers
   aws s3api delete-objects --bucket bucket-name \
     --delete "$(aws s3api list-object-versions \
                 --bucket bucket-name \
                 --output=json \
                 --query='{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}')"
   ```

2. Delete the bucket:
   ```bash
   aws s3api delete-bucket --bucket bucket-name
   ```

3. Verify bucket deletion:
   ```bash
   aws s3 ls | grep bucket-name
   ```

#### 1.9 Delete MFA-Protected Buckets

1. If MFA deletion is enabled, you need the MFA device serial number and current token:
   ```bash
   aws s3api delete-bucket --bucket bucket-name --mfa "arn:aws:iam::123456789012:mfa/user MFA-TOKEN"
   ```

2. To disable MFA Delete first (requires root or privileged IAM user):
   ```bash
   aws s3api put-bucket-versioning \
     --bucket bucket-name \
     --versioning-configuration Status=Suspended \
     --mfa "arn:aws:iam::123456789012:mfa/user MFA-TOKEN"
   ```

#### 1.10 S3 Data Destruction Verification

1. Verify bucket is no longer listed:
   ```bash
   aws s3 ls | grep bucket-name
   ```

2. Check CloudTrail logs for deletion events:
   ```bash
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObject \
     --start-time "2023-01-01T00:00:00Z" \
     --end-time "2023-01-02T00:00:00Z"
   ```

3. Document the deletion with timestamps, object counts, and verification method.

### Section 2: AWS EBS Volume Destruction

#### 2.1 Understanding EBS Volume Deletion

- Deleting an EBS volume permanently removes all data
- AWS performs block-level wiping before reallocating storage
- Volume must be detached from instances before deletion
- Snapshot dependencies should be considered
- Encrypted volumes provide additional security (cryptographic erasure)

#### 2.2 Preliminary Steps

1. Identify EBS volumes:
   ```bash
   aws ec2 describe-volumes --query "Volumes[*].{ID:VolumeId,State:State,Size:Size,Type:VolumeType,InstanceId:Attachments[0].InstanceId,Device:Attachments[0].Device}"
   ```

2. Identify volumes to be destroyed:
   ```bash
   # Volumes attached to a specific instance
   aws ec2 describe-volumes --filters "Name=attachment.instance-id,Values=i-1234567890abcdef0" --query "Volumes[*].{ID:VolumeId,Size:Size,Type:VolumeType,Device:Attachments[0].Device}"
   
   # Volumes with specific tag
   aws ec2 describe-volumes --filters "Name=tag:Environment,Values=Production" --query "Volumes[*].{ID:VolumeId,State:State,Size:Size}"
   ```

3. Check for snapshot dependencies:
   ```bash
   aws ec2 describe-snapshots --filters "Name=volume-id,Values=vol-1234567890abcdef0" --query "Snapshots[*].{ID:SnapshotId,StartTime:StartTime,Description:Description}"
   ```

#### 2.3 Create Snapshot (for backup if needed)

1. Go to EC2 dashboard in AWS Management Console
   - Click "Services" at the top
   - Under "Compute", select "EC2"
2. In the left navigation pane, click "Volumes" under "Elastic Block Store"
3. Select the target volume by clicking the checkbox next to it
4. Click "Actions" dropdown
5. Select "Create Snapshot"
6. In the "Create Snapshot" dialog:
   - Provide a descriptive name: "Final-Backup-[Volume-ID]-[Date]"
   - Add a detailed description including reason for backup, date, and volume details
   - Add tags (optional but recommended):
     - Key: "Purpose", Value: "Final Backup"
     - Key: "DeleteAfter", Value: "[retention date]"
   - Click "Create Snapshot"
7. Note the snapshot ID for future reference
8. Monitor snapshot creation progress:
   - Go to "Snapshots" in the left navigation pane
   - Find your snapshot in the list
   - Wait for "Status" to change from "pending" to "completed"

#### 2.4 Data Overwriting for Sensitive Volumes (Optional)

For volumes containing sensitive data:

1. Create a temporary EC2 instance:
   ```bash
   aws ec2 run-instances \
     --image-id ami-12345678 \
     --instance-type t3.micro \
     --key-name MyKeyPair \
     --security-group-ids sg-12345678 \
     --subnet-id subnet-12345678 \
     --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=DataWiper}]'
   ```

2. Attach the volume to wipe:
   ```bash
   aws ec2 attach-volume \
     --volume-id vol-1234567890abcdef0 \
     --instance-id i-1234567890abcdef0 \
     --device /dev/sdf
   ```

3. SSH into the instance and overwrite the volume:
   ```bash
   # Login to instance
   ssh -i MyKeyPair.pem ec2-user@instance-public-ip
   
   # Identify the attached volume
   lsblk
   
   # Overwrite with zeros (DoD 5220.22-M single pass)
   sudo dd if=/dev/zero of=/dev/nvme1n1 bs=1M status=progress
   
   # For more secure wiping (DoD 5220.22-M three-pass):
   # Pass 1: All zeros
   sudo dd if=/dev/zero of=/dev/nvme1n1 bs=1M status=progress
   
   # Pass 2: All ones
   sudo dd if=/dev/one of=/dev/nvme1n1 bs=1M status=progress
   # Note: Create /dev/one first: sudo sh -c 'tr "\000" "\377" < /dev/zero > /dev/one' &
   
   # Pass 3: Random data
   sudo dd if=/dev/urandom of=/dev/nvme1n1 bs=1M status=progress
   ```

4. Detach volume after wiping:
   ```bash
   aws ec2 detach-volume --volume-id vol-1234567890abcdef0
   ```

5. Terminate temporary instance:
   ```bash
   aws ec2 terminate-instances --instance-ids i-1234567890abcdef0
   ```

#### 2.5 Detach Volume

1. Using AWS Management Console:
   - Go to EC2 dashboard
   - Click "Volumes" in the left navigation pane
   - Select the volume to detach
   - Click "Actions" > "Detach Volume"
   - In the confirmation dialog, click "Yes, Detach"
   - Monitor "State" until it changes from "detaching" to "available"

2. Using AWS CLI:
   ```bash
   # Check if volume is attached
   aws ec2 describe-volumes --volume-ids vol-1234567890abcdef0 --query "Volumes[0].Attachments"
   
   # Force detach if necessary (use with caution)
   aws ec2 detach-volume --volume-id vol-1234567890abcdef0 --force
   
   # Standard detach
   aws ec2 detach-volume --volume-id vol-1234567890abcdef0
   
   # Verify detachment
   aws ec2 describe-volumes --volume-ids vol-1234567890abcdef0 --query "Volumes[0].State"
   ```

3. Wait until the volume state is "available" before proceeding:
   ```bash
   aws ec2 wait volume-available --volume-ids vol-1234567890abcdef0
   ```

#### 2.6 Delete Volume

1. Using AWS Management Console:
   - Ensure volume state is "available"
   - Select the volume
   - Click "Actions" > "Delete Volume"
   - In the confirmation dialog, click "Yes, Delete"
   - Monitor until the volume disappears from the volume list

2. Using AWS CLI:
   ```bash
   # Delete volume
   aws ec2 delete-volume --volume-id vol-1234567890abcdef0
   
   # Verify deletion
   aws ec2 describe-volumes --volume-ids vol-1234567890abcdef0
   # Should return an error indicating the volume does not exist
   ```

3. For batch deletion of multiple volumes:
   ```bash
   # Get all available volumes
   VOLUMES=$(aws ec2 describe-volumes --filters "Name=status,Values=available" --query "Volumes[*].VolumeId" --output text)
   
   # Delete each volume
   for vol in $VOLUMES; do
     echo "Deleting volume: $vol"
     aws ec2 delete-volume --volume-id $vol
   done
   ```

#### 2.7 Clean Snapshots

1. Using AWS Management Console:
   - Go to EC2 dashboard
   - Click "Snapshots" in the left navigation pane
   - Use filters to identify snapshots of the deleted volume
   - Select snapshots to delete
   - Click "Actions" > "Delete Snapshot"
   - In the confirmation dialog, click "Yes, Delete"

2. Using AWS CLI:
   ```bash
   # List snapshots for a specific volume
   aws ec2 describe-snapshots --filters "Name=volume-id,Values=vol-1234567890abcdef0" --query "Snapshots[*].SnapshotId"
   
   # Delete a specific snapshot
   aws ec2 delete-snapshot --snapshot-id snap-1234567890abcdef0
   
   # Delete all snapshots for a volume
   SNAPS=$(aws ec2 describe-snapshots --filters "Name=volume-id,Values=vol-1234567890abcdef0" --query "Snapshots[*].SnapshotId" --output text)
   for snap in $SNAPS; do
     echo "Deleting snapshot: $snap"
     aws ec2 delete-snapshot --snapshot-id $snap
   done
   ```

#### 2.8 EBS Data Destruction Verification

1. Verify volume no longer exists:
   ```bash
   aws ec2 describe-volumes --volume-ids vol-1234567890abcdef0
   # Should return an error
   ```

2. Check CloudTrail for deletion events:
   ```bash
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=ResourceName,AttributeValue=vol-1234567890abcdef0
   ```

3. Document the deletion with timestamps and verification method.

### Section 3: AWS RDS Database Destruction

#### 3.1 Understanding RDS Deletion Implications

- RDS deletion removes the database instance and, optionally, automated backups
- Final snapshots can be created for archival purposes
- Multi-AZ deployments are fully removed
- Parameter groups and option groups are not automatically deleted
- Custom subnet groups are not automatically deleted
- Deletion protection might prevent immediate deletion

#### 3.2 Preliminary RDS Assessment

1. Identify all RDS instances:
   ```bash
   aws rds describe-db-instances --query "DBInstances[*].{DBInstanceIdentifier:DBInstanceIdentifier,Engine:Engine,Status:DBInstanceStatus,MultiAZ:MultiAZ,DeletionProtection:DeletionProtection}"
   ```

2. Check for deletion protection:
   ```bash
   aws rds describe-db-instances --db-instance-identifier database-name --query "DBInstances[0].DeletionProtection"
   ```

3. Identify read replicas:
   ```bash
   aws rds describe-db-instances --query "DBInstances[?ReadReplicaSourceDBInstanceIdentifier!=null].{ReplicaID:DBInstanceIdentifier,Source:ReadReplicaSourceDBInstanceIdentifier}"
   ```

4. Check automated backup retention:
   ```bash
   aws rds describe-db-instances --db-instance-identifier database-name --query "DBInstances[0].BackupRetentionPeriod"
   ```

#### 3.3 Create Final Backup

1. Using AWS Management Console:
   - Go to RDS dashboard
   - Click "Databases" in the left navigation pane
   - Select the database instance
   - Click "Actions" > "Take snapshot"
   - Provide a snapshot identifier: "final-snapshot-[db-name]-[date]"
   - Add a description detailing the purpose of the snapshot
   - Click "Take Snapshot"
   - Monitor snapshot creation in the "Snapshots" section

2. Using AWS CLI:
   ```bash
   # Create manual snapshot
   aws rds create-db-snapshot \
     --db-instance-identifier database-name \
     --db-snapshot-identifier final-snapshot-database-name-20230101 \
     --tags Key=Purpose,Value=FinalBackup
   
   # Monitor snapshot creation
   aws rds describe-db-snapshots \
     --db-snapshot-identifier final-snapshot-database-name-20230101 \
     --query "DBSnapshots[0].Status"
   
   # Wait for snapshot to complete
   aws rds wait db-snapshot-available \
     --db-snapshot-identifier final-snapshot-database-name-20230101
   ```

#### 3.4 Export Database for Long-term Archival (Optional)

1. For critical data, export to S3:
   ```bash
   aws rds start-export-task \
     --export-task-identifier export-database-name-20230101 \
     --source-arn arn:aws:rds:region:account-id:snapshot:final-snapshot-database-name-20230101 \
     --s3-bucket-name export-bucket \
     --iam-role-arn arn:aws:iam::account-id:role/RDSExportRole \
     --kms-key-id arn:aws:kms:region:account-id:key/key-id
   ```

2. Monitor export progress:
   ```bash
   aws rds describe-export-tasks \
     --export-task-identifier export-database-name-20230101
   ```

#### 3.5 Remove Read Replicas First

Read replicas must be deleted before the source instance:

1. Identify all read replicas:
   ```bash
   aws rds describe-db-instances \
     --query "DBInstances[?ReadReplicaSourceDBInstanceIdentifier=='database-name'].DBInstanceIdentifier"
   ```

2. Delete each read replica:
   ```bash
   # Disable deletion protection if enabled
   aws rds modify-db-instance \
     --db-instance-identifier replica-name \
     --no-deletion-protection \
     --apply-immediately
   
   # Delete replica without final snapshot
   aws rds delete-db-instance \
     --db-instance-identifier replica-name \
     --skip-final-snapshot
   
   # Wait for deletion to complete
   aws rds wait db-instance-deleted \
     --db-instance-identifier replica-name
   ```

#### 3.6 Disable Deletion Protection

1. Using AWS Management Console:
   - Go to RDS dashboard
   - Select the database instance
   - Click "Modify"
   - Scroll to "Deletion protection"
   - Uncheck the "Enable deletion protection" checkbox
   - Under "Scheduling of modifications", select "Apply immediately"
   - Click "Continue" 
   - Review the changes
   - Click "Modify DB Instance"
   - Wait for the modification to complete

2. Using AWS CLI:
   ```bash
   # Disable deletion protection
   aws rds modify-db-instance \
     --db-instance-identifier database-name \
     --no-deletion-protection \
     --apply-immediately
   
   # Verify deletion protection is disabled
   aws rds describe-db-instances \
     --db-instance-identifier database-name \
     --query "DBInstances[0].DeletionProtection"
   
   # Wait for modification to complete
   aws rds wait db-instance-available \
     --db-instance-identifier database-name
   ```

#### 3.7 Delete Database Instance

1. Using AWS Management Console:
   - Go to RDS dashboard
   - Select the database instance
   - Click "Actions" > "Delete"
   - In the deletion dialog:
     - Choose whether to create a final snapshot
     - If creating a final snapshot, provide a snapshot name
     - Enter the database name to confirm deletion
     - Select "Delete automated backups" (if you want all backups removed)
     - Click "Delete"
   - Monitor the deletion process in the database list

2. Using AWS CLI:
   ```bash
   # Delete with final snapshot
   aws rds delete-db-instance \
     --db-instance-identifier database-name \
     --final-db-snapshot-identifier final-deletion-snapshot-database-name-20230101
   
   # Delete without final snapshot (complete removal)
   aws rds delete-db-instance \
     --db-instance-identifier database-name \
     --skip-final-snapshot
   ```

3. Wait for deletion to complete:
   ```bash
   aws rds wait db-instance-deleted \
     --db-instance-identifier database-name
   ```

#### 3.8 Delete Automated Backups

1. Using AWS Management Console:
   - Go to RDS dashboard
   - Click "Automated backups" in the left navigation pane
   - Click the "Retained" tab to see automated backups
   - Select backups associated with the deleted database
   - Click "Delete"
   - Confirm deletion

2. Using AWS CLI:
   ```bash
   # List retained automated backups
   aws rds describe-db-instance-automated-backups \
     --query "DBInstanceAutomatedBackups[?DBInstanceIdentifier=='database-name']"
   
   # Delete specific automated backups
   aws rds delete-db-instance-automated-backups \
     --dbi-resource-id dbinstance-resource-id
   ```

#### 3.9 Delete Parameter Groups and Option Groups (Optional)

1. Delete custom parameter groups:
   ```bash
   # List parameter groups
   aws rds describe-db-parameter-groups \
     --query "DBParameterGroups[?DBParameterGroupName!='default*']"
   
   # Delete parameter group
   aws rds delete-db-parameter-group \
     --db-parameter-group-name custom-parameter-group-name
   ```

2. Delete custom option groups:
   ```bash
   # List option groups
   aws rds describe-option-groups \
     --query "OptionGroups[?OptionGroupName!='default*']"
   
   # Delete option group
   aws rds delete-option-group \
     --option-group-name custom-option-group-name
   ```

#### 3.10 Delete DB Subnet Groups (Optional)

```bash
# List subnet groups
aws rds describe-db-subnet-groups \
  --query "DBSubnetGroups[?DBSubnetGroupName!='default']"

# Delete subnet group
aws rds delete-db-subnet-group \
  --db-subnet-group-name custom-subnet-group-name
```

#### 3.11 RDS Data Destruction Verification

1. Verify instance no longer exists:
   ```bash
   aws rds describe-db-instances \
     --db-instance-identifier database-name
   # Should return an error
   ```

2. Verify automated backups are removed:
   ```bash
   aws rds describe-db-instance-automated-backups \
     --query "DBInstanceAutomatedBackups[?DBInstanceIdentifier=='database-name']"
   # Should return empty list
   ```

3. Check CloudTrail for deletion events:
   ```bash
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=ResourceName,AttributeValue=database-name
   ```

4. Document the deletion with timestamps and verification method.

---

## Part 2: Microsoft Azure Data Destruction

### Section 1: Azure Blob Storage Destruction

#### 1.1 Understanding Azure Blob Storage Deletion

- By default, deleted blobs can be recovered within the retention period
- Soft delete feature allows recovery of accidentally deleted data
- Blob versions and snapshots must be explicitly removed
- Legal holds and immutable storage policies may prevent deletion
- Container deletion does not immediately delete blobs if soft delete is enabled

#### 1.2 Preliminary Assessment

1. Install the latest Azure CLI:
   ```bash
   # For Linux
   curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
   
   # For Windows (PowerShell)
   Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi
   Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'
   ```

2. Login to Azure:
   ```bash
   az login
   ```

3. Identify storage accounts:
   ```bash
   az storage account list --output table
   ```

4. Check soft delete settings:
   ```bash
   az storage blob service-properties show \
     --account-name <storage-account-name> \
     --query deleteRetentionPolicy
   ```

5. Check for legal holds or immutable policies:
   ```bash
   az storage container immutability-policy show \
     --account-name <storage-account-name> \
     --container-name <container-name>
   ```

#### 1.3 Enable Soft Delete and Configure Lifecycle Management

1. Using Azure Portal:
   - Sign in to the Azure Portal (https://portal.azure.com)
   - Navigate to your Storage Account
     - Click "All resources" or search for your storage account
     - Click on your storage account name
   - Under "Blob service" in the left menu, click "Data protection"
   - In the "Soft delete" section:
     - Enable "Soft delete for blobs" by checking the box
     - Set retention period (1-365 days)
     - Click "Save"
   - Go to "Lifecycle management" under "Blob service"
   - Click "+ Add a rule"
   - Provide rule details:
     - Name: "Data-Destruction-Policy"
     - Rule scope: Select "Apply rule to all blobs in storage account" or limit to containers
   - Set blob base conditions:
     - Check "Delete blob" under "Actions"
     - Set "Days after last modification" to appropriate value (e.g., 1 day)
   - Add additional settings for blob snapshots:
     - Check "Delete snapshot"
     - Set appropriate days value
   - Add additional settings for blob versions:
     - Check "Delete version"
     - Set appropriate days value
   - Click "Add" to save the rule

2. Using Azure CLI:
   ```bash
   # Enable soft delete with 7-day retention
   az storage blob service-properties update \
     --account-name <storage-account-name> \
     --enable-delete-retention true \
     --delete-retention-days 7
   
   # Create lifecycle management rule
   az storage account management-policy create \
     --account-name <storage-account-name> \
     --policy @policy.json
   ```

   Example `policy.json`:
   ```json
   {
     "rules": [
       {
         "enabled": true,
         "name": "Data-Destruction-Policy",
         "type": "Lifecycle",
         "definition": {
           "actions": {
             "baseBlob": {
               "delete": {
                 "daysAfterModificationGreaterThan": 1
               }
             },
             "snapshot": {
               "delete": {
                 "daysAfterCreationGreaterThan": 1
               }
             },
             "version": {
               "delete": {
                 "daysAfterCreationGreaterThan": 1
               }
             }
           },
           "filters": {
             "blobTypes": ["blockBlob"]
           }
         }
       }
     ]
   }
   ```

#### 1.4 Delete Individual Blobs (Portal Method)

1. Navigate to the Storage Account
   - Sign in to the Azure Portal
   - Search for "Storage accounts" in the search bar
   - Select your storage account from the list
2. Go to "Containers"
   - In the left menu, click "Containers" under "Data storage"
3. Select the container containing target blobs
   - Click on the container name to open it
4. Browse and select the blob(s) to delete
   - Check the boxes next to the blobs you want to delete
   - For large containers, use the filter and search functions
5. Click "Delete" in the top menu
6. In the confirmation dialog:
   - Review the selected blobs
   - Check "Permanently delete blobs that are under retention policy or legal hold" if you want to override soft delete
   - Click "Delete"
7. Monitor the delete operation in the notifications area
8. Refresh the blob list to verify deletion

#### 1.5 Delete Individual Blobs (Azure CLI)

1. Delete a single blob:
   ```bash
   az storage blob delete \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --name <blob-name> \
     --auth-mode login
   ```

2. Delete multiple blobs with prefix:
   ```bash
   az storage blob delete-batch \
     --account-name <storage-account-name> \
     --source <container-name> \
     --pattern "<prefix>*" \
     --auth-mode login
   ```

3. Delete all blobs in a container:
   ```bash
   az storage blob delete-batch \
     --account-name <storage-account-name> \
     --source <container-name> \
     --auth-mode login
   ```

4. Delete blob snapshots:
   ```bash
   # Delete a specific snapshot
   az storage blob delete \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --name <blob-name> \
     --snapshot <snapshot-timestamp> \
     --auth-mode login
   
   # Delete all snapshots for a blob
   az storage blob delete \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --name <blob-name> \
     --delete-snapshots only \
     --auth-mode login
   ```

5. Delete blob versions:
   ```bash
   # List versions
   az storage blob list \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --include v \
     --query "[?name=='<blob-name>']" \
     --auth-mode login
   
   # Delete specific version
   az storage blob delete \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --name <blob-name> \
     --version-id <version-id> \
     --auth-mode login
   ```

#### 1.6 Data Overwriting for Sensitive Blobs

For sensitive data, overwrite before deletion:

1. Create a zero or random file locally:
   ```bash
   # Create 1MB file with zeros
   dd if=/dev/zero of=zeros.bin bs=1M count=1
   
   # Create 1MB file with random data
   dd if=/dev/urandom of=random.bin bs=1M count=1
   ```

2. Overwrite each sensitive blob multiple times:
   ```bash
   # Get blob size first
   blob_size=$(az storage blob show \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --name <blob-name> \
     --query properties.contentLength \
     --output tsv \
     --auth-mode login)
   
   # Create appropriate size overwrite file
   dd if=/dev/urandom of=random.bin bs=1M count=$((($blob_size/1024/1024)+1))
   
   # Overwrite blob multiple times (DoD 5220.22-M style)
   for i in {1..3}; do
     az storage blob upload \
       --account-name <storage-account-name> \
       --container-name <container-name> \
       --name <blob-name> \
       --file random.bin \
       --overwrite \
       --auth-mode login
   done
   
   # Delete the overwritten blob
   az storage blob delete \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --name <blob-name> \
     --auth-mode login
   ```

3. For automation with multiple blobs:
   ```bash
   #!/bin/bash
   STORAGE_ACCOUNT="<storage-account-name>"
   CONTAINER="<container-name>"
   PREFIX="<prefix>"
   
   # List all blobs with prefix
   blobs=$(az storage blob list \
     --account-name $STORAGE_ACCOUNT \
     --container-name $CONTAINER \
     --prefix $PREFIX \
     --query "[].name" \
     --output tsv \
     --auth-mode login)
   
   # Create overwrite file
   dd if=/dev/urandom of=random.bin bs=1M count=10
   
   # Overwrite each blob
   for blob in $blobs; do
     echo "Overwriting $blob"
     for i in {1..3}; do
       az storage blob upload \
         --account-name $STORAGE_ACCOUNT \
         --container-name $CONTAINER \
         --name "$blob" \
         --file random.bin \
         --overwrite \
         --auth-mode login
     done
     
     # Delete the overwritten blob
     az storage blob delete \
       --account-name $STORAGE_ACCOUNT \
       --container-name $CONTAINER \
       --name "$blob" \
       --auth-mode login
   done
   ```

#### 1.7 Delete Container (Portal Method)

1. Navigate to Storage Account in Azure Portal
   - Sign in to the Azure Portal
   - Go to your storage account
2. Go to "Containers"
   - Click "Containers" in the left menu
3. Select the container(s) to delete
   - Check the box next to each container
4. Click "Delete" in the top menu
5. In the confirmation dialog:
   - Confirm you want to delete the container(s)
   - Click "Delete"
6. Monitor the deletion in the notifications area
7. Refresh the container list to verify deletion

#### 1.8 Delete Container (Azure CLI)

1. Delete a single container:
   ```bash
   az storage container delete \
     --account-name <storage-account-name> \
     --name <container-name> \
     --auth-mode login
   ```

2. For multiple containers:
   ```bash
   # List containers with a specific prefix
   containers=$(az storage container list \
     --account-name <storage-account-name> \
     --prefix <prefix> \
     --query "[].name" \
     --output tsv \
     --auth-mode login)
   
   # Delete each container
   for container in $containers; do
     echo "Deleting container: $container"
     az storage container delete \
       --account-name <storage-account-name> \
       --name "$container" \
       --auth-mode login
   done
   ```

#### 1.9 Purge Soft-Deleted Data

1. List soft-deleted blobs:
   ```bash
   az storage blob list \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --include d \
     --auth-mode login
   ```

2. Restore a soft-deleted blob (if needed):
   ```bash
   az storage blob undelete \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --name <blob-name> \
     --auth-mode login
   ```

3. For immediate purge of soft-deleted blobs (requires special permissions):
   ```bash
   # This is an example using Azure Storage REST API via curl
   # Note: Requires appropriate authorization headers
   
   curl -X DELETE "https://<storage-account>.blob.core.windows.net/<container>/<blob>?comp=expiry" \
     -H "Authorization: Bearer <token>" \
     -H "x-ms-version: 2020-04-08"
   ```

4. Wait for the retention period to expire for automatic purging

5. For soft-deleted containers:
   ```bash
   # List deleted containers
   az storage container list-deleted \
     --account-name <storage-account-name> \
     --auth-mode login
   
   # Restore a container if needed
   az storage container restore \
     --account-name <storage-account-name> \
     --name <container-name> \
     --deleted-version <version-id> \
     --auth-mode login
   ```

#### 1.10 Blob Storage Destruction Verification

1. Verify blobs are no longer listed:
   ```bash
   az storage blob list \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --prefix <prefix> \
     --auth-mode login
   ```

2. Check for soft-deleted blobs:
   ```bash
   az storage blob list \
     --account-name <storage-account-name> \
     --container-name <container-name> \
     --include d \
     --auth-mode login
   ```

3. Verify containers are no longer listed:
   ```bash
   az storage container list \
     --account-name <storage-account-name> \
     --prefix <prefix> \
     --auth-mode login
   ```

4. Check Azure Activity Log for deletion operations:
   ```bash
   az monitor activity-log list \
     --resource-group <resource-group> \
     --start-time <start-time> \
     --filters "resourceProvider eq 'Microsoft.Storage'"
   ```

5. Document the deletion with timestamps and verification method.

### Section 2: Azure Managed Disk Destruction

#### 2.1 Understanding Azure Disk Deletion

- Managed disks are stored as page blobs in Microsoft-managed storage accounts
- Deleted disks are retained in soft-deleted state for default period
- Snapshots and images must be deleted separately
- Azure does not guarantee immediate data sanitization after deletion
- Encryption provides cryptographic erasure protection

#### 2.2 Preliminary Assessment

1. List all managed disks:
   ```bash
   az disk list --output table
   ```

2. Check for disk attachments:
   ```bash
   az disk list --query "[?managedBy!=null].{Name:name, AttachedTo:managedBy}" --output table
   ```

3. Check for disk encryption:
   ```bash
   az disk list --query "[].{Name:name, EncryptionType:encryption.type}" --output table
   ```

4. Check for snapshots and images:
   ```bash
   # List snapshots
   az snapshot list --output table
   
   # List images
   az image list --output table
   ```

#### 2.3 Create Snapshot (if needed)

1. Using Azure Portal:
   - Sign in to the Azure Portal
   - Navigate to "Disks" (search in the top search bar)
   - Select the target disk
   - Click "Create snapshot" from the top menu
   - Provide snapshot details:
     - Name: "Final-Backup-[Disk-Name]-[Date]"
     - Resource group: Select appropriate resource group
     - Account type: Select storage redundancy option
     - Add appropriate tags for tracking
   - Click "Create"
   - Monitor the snapshot creation process in the notifications area

2. Using Azure CLI:
   ```bash
   # Create snapshot
   az snapshot create \
     --resource-group <resource-group> \
     --name "Final-Backup-<disk-name>-$(date +%Y%m%d)" \
     --source <disk-id> \
     --tags "Purpose=FinalBackup" "DeleteAfter=$(date -d '+30 days' +%Y-%m-%d)"
   
   # Monitor creation
   az snapshot show \
     --resource-group <resource-group> \
     --name "Final-Backup-<disk-name>-$(date +%Y%m%d)" \
     --query "provisioningState"
   ```

#### 2.4 Secure Erase for Confidential Data

For disks containing sensitive data:

1. Enable encryption if not already enabled:
   ```bash
   # Check encryption status
   az disk show \
     --resource-group <resource-group> \
     --name <disk-name> \
     --query "encryption"
   
   # Enable encryption with platform-managed key
   az disk update \
     --resource-group <resource-group> \
     --name <disk-name> \
     --encryption-type EncryptionAtRestWithPlatformKey
   ```

2. For customer-managed keys, rotate the key before deletion:
   ```bash
   # Update disk to use a new key
   az disk update \
     --resource-group <resource-group> \
     --name <disk-name> \
     --encryption-type EncryptionAtRestWithCustomerKey \
     --key-url "https://<keyvault-name>.vault.azure.net/keys/<new-key-name>/<new-key-version>"
   ```

3. For VM-attached disks requiring data wipe:
   ```bash
   # SSH into the VM and securely wipe the disk
   # Example for Linux using shred (replace /dev/sdX with actual device)
   sudo shred -vzn 3 /dev/sdX
   
   # Example for Windows using PowerShell and cipher (run inside VM)
   cipher /w:C:
   ```

#### 2.5 Detach Disk from VM

1. Using Azure Portal:
   - Sign in to the Azure Portal
   - Search for and select "Virtual machines"
   - Click on the VM using the disk
   - Under "Settings", click "Disks"
   - Find the data disk in the list
   - Click the "Detach" icon (X) at the far right
   - Click "Save" at the top
   - Monitor the operation in the notifications area

2. Using Azure CLI:
   ```bash
   # Identify the VM and attached disks
   az vm disk list \
     --resource-group <resource-group> \
     --vm-name <vm-name> \
     --query "[].{Name:name, Lun:lun}" \
     --output table
   
   # Detach disk by LUN
   az vm disk detach \
     --resource-group <resource-group> \
     --vm-name <vm-name> \
     --lun <lun-number>
   
   # Verify detachment
   az vm disk list \
     --resource-group <resource-group> \
     --vm-name <vm-name> \
     --output table
   ```

3. For PowerShell:
   ```powershell
   # Detach disk
   $vm = Get-AzVM -ResourceGroupName <resource-group> -Name <vm-name>
   Remove-AzVMDataDisk -VM $vm -Name <disk-name>
   Update-AzVM -ResourceGroupName <resource-group> -VM $vm
   ```

4. Wait for the detach operation to complete:
   ```bash
   # Check disk status
   az disk show \
     --resource-group <resource-group> \
     --name <disk-name> \
     --query managedBy
   # Should return null when detached
   ```

#### 2.6 Delete the Disk

1. Using Azure Portal:
   - Navigate to "Disks" in the Azure Portal
   - Select the disk(s) to delete
   - Click "Delete" from the top menu
   - In the confirmation dialog, type "yes" to confirm
   - Click "Delete"
   - Monitor the deletion in the notifications area

2. Using Azure CLI:
   ```bash
   # Delete a single disk
   az disk delete \
     --resource-group <resource-group> \
     --name <disk-name> \
     --yes
   
   # Delete multiple disks
   disks=$(az disk list \
     --resource-group <resource-group> \
     --query "[?tags.Environment=='Development'].id" \
     --output tsv)
   
   for disk in $disks; do
     echo "Deleting disk: $disk"
     az disk delete --ids $disk --yes
   done
   ```

3. For PowerShell:
   ```powershell
   # Delete disk
   Remove-AzDisk -ResourceGroupName <resource-group> -DiskName <disk-name> -Force
   ```

4. Verify deletion:
   ```bash
   az disk show \
     --resource-group <resource-group> \
     --name <disk-name>
   # Should return an error indicating the disk doesn't exist
   ```

#### 2.7 Delete Associated Snapshots and Images

1. Delete associated snapshots:
   ```bash
   # Find snapshots for the disk
   az snapshot list \
     --query "[?contains(name, '<disk-name>')].{Name:name, ResourceGroup:resourceGroup}" \
     --output table
   
   # Delete each snapshot
   az snapshot delete \
     --resource-group <resource-group> \
     --name <snapshot-name> \
     --yes
   ```

2. Delete associated images:
   ```bash
   # Find images potentially using the disk
   az image list \
     --query "[?contains(name, '<disk-name>')].{Name:name, ResourceGroup:resourceGroup}" \
     --output table
   
   # Delete each image
   az image delete \
     --resource-group <resource-group> \
     --name <image-name>
   ```

#### 2.8 Disk Destruction Verification

1. Verify disk no longer exists:
   ```bash
   az disk show \
     --resource-group <resource-group> \
     --name <disk-name>
   # Should return an error
   ```

2. Check Azure Activity Log for deletion operations:
   ```bash
   az monitor activity-log list \
     --resource-group <resource-group> \
     --start-time <start-time> \
     --filters "resourceProvider eq 'Microsoft.Compute'" "resourceType eq 'disks'"
   ```

3. Document the deletion with timestamps and verification method.

### Section 3: Azure SQL Database Destruction

#### 3.1 Understanding SQL Database Deletion

- SQL database deletion removes the database permanently after retention period
- Automated backups are retained according to backup retention settings
- Point-in-time restores are available during retention period
- Long-term backups must be handled separately
- Geo-replicated databases must be handled separately

#### 3.2 Preliminary Assessment

1. List all SQL servers and databases:
   ```bash
   # List servers
   az sql server list --output table
   
   # List databases for a server
   az sql db list \
     --resource-group <resource-group> \
     --server <server-name> \
     --output table
   ```

2. Check for replicas and failover groups:
   ```bash
   # Check for geo-replicated databases
   az sql db replica list \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name>
   
   # Check for failover groups
   az sql failover-group list \
     --resource-group <resource-group> \
     --server <server-name>
   ```

3. Check backup retention settings:
   ```bash
   az sql db show \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <database-name> \
     --query "backupRetentionDays"
   ```

4. Check for long-term retention backups:
   ```bash
   az sql db ltr-backup list \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name> \
     --only-latest-per-database
   ```

#### 3.3 Create Final Backup (if needed)

1. Using Azure Portal:
   - Sign in to the Azure Portal
   - Navigate to the SQL database
     - Search for "SQL databases" in the top search bar
     - Select your database from the list
   - Click "Export" in the top menu
   - Configure export settings:
     - Storage account: Select target storage account
     - Container: Select or create a container
     - Database file type: Select appropriate format (BACPAC recommended)
     - Add appropriate login credentials
   - Click "OK" to start the export
   - Monitor the export operation in the notifications area

2. Using Azure CLI:
   ```bash
   # Create a storage container for the backup
   az storage container create \
     --account-name <storage-account-name> \
     --name "final-backups" \
     --auth-mode login
   
   # Generate SAS token for the storage account
   sas=$(az storage account generate-sas \
     --account-name <storage-account-name> \
     --permissions rw \
     --expiry $(date -d "+1 day" +%Y-%m-%dT%H:%MZ) \
     --resource-types co \
     --services b \
     --https-only \
     --output tsv)
   
   # Export database to BACPAC
   az sql db export \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <database-name> \
     --admin-user <admin-username> \
     --admin-password <admin-password> \
     --storage-key-type SharedAccessKey \
     --storage-key "$sas" \
     --storage-uri "https://<storage-account-name>.blob.core.windows.net/final-backups/<database-name>-final-$(date +%Y%m%d).bacpac"
   ```

3. For PowerShell:
   ```powershell
   # Export database
   $storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName <resource-group> -Name <storage-account-name>)[0].Value
   $bcpArgs = New-Object Microsoft.Azure.Commands.Sql.Database.Model.DatabaseExportBacpacProperties
   $bcpArgs.StorageKeyType = "StorageAccessKey"
   $bcpArgs.StorageKey = $storageAccountKey
   $bcpArgs.StorageUri = "https://<storage-account-name>.blob.core.windows.net/final-backups/<database-name>-final-$(Get-Date -Format 'yyyyMMdd').bacpac"
   $bcpArgs.AdministratorLogin = "<admin-username>"
   $bcpArgs.AdministratorLoginPassword = (ConvertTo-SecureString -String "<admin-password>" -AsPlainText -Force)
   
   $exportRequest = New-AzSqlDatabaseExport -ResourceGroupName <resource-group> -ServerName <server-name> -DatabaseName <database-name> -DatabaseExportBacpacProperties $bcpArgs
   
   # Check status
   Get-AzSqlDatabaseImportExportStatus -OperationStatusLink $exportRequest.OperationStatusLink
   ```

#### 3.4 Handle Geo-Replicas and Failover Groups

1. Remove database from failover group:
   ```bash
   # List databases in failover group
   az sql failover-group show \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <failover-group-name> \
     --query "databases"
   
   # Remove database from failover group
   az sql failover-group update \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <failover-group-name> \
     --remove-db <database-name>
   ```

2. Delete geo-replicated databases:
   ```bash
   # List replicas
   az sql db replica list \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name>
   
   # Delete each secondary replica
   az sql db delete \
     --resource-group <secondary-resource-group> \
     --server <secondary-server-name> \
     --name <database-name> \
     --yes
   ```

#### 3.5 Delete Long-Term Retention Backups

1. List long-term retention backups:
   ```bash
   # Get all LTR backups for the database
   az sql db ltr-backup list \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name> \
     --output table
   ```

2. Delete specific LTR backup:
   ```bash
   az sql db ltr-backup delete \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name> \
     --backup-name <backup-name> \
     --yes
   ```

3. Delete all LTR backups for a database:
   ```bash
   # Get list of backups
   backups=$(az sql db ltr-backup list \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name> \
     --query "[].{Name:name}" \
     --output tsv)
   
   # Delete each backup
   for backup in $backups; do
     echo "Deleting LTR backup: $backup"
     az sql db ltr-backup delete \
       --resource-group <resource-group> \
       --server <server-name> \
       --database <database-name> \
       --backup-name $backup \
       --yes
   done
   ```

#### 3.6 Delete Database

1. Using Azure Portal:
   - Sign in to the Azure Portal
   - Navigate to SQL databases
   - Select the database to delete
   - Click "Delete" from the top menu
   - In the confirmation dialog:
     - Read the warning about deletion
     - Type the database name to confirm
     - Click "Delete"
   - Monitor the deletion in the notifications area

2. Using Azure CLI:
   ```bash
   # Delete database
   az sql db delete \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <database-name> \
     --yes
   ```

3. For PowerShell:
   ```powershell
   # Delete database
   Remove-AzSqlDatabase -ResourceGroupName <resource-group> -ServerName <server-name> -DatabaseName <database-name> -Force
   ```

4. Verify deletion:
   ```bash
   az sql db show \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <database-name>
   # Should return an error indicating the database doesn't exist
   ```

#### 3.7 Delete Elastic Pools (if applicable)

1. Check if there are any remaining databases in the elastic pool:
   ```bash
   az sql elastic-pool list-dbs \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <pool-name>
   ```

2. Delete the elastic pool if it's empty:
   ```bash
   az sql elastic-pool delete \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <pool-name> \
     --yes
   ```

#### 3.8 Delete SQL Server (if no longer needed)

1. Check for remaining databases:
   ```bash
   az sql db list \
     --resource-group <resource-group> \
     --server <server-name> \
     --output table
   ```

2. Delete the server:
   ```bash
   az sql server delete \
     --resource-group <resource-group> \
     --name <server-name> \
     --yes
   ```

#### 3.9 SQL Database Destruction Verification

1. Verify database no longer exists:
   ```bash
   az sql db show \
     --resource-group <resource-group> \
     --server <server-name> \
     --name <database-name>
   # Should return an error
   ```

2. Verify no restorable backups exist:
   ```bash
   # Check for restorable deleted databases
   az sql db list-deleted \
     --resource-group <resource-group> \
     --server <server-name>
   
   # Check for LTR backups
   az sql db ltr-backup list \
     --resource-group <resource-group> \
     --server <server-name> \
     --database <database-name>
   ```

3. Check Azure Activity Log for deletion operations:
   ```bash
   az monitor activity-log list \
     --resource-group <resource-group> \
     --start-time <start-time> \
     --filters "resourceProvider eq 'Microsoft.Sql'"
   ```

4. Document the deletion with timestamps and verification method.

### Section 4: Azure Cosmos DB Destruction

#### 4.1 Understanding Cosmos DB Deletion

- Cosmos DB data can exist at multiple levels: account, database, container, items
- Backups may exist depending on backup policy configuration
- Continuous backup mode enables point-in-time restoration
- Multi-region deployments replicate data to all configured regions
- Soft delete features may retain deleted items

#### 4.2 Preliminary Assessment

1. List all Cosmos DB accounts:
   ```bash
   az cosmosdb list --output table
   ```

2. List databases in an account:
   ```bash
   az cosmosdb sql database list \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --output table
   ```

3. List containers in a database:
   ```bash
   az cosmosdb sql container list \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --database-name <database-name> \
     --output table
   ```

4. Check backup policy:
   ```bash
   az cosmosdb show \
     --resource-group <resource-group> \
     --name <account-name> \
     --query "backupPolicy"
   ```

5. Check consistency level and replication configuration:
   ```bash
   az cosmosdb show \
     --resource-group <resource-group> \
     --name <account-name> \
     --query "{Consistency:consistencyPolicy.defaultConsistencyLevel, Regions:locations}"
   ```

#### 4.3 Export Data (if needed)

1. Using Data Migration Tool:
   - Download the Cosmos DB Data Migration Tool
   - Configure source connection to Cosmos DB account
   - Configure target connection to file or other storage
   - Execute the export

2. Using Azure Portal Data Explorer:
   - Sign in to the Azure Portal
   - Navigate to your Cosmos DB account
   - Click "Data Explorer" in the left menu
   - Select the database and container
   - Click "Export" in the top menu
   - Configure the export settings
   - Start the export operation

3. Using Azure CLI and custom script:
   ```bash
   # Example script to export using the CosmosDB REST API
   # Requires jq for JSON processing
   
   # Set variables
   ACCOUNT_NAME="<account-name>"
   DATABASE_NAME="<database-name>"
   CONTAINER_NAME="<container-name>"
   RESOURCE_GROUP="<resource-group>"
   OUTPUT_FILE="${DATABASE_NAME}-${CONTAINER_NAME}-export.json"
   
   # Get master key
   MASTER_KEY=$(az cosmosdb keys list \
     --resource-group $RESOURCE_GROUP \
     --name $ACCOUNT_NAME \
     --type keys \
     --query primaryMasterKey \
     --output tsv)
   
   # Get endpoint
   ENDPOINT=$(az cosmosdb show \
     --resource-group $RESOURCE_GROUP \
     --name $ACCOUNT_NAME \
     --query documentEndpoint \
     --output tsv)
   
   # Create a date for the authorization header
   DATE=$(date -u "+%a, %d %b %Y %H:%M:%S GMT")
   
   # Set up continuation token variable
   CONTINUATION=""
   
   # Loop until all documents are exported
   echo "[" > $OUTPUT_FILE
   FIRST=true
   
   while true; do
     # Build the authorization token
     VERB="GET"
     RESOURCE_TYPE="docs"
     RESOURCE_LINK="dbs/${DATABASE_NAME}/colls/${CONTAINER_NAME}"
     
     # Create the authorization signature
     SIGNATURE="$(echo -en "${VERB}\n${RESOURCE_TYPE}\n${RESOURCE_LINK}\n${DATE}\n\n" | \
                  openssl dgst -sha256 -mac HMAC -macopt "key:$MASTER_KEY" -binary | \
                  base64)"
     
     # URL encode the signature
     ENCODED_SIGNATURE=$(echo $SIGNATURE | sed 's/+/%2B/g' | sed 's/\//%2F/g' | sed 's/=/%3D/g')
     
     # Build the authorization header
     AUTH_HEADER="type=master&ver=1.0&sig=${ENCODED_SIGNATURE}"
     
     # Build the URL
     URL="${ENDPOINT}${RESOURCE_LINK}/docs"
     
     # Add continuation token if available
     CONT_HEADER=""
     if [ ! -z "$CONTINUATION" ]; then
       CONT_HEADER="-H 'x-ms-continuation:$CONTINUATION'"
     fi
     
     # Make the request
     RESPONSE=$(curl -s -X GET "$URL" \
       -H "Authorization: $AUTH_HEADER" \
       -H "x-ms-date: $DATE" \
       -H "x-ms-version: 2018-12-31" \
       $CONT_HEADER)
     
     # Extract documents
     DOCS=$(echo $RESPONSE | jq -c '.Documents[]')
     
     # Write to file
     for DOC in $DOCS; do
       if [ "$FIRST" = true ]; then
         FIRST=false
       else
         echo "," >> $OUTPUT_FILE
       fi
       echo "$DOC" >> $OUTPUT_FILE
     done
     
     # Get continuation token
     CONTINUATION=$(echo $RESPONSE | jq -r '."x-ms-continuation"')
     
     # Exit if no continuation token
     if [ "$CONTINUATION" = "null" ] || [ -z "$CONTINUATION" ]; then
       break
     fi
   done
   
   echo "]" >> $OUTPUT_FILE
   echo "Export completed to $OUTPUT_FILE"
   ```

#### 4.4 Delete Items (Data Level)

For selective data deletion:

1. Using Azure Portal Data Explorer:
   - Navigate to the Cosmos DB account in Azure Portal
   - Click "Data Explorer" in the left menu
   - Browse to the database and container
   - Use the query editor to find items to delete
   - Select items and click "Delete" in the top menu
   - Confirm deletion

2. Using Azure CLI and SDK:
   ```python
   # Python script for batch deletion of items
   from azure.cosmos import CosmosClient, PartitionKey
   import os
   
   # Set up credentials
   endpoint = "https://<account-name>.documents.azure.com:443/"
   key = "<master-key>"
   
   # Initialize client
   client = CosmosClient(endpoint, key)
   
   # Get reference to database and container
   database = client.get_database_client("<database-name>")
   container = database.get_container_client("<container-name>")
   
   # Query for items to delete (customize as needed)
   query = "SELECT c.id, c.<partition-key-path> FROM c WHERE c.status = 'Archived'"
   
   # Delete each item
   items_deleted = 0
   for item in container.query_items(query=query, enable_cross_partition_query=True):
     partition_key_value = item["<partition-key-path>"]
     container.delete_item(item=item["id"], partition_key=partition_key_value)
     items_deleted += 1
     if items_deleted % 100 == 0:
       print(f"Deleted {items_deleted} items...")
   
   print(f"Total items deleted: {items_deleted}")
   ```

3. To delete all items while preserving the container:
   ```bash
   # Bash script to delete all items using the Cosmos DB REST API
   
   # Set variables
   ACCOUNT_NAME="<account-name>"
   DATABASE_NAME="<database-name>"
   CONTAINER_NAME="<container-name>"
   RESOURCE_GROUP="<resource-group>"
   PARTITION_KEY_NAME="<partition-key-name>"
   
   # Get master key
   MASTER_KEY=$(az cosmosdb keys list \
     --resource-group $RESOURCE_GROUP \
     --name $ACCOUNT_NAME \
     --type keys \
     --query primaryMasterKey \
     --output tsv)
   
   # Get endpoint
   ENDPOINT=$(az cosmosdb show \
     --resource-group $RESOURCE_GROUP \
     --name $ACCOUNT_NAME \
     --query documentEndpoint \
     --output tsv)
   
   # First, query for all document IDs and partition keys
   echo "Querying for all documents..."
   
   # Execute query to get IDs and partition keys (assuming a simple partition key structure)
   # Save query results to a temporary file
   az cosmosdb sql query \
     --resource-group $RESOURCE_GROUP \
     --account-name $ACCOUNT_NAME \
     --database-name $DATABASE_NAME \
     --container-name $CONTAINER_NAME \
     --query "SELECT c.id, c.$PARTITION_KEY_NAME FROM c" \
     > documents.json
   
   # Delete each document
   echo "Starting deletion process..."
   TOTAL=$(jq '.[] | length' documents.json)
   COUNTER=0
   
   cat documents.json | jq -c '.[]' | while read -r doc; do
     ID=$(echo $doc | jq -r '.id')
     PARTITION_KEY=$(echo $doc | jq -r ".$PARTITION_KEY_NAME")
     
     # Delete the document
     az cosmosdb sql delete \
       --resource-group $RESOURCE_GROUP \
       --account-name $ACCOUNT_NAME \
       --database-name $DATABASE_NAME \
       --container-name $CONTAINER_NAME \
       --item-id $ID \
       --partition-key $PARTITION_KEY
     
     COUNTER=$((COUNTER+1))
     if [ $((COUNTER % 100)) -eq 0 ]; then
       echo "Deleted $COUNTER of $TOTAL documents..."
     fi
   done
   
   echo "Deletion complete. Deleted $COUNTER documents."
   rm documents.json
   ```

#### 4.5 Delete Collections/Containers

1. Using Azure Portal:
   - Navigate to the Cosmos DB account
   - Click "Data Explorer" in the left menu
   - Expand the database containing your container
   - Right-click on the container
   - Select "Delete Container"
   - Type the container name to confirm
   - Click "OK"

2. Using Azure CLI:
   ```bash
   # Delete a SQL API container
   az cosmosdb sql container delete \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --database-name <database-name> \
     --name <container-name> \
     --yes
   
   # For other APIs (MongoDB, Cassandra, Gremlin, Table)
   # Use the corresponding command, e.g., for MongoDB:
   az cosmosdb mongodb collection delete \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --database-name <database-name> \
     --name <collection-name> \
     --yes
   ```

3. Batch delete all containers in a database:
   ```bash
   # List all containers
   containers=$(az cosmosdb sql container list \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --database-name <database-name> \
     --query "[].name" \
     --output tsv)
   
   # Delete each container
   for container in $containers; do
     echo "Deleting container: $container"
     az cosmosdb sql container delete \
       --resource-group <resource-group> \
       --account-name <account-name> \
       --database-name <database-name> \
       --name "$container" \
       --yes
   done
   ```

#### 4.6 Delete Database

1. Using Azure Portal:
   - Navigate to the Cosmos DB account
   - Click "Data Explorer" in the left menu
   - Right-click on the database
   - Select "Delete Database"
   - Type the database name to confirm
   - Click "OK"

2. Using Azure CLI:
   ```bash
   # Delete a SQL API database
   az cosmosdb sql database delete \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --name <database-name> \
     --yes
   
   # For other APIs (MongoDB, Cassandra, Gremlin, Table)
   # Use the corresponding command, e.g., for MongoDB:
   az cosmosdb mongodb database delete \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --name <database-name> \
     --yes
   ```

3. Batch delete all databases in an account:
   ```bash
   # List all databases
   databases=$(az cosmosdb sql database list \
     --resource-group <resource-group> \
     --account-name <account-name> \
     --query "[].name" \
     --output tsv)
   
   # Delete each database
   for db in $databases; do
     echo "Deleting database: $db"
     az cosmosdb sql database delete \
       --resource-group <resource-group> \
       --account-name <account-name> \
       --name "$db" \
       --yes
   done
   ```

#### 4.7 Delete Cosmos DB Account

1. Using Azure Portal:
   - Navigate to "Azure Cosmos DB accounts" in the portal
   - Select the account you want to delete
   - Click "Delete" from the top menu
   - In the confirmation dialog:
     - Type the account name to confirm
     - Click "Delete"
   - Monitor the deletion process in the notifications area

2. Using Azure CLI:
   ```bash
   # Delete Cosmos DB account
   az cosmosdb delete \
     --resource-group <resource-group> \
     --name <account-name> \
     --yes
   ```

3. For PowerShell:
   ```powershell
   # Delete Cosmos DB account
   Remove-AzCosmosDBAccount -ResourceGroupName <resource-group> -Name <account-name> -Force
   ```

4. Verify deletion:
   ```bash
   az cosmosdb show \
     --resource-group <resource-group> \
     --name <account-name>
   # Should return an error indicating the account doesn't exist
   ```

#### 4.8 Cosmos DB Destruction Verification

1. Verify account no longer exists:
   ```bash
   az cosmosdb show \
     --resource-group <resource-group> \
     --name <account-name>
   # Should return an error
   ```

2. Check for any backup resources:
   ```bash
   # Check for any backup vaults containing Cosmos DB backups
   az backup vault list \
     --resource-group <resource-group>
   ```

3. Check Azure Activity Log for deletion operations:
   ```bash
   az monitor activity-log list \
     --resource-group <resource-group> \
     --start-time <start-time> \
     --filters "resourceProvider eq 'Microsoft.DocumentDB'"
   ```

4. Document the deletion with timestamps and verification method.

### Section 5: Azure Data Factory Pipelines for Secure Data Destruction

#### 5.1 Understanding Data Factory for Destruction

- Azure Data Factory can automate and orchestrate complex data destruction workflows
- Can handle multi-step processes across various data stores
- Provides logging and monitoring capabilities
- Enables scheduled or triggered destruction processes
- Can implement data overwriting before deletion

#### 5.2 Creating a Data Destruction Pipeline

1. Sign in to the Azure Portal
2. Navigate to your Azure Data Factory instance
   - Search for "Data factories" in the search bar
   - Select your Data Factory or create a new one
3. Click "Author & Monitor" to open the ADF studio
4. Create a new pipeline:
   - Click "+" and select "Pipeline"
   - Name it "Data-Destruction-Pipeline"
   - Add a description detailing its purpose

#### 5.3 Configure Pipeline Variables

1. Click on the pipeline canvas background
2. Go to "Variables" tab and add the following:
   - `DataStorageType`: String, default: "BlobStorage"
   - `ContainerName`: String
   - `AccountName`: String
   - `ResourceGroup`: String
   - `ConfirmDestruction`: Boolean, default: false

#### 5.4 Add Validation Activities

1. Add a "Set variable" activity:
   - Name it "ValidateDestructionRequest"
   - Variable: "ConfirmDestruction"
   - Value: `@pipeline().parameters.confirmDestruction`

2. Add an "If Condition" activity:
   - Name it "CheckDestructionConfirmation"
   - Expression: `@variables('ConfirmDestruction')`
   - Connect from the previous activity

3. In the "True" path, continue with destruction activities
4. In the "False" path, add a "Fail" activity:
   - Name it "AbortDestruction"
   - Error message: "Destruction not confirmed. Process aborted."
   - Error code: "USER_ABORT"

#### 5.5 Add Data Overwrite Step (for sensitive data)

In the "True" path of the condition:

1. Add a "ForEach" activity:
   - Name it "IterateThroughStorageLocations"
   - Configure the "Items" field with your data location list

2. Inside the ForEach, add a "Copy" activity:
   - Name it "OverwriteWithRandomData"
   - Source: Configure "Data Generator" as source type
     - Number of rows: 1000
     - Column pattern:
       - Name: "data"
       - Pattern: Random
       - Length: 1024
   - Sink: Configure your data store (Blob, SQL, etc.)
   - Enable "Preserve settings"

3. Add another "Copy" activity after the overwrite:
   - Name it "OverwriteWithZeros"
   - Similar configuration but set pattern to constant zeros
   - Connect from the previous activity

#### 5.6 Add Deletion Activities

After the overwrite steps, add the appropriate deletion activities:

1. For Blob Storage:
   - Add an "Azure Blob Delete" activity:
     - Name it "DeleteBlobData"
     - Connect from the overwrite activity
     - Configure connection to your storage account
     - Blob path: `@item().path`

2. For SQL Database:
   - Add a "Stored Procedure" activity:
     - Name it "ExecuteSQLDeletion"
     - Configure connection to your SQL server
     - Stored procedure name: (a procedure that truncates/drops tables)
     - Parameters: Pass relevant parameters

3. For Cosmos DB:
   - Add an "Azure Cosmos DB" activity:
     - Name it "DeleteCosmosData"
     - Configure connection to your Cosmos DB account
     - Operation: "DeleteCollection"
     - Parameters: Pass database and collection names

#### 5.7 Add Logging and Notification

1. Add a "Web" activity for logging:
   - Name it "LogDeletionActivity"
   - URL: Your logging endpoint
   - Method: POST
   - Body: JSON containing deletion details
   - Connect from deletion activities

2. Add an "Azure Function" activity for notification:
   - Name it "SendNotification"
   - Function name: (a function that sends notifications)
   - Parameters: Pass deletion details
   - Connect from logging activity

#### 5.8 Execute and Monitor

1. Validate the pipeline:
   - Click "Validate" in the toolbar
   - Address any validation errors

2. Publish changes:
   - Click "Publish all" to save the pipeline

3. Execute the pipeline:
   - Click "Add trigger" > "Trigger now"
   - Enter required parameters
   - Confirm pipeline execution

4. Monitor execution:
   - Go to the "Monitor" tab
   - Select your pipeline run
   - View detailed execution information
   - Check activity outputs and logs

#### 5.9 Create Reusable Pipeline Template

For repeatable destruction operations:

1. Export the pipeline as a template:
   - Click on the pipeline
   - Click "Export template"
   - Save the ARM template

2. Create a script to deploy and execute:
   ```bash
   # Deploy pipeline template
   az deployment group create \
     --resource-group <resource-group> \
     --template-file destruction-pipeline-template.json \
     --parameters @parameters.json
   
   # Execute pipeline with parameters
   az datafactory pipeline create-run \
     --resource-group <resource-group> \
     --factory-name <data-factory-name> \
     --pipeline-name Data-Destruction-Pipeline \
     --parameters "{ \"dataStorageType\": \"BlobStorage\", \"containerName\": \"<container-name>\", \"confirmDestruction\": true }"
   ```

### Section 6: Azure Key Vault Destruction (for Encrypted Data)

#### 6.1 Understanding Key Vault Deletion Impact

- Deleting keys in Key Vault renders encrypted data inaccessible (cryptographic erasure)
- Soft delete feature retains deleted keys for recovery period
- Purge protection may prevent immediate permanent deletion
- Key rotation creates new key versions but doesn't delete old versions by default
- Access policies and RBAC control who can delete keys

#### 6.2 Preliminary Assessment

1. List all Key Vaults:
   ```bash
   az keyvault list --output table
   ```

2. Check soft delete and purge protection settings:
   ```bash
   az keyvault show \
     --name <keyvault-name> \
     --query "{SoftDelete:properties.enableSoftDelete, PurgeProtection:properties.enablePurgeProtection}"
   ```

3. List keys and secrets:
   ```bash
   # List keys
   az keyvault key list \
     --vault-name <keyvault-name> \
     --output table
   
   # List secrets
   az keyvault secret list \
     --vault-name <keyvault-name> \
     --output table
   ```

4. Check for key usage:
   ```bash
   # Example: Check for disk encryption using this key vault
   az disk list \
     --query "[?encryption.type=='EncryptionAtRestWithCustomerKey'].{Name:name, KeyUrl:encryption.diskEncryptionSetId}" \
     --output table
   ```

#### 6.3 Identify Keys and Secrets

1. Catalog all keys with purpose:
   ```bash
   # List all keys with details
   az keyvault key list \
     --vault-name <keyvault-name> \
     --query "[].{Name:name, Enabled:attributes.enabled, Created:attributes.created, Updated:attributes.updated}" \
     --output table
   ```

2. Catalog all secrets with purpose:
   ```bash
   # List all secrets with details
   az keyvault secret list \
     --vault-name <keyvault-name> \
     --query "[].{Name:name, Enabled:attributes.enabled, Created:attributes.created, Updated:attributes.updated}" \
     --output table
   ```

3. Document each key's usage:
   - Create a spreadsheet or document listing each key
   - Identify which systems/data rely on each key
   - Determine impact of key deletion
   - Note any dependencies between keys

#### 6.4 Disable Keys and Secrets

1. Using Azure Portal:
   - Navigate to your Key Vault
   - Select "Keys" or "Secrets" in the left menu
   - Click on the key/secret you want to disable
   - Click on the current version
   - Click "Disable" at the top
   - Confirm the action

2. Using Azure CLI:
   ```bash
   # Disable a key
   az keyvault key set-attributes \
     --vault-name <keyvault-name> \
     --name <key-name> \
     --enabled false
   
   # Disable a secret
   az keyvault secret set-attributes \
     --vault-name <keyvault-name> \
     --name <secret-name> \
     --enabled false
   ```

3. Batch disable all keys:
   ```bash
   # Get all keys
   keys=$(az keyvault key list \
     --vault-name <keyvault-name> \
     --query "[].name" \
     --output tsv)
   
   # Disable each key
   for key in $keys; do
     echo "Disabling key: $key"
     az keyvault key set-attributes \
       --vault-name <keyvault-name> \
       --name "$key" \
       --enabled false
   done
   ```

4. Batch disable all secrets:
   ```bash
   # Get all secrets
   secrets=$(az keyvault secret list \
     --vault-name <keyvault-name> \
     --query "[].name" \
     --output tsv)
   
   # Disable each secret
   for secret in $secrets; do
     echo "Disabling secret: $secret"
     az keyvault secret set-attributes \
       --vault-name <keyvault-name> \
       --name "$secret" \
       --enabled false
   done
   ```

#### 6.5 Delete Keys and Secrets

1. Using Azure Portal:
   - Navigate to your Key Vault
   - Select "Keys" or "Secrets" in the left menu
   - Select the key/secret to delete
   - Click "Delete" at the top
   - Confirm the deletion
   - Note: This performs a soft delete if enabled

2. Using Azure CLI:
   ```bash
   # Delete a key (soft delete)
   az keyvault key delete \
     --vault-name <keyvault-name> \
     --name <key-name>
   
   # Delete a secret (soft delete)
   az keyvault secret delete \
     --vault-name <keyvault-name> \
     --name <secret-name>
   ```

3. Batch delete all keys:
   ```bash
   # Get all keys
   keys=$(az keyvault key list \
     --vault-name <keyvault-name> \
     --query "[].name" \
     --output tsv)
   
   # Delete each key
   for key in $keys; do
     echo "Deleting key: $key"
     az keyvault key delete \
       --vault-name <keyvault-name> \
       --name "$key"
   done
   ```

4. Batch delete all secrets:
   ```bash
   # Get all secrets
   secrets=$(az keyvault secret list \
     --vault-name <keyvault-name> \
     --query "[].name" \
     --output tsv)
   
   # Delete each secret
   for secret in $secrets; do
     echo "Deleting secret: $secret"
     az keyvault secret delete \
       --vault-name <keyvault-name> \
       --name "$secret"
   done
   ```

#### 6.6 Purge Deleted Keys and Secrets

If purge protection is not enabled:

1. Using Azure Portal:
   - Navigate to your Key Vault
   - Select "Keys" or "Secrets" in the left menu
   - Click "Manage deleted keys" or "Manage deleted secrets"
   - Select the deleted key/secret
   - Click "Purge" to permanently delete it

2. Using Azure CLI:
   ```bash
   # List deleted keys
   az keyvault key list-deleted \
     --vault-name <keyvault-name> \
     --output table
   
   # Purge a deleted key
   az keyvault key purge \
     --vault-name <keyvault-name> \
     --name <key-name>
   
   # List deleted secrets
   az keyvault secret list-deleted \
     --vault-name <keyvault-name> \
     --output table
   
   # Purge a deleted secret
   az keyvault secret purge \
     --vault-name <keyvault-name> \
     --name <secret-name>
   ```

3. Batch purge all deleted keys:
   ```bash
   # Get all deleted keys
   deleted_keys=$(az keyvault key list-deleted \
     --vault-name <keyvault-name> \
     --query "[].name" \
     --output tsv)
   
   # Purge each deleted key
   for key in $deleted_keys; do
     echo "Purging key: $key"
     az keyvault key purge \
       --vault-name <keyvault-name> \
       --name "$key"
   done
   ```

4. Batch purge all deleted secrets:
   ```bash
   # Get all deleted secrets
   deleted_secrets=$(az keyvault secret list-deleted \
     --vault-name <keyvault-name> \
     --query "[].name" \
     --output tsv)
   
   # Purge each deleted secret
   for secret in $deleted_secrets; do
     echo "Purging secret: $secret"
     az keyvault secret purge \
       --vault-name <keyvault-name> \
       --name "$secret"
   done
   ```

#### 6.7 Delete the Key Vault

1. Using Azure Portal:
   - Navigate to your Key Vault
   - Click "Delete" in the top menu
   - Type the vault name to confirm
   - Click "Delete"
   - Note: This performs a soft delete if enabled

2. Using Azure CLI:
   ```bash
   # Delete the key vault (soft delete)
   az keyvault delete \
     --name <keyvault-name> \
     --resource-group <resource-group>
   ```

3. Purge the deleted Key Vault (if purge protection is not enabled):
   ```bash
   # List deleted vaults
   az keyvault list-deleted --output table
   
   # Purge a deleted vault
   az keyvault purge --name <keyvault-name>
   ```

#### 6.8 Key Vault Destruction Verification

1. Verify keys no longer exist:
   ```bash
   az keyvault key show \
     --vault-name <keyvault-name> \
     --name <key-name>
   # Should return an error
   ```

2. Verify secrets no longer exist:
   ```bash
   az keyvault secret show \
     --vault-name <keyvault-name> \
     --name <secret-name>
   # Should return an error
   ```

3. Verify vault no longer exists:
   ```bash
   az keyvault show \
     --name <keyvault-name>
   # Should return an error
   ```

4. Check for deleted but not purged resources:
   ```bash
   # Check for deleted keys
   az keyvault key list-deleted \
     --vault-name <keyvault-name>
   
   # Check for deleted secrets
   az keyvault secret list-deleted \
     --vault-name <keyvault-name>
   
   # Check for deleted vaults
   az keyvault list-deleted
   ```

5. Check Azure Activity Log for deletion operations:
   ```bash
   az monitor activity-log list \
     --resource-group <resource-group> \
     --start-time <start-time> \
     --filters "resourceProvider eq 'Microsoft.KeyVault'"
   ```

6. Document the deletion with timestamps and verification method.

---

## Part 3: Cross-Platform Considerations

### Section 1: Compliance Verification

#### 1.1 Understanding Compliance Requirements

- Different regulations have specific data destruction requirements:
  - GDPR: Right to erasure (Article 17)
  - HIPAA: Media sanitization requirements
  - PCI DSS: Secure deletion of cardholder data
  - SOC 2: Data disposal procedures
  - NIST SP 800-88: Media sanitization guidelines
- Organization-specific policies may require additional steps
- Verification and documentation are essential for compliance
- Chain of custody should be maintained
- Third-party verification may be required

#### 1.2 Document Destruction Process

1. Create a Data Destruction Log:
   - Date and time of destruction
   - Description of data destroyed
   - Data classification level
   - Location of data (cloud provider, region, resource ID)
   - Destruction method used
   - Personnel performing destruction
   - Verification method
   - Approvals received

2. Data Destruction Log Template:
   ```
   Data Destruction Log
   -------------------
   
   Organization: [Organization Name]
   Project/System: [Project/System Name]
   
   Destruction Details:
   - Request Date: [Date request received]
   - Approval Date: [Date approved]
   - Execution Date: [Date destruction performed]
   - Completion Date: [Date verification completed]
   
   Data Details:
   - Description: [Brief description of data]
   - Classification: [Confidential/Restricted/Public]
   - Format: [Database/Files/Documents/etc.]
   - Volume: [Size or record count]
   - Retention Period: [Required retention period]
   - Retention End Date: [Date retention period ended]
   
   Location Details:
   - Cloud Provider: [AWS/Azure/Both]
   - Regions: [List of regions]
   - Resource IDs: [List of resource IDs]
   
   Destruction Method:
   - Technique Used: [Deletion/Overwrite/Encryption/etc.]
   - Tools Used: [List of tools/commands]
   - Standards Followed: [NIST SP 800-88/DoD 5220.22-M/etc.]
   
   Personnel:
   - Requestor: [Name and role]
   - Approver: [Name and role]
   - Executor: [Name and role]
   - Verifier: [Name and role]
   
   Verification:
   - Method: [Audit logs/Manual inspection/etc.]
   - Results: [Pass/Fail/Partial]
   - Evidence: [Reference to attached evidence]
   - Exceptions: [Any data that couldn't be destroyed]
   
   Additional Notes:
   [Any relevant information]
   
   Signatures:
   
   Executor: ________________________ Date: ________
   
   Verifier: ________________________ Date: ________
   
   Compliance Officer: ______________ Date: ________
   ```

3. Include detailed technical logs:
   - Command outputs
   - Screenshots of console operations
   - Error messages and resolutions
   - Timestamps of each action

4. Maintain documentation for the required retention period:
   - Store securely with access controls
   - Encrypt if containing sensitive information
   - Include in backup systems
   - Apply appropriate retention policies

#### 1.3 Run Audit Reports

1. AWS CloudTrail Audit:
   ```bash
   # Create a temporary directory for audit files
   mkdir -p audit/$(date +%Y%m%d)
   cd audit/$(date +%Y%m%d)
   
   # Set time range for audit
   START_TIME="$(date -d '7 days ago' --iso-8601=seconds)"
   END_TIME="$(date --iso-8601=seconds)"
   
   # Get S3 deletion events
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObject \
     --start-time "$START_TIME" \
     --end-time "$END_TIME" \