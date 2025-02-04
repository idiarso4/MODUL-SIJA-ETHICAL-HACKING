# Praktikum Modul 8: Cloud Security

## Pendahuluan

Praktikum ini fokus pada implementasi keamanan dalam lingkungan cloud. Siswa akan mempelajari dan mempraktikkan berbagai aspek keamanan cloud, termasuk konfigurasi infrastruktur, manajemen identitas, dan pengamanan data.

## Tujuan Pembelajaran

Setelah menyelesaikan praktikum ini, siswa diharapkan mampu:
1. Mengkonfigurasi keamanan cloud infrastructure
2. Mengimplementasikan IAM policies
3. Mengamankan data dan aplikasi cloud
4. Melakukan monitoring dan logging
5. Menerapkan security best practices

## Persiapan Lab Environment

### A. AWS Setup

1. **Account Setup**
   ```bash
   # Configure AWS CLI
   aws configure
   
   # Verify configuration
   aws sts get-caller-identity
   ```

2. **Security Groups**
   ```bash
   # Create security group
   aws ec2 create-security-group \
       --group-name WebServerSG \
       --description "Web Server Security Group"
   
   # Add inbound rules
   aws ec2 authorize-security-group-ingress \
       --group-name WebServerSG \
       --protocol tcp \
       --port 80 \
       --cidr 0.0.0.0/0
   ```

### B. Azure Setup

1. **Resource Group**
   ```bash
   # Create resource group
   az group create \
       --name SecurityLab \
       --location eastus
   
   # Create network security group
   az network nsg create \
       --resource-group SecurityLab \
       --name WebNSG
   ```

2. **Network Rules**
   ```bash
   # Add security rules
   az network nsg rule create \
       --resource-group SecurityLab \
       --nsg-name WebNSG \
       --name allow-http \
       --protocol tcp \
       --priority 100 \
       --destination-port-range 80
   ```

## Lab 1: Identity and Access Management

### A. AWS IAM

1. **User Management**
   ```bash
   # Create user
   aws iam create-user --user-name test-user
   
   # Create access key
   aws iam create-access-key --user-name test-user
   
   # Attach policy
   aws iam attach-user-policy \
       --user-name test-user \
       --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
   ```

2. **Role Management**
   ```bash
   # Create role
   aws iam create-role \
       --role-name S3AccessRole \
       --assume-role-policy-document file://trust-policy.json
   
   # Attach policy
   aws iam attach-role-policy \
       --role-name S3AccessRole \
       --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
   ```

### B. Azure RBAC

1. **Role Assignment**
   ```bash
   # Create custom role
   az role definition create --role-definition @custom-role.json
   
   # Assign role
   az role assignment create \
       --assignee user@example.com \
       --role "Reader" \
       --scope /subscriptions/{subscription-id}
   ```

2. **Policy Management**
   ```bash
   # Create policy
   az policy definition create \
       --name 'require-tag-owner' \
       --rules @policy.json
   
   # Assign policy
   az policy assignment create \
       --name 'require-tag-owner' \
       --policy 'require-tag-owner'
   ```

## Lab 2: Network Security

### A. Virtual Networks

1. **VPC Configuration**
   ```bash
   # Create VPC
   aws ec2 create-vpc --cidr-block 10.0.0.0/16
   
   # Create subnet
   aws ec2 create-subnet \
       --vpc-id vpc-xxx \
       --cidr-block 10.0.1.0/24
   ```

2. **Network ACLs**
   ```bash
   # Create NACL
   aws ec2 create-network-acl --vpc-id vpc-xxx
   
   # Add rules
   aws ec2 create-network-acl-entry \
       --network-acl-id acl-xxx \
       --rule-number 100 \
       --protocol tcp \
       --port-range From=80,To=80 \
       --cidr-block 0.0.0.0/0 \
       --rule-action allow \
       --ingress
   ```

### B. Security Groups

1. **Web Server Security**
   ```bash
   # Create security group
   aws ec2 create-security-group \
       --group-name WebSG \
       --description "Web Security Group"
   
   # Configure rules
   aws ec2 authorize-security-group-ingress \
       --group-id sg-xxx \
       --protocol tcp \
       --port 443 \
       --cidr 0.0.0.0/0
   ```

2. **Database Security**
   ```bash
   # Create DB security group
   aws ec2 create-security-group \
       --group-name DBSG \
       --description "Database Security Group"
   
   # Allow web tier access
   aws ec2 authorize-security-group-ingress \
       --group-id sg-xxx \
       --protocol tcp \
       --port 3306 \
       --source-group sg-web
   ```

## Lab 3: Data Security

### A. Encryption

1. **S3 Encryption**
   ```bash
   # Enable bucket encryption
   aws s3api put-bucket-encryption \
       --bucket my-secure-bucket \
       --server-side-encryption-configuration file://encryption.json
   
   # Upload encrypted object
   aws s3 cp file.txt s3://my-secure-bucket/ \
       --sse aws:kms \
       --sse-kms-key-id key-id
   ```

2. **KMS Management**
   ```bash
   # Create key
   aws kms create-key \
       --description "Data encryption key"
   
   # Create alias
   aws kms create-alias \
       --alias-name alias/data-key \
       --target-key-id key-id
   ```

### B. Access Control

1. **Bucket Policies**
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Sid": "PublicReadGetObject",
               "Effect": "Allow",
               "Principal": "*",
               "Action": "s3:GetObject",
               "Resource": "arn:aws:s3:::my-bucket/*",
               "Condition": {
                   "IpAddress": {
                       "aws:SourceIp": "192.168.1.0/24"
                   }
               }
           }
       ]
   }
   ```

2. **CORS Configuration**
   ```json
   {
       "CORSRules": [
           {
               "AllowedOrigins": ["https://www.example.com"],
               "AllowedMethods": ["GET"],
               "MaxAgeSeconds": 3000,
               "AllowedHeaders": ["Authorization"]
           }
       ]
   }
   ```

## Lab 4: Monitoring and Logging

### A. CloudWatch

1. **Metric Monitoring**
   ```bash
   # Create alarm
   aws cloudwatch put-metric-alarm \
       --alarm-name cpu-utilization \
       --metric-name CPUUtilization \
       --namespace AWS/EC2 \
       --statistic Average \
       --period 300 \
       --threshold 70 \
       --comparison-operator GreaterThanThreshold \
       --evaluation-periods 2 \
       --alarm-actions arn:aws:sns:region:account-id:topic
   ```

2. **Log Analysis**
   ```bash
   # Create log group
   aws logs create-log-group \
       --log-group-name /aws/ec2/webserver
   
   # Create metric filter
   aws logs put-metric-filter \
       --log-group-name /aws/ec2/webserver \
       --filter-name errors \
       --filter-pattern "ERROR" \
       --metric-transformations \
           metricName=ErrorCount,metricNamespace=WebServer,metricValue=1
   ```

### B. Security Hub

1. **Security Findings**
   ```bash
   # Enable Security Hub
   aws securityhub enable-security-hub
   
   # Get findings
   aws securityhub get-findings \
       --filters '{"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}]}'
   ```

2. **Compliance Checks**
   ```bash
   # Enable standards
   aws securityhub batch-enable-standards \
       --standards-subscription-requests \
           '[{"StandardsArn":"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"}]'
   
   # Get compliance status
   aws securityhub get-enabled-standards
   ```

## Evaluasi

### A. Kriteria Penilaian

1. **Technical Skills (40%)**
   - Configuration
   - Implementation
   - Security controls
   - Problem solving

2. **Documentation (30%)**
   - Setup guide
   - Security policies
   - Configurations
   - Best practices

3. **Analysis (30%)**
   - Security assessment
   - Risk analysis
   - Mitigation strategies
   - Recommendations

### B. Deliverables

1. **Lab Report**
   - Setup documentation
   - Security configurations
   - Implementation details
   - Security findings
   - Recommendations

2. **Presentation**
   - 15 minutes
   - Live demo
   - Q&A session
   - Technical depth

## Referensi

1. AWS Security Documentation
2. Azure Security Best Practices
3. Cloud Security Alliance Guidelines
4. NIST Cloud Computing Standards

## Appendix

### A. Tool Commands

1. **AWS CLI**
   ```bash
   # List users
   aws iam list-users
   
   # List buckets
   aws s3 ls
   
   # Describe instances
   aws ec2 describe-instances
   ```

2. **Azure CLI**
   ```bash
   # List resources
   az resource list
   
   # List roles
   az role definition list
   
   # List policies
   az policy definition list
   ```

### B. Configuration Files

1. **Security Group**
   ```json
   {
       "GroupName": "WebServerSG",
       "Description": "Web Server Security Group",
       "IpPermissions": [
           {
               "IpProtocol": "tcp",
               "FromPort": 80,
               "ToPort": 80,
               "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
           }
       ]
   }
   ```

2. **IAM Policy**
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": [
                   "s3:GetObject",
                   "s3:PutObject"
               ],
               "Resource": "arn:aws:s3:::example-bucket/*"
           }
       ]
   }
   ```

### C. Security Checklist

1. **Infrastructure Security**
   - [ ] Network segmentation
   - [ ] Security groups
   - [ ] Access controls
   - [ ] Encryption
   - [ ] Monitoring
   - [ ] Backup
   - [ ] Disaster recovery
   - [ ] Incident response

2. **Data Security**
   - [ ] Encryption at rest
   - [ ] Encryption in transit
   - [ ] Access controls
   - [ ] Key management
   - [ ] Backup
   - [ ] Retention
   - [ ] Compliance
   - [ ] Auditing
