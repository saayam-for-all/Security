import boto3
from botocore.exceptions import ClientError
from tabulate import tabulate

session = boto3.Session(profile_name="saayam")
s3 = session.client("s3")

'''
List all S3 buckets in the account.
For each bucket, check:
Public vs Private access. --- DONE
Bucket policies & ACLs. ---DONE
Encryption settings (KMS). ---DONE
Versioning status. ---DONE
Document findings in a table

'''
s3_buckets = []
s3_pab = []
s3_vers = []
s3_encryption = []
s3_policy_sts = []

def task1_get_buckets():
    buckets = s3.list_buckets()["Buckets"]
    if not buckets:
        print("No S3 Buckets Found")
        return
    
    for bucket in buckets:
        s3_buckets.append(bucket['Name'])
    
# Get Public Access Block configuration for each bucket
def task1_get_pab(bucket_name):
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        current_policy = response["PublicAccessBlockConfiguration"]
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NoSuchPublicAccessBlockConfiguration":
            print(f"❌ Public Access Block (PAB) Configuration Not Found")
            current_policy = None
        else:
            raise
    # Create a dictionary of public access block for each s3 bucket
    pab = {}
    pab[bucket_name] = []
    for policy, status in current_policy.items():
        if status != True:
            pab[bucket_name].append(f"{policy} = FALSE")
        else:
            pab[bucket_name].append(f"{policy} = TRUE")

    # If the public access block has a policy which is not true, add it to the s3_pab list
    if len(pab[bucket_name]) != 0:
        s3_pab.append(pab)

# Check public versus private access for each bucket
def task1_bucket_versioning(bucket_name):
    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)
        status = response.get("Status", "Disabled")
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        print(error_code)
        raise

    vers = {}
    vers[bucket_name] = []
    vers[bucket_name].append(status)
    s3_vers.append(vers)

# Check public versus private access for each bucket
def task1_bucket_encryption(bucket_name):
    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)
        current_encryption = response['ServerSideEncryptionConfiguration']
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ServerSideEncryptionConfiguration":
            print(f"❌ Server Side Encryption Not Found")
            current_encryption = None
        else:
            raise
    # sse is Server Side Encryption
    sse = {}
    sse[bucket_name] = []
    
    if not current_encryption:
        sse[bucket_name] = "No server side encryption settings found"
    else:
        rules = current_encryption['Rules'][0]
        encryption = rules['ApplyServerSideEncryptionByDefault']
        BucketKeyEnabled = rules['BucketKeyEnabled']
        # Check if SSEAlgorithm = AES256
        if encryption['SSEAlgorithm'] == 'AES256':
            # If SSE-S3 exists, it is a compliant S3 bucket
            sse[bucket_name] = f"SSE-S3 ({encryption['SSEAlgorithm']}) enabled. (BucketKeyEnabled={BucketKeyEnabled})"
        elif encryption['SSEAlgorithm'] == 'aws:kms':
            # If SSE-KMS exists, it is a compliant S3 bucket
            kms_key = rules['ApplyServerSideEncryptionByDefault'].get('KMSMasterKeyID')
            sse[bucket_name] = f"SSE-KMS (kms-key: {kms_key}) enabled. (BucketKeyEnabled={BucketKeyEnabled})"
        else:
            # If unknown SSE exists, assign it as non-compliant bucket ---- NEED TO KNOW HOW TO HANDLE?
            sse[bucket_name] = f"Unexpected Server Side Encryption Enabled: {encryption}"
    
    s3_encryption.append(sse)

def task1_bucket_policy(bucket_name):
    sts = {}
    sts[bucket_name] = []
    try:
        policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)['PolicyStatus']
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            sts[bucket_name] = 'No Bucket Policy Status Found'
            s3_policy_sts.append(sts)
            return False
        else:
            raise

    sts[bucket_name] = policy_status['IsPublic']
    s3_policy_sts.append(sts)

# TASK 1 - S3 Bucket Security Policies
def s3_sec_controls():
    task1_get_buckets()
    for bucket_name in s3_buckets:
        task1_get_pab(bucket_name)
        task1_bucket_versioning(bucket_name)
        task1_bucket_encryption(bucket_name)
        task1_bucket_policy(bucket_name)

    
def task1_print_report():
    print("\nTASK 1: S3 BUCKET REPORT")
    rows = []

    for bucket in s3_buckets:
        name = bucket
        versioning = None
        encryption = None
        pab = None
        policy = None

        # Check Versioniong
        for elm in s3_vers:
            if name in elm:
                versioning = elm[name][0]
                break
            else:
                versioning = 'None'

        # Check pab
        for elm in s3_pab:
            if name in elm:
                pab = ", \n".join(elm[name])
                break
            else:
                pab = 'None'
        
        # Check encryption
        for elm in s3_encryption:
            if name in elm:
                encryption = elm[name]
                break
            else:
                encryption = 'None'

        # Check Policy Status if is public
        for elm in s3_policy_sts:
            if name in elm:
                policy = elm[name]
                break
            else:
                policy = 'None'

        rows.append([name, versioning, pab, encryption, policy])

    headers = ["Bucket", "Versioning", "Public Access Block", "Encryption", "Is Public?"]

    print(tabulate(rows, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    s3_sec_controls()
    task1_print_report()