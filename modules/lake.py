import os
import glob
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

def sync_to_s3():
    bucket_name = os.environ.get('AWS_S3_BUCKET')
    
    if not bucket_name:
        print("[!] S3 Sync Aborted: 'KESTREL_S3_BUCKET' environment variable not set.")
        return

    print(f"\n[*] PROJECT LAKE: Initiating Data Sync to S3 Bucket ({bucket_name})...")
    
    try:
        s3 = boto3.client('s3')
    except Exception as e:
        print(f"  [!] Failed to initialize boto3 client: {e}")
        return

    # Gather all operational data
    files_to_upload = []
    files_to_upload.extend(glob.glob('data/sessions/*.db'))
    files_to_upload.extend(glob.glob('docs/*')) # The SaaS MVP files
    
    if os.path.exists('data/training_ledger.csv'):
        files_to_upload.append('data/training_ledger.csv')

    success_count = 0
    for file_path in files_to_upload:
        # We use the file path as the S3 object key to preserve folder structure
        s3_key = file_path 
        try:
            s3.upload_file(file_path, bucket_name, s3_key)
            print(f"  [+] Synced: {file_path}")
            success_count += 1
        except NoCredentialsError:
            print("  [!] AWS credentials not found. Sync aborted.")
            return
        except PartialCredentialsError:
            print("  [!] Incomplete AWS credentials. Sync aborted.")
            return
        except Exception as e:
            print(f"  [!] Failed to upload {file_path}: {e}")
            
    print(f"[+] S3 Data Lake Sync Complete. {success_count} files secured.")

if __name__ == "__main__":
    sync_to_s3()
