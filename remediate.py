import boto3
import os
import json

def lambda_handler(event, context):
    #Connect to s3 service
    s3 = boto3.client('s3')
    #Check to see if in test mode
    #Pull information from main.tf
    DRY_RUN = os.environ.get()

    #Get the name of bucket that triggered alarm
    bucket_name = event['detail']['requestParameters']['bucketName']

    print(f"Checking Bucket: {bucket_name}")

    if DRY_RUN:
        print("DRY_RUN: I found that {bucket_name} is public, but im not locking it.")
        return { 'status': 'checked' }
    
    #locking the bucket
    s3.put_public_access_block(
        Bucket=bucket_name, PublicAccessBlockConfigurations={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True,
        }
    )
    print("SUCCESS: {bucket_names} has been locked.")
    


