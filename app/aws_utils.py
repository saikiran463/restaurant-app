
import boto3
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# AWS Credentials and Regions
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'ap-south-1')
DYNAMODB_REGION = os.getenv('DYNAMODB_REGION', AWS_REGION)
SNS_REGION = os.getenv('SNS_REGION', AWS_REGION)

# DynamoDB (support multiple tables)
dynamodb = boto3.resource(
    'dynamodb',
    region_name=DYNAMODB_REGION,
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
)

def get_table(table_name):
    return dynamodb.Table(table_name)

# SNS
SNS_TOPIC_ARN = os.getenv('SNS_TOPIC_ARN')
sns = boto3.client(
    'sns',
    region_name=SNS_REGION,
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
)

def publish_sns_message(message):
    response = sns.publish(TopicArn=SNS_TOPIC_ARN, Message=message)
    return response

# S3
S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
s3 = boto3.client(
    's3',
    region_name=AWS_REGION,
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
)

def upload_to_s3(file_obj, filename):
    s3.upload_fileobj(file_obj, S3_BUCKET_NAME, filename)
    return f'https://{S3_BUCKET_NAME}.s3.amazonaws.com/{filename}'
