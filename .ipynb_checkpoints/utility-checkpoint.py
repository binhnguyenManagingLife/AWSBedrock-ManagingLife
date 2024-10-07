import boto3
import random
import time
import json

suffix = random.randrange(200, 900)
boto3_session = boto3.session.Session()
region_name = boto3_session.region_name or 'ca-central-1'
iam_client = boto3_session.client('iam')
account_number = boto3.client('sts').get_caller_identity().get('Account')
identity = boto3.client('sts').get_caller_identity()['Arn']

encryption_policy_name = f"bedrock-sample-rag-sp-{suffix}"
network_policy_name = f"bedrock-sample-rag-np-{suffix}"
access_policy_name = f'bedrock-sample-rag-ap-{suffix}'
bedrock_execution_role_name = f'AmazonBedrockExecutionRoleForKnowledgeBase_{suffix}'
fm_policy_name = f'AmazonBedrockFoundationModelPolicyForKnowledgeBase_{suffix}'
s3_policy_name = f'AmazonBedrockS3PolicyForKnowledgeBase_{suffix}'
sm_policy_name = f'AmazonBedrockSecretPolicyForKnowledgeBase_{suffix}'
oss_policy_name = f'AmazonBedrockOSSPolicyForKnowledgeBase_{suffix}'


def retrieveAndGenerate(input, region = 'ca-central-1', sourceType= "S3", model_id = "anthropic.claude-3-sonnet-20240229-v1:0"):
    model_arn = f'arn:aws:bedrock:{region}::foundation-model/{model_id}'
    print (document_s3_uri)
    return bedrock_agent_client.retrieve_and_generate(
        input={
            'text': input
        },
        retrieveAndGenerateConfiguration={
            'type': 'EXTERNAL_SOURCES',
            'externalSourcesConfiguration': {
                'modelArn': model_arn,
                "sources": [
                    {
                        "sourceType": sourceType,
                        "s3Location": {
                            "uri": document_s3_uri
                        }
                    }
                ]
            }
        }
    )
    

def generate_message(bedrock_runtime, model_id, messages, max_tokens=512,top_p=1,temp=0.5,system=''):

    body=json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": messages,
            "temperature": temp,
            "top_p": top_p,
            "system": system
        }  
    )  
    
    response = bedrock_runtime.invoke_model(body=body, modelId=model_id)
    response_body = json.loads(response.get('body').read())

    return response_body


def invoke_bedrock_model(client, id, prompt, max_tokens=2000, temperature=0, top_p=0.9):
    response = ""
    try:
        response = client.converse(
            modelId=id,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ],
            inferenceConfig={
                "temperature": temperature,
                "maxTokens": max_tokens,
                "topP": top_p
            }
            #additionalModelRequestFields={
            #}
        )
    except Exception as e:
        print(e)
        result = "Model invocation error"
    try:
        result = response['output']['message']['content'][0]['text'] \
        + '\n--- Latency: ' + str(response['metrics']['latencyMs']) \
        + 'ms - Input tokens:' + str(response['usage']['inputTokens']) \
        + ' - Output tokens:' + str(response['usage']['outputTokens']) + ' ---\n'
        return result
    except Exception as e:
        print(e)
        result = "Output parsing error"
    return result

def test_aws_connection():
    try:
        # Create an S3 client (or use another AWS service)
        s3 = boto3.client('s3')
        
        # Attempt to list S3 buckets
        response = s3.list_buckets()
        
        # Print out bucket names to confirm connection
        print("Connected successfully! Buckets:")
        for bucket in response['Buckets']:
            print(f"  {bucket['Name']}")
    except NoCredentialsError:
        print("AWS credentials not found.")
    except PartialCredentialsError:
        print("Incomplete AWS credentials found.")
    except Exception as e:
        print(f"Error: {str(e)}")



def create_bedrock_execution_role(bucket_name):
    foundation_model_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "bedrock:InvokeModel",
                ],
                "Resource": [
                    f"arn:aws:bedrock:{region_name}::foundation-model/amazon.titan-embed-text-v1",
                    f"arn:aws:bedrock:{region_name}::foundation-model/amazon.titan-embed-text-v2:0"
                ]
            }
        ]
    }

    s3_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*"
                ],
                "Condition": {
                    "StringEquals": {
                        "aws:ResourceAccount": f"{account_number}"
                    }
                }
            }
        ]
    }

    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "bedrock.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    # create policies based on the policy documents
    fm_policy = iam_client.create_policy(
        PolicyName=fm_policy_name,
        PolicyDocument=json.dumps(foundation_model_policy_document),
        Description='Policy for accessing foundation model',
    )

    s3_policy = iam_client.create_policy(
        PolicyName=s3_policy_name,
        PolicyDocument=json.dumps(s3_policy_document),
        Description='Policy for reading documents from s3')

    # create bedrock execution role
    bedrock_kb_execution_role = iam_client.create_role(
        RoleName=bedrock_execution_role_name,
        AssumeRolePolicyDocument=json.dumps(assume_role_policy_document),
        Description='Amazon Bedrock Knowledge Base Execution Role for accessing OSS and S3',
        MaxSessionDuration=3600
    )

    # fetch arn of the policies and role created above
    bedrock_kb_execution_role_arn = bedrock_kb_execution_role['Role']['Arn']
    s3_policy_arn = s3_policy["Policy"]["Arn"]
    fm_policy_arn = fm_policy["Policy"]["Arn"]
    

    # attach policies to Amazon Bedrock execution role
    iam_client.attach_role_policy(
        RoleName=bedrock_kb_execution_role["Role"]["RoleName"],
        PolicyArn=fm_policy_arn
    )
    iam_client.attach_role_policy(
        RoleName=bedrock_kb_execution_role["Role"]["RoleName"],
        PolicyArn=s3_policy_arn
    )
    return bedrock_kb_execution_role


def create_oss_policy_attach_bedrock_execution_role(collection_id, bedrock_kb_execution_role):
    # define oss policy document
    oss_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "aoss:APIAccessAll"
                ],
                "Resource": [
                    f"arn:aws:aoss:{region_name}:{account_number}:collection/{collection_id}"
                ]
            }
        ]
    }
    oss_policy = iam_client.create_policy(
        PolicyName=oss_policy_name,
        PolicyDocument=json.dumps(oss_policy_document),
        Description='Policy for accessing opensearch serverless',
    )
    oss_policy_arn = oss_policy["Policy"]["Arn"]
    print("Opensearch serverless arn: ", oss_policy_arn)

    iam_client.attach_role_policy(
        RoleName=bedrock_kb_execution_role["Role"]["RoleName"],
        PolicyArn=oss_policy_arn
    )
    return None


def create_policies_in_oss(vector_store_name, aoss_client, bedrock_kb_execution_role_arn):
    encryption_policy = aoss_client.create_security_policy(
        name=encryption_policy_name,
        policy=json.dumps(
            {
                'Rules': [{'Resource': ['collection/' + vector_store_name],
                           'ResourceType': 'collection'}],
                'AWSOwnedKey': True
            }),
        type='encryption'
    )

    network_policy = aoss_client.create_security_policy(
        name=network_policy_name,
        policy=json.dumps(
            [
                {'Rules': [{'Resource': ['collection/' + vector_store_name],
                            'ResourceType': 'collection'}],
                 'AllowFromPublic': True}
            ]),
        type='network'
    )
    access_policy = aoss_client.create_access_policy(
        name=access_policy_name,
        policy=json.dumps(
            [
                {
                    'Rules': [
                        {
                            'Resource': ['collection/' + vector_store_name],
                            'Permission': [
                                'aoss:CreateCollectionItems',
                                'aoss:DeleteCollectionItems',
                                'aoss:UpdateCollectionItems',
                                'aoss:DescribeCollectionItems'],
                            'ResourceType': 'collection'
                        },
                        {
                            'Resource': ['index/' + vector_store_name + '/*'],
                            'Permission': [
                                'aoss:CreateIndex',
                                'aoss:DeleteIndex',
                                'aoss:UpdateIndex',
                                'aoss:DescribeIndex',
                                'aoss:ReadDocument',
                                'aoss:WriteDocument'],
                            'ResourceType': 'index'
                        }],
                    'Principal': [identity, bedrock_kb_execution_role_arn],
                    'Description': 'Easy data policy'}
            ]),
        type='data'
    )
    return encryption_policy, network_policy, access_policy


def delete_iam_role_and_policies():
    fm_policy_arn = f"arn:aws:iam::{account_number}:policy/{fm_policy_name}"
    s3_policy_arn = f"arn:aws:iam::{account_number}:policy/{s3_policy_name}"
    oss_policy_arn = f"arn:aws:iam::{account_number}:policy/{oss_policy_name}"
    sm_policy_arn = f"arn:aws:iam::{account_number}:policy/{sm_policy_name}"

    iam_client.detach_role_policy(
        RoleName=bedrock_execution_role_name,
        PolicyArn=s3_policy_arn
    )
    iam_client.detach_role_policy(
        RoleName=bedrock_execution_role_name,
        PolicyArn=fm_policy_arn
    )
    iam_client.detach_role_policy(
        RoleName=bedrock_execution_role_name,
        PolicyArn=oss_policy_arn
    )
    iam_client.detach_role_policy(
        RoleName=bedrock_execution_role_name,
        PolicyArn=sm_policy_arn
    )
    iam_client.delete_role(RoleName=bedrock_execution_role_name)
    iam_client.delete_policy(PolicyArn=s3_policy_arn)
    iam_client.delete_policy(PolicyArn=fm_policy_arn)
    iam_client.delete_policy(PolicyArn=oss_policy_arn)
    iam_client.delete_policy(PolicyArn=sm_policy_arn)
    return 0


def interactive_sleep(seconds: int):
    dots = ''
    for i in range(seconds):
        dots += '.'
        print(dots, end='\r')
        time.sleep(1)

def create_bedrock_execution_role_multi_ds(bucket_names = None, secrets_arns = None):
    
    # 0. Create bedrock execution role

    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "bedrock.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    
    # create bedrock execution role
    bedrock_kb_execution_role = iam_client.create_role(
        RoleName=bedrock_execution_role_name,
        AssumeRolePolicyDocument=json.dumps(assume_role_policy_document),
        Description='Amazon Bedrock Knowledge Base Execution Role for accessing OSS, secrets manager and S3',
        MaxSessionDuration=3600
    )

    # fetch arn of the role created above
    bedrock_kb_execution_role_arn = bedrock_kb_execution_role['Role']['Arn']

    # 1. Cretae and attach policy for foundation models
    foundation_model_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "bedrock:InvokeModel",
                ],
                "Resource": [
                    f"arn:aws:bedrock:{region_name}::foundation-model/amazon.titan-embed-text-v1",
                    f"arn:aws:bedrock:{region_name}::foundation-model/amazon.titan-embed-text-v2:0"
                ]
            }
        ]
    }
    
    fm_policy = iam_client.create_policy(
        PolicyName=fm_policy_name,
        PolicyDocument=json.dumps(foundation_model_policy_document),
        Description='Policy for accessing foundation model',
    )
  
    # fetch arn of this policy 
    fm_policy_arn = fm_policy["Policy"]["Arn"]
    
    # attach this policy to Amazon Bedrock execution role
    iam_client.attach_role_policy(
        RoleName=bedrock_kb_execution_role["Role"]["RoleName"],
        PolicyArn=fm_policy_arn
    )

    # 2. Cretae and attach policy for s3 bucket
    if bucket_names:
        s3_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:ListBucket"
                    ],
                    "Resource": [item for sublist in [[f'arn:aws:s3:::{bucket}', f'arn:aws:s3:::{bucket}/*'] for bucket in bucket_names] for item in sublist], 
                    "Condition": {
                        "StringEquals": {
                            "aws:ResourceAccount": f"{account_number}"
                        }
                    }
                }
            ]
        }
        # create policies based on the policy documents
        s3_policy = iam_client.create_policy(
            PolicyName=s3_policy_name,
            PolicyDocument=json.dumps(s3_policy_document),
            Description='Policy for reading documents from s3')

        # fetch arn of this policy 
        s3_policy_arn = s3_policy["Policy"]["Arn"]
        
        # attach this policy to Amazon Bedrock execution role
        iam_client.attach_role_policy(
            RoleName=bedrock_kb_execution_role["Role"]["RoleName"],
            PolicyArn=s3_policy_arn
        )

    # 3. Cretae and attach policy for secrets manager
    if secrets_arns:
        secrets_manager_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:PutSecretValue"
                    ],
                    "Resource": secrets_arns
                }
            ]
        }
        # create policies based on the policy documents
        
        secrets_manager_policy = iam_client.create_policy(
            PolicyName=sm_policy_name,
            PolicyDocument=json.dumps(secrets_manager_policy_document),
            Description='Policy for accessing secret manager',
        )

        # fetch arn of this policy
        sm_policy_arn = secrets_manager_policy["Policy"]["Arn"]

        # attach policy to Amazon Bedrock execution role
        iam_client.attach_role_policy(
            RoleName=bedrock_kb_execution_role["Role"]["RoleName"],
            PolicyArn=sm_policy_arn
        )
    
    return bedrock_kb_execution_role
