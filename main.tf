#tells terraform to download the AWS Plugin
terraform {
    required_providers {
        aws = {
            source = "hashicorp/aws"
            version = "~> 5.0"
        }
    }
}

#This is security account
provider "aws" {
    region = "us-east-1"
}

#This tells AWS to take python file and get it ready to run
resource "aws_lambda_function" "s3_remidator" {
    filename = "remediate.zip" # This will contain python code
    function_name = "S3_Public_Bucket_Blocker"
    role = aws_iam_role.lambda_exec_role.arn #The ID badge for the robot
    handler = "remediate.lambda_handler" #Tells AWS, when the robot wakes up, look inside remediate.py file and start running function named lambda_handler
    runtime = "python3.9" #tells AWS what language the robot speaks

    #This is Dry Run switch
    environment {
        variables = {
            DRY_RUN = "true"
        }
    }
}

resource "aws_iam_role" "lambda_exec_role" {
    name = "s3_remediator_role"

    #This says: allow Lambda service to use this badge
    assume_role_policy = jsonencode ({
        Version = "2012-10-17"
        Statement = [{
            Action = "sts:AssumeRole"
            Effect = "Allow"
            Principal = { Service = "lambda.amazonaws.com" }
        }]
    })
}

#The camera watching over resources / think of it like the eyes of the system
resource "aws_config_configuration_recorder" "main" {
    #build a recorder object and name it main
    name = "s3_recorder"
    #official name that will appear in the AWS Console
    role_arn = aws_iam_role.config_role.arn 
    #badge for the camera to watch things / Similar to the Lambda bot because everything needs permissions to look at S3 Buckets
}

#ON switch for camera
resource "aws_config_configuration_recorder_status" "main" {
    name = aws_config_configuration_recorder.main.name
    is_enabled = true
    depends_on = [aws_config_delivery_channel.main]
}
#Where to save "tapes" (footage of what happened like a security camera)
resource "aws_config_delivery_channel" "main" {
    name = "s3_delivery_channel"
    s3_bucket_name = aws_s3_bucket.config_logs.bucket
    #tells recorder, When you find a change, save the report in this S3 Bucket
}

# "Rulebook" so the camera knows what to look for
resource = "aws_config_config_rule" "s3_public_prohibited" {
    name = "s3-bucket-public-read-prohibited
    description = "Alerts if a bucket is public"

    source {
        owner = "AWS"
        #means we are using a "managed rule", AWS already wrote the rule to detect public buckets, we are just using it for this account
        source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
        #ID for law we want to enforce
    }
    #makes sure the recorder is running before the rule begins looking
    depends_on = [aws_config_configuration_recorder.main]
    #means don't turn on the power until the cable is plugged in(metaphorically)
}

#Tells RULE to send its findings to Lambda robot / like landline to call robot
resource "aws_lambda_permission" "allow_config" {
    statement_id = "AllowConfigInvocation"
    action = "lambda:InvokeFunction"
    #This specific function is the right to run code
    function_name = aws_lambda_function.s3_remediator.function_name
    #points to robot's real name
    principal = "config.amazonaws.com"
    #Says ONLY the AWS Config service is allowed to use this phone line to wake up the robot. Prevents random tampering.
}

#BUILDING THE VAULT FOR THE RECORDINGS

resource "aws_s3_bucket" "config_logs" {
    #tells AWS to create storage space called config_logs
    bucket = "my-security-audit-logs-${random_id.suffix.hex}" #must be globally unique
    #Use random id because S3 buckets cannot have the same name
    force_destroy = true #Allows terraform to delete it even if it has logs inside
    #Usually AWS wont let you delete buckets if it has files so this makes it easier to clean-up
}

#Double Lock - Blocking Public Access  
resource "aws_s3_bucket_public_access_block" "config_logs_block" {
    bucket = "aws_s3_bucket.config_logs.id" {
        block_public_acls = true
        block_public_policy = true
        ignore_public_acls = true
        restrict_public_buckets = true
    } 
}

#Permit to the vault door for Access

resource "aws_s3_bucket_policy" "allow_config_logging" {
    bucket = aws_s3_bucket.config_logs.id
    policy = jsoncode ({
        Version = "2012-10-17"
        Statement = [
            {
                Sid = "AllowConfigWrite"
                Effect = "Allow"
                Principal = { Service = "config.amazonaws.com" } #This is the who only the AWS Config service itself is allowed this permit
                Action = "s3:PutObject"
                #Only ability to upload logs / LEAST PRIVILAGE
                Resource = "${aws_s3_bucket.config_logs.arn}/*"
                #This is "where", the sensor can only upload inside the specific bucket
            }
        ]
    })
}

#Final birdge between the sensor and the robot

resource "aws_config_remediation_configuration" "s3_auto_fix" { # engine that handles auto fixes and name
    config_rule_name = aws_config_config_rule.s3_public_prohibited.name #Input / Tells the remediation engine Listen to the specific rule we created earlier
    resource_type = "AWS::S3::Bucket" #Confirms we are only searching for S3 buckets only
    target_type = "SSM_DOCUMENT" #Stands for Systems Manager and its like a pre-written recipe. Instead of writing our own Python code for every little task, we can use this library of pre-made fixes
    target_id = "AWS-PublishSNSnotification"

    automatic = true #IMPORTANT / turns this into a true automated project
    maximum_automatic_attempts = 5 #If a robot fails to close the bucket, it will try 5 more times
    retry_attempts_seconds = 60 #wait one minute between each try to not spam the system

    parameter {
        name = "AutomationAssumeRole" #Remediation Engine Badge(IAM) 
        static_value = aws_iam_role.remediation_role.arn
    }
}