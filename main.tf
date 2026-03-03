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
    handler = "remediate.lambda_handler #Tells AWS, "when the robot wakes up, look inside remediate.py file and start running function named lambda_handler"
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

#The camera watching over resources
resource "aws_config_configuration_recorder "main" {
    name = "s3_recorder"
    role_arn = aws_iam_role.config_role.arn #badge for the camera to watch things
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
}

# "Rulebook" so the camera knows what to look for
resource = "aws_config_config_rule" "s3_public_prohibited" {
    name = "s3-bucket-public-read-s3_public_prohibited
    description = "Alerts if a bucket is public"

    source {
        owner = "AWS"
        source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    }
    #makes sure the recorder is running before the rule begins looking
    depends_on = [aws_config_configuration_recorder.main]
}

#Tells RULE to send its findings to Lambda robot
resource "aws_lambda_permission" "allow_config" {
    statement_id = "AllowConfigInvocation"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.s3_remediator.function_name
    principal = "config.amazonaws.com"
}

