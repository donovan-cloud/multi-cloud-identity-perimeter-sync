import json
import boto3
import logging
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam_client = boto3.client('iam')

def lambda_handler(event, context):
    """
    Ingests cryptographically verified webhooks forwarded from Azure Entra ID.
    Enforces instantaneous session invalidation across corresponding AWS IAM surfaces.
    """
    logger.info(f"Received Inbound Identity Payload from Azure Gateway: {json.dumps(event)}")
    
    # Parse the inbound body from the API Gateway wrapper
    try:
        body = json.loads(event.get('body', '{}'))
    except Exception:
        body = event # Fallback for local unit simulation structures
        
    entra_upn = body.get('userPrincipalName')
    account_status = body.get('accountEnabled', True)
    risk_level = body.get('riskLevel', 'low')
    
    logger.info(f"Identity Profile: {entra_upn} | Enabled Status: {account_status} | Security Risk: {risk_level}")
    
    # Enforce revocation rules if account is disabled or marked as high security risk
    if not account_status or risk_level.lower() == 'high':
        # Translate corporate Entra UPN into the configured AWS IAM Role mapping pattern
        mapped_role_name = determine_aws_role_mapping(entra_upn)
        if mapped_role_name:
            revoke_active_aws_sessions(mapped_role_name)
            
    return {
        'statusCode': 200,
        'body': json.dumps('Cross-Cloud Identity Boundary Sync Execution Complete.')
    }

def determine_aws_role_mapping(upn):
    """
    Simulates identity provider federation translation mapping logic.
    Converts corporate email domain contexts to AWS deployment roles.
    """
    if "fintech.com" not in upn:
        logger.error(f"Security Alert: Received untrusted cross-cloud domain origin: {upn}")
        return None
        
    # Extract the user prefix handle to match local infrastructure standards
    user_handle = upn.split('@')[0]
    if "dev-lead" in user_handle:
        return "FinTech-Engineering-Lead-Role"
    return "FinTech-Standard-Developer-Role"

def revoke_active_aws_sessions(role_name):
    """
    Generates and applies an active inline policy condition to break open STS sessions.
    Injects a time boundary condition enforcing all issued tokens prior to now are rejected.
    """
    current_time_iso = datetime.now(timezone.utc).isoformat()
    
    # Enterprise standard logic to instantly revoke all active STS tokens for a role
    revocation_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {
                        "aws:TokenIssueTime": current_time_iso
                    }
                }
            }
        ]
    }
    
    logger.warning(f"INITIATING SESSIONS REVOCATION: Evicting all active access points for role: {role_name}")
    
    try:
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName='Emergency-Cross-Cloud-Session-Invalidation-Boundary',
            PolicyDocument=json.dumps(revocation_policy)
        )
        logger.info(f"SUCCESS: Mapped corporate identity terminated. AWS Role {role_name} hardened at timestamp {current_time_iso}")
    except Exception as error:
        logger.error(f"FAIL: Cross-cloud boundary propagation rejected by IAM API: {str(error)}")
        raise error
