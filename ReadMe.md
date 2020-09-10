
# Cloudops Base APIs  

Author: Kaila, Sukhwinder Singh

## Description:

  This project hold CloudOps APIs backed by lambda functions.

  For authentication this project uses Cognito UserPool.
  API gateway uses Cognito Authorizer to validate Authorization token and once request is validated, API gateway forwards requests to lambda functions.

  Refer to flow diagram at end of this doc.

## Deploy:

### PreRequisites:  
* cvent-aws-cli  
* serverless cli: https://serverless.com/cli/  

### To deploy stack follow instructions below:
```  
sls plugin install -n serverless-python-requirements
sls plugin install -n serverless-plugin-scripts
sls plugin install -n serverless-domain-manager
serverless deploy
```  

## Few other useful commands:

### Command to change user password in Cognito User Pool  

`aws cognito-idp admin-set-user-password --user-pool-id <user_pool_id> --username <username> --password <password> --permanent --profile cvent-sandbox`

#### Flow Diagram
![flow diag](etc/flow_diag.png)

References:
* https://snyk.io/blog/10-serverless-security-best-practices/
* https://serverless.com/framework/docs/providers/aws/guide/layers/#aws---layers
* https://medium.com/@Da_vidgf/using-cognito-for-users-management-in-your-serverless-application-1695fec9e225
* https://serverless.com/blog/serverless-api-gateway-domain/
