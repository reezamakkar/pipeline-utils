import json
import time
import urllib.request
import base64
import hmac
import hashlib
import boto3
import re
from jose import jwk, jwt
from jose.utils import base64url_decode
from pynamodb.models import Model
from pynamodb.attributes import UnicodeAttribute, ListAttribute, BooleanAttribute, MapAttribute

class Whitelist(Model):
    """
    Map DynamoDB schema 
    """
    class Meta:
        table_name = "tlsint_whitelist"
    L1_method = ListAttribute(null=True)
    level = UnicodeAttribute(range_key=True)
    role = UnicodeAttribute(hash_key=True)
    L2_rules = ListAttribute(null=True)

class RuleEvaluator(object):
    def __init__(self, b):
        self.method_name = 'evaluate_' + str(b)

    def send_evaluate_result(self, a, b):
        method = getattr(self, self.method_name, lambda: False)
        return method(a, b)

    def evaluate_equals(self, a, b):
        return a == b

    def evaluate_contains(self, a, b):
        return b in a

    def evaluate_containsKey(self, a, b):
        return b in a


def load_jwks_keys(region, userpool_id):
    """
    It is recommended to download keys on cold start
    instead of re-downloading the public keys every time

    Parameters
    ----------
        region : str
            AWS region
        userpool_id : str
            Cognito UserPool Id
    """
    output = {
        'response': 'error',
        'message': ''
    }
    try:
        keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, userpool_id)
        with urllib.request.urlopen(keys_url) as f:
            response = f.read()
        keys = json.loads(response.decode('utf-8'))['keys']
        output['message'] = keys
        output['response'] = 'ok'
    except Exception as ex:
        output['message'] = 'Could not load cognito public keys: {}'.format(str(ex))
    return output


def verify_jwt_token(token, app_client_id, preloaded_keys=[], aws_region='', userpool_id=''):
    """
    This method verifies if a cognito JWT is valid ot not and returns claims if it is

    Parameters
    ----------
        token : str
            Token to be verified
        app_client_id : str
            UserPool App Client Id
        preloaded_keys : list, optional
            Public keys for cognito Userpool,
        aws_region : str, optional
            AWS region, required when preloaded_keys are not passed
        userpool_id : str, optional
            Cognito UserPool Id, required when preloaded_keys are not passed

    Returns
    -------
        dict
            response : str
            message : str or object

    """
    output = {
        'response': 'error',
        'message': ''
    }
    if not preloaded_keys and (not aws_region or not userpool_id):
        output['message'] = 'Error cognito public keys were not loaded due to ' \
                            'missing arguments passed to token verifier'
        return output

    keys = preloaded_keys
    if not keys and aws_region and userpool_id:
        result = load_jwks_keys(aws_region, userpool_id)
        if result['response'] == 'error':
            return result
        keys = result['message']

    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']
    key_matched = list(filter(lambda k: k['kid'] == kid, keys))

    if not key_matched:
        output['message'] = 'No matching public key found in jwks.json for passed token'
        return output

    # construct the public key
    public_key = jwk.construct(key_matched[0])

    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)

    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        output['message'] = 'Failed to verify token signature'
        return output

    # print('Token signature verified, fetching claims')
    claims = jwt.get_unverified_claims(token)

    # verify the token expiration
    if time.time() > claims['exp']:
        output['message'] = 'Token has expired'
        return output
    # Verify the Audience / app_client_id
    if claims['token_use'] == 'id':
        if claims['aud'] != app_client_id:
            output['message'] = 'Token was not issued for this audience/app client'
            return output
    elif claims['token_use'] == 'access':
        if claims['client_id'] != app_client_id:
            output['message'] = 'Token was not issued for this audience/app client'
            return output
    else:
        output['message'] = 'Token type not supported yet'
        return output

    output['response'] = 'ok'
    output['message'] = claims
    return output


def get_signature(username, client_id, secret_key):
    """
    Generates Secret Hash for AWS cognito User Pool Client

    Parameters
    ----------
        username
        client_id
        secret_key

    Returns
    -------
        str
    """
    digest = hmac.new(key=bytes(secret_key, 'utf8'),
                      msg=bytes(username + client_id, 'utf8'),
                      digestmod=hashlib.sha256
                      ).digest()
    signature = base64.b64encode(digest).decode()
    return signature


def authorize_level1(rules, input_method):
    """
    Returns a boolean value based on checks against level1 whitelist rules

    Parameters
    ----------
        rules: dict
            Level1 whitelist rules for a given role
        input_method: str
            The tlsint method from the input request

    Returns
    -------
        Boolean
    """
    for rule in rules:
        if re.match(rule, input_method):
            print(f"Level 1 Authorization passed")
            return True
    return False


def authorize_level2(rules, input_method, input_params):
    """
    Returns a boolean value based on checks against level2 whitelist rules

    Parameters
    ----------
        rules: dict
            Level2 whitelist rules for a given role
        input_method: str
            The tlsint method from the input request
        input_params: dict
            The method params from input tlsint api request

    Returns
    -------
        Boolean
    """

    if input_method not in rules:
        print(f"No method named {input_method} available in level2 whitelist")
        return True
    for item in rules[input_method]:
        evaluator_obj = RuleEvaluator(item['operator'])
        check_passed = evaluator_obj.send_evaluate_result(input_params[item['key']], item['value'])
        if check_passed:
            print(f"Level 2 Authorization passed")
            return True
    return False


def authorize_tlsint_request(user_claims, request_body):
    """
    This method authorizes the input tlsint request by two-level whitelisting

    Parameters
    ----------
        user_claims: dict
            Requesting user's identity details from cognito
        request_body: dict
            Body of the input tlsint api request

    Returns
    -------
        dict
            response : str
            message : str or object
    """

    output = {
        'response': 'error',
        'message': f"User {user_claims['cognito:username']} is not authorized to make this toolsint api call."
    }
    if 'cognito:groups' not in user_claims:
        output['message'] = f"Authorization Error: No role is assigned to the user {user_claims['cognito:username']}."
        return output

    roles = user_claims['cognito:groups']

    l1_rules = get_l1_rules(roles)
    if l1_rules['response'] == 'error':
        return l1_rules
    l1_rules = l1_rules['message']

    l2_rules = get_l2_rules(roles)
    if l2_rules['response'] == 'error':
        return l2_rules
    l2_rules = l2_rules['message']

    authorized = False

    for role in roles:
        if role not in l1_rules:
            continue
        level1_passed = authorize_level1(l1_rules[role], request_body['method'])
        if not level1_passed:
            continue

        level2_passed = True
        if l2_rules and role in l2_rules:
            level2_passed = authorize_level2(l2_rules[role], request_body['method'], request_body['params'])
            if not level2_passed:
                output['message'] = f"[Level2]: User {user_claims['cognito:username']} is not authorized to make this " \
                                    f"toolsint api call. "
                return output
        if level1_passed and level2_passed:
            authorized = True
            break

    if authorized:
        output['response'] = 'ok'
        output['message'] = ''

    return output


def get_l1_rules(roles):
    output= {
        'response': "error",
        'message': {}
    }

    for role in roles:
        try:
            queried_data = Whitelist.get(role,"L1")
            output['message'][role] = queried_data.L1_method
        except Exception as e:
            output['message'] = f"Unable to fetch L1 records for ${role}"
            return output
    output['response'] = 'ok'
    return output


def get_l2_rules(roles):
    output = {
        'response' : 'error',
        'message' : {}
    }
    data = {}
    final_data = {}
    for role in roles:
        final_data[role] = dict()
        try:
            queried_data = Whitelist.get(role,"L2")
        except Whitelist.DoesNotExist: # If no entry for a role, then continue
            continue
        except Exception as ex:
            output['Message'] = f'Unable to fetch records for role ${role}: {str(ex)} '
            return output
        else:
            unique_method = []

            for item in queried_data.L2_rules:
                unique_method.append(item['method'])
            unique_method = set(unique_method)   # Get unique methods for a role
            
            for item in unique_method:
                final_data[role][item] = []  # Reset the final[role] so it contains only map where data[method] == item
                for data in queried_data.L2_rules:
                    if data['method'] == item:
                        final_data[role][item].append(data)
            
    output['response'] = 'ok'
    output['message'] = final_data
    return output

def basic_token_auth_flow(auth_header, userpool_id, app_client_id):
    """
    Authenticates and generates ID token for username and pass passed through authorization header

    Parameters
    ----------
        auth_header : str
            Authorization header
        userpool_id : str
            Cognito UserPool Id the user needs to be authenticated against
        app_client_id : str
            Cognito UserPool App Client Id the user needs to be authenticated against

    Returns
    -------

    """
    output = {
        'response': 'error',
        'message': ''
    }
    cognito = boto3.client('cognito-idp')
    try:
        auth_cred = base64.b64decode(str(auth_header).lstrip('Basic')).decode("utf-8")
        username, password = auth_cred.split(":")

        admin_login_payload = {
            'UserPoolId': userpool_id,
            'ClientId': app_client_id
        }

        app_client = cognito.describe_user_pool_client(**admin_login_payload)
        if 'UserPoolClient' not in app_client or not app_client['UserPoolClient']:
            output['message'] = 'UserPool App client was not found'
            return output

        admin_login_payload = {
            'UserPoolId': userpool_id,
            'ClientId': app_client_id,
            'AuthFlow': 'ADMIN_NO_SRP_AUTH',
            'AuthParameters': {
                'USERNAME': username,
                'PASSWORD': password
            }
        }
        # Set Client Secret if Userpool client needs a secret hashed
        if 'ClientSecret' in app_client['UserPoolClient'] and app_client['UserPoolClient']['ClientSecret']:
            admin_login_payload['AuthParameters']['SECRET_HASH'] = get_signature(username, app_client_id,
                                                                                 app_client['UserPoolClient'][
                                                                                     'ClientSecret'])
        result = cognito.admin_initiate_auth(**admin_login_payload)

        # This part is for completing user registration in cognito so we can test out multiple users
        # This will be removed later
        if 'ChallengeName' in result and result.get('ChallengeName') == 'NEW_PASSWORD_REQUIRED':
            challenge_name = result.get('ChallengeName')
            session = result.get('Session')
            finish_reg = {
                'UserPoolId': userpool_id,
                'ClientId': app_client_id,
                'ChallengeName': challenge_name,
                'Session': session,
                'ChallengeResponses': {
                    'USERNAME': username,
                    'NEW_PASSWORD': password
                }
            }

            finish_reg['ChallengeResponses']['SECRET_HASH'] = admin_login_payload['AuthParameters']['SECRET_HASH']

            response = cognito.admin_respond_to_auth_challenge(**finish_reg)
            # re authenticate, after challenge requirement has been satisfied
            result = cognito.admin_initiate_auth(**admin_login_payload)

        if "AuthenticationResult" not in result:
            output['message'] = 'Failed to authenticate via Cognito'
            return output

        output['response'] = 'ok'
        output['message'] = result['AuthenticationResult']
    except cognito.exceptions.NotAuthorizedException as aex:
        output['message'] = str(aex)
    except Exception as ex:
        output['message'] = f"Encountered exception {repr(ex)}"

    return output


# For testing locally
if __name__ == '__main__':
    auth = 'Basic aXRhdXRvbWF0aW9uQGN2ZW50LmNvbTp2ZHlLRFhmUTZjaml0byE='
    userpool = 'us-east-1_khSiHGGVE'
    client = '7ghe1nur5ed8buiforgbre8aiq'
    request_body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "f5_update_data_group",
        "params": {
            "cluster": "mg20",
            "name": "L2_LIVE_DEPLOY",
            "records": [
                {
                    "name": "blue"
                }
            ]
        }
    }

    region = userpool.split('_')[0]
    args = {
        'auth_header': auth,
        'userpool_id': userpool,
        'app_client_id': client
    }
    boto3.setup_default_session(region_name=region)
    authentication_result = basic_token_auth_flow(**args)
    if authentication_result['response'] == 'error':
        print(authentication_result)
        exit()
    args = {
        'token': authentication_result['message']['IdToken'],
        'aws_region': region,
        'userpool_id': userpool,
        'app_client_id': client
    }
    user_claims = verify_jwt_token(**args)['message']
    result = authorize_tlsint_request(user_claims, request_body)
    print(result)
