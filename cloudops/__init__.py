import json
import logging
import os
import sys
import base64
import yaml
import boto3
import requests
import uuid

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


def get_config():
    """
    The function to read local configs from a yaml file

    Returns
    -------
        configurations from yaml file in python object
    """
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open("{0}/config.yaml".format(dir_path), 'r') as ymlfile:
        cfg = yaml.safe_load(ymlfile)

    return cfg


def get_parameter_store_config(config):
    """
    This function loads configs from parameter store in dictionary

    Parameters
    ----------
        config: Pass dictionary of all parameter stores to be loaded into returning config

    Returns
    ------
        For each key in parameter value will be replaced by value from parameter store
    """
    parameter_store = config
    ps_keys = list(parameter_store.keys())
    ssm = boto3.client('ssm')
    LOGGER.info(f"Loading configurations from Parameter Store for {config}")
    for ps_key in ps_keys:
        ps_name = parameter_store[ps_key]
        result = ssm.get_parameter(
            Name=ps_name,
            WithDecryption=True
        )
        parameter_store[ps_key] = result['Parameter']['Value']
    return parameter_store


def get_basic_auth_token(username, password):
    """
    This function return authentication token that
    can be used for Basic authentication for API calls

    Parameters
    ----------
        username:   Username
        password:   Password
    """
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode('ascii')
    return f"Basic {token}"


def get_file_from_s3(bucket_name, file_name, json_parse=True):
    """
    The function to read contents of file in S3
    if json file is being read, to convert file from json string to python object
    set json_parse argument to true

    Parameters
    ----------
        bucket_name:    S3 bucket name
        file_name:      S3 file path in bucket
        json_parse:     if file is json file, then parse. Default: True

    Returns
    ------
        Contents of file in python object
    """
    s3_client = boto3.client('s3')
    s3_file = s3_client.get_object(Bucket=bucket_name, Key=file_name)
    try:
        file_contents = s3_file['Body'].read()
        if json_parse:
            file_contents = json.loads(file_contents)
    except Exception as exc:
        LOGGER.error('Encountered error reading s3 file')
        raise exc
    return file_contents


def get_cors_headers():
    """
    The function to centrally manage cors headers for any source
    TODO: parameterize and support for restricted origins as passed in args
    """
    return {
        "X-Requested-With": '*',
        "Access-Control-Allow-Headers":
            'Content-Type,X-Amz-Date,Authorization,X-Api-Key,x-requested-with',
        "Access-Control-Allow-Origin": '*',
        "Access-Control-Allow-Methods": 'POST,GET,OPTIONS'
    }


# ----- functions to send REST responses in appropriate format  -----
def make_proxy_response(http_code, body_model, headers=None, multi_value_headers=False):
    """
    The function to tailor the lambda output for lambda-proxy type api-gateway endpoint

    Parameters
    ----------
        http_code:  HTTP status code that api end point should return the response with
        headers:    HTTP response headers
        body_model:      Lambda output to be returned with response

    """
    if not headers and not isinstance(headers, dict):
        headers = get_cors_headers()
    response = {
        "isBase64Encoded": False,
        "statusCode": int(http_code),
        "body": json.dumps(body_model)
    }
    if multi_value_headers:
        headers = {k: v if isinstance(v, list) else [v] for k, v in headers.items()}
        response['multiValueHeaders'] = headers
    else:
        response["headers"] = headers
    return response


def make_alb_response(http_code, body_model, headers=None, multi_value_headers=True):
    """
    The function to tailor the lambda output for ALB type endpoint

    Parameters
    ----------
        http_code:      HTTP status code that api end point should return the response with
        body_model:     Lambda output to be returned with response
        headers:        HTTP response headers
        multi_value_headers : bool, optional
            For multi value headers response headers are required to be set differently
            https://aws.amazon.com/blogs/compute/support-for-multi-value-parameters-in-amazon-api-gateway/
    """
    return make_proxy_response(http_code, body_model, headers, multi_value_headers)


def return_alb_response(status_code, response_code, message, headers=None, multi_value_headers=True,
                        jsonrpc_response=False):
    """
    The function normalized commonly used lambda output for alb type endpoint

    Parameters
    ----------
        status_code:    HTTP status code that api end point should return the response with
        response_code:  Lambda status, 0 = success, 1 = failed/error
        message:        Lambda output to be returned with response
        headers:    dict, optional
            Response headers, Pass headers in dict format
        multi_value_headers:    bool, optional
            Set to false if ALB is not configured for multi valued headers
        jsonrpc_response: bool, optional
            Format output body into jsonrpc
    """
    if response_code == 0:
        response_body = {'response': 'ok', 'message': message}
        if jsonrpc_response:
            response_body = {
                'jsonrpc': '2.0',
                'id': message['id'] if 'id' in message else "1",
                'result': message
            }
        return make_alb_response(status_code, response_body, headers, multi_value_headers)
    else:
        response_body = {'response': 'error', 'message': message}
        if jsonrpc_response:
            response_body = {
                'jsonrpc': '2.0',
                'id': message['id'] if 'id' in message else "1",
                'error': {
                    'code': response_code,
                    'message': str(message)
                }
            }
        return make_alb_response(status_code, response_body, headers, multi_value_headers)


def return_response(status_code, response_code, message, headers=None, multi_value_headers=False,
                    jsonrpc_response=False):
    """
    The function normalized commonly used lambda output for lambda-proxy type api-gateway endpoint

    Parameters
    ----------
        headers:    dict, optional
            Response headers, Pass headers in dict format
        status_code:    HTTP status code that api end point should return the response with
        response_code:  Lambda status, 0 = success, 1 = failed/error
        message:        Lambda output to be returned with response
    """
    if response_code == 0:
        response_body = {'response': 'ok', 'message': message}
        if jsonrpc_response:
            response_body = {
                'jsonrpc': '2.0',
                'id': message['id'] if 'id' in message else "1",
                'result': message
            }
        return make_proxy_response(status_code, response_body, headers, multi_value_headers)
    else:
        response_body = {'response': 'error', 'message': message}
        if jsonrpc_response:
            response_body = {
                'jsonrpc': '2.0',
                'id': message['id'] if 'id' in message else "1",
                'error': {
                    'code': response_code,
                    'message': str(message)
                }
            }
        return make_proxy_response(status_code, response_body, headers, multi_value_headers)


# ----- end of return response -----


def toolsint_call(options, data):
    """
    This function is to provides a generic method to make toolsint api calls

    Parameters
    ----------
        options:
            api_endpoint:   URL of ToolsInt endpoint
            toolsint_user:  Credentials required for authentication
            toolsint_pass:  Credentials required for authentication
        data:               ToolsInt Request payload to be sent
    """
    api_url = options['api_endpoint']
    auth = get_basic_auth_token(
        options['toolsint_user'],
        options['toolsint_pass'])
    payload = data

    if 'id' not in payload or not payload['id']:
        payload['id'] = uuid.uuid4().hex  # generates alpha numeric random id

    if 'jsonrpc' not in payload or not payload['jsonrpc']:
        payload['jsonrpc'] = '2.0'
    # sending get request and saving the response as response object
    result = requests.post(
        url=api_url,
        data=json.dumps(payload),
        verify=False,
        headers={
            'Accept': 'application/json',
            'Authorization': auth})
    # if result['id'] != payload['id']:
    #     LOGGER.error(f"Found mismatch in request and response id")
    if 'error' in result:
        LOGGER.error(
            f"ToolsInt Api call failed: Error: {result.error} Request: {data}")
    else:
        LOGGER.debug(
            f"ToolsInt API call succeeded: Request: {data}")
    return result


def invoke_lambda(lambda_name, lambda_payload):
    """
    This method is a utility method for invoking a lambda

    Parameters
    ----------
        lambda_name : str
            Lambda to be invoked
        lambda_payload : object
            Lambda Payload
    """
    try:
        LOGGER.debug(f"Sending request to '{lambda_name}' method: {lambda_payload}")
        client = boto3.client('lambda')
        invoke_response = client.invoke(FunctionName=lambda_name,
                                        InvocationType="RequestResponse",
                                        Payload=json.dumps(lambda_payload))
        response = json.loads(invoke_response['Payload'].read())
    except Exception as ex:
        LOGGER.debug(f"Error encountered while invoking lambda method '{lambda_name}': {repr(ex)}")

    return response
