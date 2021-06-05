#!/usr/bin/python3
# -*- coding: utf-8 -*-
import boto3
import datetime
import gzip
import urllib
import logging
from requests_aws4auth import AWS4Auth
import requests
from io import BytesIO
import re
import os
import json
import time
from elasticsearch import Elasticsearch, RequestsHttpConnection
from elasticsearch import helpers
from botocore.client import Config


aws_region = os.environ.get('REGION')
service = os.environ.get('SERVICE', "es")
es_index_prefix = os.environ.get('ES_INDEX_PREFIX', "alb-logs")
es_index_doc_type = os.environ.get('ES_INDEX_DOC_TYPE')
es_endpoint = os.environ.get('ES_ENDPOINT')
es_kibana_endpoint = os.environ.get('ES_KIBANA_ENDPOINT')
es_bulk_chunk_size = os.environ.get('ES_BULK_CHUNK_SIZE', "500")
es_bulk_initial_backoff = os.environ.get('ES_BULK_INITIAL_BACKOFF', "3")
es_bulk_max_retries = os.environ.get('ES_BULK_MAX_RETRIES', "5")

# Initialize Logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    config = Config(connect_timeout=5, retries={'max_attempts': 0})
    s3 = boto3.client('s3', region_name=aws_region, config=config)
    credentials = boto3.Session().get_credentials()
    awsauth = AWS4Auth(credentials.access_key,
                       credentials.secret_key,
                       aws_region,
                       service,
                       session_token=credentials.token
                       )

    logger.info("Received event: " + json.dumps(event, indent=2))

    try:
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = urllib.parse.unquote_plus(
            event['Records'][0]['s3']['object']['key'])

        # Get documet (obj) form S3
        obj = s3.get_object(Bucket=bucket, Key=key)

    except Exception as e:
        logger.error('ERROR: {0}'.format(str(e)))
        logger.error(
        'ERROR: Unable able to GET object:{0} from S3 Bucket:{1}. Verify object exists.'.format(key, bucket))

    if (key.endswith('.gz')) or (key.endswith('.tar.gz')):
        mycontentzip = gzip.GzipFile(
            fileobj=BytesIO(obj['Body'].read())).read()
        lines = mycontentzip.decode("utf-8").replace("'", '"')
    else:
        lines = obj['Body'].read().decode("utf-8").replace("'", '"')

    logger.info('SUCCESS: Retrieved object from S3')

    # Split (S3 object/Log File) by lines
    lines = lines.splitlines()
    if isinstance(lines, str):
        lines = [lines]

    # Index each line to ES Domain
    index_name = es_index_prefix + '-' + \
                 str(datetime.date.today().year) + '-' + \
                 str(datetime.date.today().month) + '-' + \
                 str(datetime.date.today().day)

    es = Elasticsearch(
        hosts=[{'host': es_endpoint, 'port': 443}],
        http_auth=awsauth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection
    )

    doc_data = {}
    cnt = 0
    fields = [
        "type",
        "timestamp",
        "alb",
        "client_ip",
        "client_port",
        "backend_ip",
        "backend_port",
        "request_processing_time",
        "backend_processing_time",
        "response_processing_time",
        "alb_status_code",
        "backend_status_code",
        "received_bytes",
        "sent_bytes",
        "request_verb",
        "request_url",
        "request_proto",
        "user_agent",
        "ssl_cipher",
        "ssl_protocol",
        "target_group_arn",
        "trace_id",
        "domain_name",
        "chosen_cert_arn",
        "matched_rule_priority",
        "request_creation_time",
        "actions_executed",
        "redirect_url",
        "error_reason",
        "target_status_code_list",
        "classification",
        "classification_reason"
    ]
    regex = r"([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[" \
            r"-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) \"([^ ]*) ([^ ]*) (- |[^ ]*)\" \"([^\"]*)\" ([A-Z0-9-]+) ([" \
            r"A-Za-z0-9.-]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\" ([-.0-9]*) ([^ ]*) \"([^\"]*)\" (.*) (.*) " \
            r"(.*) (.*) (.*) "
    actions = []

    for line in lines:
        matches = re.search(regex, line)
        if matches:
            cnt += 1
            for i, field in enumerate(fields):
                doc_data[field] = matches.group(i + 1)
            actions.append(doc_data.copy())
        if cnt % int(es_bulk_chunk_size) == 0:
            print(helpers.bulk(es, actions, index=index_name, doc_type=es_index_doc_type, chunk_size=es_bulk_chunk_size, initial_backoff=es_bulk_initial_backoff, max_retries=es_bulk_max_retries))
            actions = []
    print(helpers.bulk(es, actions, index=index_name, doc_type=es_index_doc_type, chunk_size=es_bulk_chunk_size, initial_backoff=es_bulk_initial_backoff, max_retries=es_bulk_max_retries))

    logger.info('File processing complete. Check logs at %s' % es_kibana_endpoint)

if __name__ == '__main__':
    lambda_handler(None, None)
