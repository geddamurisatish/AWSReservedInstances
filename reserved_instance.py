#!/usr/bin/env python
"""
This script is to audit reserved instances to find out
#1 --> Unused reserved RDS instances
#2 --> Instances which will expire in <warn_time> days
#3 --> On-demand RDS instances, which haven't got a reserved RDS instance

pre-requisites:
aws config must be present with role, region & warn_time
"""

__author__ = 'satish geddamuri'


import datetime
import json
import boto3.session
from dateutil.tz import tzutc

def assume_role(role_arn,aws_region):
    """
    this method is used to assume role for to access cross account rds details
    """
    sts_session = boto3.client('sts')
    sts_token = sts_session.assume_role(RoleArn = role_arn,RoleSessionName = 'role_session')
    session_token = sts_token['Credentials']['SessionToken']
    sts_access_key = sts_token['Credentials']['AccessKeyId']
    sts_secret_key = sts_token['Credentials']['SecretAccessKey']
    
    cross_account_session = boto3.Session(aws_access_key_id = sts_access_key,
                                          aws_secret_access_key = sts_secret_key,
                                          aws_session_token = session_token,
                                          region_name = aws_region)
    return cross_account_session


def aws_session(role,region):
    """
    create aws active session
    """
    session = assume_role(role,region)
    rds_client = session.client('rds')
    return(rds_client)


def load_aws_config():
    """
    Load the runtime parameters
    """
    with open('prod_config.json') as awsConfigFile:
        awsConfig = json.load(awsConfigFile)
    return awsConfig


def get_running_instances(role,region,warn_time):
   """
    This module collects all the running instances in a specific zone
    """
    rds_client = aws_session(role,region)
    instances = rds_client.describe_db_instances()['DBInstances']
    running_instances = {}
    for i in instances:
        if i['DBInstanceStatus'] != 'available': 
            continue
        if not i['AvailabilityZone'].startswith(region):
            continue
        a_zone = region
        key = (i['DBInstanceClass'], a_zone) 
        running_instances[key] = running_instances.get(key, 0) + 1
    return (running_instances)


def get_reserved_instances(role,region,warn_time):
	"""
	This module will return three items 
	1) Unused reserved RDS instances
	2) Expiring soon (less than %sd) reserved RDS instances
	3) On-demand RDS instances, which haven't got a reserved RDS instance
	"""
    running_instances = get_running_instances(role,region,warn_time)
    reserved_instances = {}
    about_to_expire = {}
    rds_client = aws_session(role,region)
    instances = rds_client.describe_db_instances()['DBInstances']
    reserved_rds_instances = rds_client.describe_reserved_db_instances()
    reservations = reserved_rds_instances['ReservedDBInstances']  
    now = datetime.datetime.utcnow().replace(tzinfo=tzutc())
    for ri in reservations:
        if ri['State'] == 'retired':
            continue
        ri_id = ri['ReservedDBInstanceId']
        ri_type = ri['DBInstanceClass']
        ri_count = ri['DBInstanceCount']
        key = (ri_type, region)
        reserved_instances[(ri_type, region)] = \
            reserved_instances.get(key, 0) + ri_count
        ri_start_time = ri['StartTime']
        ri_duration = ri['Duration']
        expire_time = ri_start_time + datetime.timedelta(seconds=ri['Duration'])
        if (expire_time - now) < datetime.timedelta(days=int(warn_time)):
            about_to_expire[ri_id] = (ri_type, region, expire_time)

        diff = dict([(x, reserved_instances[x] - running_instances.get(x, 0))
                 for x in reserved_instances])
    for pkey in running_instances:
        if pkey not in reserved_instances:
            diff[pkey] = -running_instances[pkey]
    unused_ri = {}
    unreserved_instances = {}
    for k, v in diff.iteritems():
        if v > 0:
            unused_ri[k] = v
        elif v < 0:
            unreserved_instances[k] = -v

    # Report
    print("Unused reserved RDS instances:")
    for k, v in sorted(unused_ri.iteritems(), key=lambda x: x[0]):
        print("\t(%s)\t%s\t%s" %(v, k[0], k[1]))
    if not unused_ri:
        print("\tNone")
    print("")

    print("Expiring soon (less than %sd) reserved RDS instances:" % warn_time)
    for k, v in sorted(about_to_expire.iteritems(), key=lambda x: x[1][:2]):
        print("\t%s\t%s\t%s\t%s" %(
            k, v[0], v[1], v[2].strftime('%Y-%m-%d')))
    if not about_to_expire:
        print("\tNone")
    print("")

    print("On-demand RDS instances, which haven't got a reserved RDS instance:")
    for k, v in sorted(unreserved_instances.iteritems(), key=lambda x: x[0]):
        print("\t(%s)\t%s\t%s" %(v, k[0], k[1]))
    if not unreserved_instances:
        print("\tNone")
    print("")

    print("Total running RDS instances: %s" % sum(running_instances.values()))
    print("Total reserved RDS instances: %s" % sum(reserved_instances.values()))
    print("")



def main():
    loaded_config = load_aws_config()
    awsConfig = loaded_config['aws']
    get_reserved_instances(awsConfig['role'],awsConfig['region'],awsConfig['warn_time'])
   

if __name__ == '__main__':
    main()	