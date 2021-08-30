# AWSReservedInstances

## This script is to audit reserved instances to find out

### pre-requisites: aws config must be present with role, region & warn_time

* Unused reserved RDS instances

* Instances which will expire in <warn_time> days

* On-demand RDS instances, which haven't got a reserved RDS instance



Here is the explanation on aws config file:

* role -->  AWS Role which you want to use to run the script

* region --> AWS region

* warn_time --> X number of days post which you want to check if the reserved instance expiry
