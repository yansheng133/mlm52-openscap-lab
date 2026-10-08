#!/bin/bash
# Create two pay-as-you-go RHEL clients (RHEL 8.10 + RHEL 9.x) for the lab.
# Every resource is tagged Project=$TAG_PROJECT so cleanup can be scoped by tag.
# Inbound: TCP 22 from MY_IP only. 4505/4506/443 are NOT opened; they travel through tunnel.sh.
#
# Required env: AWS_PROFILE AWS_REGION VPC_ID SUBNET_ID MY_IP (x.x.x.x/32) AMI_RHEL8 AMI_RHEL9
# Find official Red Hat hourly AMIs (owner 309956199498, UsageOperation RunInstances:0010):
#   aws ec2 describe-images --owners 309956199498 --filters 'Name=name,Values=RHEL-8.10*_HVM-*-x86_64-*' ...
set -euo pipefail
: "${AWS_PROFILE:?}" "${AWS_REGION:?}" "${VPC_ID:?}" "${SUBNET_ID:?}" "${MY_IP:?}" "${AMI_RHEL8:?}" "${AMI_RHEL9:?}"
export AWS_PROFILE AWS_REGION
TAG_PROJECT=${TAG_PROJECT:-mlm-compliance-lab}
TAG="{Key=Project,Value=$TAG_PROJECT}"
KEY=${KEY:-$HOME/.ssh/lab-mlm-key}

[ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N '' -C lab-mlm-key -f "$KEY"
chmod 600 "$KEY"
aws ec2 describe-key-pairs --key-names lab-mlm-key >/dev/null 2>&1 || \
  aws ec2 import-key-pair --key-name lab-mlm-key --public-key-material "fileb://$KEY.pub" \
    --tag-specifications "ResourceType=key-pair,Tags=[$TAG]" --query KeyPairId --output text

SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=lab-mlm-sg Name=vpc-id,Values="$VPC_ID" --query 'SecurityGroups[0].GroupId' --output text)
if [ "$SG" = None ]; then
  SG=$(aws ec2 create-security-group --group-name lab-mlm-sg --description "lab mlm clients ssh only" --vpc-id "$VPC_ID" \
    --tag-specifications "ResourceType=security-group,Tags=[$TAG,{Key=Name,Value=lab-mlm-sg}]" --query GroupId --output text)
  aws ec2 authorize-security-group-ingress --group-id "$SG" --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$MY_IP}]" >/dev/null
fi

launch() { # name ami -> instance id (idempotent by Name+Project tag)
  local id
  id=$(aws ec2 describe-instances --filters Name=tag:Name,Values="$1" Name=tag:Project,Values="$TAG_PROJECT" \
       Name=instance-state-name,Values=pending,running,stopping,stopped --query 'Reservations[0].Instances[0].InstanceId' --output text)
  if [ "$id" = None ]; then
    id=$(aws ec2 run-instances --image-id "$2" --instance-type t3.medium --key-name lab-mlm-key \
      --subnet-id "$SUBNET_ID" --security-group-ids "$SG" --credit-specification CpuCredits=standard \
      --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=20,VolumeType=gp3,DeleteOnTermination=true}' \
      --metadata-options HttpTokens=required \
      --tag-specifications "ResourceType=instance,Tags=[$TAG,{Key=Name,Value=$1}]" "ResourceType=volume,Tags=[$TAG,{Key=Name,Value=$1}]" \
      --query 'Instances[0].InstanceId' --output text)
  fi
  echo "$id"
}
I8=$(launch lab-rhel8 "$AMI_RHEL8"); I9=$(launch lab-rhel9 "$AMI_RHEL9")
aws ec2 wait instance-running --instance-ids "$I8" "$I9"
for pair in "lab-rhel8:$I8" "lab-rhel9:$I9"; do
  n=${pair%%:*}; i=${pair#*:}
  a=$(aws ec2 describe-addresses --filters Name=tag:Name,Values="$n" Name=tag:Project,Values="$TAG_PROJECT" --query 'Addresses[0].AllocationId' --output text)
  [ "$a" = None ] && a=$(aws ec2 allocate-address --domain vpc --tag-specifications "ResourceType=elastic-ip,Tags=[$TAG,{Key=Name,Value=$n}]" --query AllocationId --output text)
  aws ec2 associate-address --allocation-id "$a" --instance-id "$i" >/dev/null
done
aws ec2 describe-instances --instance-ids "$I8" "$I9" --query 'Reservations[].Instances[].[Tags[?Key==`Name`]|[0].Value,InstanceId,State.Name,PublicIpAddress]' --output text
