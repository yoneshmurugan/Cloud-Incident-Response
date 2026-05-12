#!/bin/bash
# Using ping and curl to force DNS resolution (pre-installed on AL2023)
for i in {1..20}; do 
    ping -c 1 guarddutyc2activityb.com
    curl -I -s http://guarddutyc2activityb.com
    sleep 30
done
