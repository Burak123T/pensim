#!/bin/bash
# monitor.sh
for i in $(seq 1 $NUM_VMS); do
    echo "Status for student_$i:"
    docker stats student_$i --no-stream
    echo "Disk usage:"
    docker exec student_$i df -h
    echo "-------------------"
done
