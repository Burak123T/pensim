#!/bin/bash
# Start SSH daemon
/usr/sbin/sshd -D &

# Keep container running
tail -f /dev/null
