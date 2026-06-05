#!/usr/bin/env python3
"""Custom SSH wrapper for git using paramiko"""
import sys
import paramiko
import os

def main():
    # Parse SSH command args
    # git calls: ssh -p 22 user@host "git-receive-pack 'repo.git'"
    args = sys.argv[1:]
    
    host = None
    port = 22
    command = None
    
    i = 0
    while i < len(args):
        if args[i] == '-p' and i + 1 < len(args):
            port = int(args[i + 1])
            i += 2
        elif not args[i].startswith('-') and '@' in args:
            host = args[i]
            i += 1
        elif not args[i].startswith('-'):
            command = args[i]
            i += 1
        else:
            i += 1
    
    if not host or not command:
        print(f"Usage: ssh-git-wrapper.py [-p port] user@host command", file=sys.stderr)
        sys.exit(1)
    
    user, hostname = host.split('@', 1)
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    key_path = os.path.expanduser('~/.ssh/id_ed25519')
    key = paramiko.Ed25519Key.from_private_key_file(key_path)
    
    client.connect(hostname, port=port, username=user, pkey=key, timeout=30)
    
    # Set up channels for stdin/stdout/stderr forwarding
    transport = client.get_transport()
    channel = transport.open_session()
    channel.exec_command(command)
    
    # Forward data between git and SSH
    import select
    import socket
    
    channel.setblocking(0)
    sys.stdin = open(sys.stdin.fileno(), 'rb', buffering=0)
    sys.stdout = open(sys.stdout.fileno(), 'wb', buffering=0)
    
    while True:
        r, w, x = select.select([channel, sys.stdin], [], [], 1.0)
        if channel in r:
            try:
                data = channel.recv(65536)
                if not data:
                    break
                sys.stdout.write(data)
                sys.stdout.flush()
            except:
                break
        if sys.stdin in r:
            try:
                data = sys.stdin.buffer.read(65536)
                if not data:
                    channel.shutdown_write()
                else:
                    channel.send(data)
            except:
                channel.shutdown_write()
    
    exit_status = channel.recv_exit_status()
    client.close()
    sys.exit(exit_status)

if __name__ == '__main__':
    main()
