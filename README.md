# ITU: Security 1, BSc (Autumn 2024) 
## Group 11 - Miniproject

Sim: Penetration Testing Simulation Environments

# server

- creating a docker network `docker network create --subnet=10.0.1.0/24 pensim`
- run `vagrant up`.

# client

- `ssh -D 1080 pensim@130.226.143.130` # SETUP SSH TUNNEL
- `ssh -o ProxyCommand="nc -x 127.0.0.1:1080 %h %p" student@10.0.1.11` # LOGIN

# bonus

- `nmap -sT -p- -Pn -v --open -sV --proxies socks4://127.0.0.1:1080 10.0.1.11` # NMAP A CONTAINER
