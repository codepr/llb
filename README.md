llb
===

![llb CI](https://github.com/codepr/llb/workflows/llb%20CI/badge.svg?branch=master)

(**L**)ittle(**L**)oad(**B**)alancer, a dead simple event-driven load-balancer.
Supports Linux (and arguably OSX) through epoll and poll/select (kqueue on
BSD-like) as fallback, it uses an event-loop library borrowed from
[Sol](https://github.com/codepr/sol.git).

Written out of boredom/learning pupose (50/50) during self-isolation. Sure
thing there will be bugs and plenty of corner cases to be addressed.

Features:

- Logging
- Configuration file on disk
- Basic healthcheck for backends
- TLS encryption (to be refined)
- Daemon mode
- Multithread event-loop
- HTTP and TCP load-balancing
- Round-robin, weighted round-robin, hash-balancing, random-balancing, leastconn
- Pretty small (~2000 sloc) and little dependencies (openssl)

Next:

- Improvements on all previous points

## Build

```sh
$ cmake . && make
```

## Quickstart

Backend servers at http://localhost:8080 and http://localhost:8081, balancing
strategy WEIGHTED-ROUND-ROBIN

```sh
$ ./llb -v -b http://localhost:8080:2,http://localhost:8081:4 -l weighted-round-robin
```

A simple configuration can be passed in with `-c` flag:

```sh
$ ./llb -c path/to/llb.conf
```

As of now the configuration is very small and self-explanatory, default path is
located to `/etc/llb/llb.conf`:

```sh
# llb configuration file, uncomment and edit desired configuration

# accepts http | tcp
mode http

# Load-balancing settings

# Frontends are the endpoint exposed as entry point for connecting clients
frontends 127.0.0.1:8789,127.0.0.1:8790,127.0.0.1:8791

# Backends is a pool of server to load-balance requests from clients
backends 127.0.0.1:6090,127.0.0.1:6090,127.0.0.1:6090

# Set round robin as balancing algorithm
load_balancing round-robin

# Logging configuration

# Could be either DEBUG, INFO/INFORMATION, WARNING, ERROR
log_level DEBUG

log_path /tmp/llb.log

# TCP backlog, size of the complete connection queue
tcp_backlog 128

# TLS certs

#cafile certs/ca.crt
#certfile certs/alaptop.crt
#keyfile certs/alaptop.key

# TLS supported versions
#tls_protocols tlsv1,tlsv1_1,tlsv1_2,tlsv1_3
```
