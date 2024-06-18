Always wondered how DNS _actually_ works under the hood.
Now, I know.

This is based on codecrafters.io's ["Build Your Own DNS server" Challenge](https://app.codecrafters.io/courses/dns-server/overview).

> In this challenge, you'll build a DNS server that's capable of parsing and
> creating DNS packets, responding to DNS queries, handling various record types
> and doing recursive resolve. Along the way we'll learn about the DNS protocol,
> DNS packet format, root servers, authoritative servers, forwarding servers,
> various record types (A, AAAA, CNAME, etc) and more.

# Scope

- A record queries
- DNS forwarding

This project is just an excuse to dive into ["RFC 1035"](https://tools.ietf.org/html/rfc1035) & ["RFC 1034"](https://tools.ietf.org/html/rfc1034) to learn about DNS.

# Running the project

```
# Run the server
$> ./your_server.sh --resolver 8.8.8.8

# Query the server
$> dig @127.0.0.1 -p 2053 +noedns codecrafters.io google.io

; <<>> DiG 9.18.18-0ubuntu0.22.04.2-Ubuntu <<>> @127.0.0.1 -p 2053 +noedns codecrafters.io google.io
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 23402
;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;codecrafters.io.               IN      A

;; ANSWER SECTION:
codecrafters.io.        224     IN      A       76.76.21.21

;; Query time: 39 msec
;; SERVER: 127.0.0.1#2053(127.0.0.1) (UDP)
;; WHEN: Wed May 22 03:39:28 CEST 2024
;; MSG SIZE  rcvd: 64

;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41334
;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;google.io.                     IN      A

;; ANSWER SECTION:
google.io.              300     IN      A       216.58.215.36

;; Query time: 23 msec
;; SERVER: 127.0.0.1#2053(127.0.0.1) (UDP)
;; WHEN: Wed May 22 03:39:28 CEST 2024
;; MSG SIZE  rcvd: 52
```

# TODO

- Support for `TR` (Truncated) flag
- Support for forwarding without `RD` (Recursion Desired) flag
- Local Cache
