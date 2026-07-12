# 📘 Network Utilities Service — README

A modular FastAPI service providing network‑level diagnostic tools:

- **TLS certificate checks**  
- **HSTS validation**  
- **HTTP→HTTPS redirect analysis**  
- **DNS queries**  
- **WHOIS lookups**  
- **DNSSEC validation**  
- **Reverse DNS**  
- **SOA + AXFR tests**  

The service exposes clean JSON APIs suitable for automation, monitoring, and security auditing.

## 🚀 Features

- **Certificate inspection** (expiry, SAN, issuer, subject)  
- **HSTS header parsing** (max‑age, preload, includeSubDomains)  
- **Redirect chain tracing**  
- **DNS record proxy** (A, AAAA, MX, TXT, etc.)  
- **WHOIS raw + parsed output**  
- **DNSSEC RRSET validation**  
- **Reverse DNS (PTR)**  
- **SOA + AXFR zone transfer test**
- **Ping queries**  
- **Built‑in `/health` endpoint** for container orchestration  

## CORS enabled by default

CORS "*" is enabled by default. You can disable it by setting `DISABLE_CORS=true` environment variable.

## Requests timeout

DNS/HTTP Query timeout can be controlled by setting `REQUEST_TIMEOUT=XXX` environment variable.

## Basic authentication

You can protect the API with HTTP Basic Auth by setting `BASIC_AUTH=username:password`.
If this variable is unset, the service will run without authentication.

## **Running in Docker**

Pull latest image:

```
docker pull sharevb/network-utils-ws:latest
```

Run it with access to the host Docker daemon:

```
docker run \
  -p 8000:8000 \
  sharevb/network-utils-ws:latest
```

## Ping endpoint

You can ping a target IP address or hostname by calling:

```bash
curl "http://localhost:8000/ping?target=8.8.8.8&count=3&timeout=2"
```

You can also use a DNS name such as:

```bash
curl "http://localhost:8000/ping?target=example.com&count=3&timeout=2"
```

The optional `count` and `timeout` query parameters control the number of probes and the per-packet timeout in seconds.
It returns a JSON response indicating whether the host responded and the ping statistics.

## 🧰 Development

Install dependencies:

```bash
pip install -r requirements.txt
```

Run locally:

```bash
uvicorn main:app --reload
```

## 📄 License

MIT