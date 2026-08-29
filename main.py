from time import perf_counter

from fastapi import FastAPI, Query, Request
from pydantic import BaseModel, HttpUrl
import ssl
import socket
import base64
from datetime import datetime
from typing import List, Optional, Dict, Any
import httpx
from icmplib import ping as icmp_ping
from urllib.parse import urlparse
import dns.resolver
import dns.dnssec
import dns.reversename
import dns.zone
import dns.query
import dns.exception
import whois
from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
import os

app = FastAPI(title="Network Utilities Service")

request_timeout = int(os.getenv("REQUEST_TIMEOUT", "25"))

@app.get("/health")
def health():
    return {"status": "ok"}

def _get_basic_auth_credentials() -> Optional[tuple[str, str]]:
    basic_auth = os.getenv("BASIC_AUTH", "").strip()
    if not basic_auth:
        return None
    if ":" not in basic_auth:
        raise ValueError("BASIC_AUTH must be in the format username:password")
    username, password = basic_auth.split(":", 1)
    return username, password


EXPECTED_BASIC_AUTH = _get_basic_auth_credentials()


@app.middleware("http")
async def require_basic_auth(request: Request, call_next):
    if request.url.path in {"/health", "/health/"}:
        return await call_next(request)

    if not EXPECTED_BASIC_AUTH:
        return await call_next(request)

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized"},
            headers={"WWW-Authenticate": 'Basic realm="Restricted"'},
        )

    try:
        encoded_credentials = auth_header.split(" ", 1)[1]
        decoded_credentials = base64.b64decode(encoded_credentials.encode("utf-8")).decode("utf-8")
        username, password = decoded_credentials.split(":", 1)
    except Exception:
        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized"},
            headers={"WWW-Authenticate": 'Basic realm="Restricted"'},
        )

    expected_username, expected_password = EXPECTED_BASIC_AUTH
    if (username, password) != (expected_username, expected_password):
        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized"},
            headers={"WWW-Authenticate": 'Basic realm="Restricted"'},
        )

    return await call_next(request)

if not os.getenv("DISABLE_CORS"):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

# ---------- Models ----------

class CertificateCheckResult(BaseModel):
    ok: bool
    hostname: str
    port: int
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    subject: Optional[Dict[str, Any]] = None
    issuer: Optional[Dict[str, Any]] = None
    san: Optional[list] = None
    error: Optional[str] = None


class HSTSCheckResult(BaseModel):
    ok: bool
    url: str
    hsts_present: bool
    max_age: Optional[int] = None
    include_subdomains: bool = False
    preload: bool = False
    raw_header: Optional[str] = None
    error: Optional[str] = None


class RedirectCheckResult(BaseModel):
    ok: bool
    http_url: str
    redirected: bool
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    redirect_chain: Optional[list] = None
    error: Optional[str] = None


# ---------- Helpers ----------

def get_certificate(hostname: str, port: int = 443) -> CertificateCheckResult:
    ctx = ssl.create_default_context()
    # require valid cert
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((hostname, port), timeout=request_timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        if cert is None:
            raise Exception('Unable to find a certificate for %s' % (hostname))

        not_before_str = cert.get("notBefore")
        not_after_str = cert.get("notAfter")

        def parse_dt(s: str) -> datetime:
            # format like 'Jan  1 00:00:00 2025 GMT'
            return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")

        not_before = parse_dt(str(not_before_str)) if not_before_str else None
        not_after = parse_dt(str(not_after_str)) if not_after_str else None

        days_until_expiry = None
        if not_after:
            days_until_expiry = (not_after - datetime.utcnow()).days

        # subject / issuer as dicts
        subject = {str(k): v for ((k, v),) in cert.get("subject", [])} # type: ignore
        issuer = {str(k): v for ((k, v),) in cert.get("issuer", [])} # type: ignore

        san = []
        for typ, val in cert.get("subjectAltName", []):
            san.append({"type": typ, "value": val})

        return CertificateCheckResult(
            ok=True,
            hostname=hostname,
            port=port,
            not_before=not_before,
            not_after=not_after,
            days_until_expiry=days_until_expiry,
            subject=subject,
            issuer=issuer,
            san=san,
        )
    except Exception as e:
        return CertificateCheckResult(
            ok=False,
            hostname=hostname,
            port=port,
            error=str(e),
        )


def check_hsts(url: str) -> HSTSCheckResult:
    if not url.startswith("http"):
        url = "https://" + url

    try:
        with httpx.Client(timeout=request_timeout, follow_redirects=True) as client:
            resp = client.get(url)
        hsts = resp.headers.get("Strict-Transport-Security")
        if not hsts:
            return HSTSCheckResult(
                ok=False,
                url=str(resp.url),
                hsts_present=False,
                error="Strict-Transport-Security header not present",
            )

        # parse basic directives
        directives = [d.strip() for d in hsts.split(";")]
        max_age = None
        include_subdomains = False
        preload = False

        for d in directives:
            if d.lower().startswith("max-age"):
                parts = d.split("=", 1)
                if len(parts) == 2:
                    try:
                        max_age = int(parts[1].strip())
                    except ValueError:
                        pass
            elif d.lower() == "includesubdomains":
                include_subdomains = True
            elif d.lower() == "preload":
                preload = True

        return HSTSCheckResult(
            ok=True,
            url=str(resp.url),
            hsts_present=True,
            max_age=max_age,
            include_subdomains=include_subdomains,
            preload=preload,
            raw_header=hsts,
        )
    except Exception as e:
        return HSTSCheckResult(
            ok=False,
            url=url,
            hsts_present=False,
            error=str(e),
        )


def check_http_to_https_redirect(domain: str) -> RedirectCheckResult:
    # build URLs
    http_url = f"http://{domain}"

    try:
        redirect_chain = []
        with httpx.Client(follow_redirects=True, max_redirects=25, timeout=request_timeout) as client:
            resp = client.get(http_url)
            for r in resp.history:
                redirect_chain.append(
                    {
                        "status_code": r.status_code,
                        "url": str(r.url),
                        "headers": dict(r.headers),
                    }
                )
            final_url = str(resp.url)

        redirected = final_url.startswith("https://")

        return RedirectCheckResult(
            ok=redirected,
            http_url=http_url,
            redirected=redirected,
            final_url=final_url,
            status_code=resp.status_code,
            redirect_chain=redirect_chain,
            error=None if redirected else "Did not end up on HTTPS",
        )
    except Exception as e:
        return RedirectCheckResult(
            ok=False,
            http_url=http_url,
            redirected=False,
            error=str(e),
        )


# ---------- Endpoints ----------

@app.get("/check-certificate", response_model=CertificateCheckResult)
def api_check_certificate(
    host: str = Query(..., description="Hostname (e.g. example.com)"),
    port: int = Query(443, description="Port, default 443"),
):
    """
    Check if the TLS certificate is valid, not expired, and matches the hostname.
    """
    return get_certificate(host, port)


@app.get("/check-hsts", response_model=HSTSCheckResult)
def api_check_hsts(
    url: str = Query(..., description="URL or domain (e.g. https://example.com or example.com)"),
):
    """
    Check if HSTS is configured correctly and return max-age / flags.
    """
    return check_hsts(url)


@app.get("/check-redirect", response_model=RedirectCheckResult)
def api_check_redirect(
    domain: str = Query(..., description="Domain without scheme, e.g. example.com"),
):
    """
    Check if HTTP -> HTTPS redirect is working correctly.
    """
    return check_http_to_https_redirect(domain)


@app.get("/ping")
def ping(
    target: str = Query(..., description="IP address or hostname to ping"),
    count: int = Query(1, ge=1, le=10, description="Number of ICMP echo requests"),
    timeout: int = Query(2, ge=1, le=10, description="Per-packet timeout in seconds"),
):
    try:
        resolved_ip = target
        try:
            resolved_ip = socket.gethostbyname(target)
        except socket.gaierror as exc:
            return JSONResponse(
                status_code=400,
                content={
                    "ok": False,
                    "target": target,
                    "reachable": False,
                    "error": str(exc),
                },
            )

        result = icmp_ping(resolved_ip, count=count, timeout=timeout, privileged=False)
        return {
            "ok": True,
            "target": target,
            "ip": resolved_ip,
            "reachable": result.is_alive,
            "avg_rtt_ms": round(result.avg_rtt, 2) if result.avg_rtt is not None else None,
            "packet_loss": result.packet_loss,
        }
    except Exception as exc:
        return {
            "ok": False,
            "target": target,
            "reachable": False,
            "error": str(exc),
        }

# ---------- Models ----------

class DNSQueryResult(BaseModel):
    ok: bool
    domain: str
    record_type: str
    answers: Optional[list] = None
    error: Optional[str] = None


class WhoisResult(BaseModel):
    ok: bool
    domain: str
    raw: Optional[str] = None
    parsed: Optional[dict] = None
    error: Optional[str] = None


# ---------- DNS Query Tool ----------

def dns_query(domain: str, record_type: str = "A", resolver_ip: str | None = None) -> DNSQueryResult:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = request_timeout
        resolver.lifetime = request_timeout
        if resolver_ip:
            resolver.nameservers = [resolver_ip]

        result = [r.to_text() for r in resolver.resolve(domain, record_type)]

        return DNSQueryResult(
            ok=True,
            domain=domain,
            record_type=record_type,
            answers=result,
        )
    except Exception as e:
        return DNSQueryResult(
            ok=False,
            domain=domain,
            record_type=record_type,
            error=str(e),
        )


# ---------- WHOIS Tool ----------

def whois_lookup(domain: str) -> WhoisResult:
    try:
        data = whois.whois(domain, inc_raw=True)

        # python-whois returns a dict-like object
        parsed = {k: v for k, v in data.items() if k != 'raw'}

        return WhoisResult(
            ok=True,
            domain=domain,
            raw=str(data.text) if hasattr(data, "text") else None, # type: ignore
            parsed=parsed,
        )
    except Exception as e:
        return WhoisResult(
            ok=False,
            domain=domain,
            error=str(e),
        )


# ---------- Endpoints ----------

@app.get("/dns-query", response_model=DNSQueryResult)
def api_dns_query(
    domain: str = Query(..., description="Domain to query"),
    record_type: str = Query("A", description="DNS record type (A, AAAA, MX, TXT, etc.)"),
    resolver_ip: Optional[str] = None,
):
    """
    DNS proxy: performs DNS queries for any record type.
    """
    return dns_query(domain, record_type.upper(), resolver_ip)


@app.get("/whois", response_model=WhoisResult)
def api_whois(
    domain: str = Query(..., description="Domain to perform WHOIS lookup on"),
):
    """
    WHOIS proxy: returns raw and parsed WHOIS data.
    """
    return whois_lookup(domain)

class DNSSECResult(BaseModel):
    ok: bool
    domain: str
    validated: bool = False
    dnskey: Optional[str] = None
    rrsig: Optional[str] = None
    error: Optional[str] = None


class ReverseDNSResult(BaseModel):
    ok: bool
    ip: str
    ptr: Optional[str] = None
    error: Optional[str] = None


class AXFRResult(BaseModel):
    ok: bool
    domain: str
    soa: Optional[str] = None
    axfr_allowed: bool = False
    records: Optional[list] = None
    error: Optional[str] = None

def dnssec_validate(domain: str, resolver_ip: str | None = None) -> DNSSECResult:
    import dns.rdatatype
    import dns.resolver
    import dns.message
    import dns.query
    import dns.name
    import dns.dnssec
    import dns.exception

    dnskey = None
    rrsig = None

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = request_timeout
        resolver.lifetime = request_timeout
        if resolver_ip:
            resolver.nameservers = [resolver_ip]

        response = resolver.resolve(domain, rdtype=dns.rdatatype.NS)

        # use the first NS
        ns_server = response[0].to_text() # type: ignore
        response = dns.resolver.resolve(str(ns_server), rdtype=dns.rdatatype.A)
        ns_address = response[0].to_text() # type: ignore

        # get DNSKEY for zone
        request = dns.message.make_query(
            domain, dns.rdatatype.DNSKEY, want_dnssec=True)

        # set a longer timeout (in seconds)
        timeout = 30

        # try DNSSEC validation with retries
        for i in range(3):
            try:
                # send the query to the master NS
                response = dns.query.udp(request, ns_address, timeout=timeout)
                if response.rcode() != 0:
                    raise Exception("ERROR: no DNSKEY record found or SERVEFAIL")

                # find an RRSET for the DNSKEY record
                answer = response.answer
                if len(answer) != 2:
                    raise Exception("ERROR: could not find RRSET record (DNSKEY and RR DNSKEY) in zone")

                dnskey = answer[0].to_text()
                rrsig = answer[1].to_text()

                # check if is the DNSKEY record signed, RRSET validation
                name = dns.name.from_text(domain)
                dns.dnssec.validate(answer[0], answer[1], {name: answer[0]})

                break

            except dns.exception.Timeout:
                # retry on timeout
                if i == 2:
                    raise Exception("ERROR: DNSSEC validation failed after retries")
                    return result
            except dns.exception.ValidationFailure:
                raise Exception("CRITICAL: this domain is not likely signed by dnssec")

        return DNSSECResult(
            ok=True,
            domain=domain,
            validated=True,
            dnskey=dnskey,
            rrsig=rrsig,
        )

    except Exception as e:
        return DNSSECResult(
            ok=False,
            domain=domain,
            validated=False,
            dnskey=dnskey,
            rrsig=rrsig,
            error=str(e),
        )

def reverse_dns(ip: str, resolver_ip: str | None = None) -> ReverseDNSResult:
    try:
        rev = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = request_timeout
        resolver.lifetime = request_timeout
        if resolver_ip:
            resolver.nameservers = [resolver_ip]

        ptr = [r.to_text() for r in resolver.resolve(rev, "PTR")][0]

        return ReverseDNSResult(
            ok=True,
            ip=ip,
            ptr=ptr,
        )
    except Exception as e:
        return ReverseDNSResult(
            ok=False,
            ip=ip,
            error=str(e),
        )

def soa_axfr_test(domain: str, resolver_ip: str | None = None) -> AXFRResult:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = request_timeout
        resolver.lifetime = request_timeout
        if resolver_ip:
            resolver.nameservers = [resolver_ip]

        # SOA record
        soa_text = [r.to_text() for r in resolver.resolve(domain, "SOA")][0]

        # Try AXFR
        nameserver = [r.to_text() for r in resolver.resolve(domain, "NS")][0]
        zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=request_timeout))

        records = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    records.append(f"{name} {rdataset.rdtype} {rdata}")

        return AXFRResult(
            ok=True,
            domain=domain,
            soa=soa_text,
            axfr_allowed=True,
            records=records,
        )

    except ValueError:
        # AXFR refused but SOA succeeded
        return AXFRResult(
            ok=True,
            domain=domain,
            soa=soa_text,
            axfr_allowed=False,
            records=None,
            error="AXFR refused by server",
        )
    except Exception as e:
        return AXFRResult(
            ok=False,
            domain=domain,
            error=str(e),
        )

@app.get("/dnssec", response_model=DNSSECResult)
def api_dnssec(domain: str = Query(...), resolver_ip: Optional[str] = None):
    return dnssec_validate(domain, resolver_ip)


@app.get("/reverse-dns", response_model=ReverseDNSResult)
def api_reverse_dns(ip: str = Query(...), resolver_ip: Optional[str] = None):
    return reverse_dns(ip, resolver_ip)


@app.get("/soa-axfr", response_model=AXFRResult)
def api_soa_axfr(domain: str = Query(...), resolver_ip: Optional[str] = None):
    return soa_axfr_test(domain, resolver_ip)

class Hop(BaseModel):
    index: int
    url: str
    status_code: int
    duration_ms: float
    headers: dict
    is_redirect: bool
    location: Optional[str]
    body_preview: Optional[str]
    body_truncated: bool

class RedirectChain(BaseModel):
    input_url: str
    final_url: str
    hop_count: int
    chain: List[Hop]
    warnings: List[str]

def protocol(url: str) -> str:
    return url.split("://", 1)[0].lower()

@app.get("/redirect-chain", response_model=RedirectChain)
async def redirect_chain(
    url: HttpUrl,
    method: str = Query("GET", regex="^(GET|HEAD)$"),
    user_agent: str = Query("Mozilla/5.0 (Copilot Redirect Checker)"),
    preview_bytes: int = Query(512, ge=0, description="Number of bytes to preview from the response body"),
    include_body: bool = Query(False),
    max_hops: int = Query(10, ge=1, le=50, description="Maximum number of redirect hops to follow")
):
    chain: List[Hop] = []
    visited = set()
    current_url = str(url)
    warnings = []

    async with httpx.AsyncClient(follow_redirects=False, headers={"User-Agent": user_agent}) as client:
        for i in range(max_hops):
            if current_url in visited:
                warnings.append("Redirect loop detected")
                break

            visited.add(current_url)

            start = perf_counter()
            response = await client.request(method, current_url)
            duration_ms = (perf_counter() - start) * 1000

            is_redirect = response.status_code in (301, 302, 303, 307, 308)
            location = response.headers.get("Location")

            # --- BODY PREVIEW LOGIC ---
            body_preview = None
            body_truncated = False

            if include_body and method == "GET":
                raw = response.content
                if raw:
                    if len(raw) > preview_bytes:
                        body_preview = raw[:preview_bytes].decode("utf-8", errors="replace")
                        body_truncated = True
                    else:
                        body_preview = raw.decode("utf-8", errors="replace")
                        body_truncated = False

            chain.append(
                Hop(
                    index=i,
                    url=str(current_url),
                    status_code=response.status_code,
                    duration_ms=duration_ms,
                    headers=dict(response.headers),
                    is_redirect=is_redirect,
                    location=location,
                    body_preview=body_preview,
                    body_truncated=body_truncated,
                )
            )

            if not is_redirect or not location:
                break

            current_url = httpx.URL(current_url).join(location)

            # --- PROTOCOL CHANGE WARNING ---
            if chain:
                prev_proto = protocol(chain[-1].url)
                curr_proto = protocol(str(current_url))
                if prev_proto != curr_proto:
                    warnings.append(f"Protocol changed: {chain[-1].url} → {current_url}")

        else:
            warnings.append("Max redirect hops reached")

    # Final URL
    final_url = current_url

    # Extra warnings
    if len(chain) > 5:
        warnings.append("Long redirect chain (>5 hops)")
    if chain and chain[0].url.startswith("http://") and str(final_url).startswith("https://"):
        warnings.append("Protocol changed from HTTP → HTTPS")
    if chain and chain[-1].status_code != 200:
        warnings.append(f"Final status is not 200 ({chain[-1].status_code})")

    return RedirectChain(
        input_url=str(url),
        final_url=str(final_url),
        hop_count=len(chain),
        chain=chain,
        warnings=warnings,
    )


import uvicorn
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", log_level="info")