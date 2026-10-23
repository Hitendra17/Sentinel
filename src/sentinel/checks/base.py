"""Evidence-backed passive checks."""
from sentinel.models import CheckResult, Evidence

SECURITY_HEADERS = {
    "content-security-policy": ("medium", "Set a restrictive Content-Security-Policy suited to the application."),
    "x-content-type-options": ("low", "Set X-Content-Type-Options: nosniff."),
    "referrer-policy": ("low", "Choose a privacy-preserving Referrer-Policy."),
    "x-frame-options": ("low", "Set frame-ancestors in CSP or X-Frame-Options where framing is not required."),
}

def evaluate(response, expected_https: bool = False):
    evidence=[]; checks=[]
    def ev(source, desc, value):
        item=Evidence(f"E{len(evidence)+1:03}",source,desc,value); evidence.append(item); return item.id
    if response.error:
        eid=ev("http", "Request outcome", response.error)
        checks.append(CheckResult("http.request", "failed", "HTTP request did not complete successfully.", "info", "high", [eid]))
        return checks,evidence
    status_id=ev("http", "HTTP status", response.status)
    checks.append(CheckResult("http.status", "observed", f"Target returned HTTP {response.status}.", "info", "high", [status_id]))
    headers=response.headers
    for name,(severity,fix) in SECURITY_HEADERS.items():
        val=headers.get(name)
        eid=ev("headers",f"{name} response header",val if val else "absent")
        if val:
            checks.append(CheckResult("header."+name,"observed",f"{name} is present.","info","high",[eid]))
        else:
            checks.append(CheckResult("header."+name,"potential",f"{name} was not observed; impact depends on application behavior.",severity,"medium",[eid],fix))
    for line in (v for k,v in headers.items() if k == "set-cookie"):
        flags={x.strip().split("=",1)[0].lower() for x in line.split(";")}
        observed={x: x in flags for x in ("secure","httponly","samesite")}
        eid=ev("cookie","Cookie flag presence (value omitted)",observed)
        checks.append(CheckResult("cookie.flags","observed","Cookie security flags recorded without storing cookie value.","info","high",[eid]))
    server=headers.get("server")
    if server:
        eid=ev("headers","Server header",server)
        checks.append(CheckResult("server.disclosure","observed","Server header may disclose implementation details; informational only.","info","medium",[eid]))
    if expected_https and response.url.startswith("http://"):
        eid=ev("transport","HTTPS expectation", "Target configured as HTTPS expected but scanned over HTTP")
        checks.append(CheckResult("transport.https","potential","HTTP was used although scope expects HTTPS; redirect behavior was not inferred.","medium","medium",[eid],"Serve the application over HTTPS and redirect HTTP to HTTPS."))
    else:
        eid=ev("transport","Transport observation", "TLS used" if response.url.startswith("https:") else "Cleartext HTTP; local/development context")
        checks.append(CheckResult("transport.tls","observed","Transport observed; certificate validation details are not available in stdlib client.","info","medium",[eid]))
    return checks,evidence
