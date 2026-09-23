# CDN-Security-Test
Hands-on CDN security project focused on HTTP traffic analysis, suspicious activity, rate limiting, and WAF behavior.

## Project Overview

I configured and validated a CDN service, reviewed HTTP traffic, identified suspicious requests, and developed a mitigation approach for automated login activity.

The project included:

- Validating successful CDN traffic
- Reviewing HTTP requests and status codes
- Identifying automated login activity
- Identifying a SQL injection attempt
- Separating suspicious traffic from likely legitimate traffic
- Developing a rate-limiting strategy
- Reviewing WAF behavior
- Explaining security findings clearly

## Traffic Validation

I confirmed that traffic was successfully reaching the CDN service and reviewed the response data to verify successful 2XX responses.

## Security Analysis

### Automated Login Activity

Repeated POST requests to `/api/login` returned `401 Unauthorized` responses within a short period of time.

The requests used a `python-requests` user agent, which suggested scripted activity rather than normal browser traffic.

### SQL Injection Attempt

I identified a request containing a SQL injection-style payload in a product query.

The request returned `403 Forbidden`, indicating that the security control blocked it.

### Legitimate Traffic Analysis

I compared suspicious activity with traffic that appeared legitimate by reviewing:

- Source IP characteristics
- User-Agent information
- HTTP methods
- Response codes
- Requested resources
- Request sequence

## Mitigation Strategy

Instead of immediately blocking the source IP, I chose a rate-limiting approach.

Blocking the entire IP could affect legitimate users if multiple users were behind the same shared address.

The mitigation focused on repeated POST requests to `/api/login` associated with scripted traffic.

## Example VCL Logic

```vcl
penaltybox login_pbox { }
ratecounter login_rc { }

sub vcl_recv {
    if (
        req.method == "POST"
        && req.url.path == "/api/login"
        && req.http.User-Agent ~ "python-requests"
    ) {
        if (
            ratelimit.check_rate(
                req.http.User-Agent,
                login_rc,
                1,
                10,
                10,
                login_pbox,
                10 m
            )
        ) {
            error 429 "Too many requests";
        }
    }
}
