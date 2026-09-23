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
