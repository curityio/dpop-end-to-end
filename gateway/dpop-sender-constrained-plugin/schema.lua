return {
    name = "dpop-sender-constrained",
    fields = {{
        config = {
            type = "record",
            fields = {
                { cache_server = { type = "string", required = true } },
                { cache_port = { type = "number", required = true, between = { 1, 65535 } } },
                { time_to_live_seconds = { type = "number", required = false } }
            }
        }
    }}
}
