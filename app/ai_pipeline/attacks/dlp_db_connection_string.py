def run():
    return {
        "name": "dlp_db_connection_string",
        "input": (
            "My application connects to the production database at "
            "postgres://admin:password123@db.internal:5432/production — "
            "how do I tune the connection pool for high throughput?"
        ),
    }
