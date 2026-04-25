import psycopg2

def get_connection():
        host = os.environ.get("PG_HOST")
        db   = os.environ.get("PG_DB")
        user = os.environ.get("PG_USER")
        pwd  = os.environ.get("PG_PASSWORD")
        port = os.environ.get("PG_PORT", "5432")
        sslmode="require"

        if not all([host, db, user, pwd]):
        raise ValueError("Missing PostgreSQL environment variables")

    return psycopg2.connect(
        host=host,
        database=db,
        user=user,
        password=pwd,
        port=port,
        sslmode="require"
    )
