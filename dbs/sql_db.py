import psycopg2

def get_connection():
        host = os.environ.get("host")
        db   = os.environ.get("db")
        user = os.environ.get("user")
        pwd  = os.environ.get("pwd")
        port = os.environ.get("port", "5432")
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
