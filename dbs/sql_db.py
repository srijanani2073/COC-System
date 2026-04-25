import psycopg2

def get_connection():
    return psycopg2.connect(
        host="aws-1-ap-south-1.pooler.supabase.com",
        database="postgres",
        user="postgres.vjhcppcwtdknkhvbpwly",
        password="3j9J6UVaGY1YM7Th",
        port=6543,
        sslmode="require"
    )