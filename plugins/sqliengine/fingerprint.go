package sqliengine

import "strings"

// ============================================================
//  DB FINGERPRINT ENGINE — Identify database type from errors
// ============================================================

// DBFingerprint holds signature patterns for a database type.
type DBFingerprint struct {
	Name       string
	Signatures []string
}

var dbFingerprints = []DBFingerprint{
	{
		Name: "MySQL",
		Signatures: []string{
			"mysql", "MySQL", "mysql_fetch", "mysql_num_rows",
			"MYSQL_ASSOC", "mysql_result", "Warning: mysql_",
		},
	},
	{
		Name: "MariaDB",
		Signatures: []string{
			"MariaDB", "mariadb",
		},
	},
	{
		Name: "PostgreSQL",
		Signatures: []string{
			"PostgreSQL", "PSQLException", "pg_query", "pgsql",
			"pg_exec", "unterminated quoted string",
		},
	},
	{
		Name: "MSSQL",
		Signatures: []string{
			"SQLServer", "Microsoft OLE DB", "SqlException", "MSSQL",
			"WAITFOR", "mssql_query", "Microsoft SQL",
			"SQL Server Native Client",
		},
	},
	{
		Name: "Oracle",
		Signatures: []string{
			"ORA-", "Oracle", "oracle.jdbc",
			"PLS-", "TNS:",
		},
	},
	{
		Name: "SQLite",
		Signatures: []string{
			"SQLite", "sqlite3", "SQLITE_ERROR",
			"unrecognized token",
		},
	},
	{
		Name: "DB2",
		Signatures: []string{
			"DB2", "CLI Driver", "SQLCODE", "SQLSTATE",
		},
	},
}

// FingerprintDB analyzes an error response body and returns the detected DB type.
func FingerprintDB(body string) string {
	// First check MariaDB (before MySQL since it's more specific)
	for _, sig := range dbFingerprints[1].Signatures { // MariaDB
		if strings.Contains(body, sig) {
			return "MariaDB"
		}
	}

	for _, fp := range dbFingerprints {
		if fp.Name == "MariaDB" {
			continue // already checked
		}
		for _, sig := range fp.Signatures {
			if strings.Contains(body, sig) {
				return fp.Name
			}
		}
	}
	return "Unknown DB"
}

// ExtractDBVersion attempts to extract a version string from the error body.
func ExtractDBVersion(body string) string {
	// Common version patterns in error messages
	patterns := []struct {
		prefix string
		suffix string
	}{
		{"MySQL server version for the right syntax to use near", "at line"},
		{"MariaDB server version", "at line"},
		{"PostgreSQL", "on"},
		{"Microsoft SQL Server", ","},
	}

	for _, p := range patterns {
		idx := strings.Index(body, p.prefix)
		if idx == -1 {
			continue
		}
		start := idx + len(p.prefix)
		end := strings.Index(body[start:], p.suffix)
		if end == -1 || end > 100 {
			continue
		}
		version := strings.TrimSpace(body[start : start+end])
		if len(version) > 0 && len(version) < 50 {
			return version
		}
	}

	return ""
}
