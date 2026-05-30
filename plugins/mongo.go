package plugins

import (
	"DORM/models"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ==================================================
// MONGODB NO AUTH — v2.0 "Mongo Wire Inspector"
// Saf TCP + Wire Protocol (driver-free)
// isMaster · listDatabases · buildInfo
// Port 27017 + 27018
// ==================================================
type MongoPlugin struct{}

func (p *MongoPlugin) Name() string { return "MongoDB Unauthorized Access (Wire Inspector v2)" }

func (p *MongoPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if target.Port != 27017 && target.Port != 27018 {
		return nil
	}

	addr := fmt.Sprintf("%s:%d", target.IP, target.Port)

	// ── Phase 1: isMaster — Is the service MongoDB? ───────────────────────────
	isMasterResp, err := mongoQuery(addr, "admin.$cmd", bsonIsMaster())
	if err != nil {
		return nil
	}

	if !strings.Contains(isMasterResp, "ismaster") && !strings.Contains(isMasterResp, "isMaster") {
		return nil // Not MongoDB
	}

	// ── Phase 2: listDatabases — Is authentication required? ───────────────────
	listDBResp, err := mongoQuery(addr, "admin.$cmd", bsonListDatabases())

	if err == nil && strings.Contains(listDBResp, "databases") {
		// Database list retrieved without authentication → CRITICAL
		dbNames := extractDatabaseNames(listDBResp)
		dbList := strings.Join(dbNames, ", ")
		if dbList == "" {
			dbList = "(could not be parsed — raw wire response)"
		}

		return &models.Vulnerability{
			Target:   target,
			Name:     "MongoDB: Unauthenticated Database Access",
			Severity: "CRITICAL",
			CVSS:     9.8,
			Description: fmt.Sprintf(
				"MongoDB executed 'listDatabases' command without authentication.\nDatabase List: [%s]\nPort: %d\nProof: 'databases' field found in listDatabases response.",
				dbList, target.Port,
			),
			Solution:  "Start MongoDB with the --auth flag. Create an admin user and assign strong passwords to all users. Close the MongoDB port (27017) to the external network.",
			Reference: "CWE-306: Missing Authentication for Critical Function",
		}
	}

	// ── Phase 3: buildInfo — Version detection ────────────────────────────
	buildResp, err := mongoQuery(addr, "admin.$cmd", bsonBuildInfo())

	mongoVersion := "(unknown)"
	if err == nil {
		mongoVersion = extractMongoVersion(buildResp)
	}

	// Wire protocol is responding but auth is required (HIGH)
	if strings.Contains(listDBResp, "not authorized") || strings.Contains(listDBResp, "Unauthorized") {
		return &models.Vulnerability{
			Target:   target,
			Name:     "MongoDB: Wire Protocol Exposed (Auth Required)",
			Severity: "HIGH",
			CVSS:     7.5,
			Description: fmt.Sprintf(
				"MongoDB Wire Protocol is active and accessible, but authentication is required.\nAccess to listDatabases was denied, but service information leaked.\nMongoDB Version: %s\nPort: %d",
				mongoVersion, target.Port,
			),
			Solution:  "Close MongoDB to the external network. Restrict ports 27017/27018 using a firewall.",
			Reference: "CWE-284: Improper Access Control",
		}
	}

	// Wire protocol is responding, isMaster OK but listDB failed
	return &models.Vulnerability{
		Target:   target,
		Name:     "MongoDB: Wire Protocol Exposed (isMaster)",
		Severity: "HIGH",
		CVSS:     7.5,
		Description: fmt.Sprintf(
			"MongoDB Wire Protocol is active. The isMaster command responded successfully.\nMongoDB Version: %s\nPort: %d\nThis port should not be exposed to the external network.",
			mongoVersion, target.Port,
		),
		Solution:  "Open ports 27017/27018 only to the application server using a firewall. Use the --auth flag.",
		Reference: "CWE-284: Improper Access Control",
	}
}

// ==================================================
// MongoDB Wire Protocol — Helper Functions
// Sending commands via OP_QUERY (opcode 2004)
// ==================================================

// mongoQuery: Sends BSON document to the given collection, returns the response.
func mongoQuery(addr, collection string, bsonDoc []byte) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	msg := buildOPQuery(collection, bsonDoc)
	if _, err := conn.Write(msg); err != nil {
		return "", err
	}

	// Read response (max 64KB)
	buf := make([]byte, 65536)
	n, err := io.ReadAtLeast(conn, buf, 16)
	if err != nil {
		return "", err
	}

	return string(buf[:n]), nil
}

// buildOPQuery: Creates MongoDB Wire Protocol OP_QUERY message.
// Struct:
//   - MsgHeader (16 byte): messageLength + requestID + responseTo + opCode(2004)
//   - flags (4 byte)
//   - fullCollectionName (cstring)
//   - numberToSkip (4 byte)
//   - numberToReturn (4 byte)
//   - query (BSON document)
func buildOPQuery(collection string, query []byte) []byte {
	collBytes := append([]byte(collection), 0x00) // null-terminated string

	// Body = flags + collection + skip + return + query
	body := make([]byte, 0, 4+len(collBytes)+4+4+len(query))
	body = append(body, 0x00, 0x00, 0x00, 0x00) // flags = 0
	body = append(body, collBytes...)
	body = append(body, 0x00, 0x00, 0x00, 0x00) // numberToSkip = 0
	body = append(body, 0xFF, 0xFF, 0xFF, 0xFF) // numberToReturn = -1 (all)
	body = append(body, query...)

	// Header
	totalLen := int32(16 + len(body))
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(header[4:8], 1)    // requestID
	binary.LittleEndian.PutUint32(header[8:12], 0)   // responseTo
	binary.LittleEndian.PutUint32(header[12:16], 2004) // OP_QUERY

	return append(header, body...)
}

// ── Hardcoded BSON Documents ─────────────────────────────────────────────────
// Minimal BSON encoded commands — zero external dependencies

// bsonIsMaster: BSON encode of {isMaster: 1}
func bsonIsMaster() []byte {
	// { "isMaster": 1 }
	// BSON: int32(length) + 0x10(int32) + "isMaster\0" + int32(1) + 0x00(terminator)
	doc := []byte{
		// Element: int32 key "isMaster" = 1
		0x10,                                           // type: int32
		'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00, // key
		0x01, 0x00, 0x00, 0x00,                         // value: 1
		0x00, // document terminator
	}
	length := int32(4 + len(doc))
	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, uint32(length))
	return append(result, doc...)
}

// bsonListDatabases: BSON encode of {listDatabases: 1, $db: "admin"}
func bsonListDatabases() []byte {
	doc := []byte{
		// Element: int32 key "listDatabases" = 1
		0x10,
		'l', 'i', 's', 't', 'D', 'a', 't', 'a', 'b', 'a', 's', 'e', 's', 0x00,
		0x01, 0x00, 0x00, 0x00,
		// Element: string key "$db" = "admin"
		0x02,
		'$', 'd', 'b', 0x00,
		0x06, 0x00, 0x00, 0x00, // string length (incl null)
		'a', 'd', 'm', 'i', 'n', 0x00,
		// terminator
		0x00,
	}
	length := int32(4 + len(doc))
	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, uint32(length))
	return append(result, doc...)
}

// bsonBuildInfo: BSON encode of {buildInfo: 1}
func bsonBuildInfo() []byte {
	doc := []byte{
		0x10,
		'b', 'u', 'i', 'l', 'd', 'I', 'n', 'f', 'o', 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x00,
	}
	length := int32(4 + len(doc))
	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, uint32(length))
	return append(result, doc...)
}

// ── Response Parsing Helpers ─────────────────────────────────────────────────

// extractDatabaseNames: Extracts DB names from raw BSON response using simple string search.
func extractDatabaseNames(raw string) []string {
	var names []string
	// BSON string fields: Look for values coming after the "name" key
	idx := 0
	for {
		nameIdx := strings.Index(raw[idx:], "name")
		if nameIdx == -1 {
			break
		}
		idx += nameIdx + 5 // "name" + null byte

		// Extract the next printable ASCII string (DB name)
		start := idx
		end := start
		for end < len(raw) && raw[end] >= 0x20 && raw[end] < 0x7F && raw[end] != 0 {
			end++
		}

		if end > start && end-start < 64 {
			candidate := raw[start:end]
			candidate = strings.TrimSpace(candidate)
			// Only valid-looking DB names
			if len(candidate) > 0 && len(candidate) < 64 && isValidDBName(candidate) {
				names = append(names, candidate)
			}
		}
		idx = end + 1
		if idx >= len(raw) {
			break
		}
	}

	// Remove duplicates
	seen := map[string]bool{}
	unique := []string{}
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			unique = append(unique, n)
		}
	}
	return unique
}

// extractMongoVersion: Extracts version string from buildInfo response.
func extractMongoVersion(raw string) string {
	vIdx := strings.Index(raw, "version")
	if vIdx == -1 {
		return "(unknown)"
	}
	start := vIdx + 8
	if start >= len(raw) {
		return "(unknown)"
	}
	end := start
	for end < len(raw) && (raw[end] == '.' || (raw[end] >= '0' && raw[end] <= '9')) {
		end++
	}
	if end > start {
		return raw[start:end]
	}
	return "(unknown)"
}

// isValidDBName: Checks if a string is a valid MongoDB DB name.
func isValidDBName(s string) bool {
	if len(s) == 0 || len(s) > 38 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
