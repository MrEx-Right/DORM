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

	// ── Phase 1: isMaster — Servis MongoDB mi? ───────────────────────────
	isMasterResp, err := mongoQuery(addr, "admin.$cmd", bsonIsMaster())
	if err != nil {
		return nil
	}

	if !strings.Contains(isMasterResp, "ismaster") && !strings.Contains(isMasterResp, "isMaster") {
		return nil // MongoDB değil
	}

	// ── Phase 2: listDatabases — Auth gerektiriyor mu? ───────────────────
	listDBResp, err := mongoQuery(addr, "admin.$cmd", bsonListDatabases())

	if err == nil && strings.Contains(listDBResp, "databases") {
		// Auth olmadan DB listesi çekildi → CRITICAL
		dbNames := extractDatabaseNames(listDBResp)
		dbList := strings.Join(dbNames, ", ")
		if dbList == "" {
			dbList = "(parse edilemedi — raw wire response)"
		}

		return &models.Vulnerability{
			Target:   target,
			Name:     "MongoDB: Unauthenticated Database Access",
			Severity: "CRITICAL",
			CVSS:     9.8,
			Description: fmt.Sprintf(
				"MongoDB, kimlik doğrulaması olmadan 'listDatabases' komutunu çalıştırdı.\nVeritabanı Listesi: [%s]\nPort: %d\nKanıt: listDatabases yanıtında 'databases' alanı bulundu.",
				dbList, target.Port,
			),
			Solution:  "MongoDB'yi --auth bayrağıyla başlatın. Admin kullanıcı oluşturun ve tüm kullanıcılara güçlü parolalar atayın. MongoDB portunu (27017) dış ağa kapatın.",
			Reference: "CWE-306: Missing Authentication for Critical Function",
		}
	}

	// ── Phase 3: buildInfo — Versiyon tespiti ────────────────────────────
	buildResp, err := mongoQuery(addr, "admin.$cmd", bsonBuildInfo())

	mongoVersion := "(bilinmiyor)"
	if err == nil {
		mongoVersion = extractMongoVersion(buildResp)
	}

	// Wire protokolü yanıt veriyor ama auth gerekiyor (HIGH)
	if strings.Contains(listDBResp, "not authorized") || strings.Contains(listDBResp, "Unauthorized") {
		return &models.Vulnerability{
			Target:   target,
			Name:     "MongoDB: Wire Protocol Exposed (Auth Required)",
			Severity: "HIGH",
			CVSS:     7.5,
			Description: fmt.Sprintf(
				"MongoDB Wire Protocol aktif ve erişilebilir, ancak kimlik doğrulaması zorunlu.\nlistDatabases erişimi reddedildi, ancak servis bilgileri sızdı.\nMongoDB Versiyonu: %s\nPort: %d",
				mongoVersion, target.Port,
			),
			Solution:  "MongoDB'yi dış ağa kapatın. Firewall ile 27017/27018 portlarını kısıtlayın.",
			Reference: "CWE-284: Improper Access Control",
		}
	}

	// Wire protokolü yanıt veriyor, isMaster OK ama listDB başarısız
	return &models.Vulnerability{
		Target:   target,
		Name:     "MongoDB: Wire Protocol Exposed (isMaster)",
		Severity: "HIGH",
		CVSS:     7.5,
		Description: fmt.Sprintf(
			"MongoDB Wire Protocol aktif. isMaster komutu başarıyla yanıt aldı.\nMongoDB Versiyonu: %s\nPort: %d\nBu port dış ağa açık olmamalıdır.",
			mongoVersion, target.Port,
		),
		Solution:  "Firewall ile 27017/27018 portlarını yalnızca uygulama sunucusuna açın. --auth bayrağını kullanın.",
		Reference: "CWE-284: Improper Access Control",
	}
}

// ==================================================
// MongoDB Wire Protocol — Yardımcı Fonksiyonlar
// OP_QUERY (opcode 2004) üzerinden komut gönderme
// ==================================================

// mongoQuery: Verilen collection'a BSON document gönderir, yanıtı döner.
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

	// Yanıt oku (max 64KB)
	buf := make([]byte, 65536)
	n, err := io.ReadAtLeast(conn, buf, 16)
	if err != nil {
		return "", err
	}

	return string(buf[:n]), nil
}

// buildOPQuery: MongoDB Wire Protocol OP_QUERY mesajı oluşturur.
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
	body = append(body, 0xFF, 0xFF, 0xFF, 0xFF) // numberToReturn = -1 (tümü)
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
// BSON encode edilmiş minimal komutlar — sıfır dış bağımlılık

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

// extractDatabaseNames: Raw BSON yanıtından DB isimlerini basit string arama ile çıkarır.
func extractDatabaseNames(raw string) []string {
	var names []string
	// BSON string alanları: "name" key'inden sonra gelen değerleri ara
	idx := 0
	for {
		nameIdx := strings.Index(raw[idx:], "name")
		if nameIdx == -1 {
			break
		}
		idx += nameIdx + 5 // "name" + null byte

		// Sonraki printable ASCII string'i çıkar (DB adı)
		start := idx
		end := start
		for end < len(raw) && raw[end] >= 0x20 && raw[end] < 0x7F && raw[end] != 0 {
			end++
		}

		if end > start && end-start < 64 {
			candidate := raw[start:end]
			candidate = strings.TrimSpace(candidate)
			// Sadece geçerli görünen DB isimleri
			if len(candidate) > 0 && len(candidate) < 64 && isValidDBName(candidate) {
				names = append(names, candidate)
			}
		}
		idx = end + 1
		if idx >= len(raw) {
			break
		}
	}

	// Tekrarları kaldır
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

// extractMongoVersion: buildInfo yanıtından versiyon string'ini çıkarır.
func extractMongoVersion(raw string) string {
	vIdx := strings.Index(raw, "version")
	if vIdx == -1 {
		return "(bilinmiyor)"
	}
	start := vIdx + 8
	if start >= len(raw) {
		return "(bilinmiyor)"
	}
	end := start
	for end < len(raw) && (raw[end] == '.' || (raw[end] >= '0' && raw[end] <= '9')) {
		end++
	}
	if end > start {
		return raw[start:end]
	}
	return "(bilinmiyor)"
}

// isValidDBName: Bir string'in geçerli MongoDB DB adı olup olmadığını kontrol eder.
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
