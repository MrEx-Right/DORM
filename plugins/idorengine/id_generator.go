package idorengine

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
)

// ============================================================
//  ID GENERATOR — Creates variations of an ID for testing
// ============================================================

// GenerateIDVariations takes an ID and returns predictable variations
// that might be used by the backend (e.g., Base64 encoded, MD5 hashed).
func GenerateIDVariations(id string) []string {
	variations := []string{id}

	// 1. Base64
	variations = append(variations, base64.StdEncoding.EncodeToString([]byte(id)))
	variations = append(variations, base64.URLEncoding.EncodeToString([]byte(id)))

	// 2. MD5
	md5Hash := fmt.Sprintf("%x", md5.Sum([]byte(id)))
	variations = append(variations, md5Hash)

	// 3. SHA1
	sha1Hash := fmt.Sprintf("%x", sha1.Sum([]byte(id)))
	variations = append(variations, sha1Hash)

	return variations
}
