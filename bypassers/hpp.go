package bypassers

import "net/url"

// PolluteParam duplicates a query parameter across multiple values instead
// of a single key — HTTP Parameter Pollution (HPP). Many WAFs and reverse
// proxies inspect only the first (or only the last) occurrence of a
// repeated parameter, while the backend application framework may resolve
// a different occurrence (first, last, or a concatenation of both) — the
// mismatch lets a malicious value ride through unrejected while the WAF
// only "saw" a benign one.
//
// Pass the parameter's decoy value(s) followed by the real payload, e.g.
// PolluteParam(q, "id", "1", "1' OR '1'='1"). Any prior value(s) for param
// are replaced. Encode the result as usual (u.RawQuery = values.Encode()),
// which serializes repeated keys as separate "param=a&param=b" pairs.
func PolluteParam(query url.Values, param string, values ...string) url.Values {
	if query == nil {
		query = url.Values{}
	}
	query.Del(param)
	for _, v := range values {
		query.Add(param, v)
	}
	return query
}
