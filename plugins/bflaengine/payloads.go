package bflaengine

// AdminEndpointPatterns are known admin/management/internal URL paths
// probed for function-level authorization boundaries.
var AdminEndpointPatterns = []string{
	// REST Admin
	"/api/admin", "/api/admin/users", "/api/admin/user",
	"/api/admin/delete", "/api/admin/config", "/api/admin/settings",
	"/api/admin/reports", "/api/admin/logs", "/api/admin/audit",
	"/api/admin/stats", "/api/admin/metrics", "/api/admin/dashboard",
	"/api/v1/admin", "/api/v1/admin/users", "/api/v1/admin/config",
	"/api/v2/admin", "/api/v2/admin/users",
	// Management
	"/api/management", "/api/management/users",
	"/api/management/config", "/api/management/reports",
	// Privileged ops
	"/api/users/all", "/api/users/list",
	"/api/users/export", "/api/users/bulk",
	"/api/accounts/all", "/api/orders/all",
	"/api/reports/generate", "/api/billing/override",
	// Internal
	"/internal/admin", "/internal/api/users",
	"/internal/config", "/internal/management",
}

// DangerousMethods are the HTTP methods tested for method tampering.
var DangerousMethods = []string{"PUT", "DELETE", "PATCH"}

// ObjectPatterns are object-ID URL templates tested for cross-tenant
// access via method tampering ({ID} is replaced with a test ID).
var ObjectPatterns = []string{
	"/api/v1/user/{ID}", "/api/v1/users/{ID}",
	"/api/v1/profile/{ID}", "/api/v1/account/{ID}",
	"/api/v1/order/{ID}", "/api/v1/invoice/{ID}",
	"/api/v1/document/{ID}", "/api/v1/ticket/{ID}",
	"/api/v2/user/{ID}", "/api/v2/users/{ID}",
	"/api/users/{ID}", "/api/orders/{ID}",
	"/api/accounts/{ID}", "/user/{ID}",
}

// SoftErrors are phrases indicating a soft-denied (HTTP 200 body-level)
// rejection, i.e. the server returns 200 but the operation was denied.
var SoftErrors = []string{
	"permission denied", "access denied", "not authorized",
	"unauthorized", "forbidden", "insufficient", "not allowed",
	"cannot perform", "operation not permitted",
}
