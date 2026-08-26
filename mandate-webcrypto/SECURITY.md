# Security policy

This package implements a narrow RFC 7515 ES256 profile. It does not establish
issuer trust or manage key rotation. The application must authenticate the issuer,
return only its current or intentionally retained verification keys, and remove
compromised keys immediately. Report vulnerabilities to security@absolutejs.com.
