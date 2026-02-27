# NullSec CertCheck

Haskell SSL/TLS certificate analyzer demonstrating functional programming and type safety.

## Features

- **Type Safety** - Algebraic data types for certificates
- **Monadic Error Handling** - Maybe and Either monads
- **Pure Functions** - Referential transparency
- **Pattern Matching** - Exhaustive case analysis
- **Expiration Checking** - Warning and critical thresholds

## Checks

| Check | Severity | Description |
|-------|----------|-------------|
| Expired | Critical | Certificate past validity |
| Expiring Soon | Critical/Medium | Based on threshold |
| Weak Key | High | RSA < 2048, EC < 256 |
| Weak Signature | High | MD5, SHA1 |
| Self-Signed | Medium | Issuer matches subject |

## Build

```bash
# With GHC
ghc -O2 certcheck.hs -o certcheck

# With Stack
stack ghc -- certcheck.hs -o certcheck

# With Cabal
cabal build
```

## Usage

```bash
# Basic check
./certcheck example.com

# Custom port
./certcheck -p 8443 example.com

# Custom thresholds
./certcheck -w 60 -c 14 example.com

# Show chain
./certcheck --chain example.com
```

## Exit Codes

- `0` - All checks passed
- `1` - Critical or high severity issues

## Author

bad-antics | [Twitter](https://x.com/AnonAntics)

## License

MIT
