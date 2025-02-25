# jsonweb

Crate for JWT, JWA, and JWK with a focus on ease of use and simplicity.

## Usage

I currently have no intentions to publish this to crates.io, so for now if you want to use this you can add as a git
dependency using:

```toml
jsonweb = { git = "https://github.com/Jumpdrive-dev/jsonweb", tag = "1.0.0" }
```

## Features

- [ ] Simple JWT signing and verifying.
- [ ] Implementation of common algorithms:
  - [x] HS256
  - [x] RS256
  - [ ] ES256
  - [x] None
- [ ] JWKs