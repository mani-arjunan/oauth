## Oauth2 example

This repo contains a small example of how oauth2 should be used across services.

## How to run

- run servicea using `make servicea`
- open `http://localhost:8080`, create some users and also new client `serviceb` with authentication enabled and redirect uri as `http://localhost:4000/auth/callback`.
- run serviceb using `make serviceb`
- visit `http://localhost:4000`.


