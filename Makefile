.PHONY: servicea
servicea:
	cd servicea && docker compose up -d && go run cmd/api/main.go

.PHONY: serviceb
serviceb:
	cd serviceb && go run main.go
