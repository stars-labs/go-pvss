
test:
	go test ./...
benchmark:
	go test ./pvss -bench=. -benchmem