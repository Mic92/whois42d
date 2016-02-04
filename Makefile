VERSION?=1.0

container:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o whois42d .
	strip whois42d
	docker build -t mic92/whois42d:$(VERSION) .

upload:
	docker tag -f mic92/whois42d:$(VERSION) mic92/whois42d:latest
	docker push mic92/whois42d
