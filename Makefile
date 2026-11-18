.PHONY: build test lint java-key-templates

build:
	go build -o bin/tinkey ./cmd/tinkey

test:
	go test -race ./...

lint:
	golangci-lint run ./...

# Regenerates the key templates from a Java Tinkey release; needs a JDK:
#   make java-key-templates TINKEY_JAR=/path/to/tinkey_deploy.jar
java-key-templates:
	rm -rf bin/java-key-templates
	javac -cp $(TINKEY_JAR) -d bin/java-key-templates tools/java-key-templates/com/google/crypto/tink/tinkey/DumpKeyTemplates.java
	java -cp bin/java-key-templates:$(TINKEY_JAR) com.google.crypto.tink.tinkey.DumpKeyTemplates > tinkey/java_key_templates.txt
