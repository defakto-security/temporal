BUILD_DIR := build
GOBUILD = go build -trimpath

# The published image. CI overrides IMAGE/IMAGE_TAG from the environment.
IMAGE ?= ghcr.io/defakto-security/temporal
IMAGE_TAG ?= dev

all: clean build

clean:
	rm -rf $(BUILD_DIR)

# Cross-compiles the custom Temporal server build for both linux arches and
# pushes a multi-arch image. CGO is off: the binary is static (sqlite plugin
# aside, which builds pure-Go under CGO_ENABLED=0).
build:
	mkdir -p $(BUILD_DIR)
	env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/linux/arm64/ ./cmd/server
	env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/linux/amd64/ ./cmd/server
	docker buildx build --progress=plain \
		--platform linux/arm64/v8,linux/amd64 \
		-t $(IMAGE):$(IMAGE_TAG) \
		--push \
		.

push:
	docker buildx imagetools create -t $(IMAGE):latest $(IMAGE):$(IMAGE_TAG)
