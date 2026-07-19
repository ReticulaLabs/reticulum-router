ENGINE=?podman
REPO=ghcr.io/reticulalabs
TAG=`git describe --tags --dirty --match=v* --abbrev=1`b

default:
	podman manifest rm $(REPO)/reticulum-router:$(TAG) || true
	podman manifest create $(REPO)/reticulum-router:$(TAG)
	podman build --platform linux/amd64,linux/arm64 --manifest $(REPO)/reticulum-router:$(TAG) .
test:
	podman run $(REPO)/reticulum-router:$(TAG)
push:
	podman manifest push $(REPO)/reticulum-router:$(TAG)
