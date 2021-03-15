# Copyright (c) 2017 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

VERSION                := $(shell cat VERSION)
REGISTRY               := eu.gcr.io/gardener-project/gardener
PREFIX                 := vpn
SEED_IMAGE_REPOSITORY  := $(REGISTRY)/$(PREFIX)-seed
SEED_IMAGE_TAG         := $(VERSION)
SHOOT_IMAGE_REPOSITORY := $(REGISTRY)/$(PREFIX)-shoot
SHOOT_IMAGE_TAG        := $(VERSION)

PATH                   := $(GOBIN):$(PATH)

export PATH

.PHONY: revendor
revendor:
	@GO111MODULE=on go mod vendor -v 
	@GO111MODULE=on go mod tidy

.PHONY: seed-docker-image
seed-docker-image:
	@docker build -t $(SEED_IMAGE_REPOSITORY):$(SEED_IMAGE_TAG) -f seed/Dockerfile --rm .

TAG := 0.6

.PHONY: shoot-docker-image
shoot-docker-image:
	#@docker build -t $(SHOOT_IMAGE_REPOSITORY):$(SHOOT_IMAGE_TAG) -f shoot/Dockerfile --rm .
	docker build -t eu.gcr.io/gardener-project/test/vpn-shoot-dev:$(TAG)  -f shoot/Dockerfile --rm .

upload:
	docker push eu.gcr.io/gardener-project/test/vpn-shoot-dev:$(TAG)

.PHONY: docker-images
docker-images: seed-docker-image shoot-docker-image

.PHONY: release
release: docker-images docker-login docker-push

.PHONY: docker-login
docker-login:
	@gcloud auth activate-service-account --key-file .kube-secrets/gcr/gcr-readwrite.json

.PHONY: readvertiser
readvertiser:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o readvertiser \
		-mod=vendor \
		./cmd/readvertiser/main.go

.PHONY: docker-push
docker-push:
	@if ! docker images $(SEED_IMAGE_REPOSITORY) | awk '{ print $$2 }' | grep -q -F $(SEED_IMAGE_TAG); then echo "$(SEED_IMAGE_REPOSITORY) version $(SEED_IMAGE_TAG) is not yet built. Please run 'make seed-docker-image'"; false; fi
	@if ! docker images $(SHOOT_IMAGE_REPOSITORY) | awk '{ print $$2 }' | grep -q -F $(SHOOT_IMAGE_TAG); then echo "$(SHOOT_IMAGE_REPOSITORY) version $(SHOOT_IMAGE_TAG) is not yet built. Please run 'make shoot-docker-image'"; false; fi
	@gcloud docker -- push $(SEED_IMAGE_REPOSITORY):$(SEED_IMAGE_TAG)
	@gcloud docker -- push $(SHOOT_IMAGE_REPOSITORY):$(SHOOT_IMAGE_TAG)
