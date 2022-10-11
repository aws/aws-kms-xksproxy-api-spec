# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
NAME    := aws-kms-xksproxy-api-spec
VERSION := 0.9.7
RELEASE := 0
SOURCE_BUNDLE := $(NAME)-$(VERSION)-$(RELEASE).txz
PDF := $(NAME)-$(VERSION).pdf
PROJECT_ROOTDIR := $(shell basename $(CURDIR))

.PHONY: genpdf bundle
genpdf: build/$(PDF)

build/$(SOURCE_BUNDLE):
	mkdir -p build
	cd .. && tar cJfh $(PROJECT_ROOTDIR)/$@ \
		--exclude=$(PROJECT_ROOTDIR)/.git \
		--exclude=$(PROJECT_ROOTDIR)/.gitignore \
		--exclude=$(PROJECT_ROOTDIR)/Config \
		--exclude=$(PROJECT_ROOTDIR)/build \
		--exclude=$(PROJECT_ROOTDIR)/.DS_Store \
		--exclude=$(PROJECT_ROOTDIR)/$(NAME)-$(VERSION).pdf \
		$(PROJECT_ROOTDIR)

bundle: build/$(SOURCE_BUNDLE)
build/$(PDF):
	mkdir -p build
	pandoc --listings \
		-H tex/listings-setup.tex \
		--toc \
		-V geometry:"left=1cm, top=2cm, right=1cm, bottom=2cm" \
		--pdf-engine=xelatex \
		-V 'mainfont:DejaVuSerif.ttf' \
		-V 'sansfont:DejaVuSans.ttf' \
		-V 'monofont:DejaVuSansMono.ttf' \
		-V 'mathfont:texgyredejavu-math.otf' \
		-V fontsize=10pt \
		-V linkcolor:blue \
		spec/xks_proxy_api_spec.md \
		-o $@

.PHONY: install_pandoc_osx
install_pandoc_osx:
	brew install pandoc

.PHONY: clean distclean
clean:
	rm -f build/$(SOURCE_BUNDLE)
	rm -f build/$(PDF)

distclean:
	rm -rf build
