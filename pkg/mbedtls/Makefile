PKG_NAME=mbedtls
PKG_URL=https://github.com/ARMmbed/mbedtls.git
PKG_VERSION=4f0929189ab43e020b0d441919abf6bab02baf11
PKG_LICENSE=Apache-2

.PHONY: all

all: git-download 
	$(MAKE) -C $(PKG_BUILDDIR)

include $(RIOTBASE)/pkg/pkg.mk


