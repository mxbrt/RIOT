# name of your application
APPLICATION = mbedtls_example

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

USEMODULE += crypto
USEMODULE += od
USEMODULE += xtimer
USEMODULE += auto_init

USEPKG += mbedtls

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
CFLAGS += -DDEVELHELP
CFLAGS += -DCRYPTO_AES
CFLAGS += -DDEBUG_EFM

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
