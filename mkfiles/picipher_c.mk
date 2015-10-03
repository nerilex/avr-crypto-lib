# Makefile for pi-cipher
ALGO_NAME := PICIPHER_C

# comment out the following line for removement of noekeon from the build process
AEAD_CIPHERS += $(ALGO_NAME)

$(ALGO_NAME)_DIR      := pi-cipher/
$(ALGO_NAME)_INCDIR   := arcfour/
$(ALGO_NAME)_OBJ      := pi16cipher.o pi16cipher-asm.o pi16cipher-aux-asm.o pi32cipher.o pi64cipher.o
$(ALGO_NAME)_TESTBIN  := main-picipher-test.o arcfour-asm.o $(CLI_STD) performance_test.o
$(ALGO_NAME)_NESSIE_TEST      := test nessie
$(ALGO_NAME)_PERFORMANCE_TEST := performance

