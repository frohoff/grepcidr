DESTDIR=
PREFIX=/usr/local
DATAROOTDIR=$(PREFIX)/share
DATADIR=$(DATAROOTDIR)
EXEC_PREFIX=$(PREFIX)
BINDIR=$(EXEC_PREFIX)/bin
SBINDIR=$(EXEC_PREFIX)/sbin
MANDIR=$(DATAROOTDIR)/man
INFODIR=$(DATAROOTDIR)/info

CPPFLAGS=
CFLAGS=-O3 -Wall -Werror
LDFLAGS=

all: grepcidr

grepcidr: grepcidr.o
	$(CC) $(CFLAGS) grepcidr.o -o grepcidr

doc: grepcidr.1

grepcidr.1: grepcidr.sgml
	docbook-to-man $< >$@

install: grepcidr
	install -m 0755 -d $(DESTDIR)$(BINDIR)
	install -m 0755 grepcidr $(DESTDIR)$(BINDIR)/grepcidr
	install -m 0755 -d $(DESTDIR)$(MANDIR)/man1
	install -m 0644 grepcidr.1 $(DESTDIR)$(MANDIR)/man1/grepcidr.1

clean:
	rm -f grepcidr *.o

doc-clean:
	rm -f grepcidr.1
