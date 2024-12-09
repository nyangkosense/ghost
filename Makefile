include config.mk

SRC = ghost.c
OBJ = ${SRC:.c=.o}

all: ghost

.c.o:
	${CC} -c ${CFLAGS} $<

ghost: ${OBJ}
	${CC} -o $@ ${OBJ} ${LDFLAGS}

clean:
	rm -f ghost ${OBJ}

install: all
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp -f ghost ${DESTDIR}${PREFIX}/bin
	chmod 755 ${DESTDIR}${PREFIX}/bin/ghost

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/ghost

.PHONY: all clean install uninstall