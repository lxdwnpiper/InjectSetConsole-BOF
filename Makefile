CC64    ?= x86_64-w64-mingw32-gcc
TARGET  := injectconsole.x64.o
DBGDIR  := debug
DBGOBJ  := $(DBGDIR)/injectconsole.x64.o

# -c                      : relocatable object, never link
# -fno-stack-protector    : no __stack_chk_fail (loader cannot resolve it)
# -fno-unwind-tables      : drop .eh_frame / SEH metadata noise
# -fno-builtin            : never emit implicit memcpy/memset/memcmp calls
# -fno-tree-loop-distribute-patterns : keep hand-written byte loops as loops
CFLAGS  := -Os -c -Wall -Wextra \
           -fno-stack-protector \
           -fno-unwind-tables \
           -fno-asynchronous-unwind-tables \
           -fno-builtin \
           -fno-tree-loop-distribute-patterns

all: $(TARGET)

$(TARGET): injectconsole.c
	$(CC64) $(CFLAGS) $< -o $@

# debug variant: same code + stage/timing log in %TEMP%\injectconsole.log
dbg: $(DBGOBJ)

$(DBGOBJ): injectconsole.c | $(DBGDIR)
	$(CC64) $(CFLAGS) -DIC_LOG $< -o $@

$(DBGDIR):
	mkdir -p $(DBGDIR)

check: $(TARGET)
	@echo "--- undefined symbols ---"
	@x86_64-w64-mingw32-nm -u $(TARGET) || true

clean:
	rm -f *.o $(DBGDIR)/*.o

.PHONY: all dbg check clean
