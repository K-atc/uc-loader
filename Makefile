BIN := loader
CXXOPT := -Wno-pointer-arith -Wno-literal-suffix $(shell pkg-config --libs glib-2.0) -lpthread -lm -lunicorn -lcapstone

subdirs := sample_elf

.PHONY: all $(subdirs)
	@### Do Nothing

all: $(BIN) $(subdirs)
	@### Do Nothing

$(subdirs):
	make -C $@

%: %.cpp
	$(CXX) $(CXXOPT) -o $@ $^

clean:
	rm -f $(BIN) **/*.[os] **/.[0-9]* **/peda-session* **/.gdb_history

test: $(BIN) $(ASM)
	./loader sample_elf/correct-argv1.elf "flag{it's_easy!}"