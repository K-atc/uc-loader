BIN += hello correct-argv1.elf
ASM := hello.s correct-argv1.elf.s

sample_elf: $(BIN) $(ASM)

%.elf: %.nasm
	nasm -f elf64 -o $(basename $^).o $^
	ld $(basename $^).o -o $@

%: %.c
	gcc -Wl,-Ttext=0x400000 -o $@ $^

%: %.cpp
	$(CXX) $(CXXOPT) -o $@ $^

$(ASM): $(BIN)

%.elf.s: %.elf
	objdump -Mintel -d $< > $@

hello.s: hello
	objdump -Mintel -d $< > $@
