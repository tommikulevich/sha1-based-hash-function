NVCC      := nvcc
CUDAFLAGS := -arch=sm_86 -O3 -lineinfo -use_fast_math -Xcompiler -Wall -Xcompiler -Wextra -Xcompiler -Werror
RUN_ARGS  := data/attack_cases.txt

TARGET    := target/attack
SRC       := src/attack.cu

all: $(TARGET)

$(TARGET): $(SRC)
	$(NVCC) $(CUDAFLAGS) $< -o $@

run: $(TARGET)
	./$(TARGET) $(RUN_ARGS)

clean:
	rm -f $(TARGET)

.PHONY: all run clean