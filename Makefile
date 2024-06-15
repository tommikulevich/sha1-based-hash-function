NVCC      := nvcc
CUDAFLAGS := -arch=sm_86 -O3 -lineinfo -use_fast_math -Xcompiler -Wall -Xcompiler -Wextra -Xcompiler -Werror
RUN_ARGS  := data/atack_cases.txt

TARGET    := target/atack
SRC       := src/atack.cu

all: $(TARGET)

$(TARGET): $(SRC)
	$(NVCC) $(CUDAFLAGS) $< -o $@

run: $(TARGET)
	./$(TARGET) $(RUN_ARGS)

clean:
	rm -f $(TARGET)

.PHONY: all run clean