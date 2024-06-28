#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cstring>
#include <sys/time.h>
#include <cuda_runtime.h>
#include <unistd.h>

#define CUDA_CHECK(err) do { \
    cudaError_t err_ = (err); \
    if (err_ != cudaSuccess) { \
        fprintf(stderr, "CUDA error: %s at %s:%d\n", cudaGetErrorString(err_), __FILE__, __LINE__); \
        exit(-1); \
    } \
} while (0)

#define RESULTS_TXT_PATH "data/attack_results.txt"
#define CHARSET_LEN 92
#define BLOCK_SIZE 24
#define EXTENDED_W_SIZE 30
#define TOTAL_ROUNDS 30

__constant__ uint32_t F_CONSTANTS[3]   = { 0xFE887401, 0x44C38316, 0x21221602 };
__constant__ uint32_t INITIAL_STATE[4] = { 0x5AC24860, 0xDA545106, 0x716ADFDB, 0x4DA893CC };

#define CHARSET "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890!@#$%^&*-_=+([{<)]}>'\";:?,.\\/|"
#define CHARSET_LENGTH 93
#define MAX_MSG_LENGTH 8
#define HASH_SIZE 16

__device__ __forceinline__ uint32_t rotate_left( uint32_t x, uint32_t n ) {
    return (x << n) | (x >> (32 - n));
}

__device__ __forceinline__ uint32_t wrapping_add( uint32_t a, uint32_t b ) {
    return (a + b) & 0xFFFFFFFF;
}

__device__ void memcpy_mod( void* dest, const void * src, size_t count ) {
    char * d = (char *)dest;
    const char * s = (const char *)src;
    #pragma unroll
    for( size_t i = 0; i < count; i++ ) {
        d[i] = s[i];
    }
}

__device__ void extend_message_schedule( uint32_t * w ) {
    #pragma unroll
    for( int i = 0; i < EXTENDED_W_SIZE - 6; i++ ) {
        w[i + 6] = rotate_left(w[i] ^ w[i + 1] ^ wrapping_add(w[i + 3], w[i + 5]), 3);
    }
}

__device__ __forceinline__ uint32_t process_round( int i,
         uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t wi ) {
    if( i <= 9 ) {
        return wrapping_add(wrapping_add(wrapping_add((a & b), rotate_left(c, 4) ^ ~d), wi), F_CONSTANTS[0]);
    } else if( i <= 19 ) {
        return (a & b) ^ (~a & c) ^ (c & rotate_left(d, 2)) ^ wi ^ F_CONSTANTS[1];
    } else {
        return wrapping_add((a ^ rotate_left(b, 2) ^ rotate_left(c, 4) ^ rotate_left(d, 7)), wi ^ F_CONSTANTS[2]);
    }
}

__device__ void process_block( uint32_t * state, const uint32_t * block ) {
    uint32_t w[EXTENDED_W_SIZE] = {0};
    #pragma unroll
    for( int i = 0; i < BLOCK_SIZE / 4; i++ ) {
        w[i] = (block[i] >> 24) | ((block[i] >> 8) & 0xFF00) | ((block[i] << 8) & 0xFF0000) | (block[i] << 24);
    }
    extend_message_schedule(w);

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    #pragma unroll
    for( int i = 0; i < TOTAL_ROUNDS; i++ ) {
        uint32_t new_d = process_round(i, a, b, c, d, w[i]);
        a = b;
        b = c;
        c = d;
        d = new_d;
    }

    state[0] = a;
    state[1] = b;
    state[2] = c;
    state[3] = d;
}

__device__ void pad_message( const char * message, int message_length, 
        uint8_t * padded_message ) {
    int padded_length = ((message_length + BLOCK_SIZE) / BLOCK_SIZE) * BLOCK_SIZE;
    memcpy_mod(padded_message, message, message_length);
    padded_message[message_length] = 0x80;
    #pragma unroll
    for( int i = message_length + 1; i < padded_length; i++ ) {
        padded_message[i] = 0x00;
    }
}

__device__ void hash_message_bytes( const char * message, int message_length, 
        uint8_t * hash ) {
    int padded_length = ((message_length + BLOCK_SIZE) / BLOCK_SIZE) * BLOCK_SIZE;
    uint8_t padded_message[128] = {0}; 
    pad_message(message, message_length, padded_message);

    uint32_t state[4];
    memcpy_mod(state, INITIAL_STATE, sizeof(INITIAL_STATE));

    for( int i = 0; i < padded_length; i += BLOCK_SIZE ) {
        process_block(state, (const uint32_t*)(padded_message + i));
    }

    #pragma unroll
    for( int i = 0; i < 4; ++i ) {
        state[i] = (state[i] >> 24) | ((state[i] >> 8) & 0xFF00) | ((state[i] << 8) & 0xFF0000) | (state[i] << 24);
    }

    memcpy_mod(hash, state, 16); 
}

__global__ void compute_hash_kernel( const char * message, int message_length, 
        uint8_t * device_hash ) {
    hash_message_bytes(message, message_length, device_hash);
}

__global__ void kernel_bruteforce_attack( const char * charset, 
        uint64_t charset_length, uint64_t msg_length, const uint8_t * expected_hash, 
        bool * found, char * result, uint64_t total_combinations ) {
    __shared__ bool local_found;
    if( threadIdx.x == 0 ) local_found = false;
    __syncthreads();

    uint8_t hash[HASH_SIZE];
    char message[MAX_MSG_LENGTH + 1] = {0};

    uint64_t idx = blockDim.x * blockIdx.x + threadIdx.x;

    for( uint64_t i = idx; i < total_combinations && !local_found; i += gridDim.x * blockDim.x ) {
        uint64_t temp = i;
        for( int64_t j = msg_length - 1; j >= 0; j-- ) { 
            message[j] = charset[temp % charset_length];
            temp /= charset_length;
        }
        hash_message_bytes(message, msg_length, hash);

        bool match = true;
        for( uint64_t k = 0; k < HASH_SIZE; k++ ) {
            if( hash[k] != expected_hash[k] ) {
                match = false;
                break;
            }
        }
        if( match ) {
            if( atomicExch((int*)&local_found, 1) == 0 ) {
                for( uint64_t l = 0; l < msg_length; l++ ) {
                    result[l] = message[l];
                }
                result[msg_length] = '\0';
                *found = true;
            }
        }
    }
}

void run_attack_cuda( const char ** expected_hashes, const int * lengths, int num_cases) {
    for( int i = 0; i < num_cases; i++ ) {
        bool found = false;
        char result[MAX_MSG_LENGTH + 1] = {0};

        bool * d_found;
        char * d_result;
        char * d_charset;
        uint8_t target_hash[HASH_SIZE];
        uint8_t *d_expected_hash;

        for( int j = 0; j < HASH_SIZE; j++ ) {
            sscanf(expected_hashes[i] + j * 2, "%2hhx", &target_hash[j]);
        }

        cudaMalloc(&d_found, sizeof(bool));
        cudaMalloc(&d_result, (MAX_MSG_LENGTH + 1) * sizeof(char));
        cudaMalloc(&d_charset, CHARSET_LENGTH * sizeof(char));
        cudaMalloc(&d_expected_hash, HASH_SIZE * sizeof(uint8_t));

        cudaMemcpy(d_charset, CHARSET, CHARSET_LENGTH * sizeof(char), cudaMemcpyHostToDevice);
        cudaMemcpy(d_expected_hash, target_hash, HASH_SIZE * sizeof(uint8_t), cudaMemcpyHostToDevice);

        uint64_t total_combinations = static_cast<uint64_t>(pow(CHARSET_LENGTH, lengths[i]));
        printf("Theoretical maximum combinations for length %d: %lu\n", lengths[i], total_combinations);

        dim3 threadsPerBlock(256);
        dim3 blocksPerGrid(256);

        time_t start_time = time(NULL);
        kernel_bruteforce_attack<<<blocksPerGrid, threadsPerBlock>>>(d_charset, CHARSET_LENGTH, lengths[i], d_expected_hash, d_found, d_result, total_combinations);
        cudaDeviceSynchronize();

        cudaMemcpy(&found, d_found, sizeof(bool), cudaMemcpyDeviceToHost);
        cudaMemcpy(result, d_result, (MAX_MSG_LENGTH + 1) * sizeof(char), cudaMemcpyDeviceToHost);

        time_t end_time = time(NULL);

        FILE *file = fopen(RESULTS_TXT_PATH, "a");
        if( !file ) {
            perror("Failed to open results file");
            cudaFree(d_found);
            cudaFree(d_result);
            cudaFree(d_charset);
            cudaFree(d_expected_hash);
            return;
        }

        if( found ) {
            printf("Length (%d) Message found: %s\n", lengths[i], result);
            fprintf(file, "Length (%d) Message found: %s\n", lengths[i], result);
        } else {
            printf("Length (%d) No message found with the given hash\n", lengths[i]);
            fprintf(file, "Length (%d) No message found with the given hash\n", lengths[i]);
        }

        printf("Seconds: %ld\n", end_time - start_time);
        fprintf(file, "Seconds: %ld\n", end_time - start_time);

        fclose(file);

        cudaFree(d_found);
        cudaFree(d_result);
        cudaFree(d_charset);
        cudaFree(d_expected_hash);
    }
}

int main( int argc, char * argv[] ) {
    if( argc < 2 ) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    const char* filename = argv[1];
    FILE* file = fopen(filename, "r");
    if( !file ) {
        perror("Error opening file");
        return 1;
    }

    // Charset line - not supported (ignored)
    char buffer[256];
    if( !fgets(buffer, sizeof(buffer), file) ) {
        perror("Error reading charset line");
        fclose(file);
        return 1;
    }

    int num_cases = 0;
    char ** expected_hashes = NULL;
    int * lengths = NULL;

    while( fgets(buffer, sizeof(buffer), file) ) {
        num_cases++;
        char ** temp_hashes = (char **) realloc(expected_hashes, num_cases * sizeof(char*));
        int * temp_lengths = (int *) realloc(lengths, num_cases * sizeof(int));
        
        if( !temp_hashes || !temp_lengths ) {
            perror("Error allocating memory");
            free(expected_hashes);
            free(lengths);
            fclose(file);
            return 1;
        }

        expected_hashes = temp_hashes;
        lengths = temp_lengths;

        lengths[num_cases - 1] = atoi(buffer);

        if( !fgets(buffer, sizeof(buffer), file) ) {
            perror("Error reading hash line");
            free(expected_hashes);
            free(lengths);
            fclose(file);
            return 1;
        }

        buffer[strcspn(buffer, "\n")] = 0;
        expected_hashes[num_cases - 1] = strdup(buffer);
    }

    fclose(file);

    run_attack_cuda((const char **)expected_hashes, lengths, num_cases);

    for( int i = 0; i < num_cases; i++ ) {
        free(expected_hashes[i]);
    }
    free(expected_hashes);
    free(lengths);

    return 0;
}