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

#define RESULTS_TXT_PATH "data/atack_results.txt"
#define CHARSET_LEN 92
#define BLOCK_SIZE 24
#define EXTENDED_W_SIZE 30
#define TOTAL_ROUNDS 30

__constant__ uint32_t F_CONSTANTS[3]   = { 0xFE887401, 0x44C38316, 0x21221602 };
__constant__ uint32_t INITIAL_STATE[4] = { 0x5AC24860, 0xDA545106, 0x716ADFDB, 0x4DA893CC };
__constant__ char CHARSET[] = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890!@#$%^&*-_=+([{<)]}>'\";:?,.\\/|";

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

__device__ int memcmp_mod( const void * s1, const void * s2, size_t n ) {
    const unsigned char * p1 = (const unsigned char *)s1;
    const unsigned char * p2 = (const unsigned char *)s2;
    for( size_t i = 0; i < n; i++ ) {
        if( p1[i] != p2[i] ) {
            return p1[i] - p2[i];
        }
    }
    return 0;
}

__device__ uint64_t atomicAdd( uint64_t * address, uint64_t val) {
    unsigned long long int * address_as_ull = (unsigned long long int *)address;
    unsigned long long int old = atomicAdd(address_as_ull, (unsigned long long int)val);
    return old;
}

__global__ void hash_message_kernel( int charset_len, int target_len, 
		uint8_t * target_hash, uint8_t * result, int * found, uint64_t * checked_combinations, 
		uint64_t start_combination, uint64_t total_combinations )  {
    
    extern __shared__ uint64_t local_checked_combinations[];
    unsigned int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if( *found ) return;

    uint64_t local_checked = 0;
    char message[32] = {0};
    uint8_t hash[16];
    for( uint64_t combination_idx = start_combination + idx; 
    			combination_idx < total_combinations; 
    			combination_idx += gridDim.x * blockDim.x ) {
        if( *found ) return;

        uint64_t temp_comb = combination_idx;
        for( int i = 0; i < target_len; i++ ) {
            message[i] = CHARSET[temp_comb % charset_len];
            temp_comb /= charset_len;
        }

        hash_message_bytes(message, target_len, hash);

        local_checked++;
        if( memcmp_mod(hash, target_hash, 16) == 0 ) {
            for( int j = 0; j < target_len; j++ ) {
                result[j] = message[j];
            }
            atomicExch(found, 1);
            return;
        }
    }

    local_checked_combinations[threadIdx.x] = local_checked;
    __syncthreads();

    for( unsigned int s = blockDim.x / 2; s > 0; s >>= 1 ) {
        if( threadIdx.x < s ) {
            local_checked_combinations[threadIdx.x] += local_checked_combinations[threadIdx.x + s];
        }
        __syncthreads();
    }

    if( threadIdx.x == 0 ) {
        atomicAdd(checked_combinations, local_checked_combinations[0]);
    }
}

void run_atack_cuda( const char ** expected_hashes, const int * lengths, int num_cases ) {
    size_t free_mem, total_mem;
    cudaMemGetInfo(&free_mem, &total_mem);
    printf("Free memory on GPU: %zu bytes\n", free_mem);
    printf("Total memory on GPU: %zu bytes\n", total_mem);

    int deviceCount;
    cudaGetDeviceCount(&deviceCount);
    if( deviceCount == 0 ) {
        printf("No CUDA-capable devices found.\n");
        return;
    }

    cudaDeviceProp deviceProp;
    cudaGetDeviceProperties(&deviceProp, 0);

    printf("Device Name: %s\n", deviceProp.name);
    printf("Max Threads Per Block: %d\n", deviceProp.maxThreadsPerBlock);
    printf("Max Threads Dim: x = %d, y = %d, z = %d\n", 
           deviceProp.maxThreadsDim[0], 
           deviceProp.maxThreadsDim[1], 
           deviceProp.maxThreadsDim[2]);
    printf("Max Grid Size: x = %d, y = %d, z = %d\n", 
           deviceProp.maxGridSize[0], 
           deviceProp.maxGridSize[1], 
           deviceProp.maxGridSize[2]);
    
    int max_threads_per_block = deviceProp.maxThreadsPerBlock;
    int max_blocks_per_grid = deviceProp.maxGridSize[0];
    int total_threads_per_grid = max_threads_per_block * max_blocks_per_grid;

    for( int i = 0; i < num_cases; i++ ) {
        time_t init_time = time(NULL);
        FILE * file = fopen(RESULTS_TXT_PATH, "a");
        if( !file ) {
            perror("Failed to open results file");
            return;
        }

        uint8_t target_hash[16];
        for( int j = 0; j < 16; j++ ) {
            sscanf(expected_hashes[i] + j * 2, "%2hhx", &target_hash[j]);
        }

        uint8_t * d_target_hash;
        cudaMalloc(&d_target_hash, 16);
        cudaMemcpy(d_target_hash, target_hash, 16, cudaMemcpyHostToDevice);

        uint8_t * d_result;
        cudaMalloc(&d_result, lengths[i]);
        cudaMemset(d_result, 0, lengths[i]);

        int * d_found;
        cudaMalloc(&d_found, sizeof(int));
        cudaMemset(d_found, 0, sizeof(int));

        uint64_t * d_checked_combinations;
        cudaMalloc(&d_checked_combinations, sizeof(uint64_t));
        cudaMemset(d_checked_combinations, 0, sizeof(uint64_t));

        uint64_t max_combinations = pow(CHARSET_LEN, lengths[i]);
        uint64_t start_combination = 0;

        printf("\nLaunching kernel for length: %d\n", lengths[i]);
        printf("Theoretical maximum combinations for length %d: %lu\n", lengths[i], max_combinations);

        int found;
        while( start_combination < max_combinations ) {
            uint64_t remaining_combinations = max_combinations - start_combination;
            uint64_t combinations_to_process = min(remaining_combinations, (uint64_t)total_threads_per_grid);

            uint64_t blocks_needed = (combinations_to_process + max_threads_per_block - 1) / max_threads_per_block;
            dim3 grid_size(min(blocks_needed, (uint64_t)max_blocks_per_grid));

            printf("Using grid_size: %d and block_size: %d, start_combination: %lu\n", 
                grid_size.x, max_threads_per_block, start_combination);

            int shared_mem_size = max_threads_per_block * sizeof(uint64_t);
            hash_message_kernel<<<grid_size, max_threads_per_block, shared_mem_size>>>(CHARSET_LEN, lengths[i], 
                d_target_hash, d_result, d_found, d_checked_combinations, start_combination, max_combinations);
            cudaDeviceSynchronize();

            cudaMemcpy(&found, d_found, sizeof(int), cudaMemcpyDeviceToHost);
            if( found ) {
                break;
            }

            start_combination += combinations_to_process;
        }

        uint8_t result[lengths[i] + 1];
        cudaMemcpy(result, d_result, lengths[i], cudaMemcpyDeviceToHost);
        result[lengths[i]] = '\0';
        
        if( found ) {
            printf("(%d) Message found: %s\n", lengths[i], result);
            fprintf(file, "(%d) Message found: %s\n", lengths[i], result);
        } else {
            printf("(%d) No message found with the given hash\n", lengths[i]);
            fprintf(file, "(%d) No message found with the given hash\n", lengths[i]);
        }

        uint64_t checked_combinations;
        cudaMemcpy(&checked_combinations, d_checked_combinations, sizeof(uint64_t), cudaMemcpyDeviceToHost);

        printf("Checked combinations: %lu\n", checked_combinations);
        fprintf(file, "Checked combinations: %lu\n", checked_combinations);

        time_t end_time = time(NULL);
        printf("Seconds: %ld\n", end_time - init_time);
        fprintf(file, "Seconds %ld\n", end_time - init_time);

        cudaFree(d_target_hash);
        cudaFree(d_result);
        cudaFree(d_found);
        cudaFree(d_checked_combinations);

        fclose(file);
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

    run_atack_cuda((const char **)expected_hashes, lengths, num_cases);

    for( int i = 0; i < num_cases; i++ ) {
        free(expected_hashes[i]);
    }
    free(expected_hashes);
    free(lengths);

    return 0;
}
