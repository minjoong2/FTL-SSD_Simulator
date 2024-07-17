#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#define PAGE_SIZE 4096  // 4KB
#define BLOCK_SIZE (4 * 1024 * 1024)  // 4MB
#define SSD_SIZE (8 * 1024 * 1024 * 1024ULL)  // 8GB
#define PAGES_PER_BLOCK (BLOCK_SIZE / PAGE_SIZE)
#define BLOCKS_PER_SSD (SSD_SIZE / BLOCK_SIZE)

typedef struct {
    double timestamp;
    int io_type; // 1: WRITE (다른 값은 무시)
    unsigned long lba;
    unsigned int size;
    unsigned int stream_number;
} IORequest;

typedef struct {
    bool is_free;
    uint8_t valid_bitmap[PAGES_PER_BLOCK / 8]; // 각 페이지의 상태를 나타내는 비트맵
    unsigned long *oob; // Out-of-band 영역
} Block;

typedef struct QueueNode {
    int block_index;
    int page_index;
    struct QueueNode *next;
} QueueNode;

typedef struct Queue {
    QueueNode *front, *rear;
    int size;
} Queue;

// 큐 초기화
void initQueue(Queue *q) {
    q->front = q->rear = NULL;
    q->size = 0;
}

// 큐에 페이지 추가
void enqueue(Queue *q, int block_index, int page_index) {
    QueueNode *temp = (QueueNode*)malloc(sizeof(QueueNode));
    temp->block_index = block_index;
    temp->page_index = page_index;
    temp->next = NULL;
    if (q->rear == NULL) {
        q->front = q->rear = temp;
    } else {
        q->rear->next = temp;
        q->rear = temp;
    }
    q->size++;
}

// 큐에서 페이지 제거
QueueNode* dequeue(Queue *q) {
    if (q->front == NULL)
        return NULL;
    QueueNode *temp = q->front;
    q->front = q->front->next;
    if (q->front == NULL)
        q->rear = NULL;
    q->size--;
    return temp;
}

// 페이지 유효성을 설정 (유효로)
void set_page_valid(Block *block, int page_index) {
    int byte_index = page_index / 8;
    int bit_index = page_index % 8;
    block->valid_bitmap[byte_index] |= (1 << bit_index);
}

// 페이지 유효성을 설정 (무효로)
void set_page_invalid(Block *block, int page_index) {
    int byte_index = page_index / 8;
    int bit_index = page_index % 8;
    block->valid_bitmap[byte_index] &= ~(1 << bit_index);
}

// 페이지가 유효한지 확인
bool is_page_valid(Block *block, int page_index) {
    int byte_index = page_index / 8;
    int bit_index = page_index % 8;
    return (block->valid_bitmap[byte_index] & (1 << bit_index)) != 0;
}

// WAF 및 Utilization 계산 함수
double calculate_waf(unsigned long internal_writes, unsigned long host_writes) {
    return (double)internal_writes / host_writes;
}

double calculate_utilization(unsigned long used_pages, unsigned long total_pages) {
    return (double)used_pages / total_pages;
}

// Garbage Collection 함수
void garbage_collection(Block *ssd, Queue *free_block_queue, unsigned long *mapping_table, int *active_block_index, int *active_page_index, unsigned long *internal_writes, unsigned long *erase_count, unsigned long *checkpoint_erases, double *total_valid_data_ratio, int *gc_count, int *used_blocks) {
    // Greedy 방식으로 victim block 선택: valid한 페이지가 가장 적은 블록 선택
    int victim_block_index = -1;
    int min_valid_pages = PAGES_PER_BLOCK;
    int i, j;

    for (i = 0; i < BLOCKS_PER_SSD; i++) {
        if (!ssd[i].is_free) {
            int valid_pages = 0;
            for (j = 0; j < PAGES_PER_BLOCK; j++) {
                if (is_page_valid(&ssd[i], j)) {
                    valid_pages++;
                }
            }
            if (valid_pages < min_valid_pages) {
                min_valid_pages = valid_pages;
                victim_block_index = i;
            }
        }
    }

    if (victim_block_index == -1) {
        return;
    }

    // Victim block의 유효한 페이지를 현재 active block의 active page에 복사
    for (i = 0; i < PAGES_PER_BLOCK; i++) {
        if (is_page_valid(&ssd[victim_block_index], i)) {
            // Free block에서 페이지를 꺼내옴
            if (*active_block_index == -1 || *active_page_index >= PAGES_PER_BLOCK) {
                QueueNode *node = dequeue(free_block_queue);
                if (node == NULL) {
                    break;
                }
                *active_block_index = node->block_index;
                *active_page_index = 0;
                free(node);
            }

            int block_index = *active_block_index;
            int page_index = *active_page_index;

            // 페이지를 valid로 설정
            set_page_valid(&ssd[block_index], page_index);

            // OOB 영역에 논리적 페이지 주소를 기록
            ssd[block_index].oob[page_index] = ssd[victim_block_index].oob[i];

            // 맵핑 테이블에 논리적 -> 물리적 주소 저장
            unsigned long lba = ssd[victim_block_index].oob[i];
            unsigned long physical_address = block_index * PAGES_PER_BLOCK + page_index;
            mapping_table[lba] = physical_address;

            // 내부 쓰기 횟수 증가
            (*internal_writes)++;

            // victim block의 페이지 무효화
            set_page_invalid(&ssd[victim_block_index], i);
            ssd[victim_block_index].oob[i] = 0xFFFFFFFFFFFFFFFF; // OOB에서 lba 내용 삭제

            // 남은 크기와 현재 LBA 업데이트
            (*active_page_index)++;
        }
    }

    // Victim block을 free block으로 변경
    ssd[victim_block_index].is_free = true;
    for (i = 0; i < PAGES_PER_BLOCK; i++) {
        enqueue(free_block_queue, victim_block_index, i);
    }

    // 사용된 블록 수 갱신
    *used_blocks = BLOCKS_PER_SSD - free_block_queue->size / PAGES_PER_BLOCK;

    // Erase count 증가
    (*erase_count)++;
    (*checkpoint_erases)++;

    // 유효 데이터 비율 계산 및 누적
    double valid_data_ratio = (double)min_valid_pages / PAGES_PER_BLOCK;
    *total_valid_data_ratio += valid_data_ratio;
    (*gc_count)++;
}

int main() {
    FILE *file = fopen("test-fio-small", "r");
    if (!file) {
        perror("Failed to open file");
        return 1;
    }

    // SSD 초기화
    Block *ssd = (Block *)malloc(BLOCKS_PER_SSD * sizeof(Block));
    if (ssd == NULL) {
        perror("Failed to allocate memory for SSD");
        fclose(file);
        return 1;
    }
    int i, j;
    for (i = 0; i < BLOCKS_PER_SSD; i++) {
        ssd[i].is_free = true;
        ssd[i].oob = (unsigned long *)malloc(PAGES_PER_BLOCK * sizeof(unsigned long));
        if (ssd[i].oob == NULL) {
            perror("Failed to allocate memory for OOB");
            for (j = 0; j < i; j++) {
                free(ssd[j].oob);
            }
            free(ssd);
            fclose(file);
            return 1;
        }
        for (j = 0; j < PAGES_PER_BLOCK / 8; j++) {
            ssd[i].valid_bitmap[j] = 0; // 모든 페이지를 invalid로 초기화
        }
        for (j = 0; j < PAGES_PER_BLOCK; j++) {
            ssd[i].oob[j] = 0xFFFFFFFFFFFFFFFF; // 초기화
        }
    }

    // Free block을 관리하는 큐 초기화
    Queue free_block_queue;
    initQueue(&free_block_queue);

    // 초기 모든 블록을 큐에 추가
    for (i = 0; i < BLOCKS_PER_SSD; i++) {
        for (j = 0; j < PAGES_PER_BLOCK; j++) {
            enqueue(&free_block_queue, i, j);
        }
    }

    // IORequest 구조체를 위한 메모리 할당
    IORequest *request = (IORequest *)malloc(sizeof(IORequest));
    if (request == NULL) {
        perror("Failed to allocate memory");
        for (i = 0; i < BLOCKS_PER_SSD; i++) {
            free(ssd[i].oob);
        }
        free(ssd);
        fclose(file);
        return 1;
    }

    // 논리적 -> 물리적 주소 맵핑 테이블
    unsigned long *mapping_table = (unsigned long *)malloc((SSD_SIZE / PAGE_SIZE) * sizeof(unsigned long));
    if (mapping_table == NULL) {
        perror("Failed to allocate memory for mapping table");
        free(request);
        for (i = 0; i < BLOCKS_PER_SSD; i++) {
            free(ssd[i].oob);
        }
        free(ssd);
        fclose(file);
        return 1;
    }

    for (i = 0; i < (SSD_SIZE / PAGE_SIZE); i++) {
        mapping_table[i] = 0xFFFFFFFFFFFFFFFF; // 초기화
    }

    // 현재 사용 중인 블록 (active block) 변수 선언
    int active_block_index = -1;
    int active_page_index = 0;

    // 추가 변수 선언
    unsigned long total_writes = 0; // 호스트 쓰기 요청 수
    unsigned long internal_writes = 0; // 실제 SSD에 기록된 쓰기 수
    unsigned long total_erases = 0;
    unsigned long used_pages = 0;
    unsigned long last_gb_checkpoint = 0;
    unsigned long checkpoint_writes = 0;
    unsigned long checkpoint_erases = 0;
    unsigned long last_50gb_checkpoint = 0; // 마지막 50GB 체크포인트
    unsigned long writes_since_50gb = 0; // 최근 50GB 동안의 쓰기 수
    unsigned long internal_writes_since_50gb = 0; // 최근 50GB 동안의 내부 쓰기 수
    double total_valid_data_ratio = 0.0; // 50GB 동안의 총 유효 데이터 비율
    int gc_count = 0; // 50GB 동안의 GC 횟수
    int used_blocks = 0; // 현재 사용된 블록 수
    unsigned long total_read_bytes = 0; // 현재까지 읽은 총 바이트 수

    // 파일에서 줄을 읽어 구조체에 저장하고 처리
    char line[256];
    unsigned long line_number = 0; // 추가: 줄 번호
    while (fgets(line, sizeof(line), file)) {
        line_number++; // 추가: 줄 번호 증가
        if (sscanf(line, "%lf %d %lu %u %u", &request->timestamp,
                   &request->io_type, &request->lba, 
                   &request->size, &request->stream_number) != 5) {
            continue;
        }

        total_read_bytes += 4096; // 4KB씩 증가

        if (request->io_type == 1) { // WRITE 요청 처리
            unsigned long remaining_size = request->size;
            unsigned long current_lba = request->lba;

            while (remaining_size > 0) {
                // SSD의 모든 블록과 페이지를 검사하여 OOB에서 lba를 확인
                for (i = 0; i < BLOCKS_PER_SSD; i++) {
                    for (j = 0; j < PAGES_PER_BLOCK; j++) {
                        if (ssd[i].oob[j] == current_lba) {
                            set_page_invalid(&ssd[i], j);
                            ssd[i].oob[j] = 0xFFFFFFFFFFFFFFFF; // OOB에서 lba 내용 삭제
                            break;
                        }
                    }
                }

                // Free block에서 페이지를 꺼내옴
                if (active_block_index == -1 || active_page_index >= PAGES_PER_BLOCK) {
                    QueueNode *node = dequeue(&free_block_queue);
                    if (node == NULL) {
                        break;
                    }
                    active_block_index = node->block_index;
                    active_page_index = 0;
                    free(node);

                    // 사용된 블록 수 증가
                    used_blocks++;
                }

                int block_index = active_block_index;
                int page_index = active_page_index;

                // 페이지를 valid로 설정
                set_page_valid(&ssd[block_index], page_index);

                // OOB 영역에 논리적 페이지 주소를 기록
                ssd[block_index].oob[page_index] = current_lba;

                // 맵핑 테이블에 논리적 -> 물리적 주소 저장
                unsigned long physical_address = block_index * PAGES_PER_BLOCK + page_index;
                mapping_table[current_lba] = physical_address;

                // 통계 업데이트
                total_writes++; // 호스트 쓰기 요청 수 증가
                internal_writes++; // 실제 SSD 쓰기 수 증가
                checkpoint_writes++;
                writes_since_50gb++;
                internal_writes_since_50gb++;
                used_pages++;

                // 남은 크기와 현재 LBA 업데이트
                remaining_size -= PAGE_SIZE;
                current_lba += 1;
                active_page_index += 1;
            }
        }

        // Free block의 개수를 확인하고, 3개 이하이면 GC 수행
        while (free_block_queue.size <= 3) {
            garbage_collection(ssd, &free_block_queue, mapping_table, &active_block_index, &active_page_index, &internal_writes, &total_erases, &checkpoint_erases, &total_valid_data_ratio, &gc_count, &used_blocks);
        }

        // 1GB 마다 상태 출력
        if (total_read_bytes >= last_gb_checkpoint + 1 * 1024 * 1024 * 1024ULL) {
            last_gb_checkpoint += 1 * 1024 * 1024 * 1024ULL;
            double waf = calculate_waf(internal_writes, total_writes);
            double tmp_waf = writes_since_50gb > 0 ? calculate_waf(internal_writes_since_50gb, writes_since_50gb) : 0.0;
            double utilization = calculate_utilization(used_pages, BLOCKS_PER_SSD * PAGES_PER_BLOCK);
            double avg_valid_data_ratio = gc_count > 0 ? total_valid_data_ratio / gc_count : 0.0;

            printf("[Progress: %lu GiB] WAF: %.3f, TMP_WAF: %.3f, Utilization: %.3f\n", last_gb_checkpoint / (1024 * 1024 * 1024ULL), waf, tmp_waf, utilization);
            printf("GROUP 0[%d]: %.2f (ERASE: %lu)\n", used_blocks, avg_valid_data_ratio, checkpoint_erases);

            // 50GB 단위 초기화
            if (writes_since_50gb * PAGE_SIZE >= 50 * 1024 * 1024 * 1024ULL) {
                writes_since_50gb = 0;
                internal_writes_since_50gb = 0;
                checkpoint_erases = 0;
                total_valid_data_ratio = 0.0;
                gc_count = 0;
            }
        }
    }

    // 메모리 해제
    free(request);
    free(mapping_table);
    for (i = 0; i < BLOCKS_PER_SSD; i++) {
        free(ssd[i].oob);
    }
    free(ssd);
    fclose(file);

    return 0;
}

