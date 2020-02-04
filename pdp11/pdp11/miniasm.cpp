#include "miniasm.hpp"


size_t read_numbs(char *buf, size_t size, FILE *f_src);
size_t char2numbs(uint16_t *numbs, char *buf, size_t numb_amount);
void write_numbs(uint16_t *numbs, size_t size, const char *dest);



void txt2bin(const char *src, const char *dest)
{
    FILE *f_src = solver.fopen(src, "r");

    size_t size = solver.get_file_size(f_src);

    char *buf = static_cast<char *>(malloc(size+1));
    if(!buf || errno)
    {
        solver.perror("txt2bin: malloc:");
        assert(false);
        exit(EXIT_FAILURE);
    }

    memset(buf, 0, size+1);

    size_t numb_amount = read_numbs(buf, size, f_src);

    uint16_t *numbs = static_cast<uint16_t *>(malloc(sizeof(uint16_t) * numb_amount));

    char2numbs(numbs, buf, numb_amount);

    write_numbs(numbs, numb_amount, dest);

    free(buf);
    free(numbs);
    solver.fclose(f_src);
}


size_t read_numbs(char *buf, size_t size, FILE *f_src)
{
    size_t checkErr2 = fread(buf, size, 1, f_src);
    if(checkErr2 != 1 || errno)
    {
        solver.perror("fread");
        DBG_PRINTF("checkErr2 = %zu\n", checkErr2);
        exit(EXIT_FAILURE);        
    }

    checkErr2 = (size+1) % 7;
    if(checkErr2 != 0)
    {
        DBG_PRINTF("checkErr2 = %zu\n", checkErr2);
        assert(false);
        exit(EXIT_FAILURE);
    }

    size_t numb_amount = (size+1) / 7;

    return numb_amount;
}


size_t char2numbs(uint16_t *numbs, char *buf, size_t numb_amount)
{
    int j = 0;
   
    //assert(false);

#ifdef PDP11_LINUX
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#endif // PDP11_LINUX

read_cicle:
    for(int i = 0; i < 6; i++)
    {
        numbs[j] *= 8;
        numbs[j] += buf[j*7 + i] - '0';
    }
#ifdef PDP11_LINUX
#pragma GCC diagnostic pop
#endif // PDP11_LINUX

    j += 1;

    if(buf[j*7-1] != 0)
    {
        if(buf[j*7-1] != '\n')
        {
            DBG_PRINTF("buf[%d] = %d\n", j*7-1, buf[j*7-1]);
            DBG_PRINTF("\\n = %d\n", '\n');
            assert(false);
            exit(EXIT_FAILURE);
        }
        goto read_cicle;
    }

    return numb_amount;
}


void write_numbs(uint16_t *numbs, size_t size, const char *dest)
{
    FILE *f_dest = solver.fopen(dest, "wb");

    size_t checkErr = fwrite(numbs, sizeof(uint16_t), size, f_dest);
    if(errno || checkErr != size)
    {
        solver.perror("write_numbs: fwrite");
        exit(EXIT_FAILURE);
    }
    
    solver.fclose(f_dest);
}
