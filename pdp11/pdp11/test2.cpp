#include <iostream>
#define private public
#include "pdp11.hpp"
#include "asm.hpp"
#include <string.h>


struct test_str
{
    uint16_t bit1 : 1;
    uint16_t bit2 : 1;
    uint16_t bit3 : 1;
    uint16_t bit4 : 1;
    uint16_t bit5 : 1;
    uint16_t bit6 : 1;
    uint16_t bit7 : 1;
    uint16_t bit8 : 1;
    uint16_t bit9 : 1;
    uint16_t bit10 : 1;
    uint16_t bit11 : 1;
    uint16_t bit12 : 1;
    uint16_t bit13 : 1;
    uint16_t bit14 : 1;
    uint16_t bit15 : 1;
    uint16_t bit16 : 1;
};


void print_bits(uint16_t numb);
void print_cmds(pdp11_cmd *cmd);


const char txt_file[] = "1.txt";
const char bin_file[] = "2.bin";


int main()
{
    std::cout << "Hello world!" << std::endl;
    std::cout << pdp11_memory_size_sum << std::endl;

    txt2bin(txt_file, bin_file);

    pdp11 the_pdp11;

    VRet checkErr = the_pdp11.load_exec_file(bin_file);
    if(checkErr)
        printf("1.checkErr = %d\n", checkErr);

    checkErr = the_pdp11.run();
    if(checkErr)
        printf("2.checkErr = %d\n", checkErr);
    
    for(unsigned int i = 0; i < pdp11_reg_amount; i++)
    {
        std::cout << "regs[" << i << "] = " << the_pdp11.m_regs[i] << std::endl;
    }
    
    for(unsigned int i = 0; i < 15; i++)
    {
        uint16_t tmp = *(uint16_t *)&the_pdp11.m_memory[2*i+ROM_start];
        printf("mem[%u] = %06o = 0x%04X\n", 2*i+ROM_start, tmp, tmp);
    }

    
    pdp11_cmd cmd2;
    cmd2.bite = 0;
    cmd2.opcode = opcode_move;
    cmd2.mode_src = mode_nothing;
    cmd2.reg_src = 0;
    cmd2.mode_dest = mode_reg_numb;
    cmd2.reg_dest = 0;

    uint16_t *tmp_numb = reinterpret_cast<uint16_t *>(&cmd2);

    printf("cmd2 = %06o = 0x%04X\n", *tmp_numb, *tmp_numb);
    print_bits(*tmp_numb);
    
    print_cmds(&cmd2);

    return EXIT_SUCCESS;
}


void print_bits(uint16_t numb)
{
    pdp11_cmd *cmd = reinterpret_cast<pdp11_cmd *>(&numb);

    std::cout << "numb = " << numb << std::endl;
    std::cout << "cmd = " << *reinterpret_cast<uint16_t *>(cmd) << std::endl;
    printf("B = %u\n", cmd->bite);
    printf("Opcode = %u\n", cmd->opcode);
    printf("Src mode = %u\n", cmd->mode_src);
    printf("R Src = %u\n", cmd->reg_src);
    printf("Dest mode = %u\n", cmd->mode_dest);
    printf("R Dest = %u\n\n", cmd->reg_dest);

    test_str *t_str = reinterpret_cast<test_str *>(&numb);

    std::cout << "t_str = " << *reinterpret_cast<uint16_t *>(t_str) << std::endl;
    std::cout << "bit1 = " << t_str->bit1 << std::endl;
    std::cout << "bit2 = " << t_str->bit2 << std::endl;
    std::cout << "bit3 = " << t_str->bit3 << std::endl;
    std::cout << "bit4 = " << t_str->bit4 << std::endl;
    std::cout << "bit5 = " << t_str->bit5 << std::endl;
    std::cout << "bit6 = " << t_str->bit6 << std::endl;
    std::cout << "bit7 = " << t_str->bit7 << std::endl;
    std::cout << "bit8 = " << t_str->bit8 << std::endl;
    std::cout << "bit9 = " << t_str->bit9 << std::endl;
    std::cout << "bit10 = " << t_str->bit10 << std::endl;
    std::cout << "bit11 = " << t_str->bit11 << std::endl;
    std::cout << "bit12 = " << t_str->bit12 << std::endl;
    std::cout << "bit13 = " << t_str->bit13 << std::endl;
    std::cout << "bit14 = " << t_str->bit14 << std::endl;
    std::cout << "bit15 = " << t_str->bit15 << std::endl;
    std::cout << "bit16 = " << t_str->bit16 << std::endl;
}


void print_cmds(pdp11_cmd *cmd)
{
    printf("cmd = %06o\n", *reinterpret_cast<uint16_t *>(cmd));
    printf("B = %u\n", cmd->bite);
    printf("Opcode = %u\n", cmd->opcode);
    printf("Src mode = %u\n", cmd->mode_src);
    printf("R Src = %u\n", cmd->reg_src);
    printf("Dest mode = %u\n", cmd->mode_dest);
    printf("R Dest = %u\n\n", cmd->reg_dest);
}
