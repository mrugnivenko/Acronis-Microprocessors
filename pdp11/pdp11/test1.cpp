#include <iostream>
#include "pdp11.hpp"


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


int main()
{
    std::cout << "Hello world!" << std::endl;

    std::cout << pdp11_memory_size_sum << std::endl;

    uint16_t numb = 012700;


    print_bits(numb);


    return EXIT_SUCCESS;
}



void print_bits(uint16_t numb)
{
    pdp11_cmd *cmd = reinterpret_cast<pdp11_cmd *>(&numb);

    std::cout << "numb = " << numb << std::endl;
    std::cout << "cmd = " << *reinterpret_cast<uint16_t *>(cmd) << std::endl;
    std::cout << "B = " << cmd->bite << std::endl;
    std::cout << "Opcode = " << cmd->opcode << std::endl;
    std::cout << "Src mode = " << cmd->mode_src << std::endl;
    std::cout << "R Src = " << cmd->reg_src << std::endl;
    std::cout << "Dest mode = " << cmd->mode_dest << std::endl;
    std::cout << "R Dest = " << cmd->reg_dest << std::endl << std::endl;

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