#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


struct pdp11_cmd
{
    uint16_t bite = 0;
    uint16_t opcode = 0;
    uint16_t mode_src = 0;
    uint16_t reg_src = 0;
    uint16_t mode_dest = 0;
    uint16_t reg_dest = 0;
};


void get_pdp(uint16_t cmd, pdp11_cmd *pdp_cmd);
void get_cmd(uint16_t *cmd, pdp11_cmd pdp_cmd);
void print_pdp(pdp11_cmd cmd);


int main()
{
    uint16_t cmd = 010030;
    uint16_t cmd2 = 0;
    pdp11_cmd pdp;

    printf("cmd = %06o\n", cmd);
    get_pdp(cmd, &pdp);
    print_pdp(pdp);
    get_cmd(&cmd2, pdp);
    printf("cmd2 = %06o\n", cmd2);

    return EXIT_SUCCESS;
}


void get_pdp(uint16_t cmd, pdp11_cmd *pdp_cmd)
{
    pdp11_cmd pdp;
    uint16_t buf;

    buf = 0x8000;
    pdp.bite = static_cast<uint16_t>((cmd & buf) >> 15);
    buf = 0x7000;
    pdp.opcode = static_cast<uint16_t>((cmd & buf) >> 12);
    buf = 0x0e00;
    pdp.mode_src = static_cast<uint16_t>((cmd & buf) >> 9);
    buf = 0x01c0;
    pdp.reg_src = static_cast<uint16_t>((cmd & buf) >> 6);
    buf = 0x0038;
    pdp.mode_dest = static_cast<uint16_t>((cmd & buf) >> 3);
    buf = 0x0007;
    pdp.reg_dest = static_cast<uint16_t>(cmd & buf);

    *pdp_cmd = pdp;
}


void get_cmd(uint16_t *out_cmd, pdp11_cmd pdp)
{
    uint16_t cmd = 0;

    cmd = static_cast<uint16_t>(pdp.bite << 15);
    cmd += static_cast<uint16_t>(pdp.opcode << 12);
    cmd += static_cast<uint16_t>(pdp.mode_src << 9);
    cmd += static_cast<uint16_t>(pdp.reg_src << 6);
    cmd += static_cast<uint16_t>(pdp.mode_dest << 3);
    cmd += pdp.reg_dest;

    *out_cmd = cmd;
}



void print_pdp(pdp11_cmd cmd)
{
    printf("B = %u\n", cmd.bite);
    printf("Opcode = %u\n", cmd.opcode);
    printf("Src mode = %u\n", cmd.mode_src);
    printf("R Src = %u\n", cmd.reg_src);
    printf("Dest mode = %u\n", cmd.mode_dest);
    printf("R Dest = %u\n", cmd.reg_dest);
}