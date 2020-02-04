#pragma once
#include "pdp11lib.hpp"
#include "PortSolver.hpp"
#include "includes.hpp"


extern const PortSolver solver;


class logger
{
public:
    logger();

    void print_comman_cmd(const two_operand_instruction_common &pdp_cmd) const;
    void print_additional_cmd(const two_operand_instruction_additional &pdp_cmd) const;
    void print_regs() const;
    void print_io_regs() const;
    void print_cmd(uint16_t cmd) const;
    
    void print_RAM(uint32_t n);
    void print_VRAM(uint32_t n);
    void print_ROM(uint32_t n);
    void dump_n_VRAM(const char *dump_file_name, uint32_t n);
    void dump_VRAM(const char *dump_file_name);
    void dump_n_ROM(const char *dump_file_name, uint32_t n);
    void dump_ROM(const char *dump_file_name);

    void set_core(pdp11core *core);
    void set_log_file(FILE *file);

private:
    pdp11core *m_core;
    FILE *m_log_file;
};


void print_consts_dec();
void print_consts_oct();