#include "logger.hpp"
#include "pdp11.hpp"
#include <string.h>


logger::logger() :
    m_core(nullptr),
    m_log_file(stdout)
{}


void logger::print_comman_cmd(const two_operand_instruction_common &pdp_cmd) const
{
    assert(m_log_file);
    DBG_FPRINTF(m_log_file, "\tOpcode = 0%02o\n", pdp_cmd.opcode);
    DBG_FPRINTF(m_log_file, "\tSrc mode = %u\n", pdp_cmd.mode_src);
    DBG_FPRINTF(m_log_file, "\tR Src = %u\n", pdp_cmd.reg_src);
    DBG_FPRINTF(m_log_file, "\tDest mode = %u\n", pdp_cmd.mode_dest);
    DBG_FPRINTF(m_log_file, "\tR Dest = %u\n", pdp_cmd.reg_dest);
}


void logger::print_additional_cmd(const two_operand_instruction_additional &pdp_cmd) const
{
    assert(m_log_file);
    DBG_FPRINTF(m_log_file, "\tOpcode = 07%o\n", pdp_cmd.opcode);
    DBG_FPRINTF(m_log_file, "\tReg = %u\n", pdp_cmd.reg);
    DBG_FPRINTF(m_log_file, "\tOperand = %u\n", pdp_cmd.operand);
}


void logger::print_regs() const
{
    assert(m_log_file);
    uint16_t reg_amount = static_cast<uint16_t>(pdp11_reg_amount);
    for(uint16_t i = 0; i < reg_amount - 3; i++)
    {
        DBG_FPRINTF(m_log_file, "r%u = %06o\n", i, m_core->get_reg_word(i));
    }

    DBG_FPRINTF(m_log_file, "r%d = %06o (FP)\n", 5, m_core->get_reg_word(5));
    DBG_FPRINTF(m_log_file, "r%d = %06o (SP)\n", 6, m_core->get_reg_word(6));
    DBG_FPRINTF(m_log_file, "r%d = %06o (PC)\n", 7, m_core->get_reg_word(7));
}


void logger::print_io_regs() const
{
    assert(m_log_file);
    uint16_t shift_register = m_core->get_video_adapter()->shift_register;
    DBG_FPRINTF(m_log_file, "shift_reg = %06o\n", shift_register);
}


void logger::print_cmd(uint16_t cmd) const
{
    assert(m_log_file);
    DBG_FPRINTF(m_log_file, "current cmd = %06o\n", cmd);
}


void logger::print_RAM(uint32_t n)
{
    assert(m_log_file);
    for(uint32_t i = 0; i < n; i++)
    {
        DBG_FPRINTF(m_log_file, "RAM[%06o] = %06o\n", i, m_core->get_data_byte(i));
    }    
}


void logger::print_VRAM(uint32_t n)
{
    assert(m_log_file);
    for(uint32_t i = 0; i < n; i++)
    {
        DBG_FPRINTF(m_log_file, "RAM[%06o] = VRAM[%06o] = %u\n", VRAM_start + i, i, m_core->get_data_byte(VRAM_start + i));
    }    
}


void logger::print_ROM(uint32_t n)
{
    assert(m_log_file);
    for(uint32_t i = 0; i < n; i++)
    {
        DBG_FPRINTF(m_log_file, "RAM[%06o] = ROM[%06o] = %06o\n", ROM_start + i, i, m_core->get_data_byte(ROM_start + i));
    }    
}


void logger::dump_n_VRAM(const char *dump_file_name, uint32_t n)
{
    FILE* dump_file = solver.fopen_dbg(dump_file_name, "w");

    for(uint32_t i = 0; i < n; i++)
    {
        DBG_FPRINTF(dump_file, "RAM[%06o] = VRAM[%06o] = %u\n", VRAM_start + i, i, m_core->get_data_byte(VRAM_start + i));
    }

    solver.fclose_dbg(dump_file);
}


void logger::dump_VRAM(const char *dump_file_name)
{
    dump_n_VRAM(dump_file_name, VRAM_size);
}


void logger::dump_n_ROM(const char *dump_file_name, uint32_t n)
{
    FILE *dump_file = solver.fopen_dbg(dump_file_name, "w");

    for(uint32_t i = 0; i < n; i++)
    {
        DBG_FPRINTF(dump_file, "RAM[%06o] = ROM[%06o] = %03o\n", ROM_start + i, i, m_core->get_data_byte(ROM_start + i));
    }

    solver.fclose_dbg(dump_file);
}


void logger::dump_ROM(const char *dump_file_name)
{
    dump_n_ROM(dump_file_name, VRAM_size);
}


void logger::set_core(pdp11core* core)
{
    m_core = core;
}


void logger::set_log_file(FILE* file)
{
    assert(file);
    m_log_file = file;
}


void print_consts_dec()
{
    DBG_PRINTF("pdp11_memory_size = %u\n", pdp11_memory_size);
    DBG_PRINTF("pdp11_memory_size_sum = %u\n", pdp11_memory_size_sum);
    DBG_PRINTF("VRAM_start = %u\n", VRAM_start);
    DBG_PRINTF("VRAM_size = %u\n", VRAM_size);
    DBG_PRINTF("ROM_start = %u\n", ROM_start);
    DBG_PRINTF("ROM_size = %u\n", ROM_size);
    DBG_PRINTF("IO_start = %u\n", IO_start);
    DBG_PRINTF("IO_size = %u\n\n", IO_size);
}


void print_consts_oct()
{
    DBG_PRINTF("pdp11_memory_size = %06o\n", pdp11_memory_size);
    DBG_PRINTF("pdp11_memory_size_sum = %06o\n", pdp11_memory_size_sum);
    DBG_PRINTF("VRAM_start = %06o\n", VRAM_start);
    DBG_PRINTF("VRAM_size = %06o\n", VRAM_size);
    DBG_PRINTF("ROM_start = %06o\n", ROM_start);
    DBG_PRINTF("ROM_size = %06o\n", ROM_size);
    DBG_PRINTF("IO_start = %06o\n", IO_start);
    DBG_PRINTF("IO_size = %06o\n\n", IO_size);
}