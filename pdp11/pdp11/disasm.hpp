#pragma once
#include "PortSolver.hpp"
#include "CmdParser.hpp"


extern const PortSolver solver;


const char disasm_comm_instr[16][20] = 
{ 
    "",
    "mov",
    "cmp",
    "bit",
    "bic",
    "bis",
    "add",
    "",
    "",
    "movb",
    "cmpb",
    "bitb",
    "bicb",
    "bisb",
    "sub",
    ""
};


const char disasm_add_instr[8][20] =
{
    "mul",
    "div",
    "ash",
    "ashc",
    "xor",
    "illegal_cmd",
    "wait",
    "sob"
};


class disasm
{
public:
	disasm();

	void disasm_to_file(const uint16_t *bin) const;
    void disasm_to_str(const uint16_t *bin, char str_arr[ROM_size / 2][100], uint16_t bp) const; 

    void get_RAM(const uint16_t *bin, char str_arr[RAM_size / 2][100]) const;
    void get_VRAM(const uint16_t *bin, char str_arr[VRAM_size / 2][100]) const;
    void get_IO(const uint16_t *bin, char str_arr[IO_size / 2][100]) const;


private:
    void disasm_cmd_bp(uint16_t cmd, uint16_t addr, char *ret_str, bool is_bp) const;
    void disasm_cmd(uint16_t cmd, uint16_t addr, char *ret_str) const;
    void disasm_common_cmd(const two_operand_instruction_common &cmd, uint16_t addr, char *ret_str) const;
    void disasm_additional_cmd(const two_operand_instruction_additional &cmd, char *ret_str) const;

    void get_mem(uint16_t cmd, uint16_t addr, char *ret_str) const;

	CmdParser m_parser;
};