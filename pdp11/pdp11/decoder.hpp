#pragma once
#include "CmdParser.hpp"


class decoder
{
public:
    decoder(const decoder &dec) = delete;
    decoder(decoder &&dec) = delete;
    decoder &operator=(const decoder &dec) = delete;
    decoder &operator=(decoder &&dec) = delete;

    decoder();

    void decode();
    void execute();

    void decode_common(uint16_t code_cmd);
    void decode_additional(uint16_t code_cmds);
    void set_func_data(const func_data_common &func_data);
    void set_func_data(const func_data_additional &func_data);

    void mov(uint32_t src_addr, uint32_t dest_addr);
    void movb(uint32_t src_addr, uint32_t dest_addr);
    void cmp(uint32_t src_addr, uint32_t dest_addr);
    void cmpb(uint32_t src_addr, uint32_t dest_addr);
    void bit(uint32_t src_addr, uint32_t dest_addr);
    void bitb(uint32_t src_addr, uint32_t dest_addr);
    void bic(uint32_t src_addr, uint32_t dest_addr);
    void bicb(uint32_t src_addr, uint32_t dest_addr);
    void bis(uint32_t src_addr, uint32_t dest_addr);
    void bisb(uint32_t src_addr, uint32_t dest_addr);
    void add(uint32_t src_addr, uint32_t dest_addr);
    void sub(uint32_t src_addr, uint32_t dest_addr);
    [[noreturn]] void illegal_cmd(uint32_t src_addr, uint32_t dest_addr);


    void beq(uint32_t reg_numb, uint32_t source_operand);
    void bne(uint32_t reg_numb, uint32_t source_operand);
    void ash(uint32_t reg_numb, uint32_t source_operand);
    void ashc(uint32_t reg_numb, uint32_t source_operand);
    void _xor(uint32_t reg_numb, uint32_t dest_operand);
    void wait(uint32_t reg_numb, uint32_t dest_operand); //simplification
    void sob(uint32_t reg_numb, uint32_t jmp_size);

    uint32_t get_addr_register(uint16_t reg);
    uint32_t get_addr_register_deffered(uint16_t reg);
    uint32_t get_addr_autoincrement(uint16_t reg);
    uint32_t get_addr_TODO(uint16_t reg);

    uint32_t get_addr_immediate(uint16_t reg);

    void set_core(pdp11core* core);
    void set_logger(logger* _logger);


private:
    pdp11core *m_core;
    logger *m_logger;
    CmdParser m_parser;

    func_data m_func_data;
    const decode_table m_decode_table;
};
