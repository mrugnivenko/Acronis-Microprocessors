#pragma once
#include "logger.hpp"
#include "decoder.hpp"
#include "disasm.hpp"
#include "PortSolver.hpp"
#include "includes.hpp"


const uint16_t default_PC = ROM_start + 6;


enum class interrupt_type
{
    IRQ0,
    IRQ1,
    IRQ2
};


class pdp11core
{
public:
    pdp11core(const pdp11core &core) = delete;
    pdp11core(pdp11core &&core) = delete;
    pdp11core& operator=(const pdp11core &core) = delete;
    pdp11core& operator=(pdp11core &&core) = delete;

    pdp11core();
    ~pdp11core();

    VRet load_exec_file(const char *filename);
    void run();
    void run_proc();

    void decode();
    void execute();

    uint8_t get_data_byte(uint32_t addr) const;
    uint16_t get_data_word(uint32_t addr) const;
    void set_data_byte(uint32_t addr, uint8_t value);
    void set_data_word(uint32_t addr, uint16_t value);

    uint8_t get_reg_byte(uint16_t reg_numb) const;
    uint16_t get_reg_word(uint16_t reg_numb) const;    
    void set_reg_byte(uint16_t reg_numb, uint8_t value);
    void set_reg_word(uint16_t reg_numb, uint16_t value);

    uint16_t get_PC() const;
    void inc_PC();
    void double_inc_PC();
    void set_PC(uint16_t value);

    uint16_t get_current_cmd() const;

    uint32_t get_reg_addr(uint16_t reg_numb) const;
    uint32_t get_PC_addr() const;
    void inc_reg(uint16_t reg_numb);
    void dec_reg(uint16_t reg_numb);
    void double_inc_reg(uint16_t reg_numb);

    const status_flags *getFlags() const;
    void setFlag(flag_type type, bool value);

    void set_pointers();
    void set_log_file(FILE *file);

    const uint8_t *getVRAM() const;
    const video_adapter *get_video_adapter() const;

    void set_key_code(uint8_t key_code);
    void interrupt_request(interrupt_type type);

    void wait() const;

    bool requested() const;

    void print_disasm() const;
    void print_data() const;
    void print_mem() const;
    void print_regs() const;
    void reset();

    uint16_t get_breakpoint() const;
    void set_breakpoint(uint16_t bp);

    void zero_mem();
    void zero_RAM();
    void zero_VRAM();
    void zero_IO();
    void zero_regs();
    void zero_flags();
    void zero_video_adapter();
    void zero_irqs();
   
    void zero_ROM();


private:
    uint8_t m_memory[pdp11_memory_size_sum];
    status_flags m_status_flags;
    uint8_t m_flag_I;

    logger m_logger;
    decoder m_decoder;
    disasm m_disasm;

    bool m_irq0;
    bool m_irq1;
    bool m_irq2;

    bool m_is_interrupted;

    uint16_t m_breakpoint;
    uint16_t m_old_PC;

    /*
    bool m_stop;
    bool m_step;
    */
};