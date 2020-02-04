#pragma once
#include "pdp11core.hpp"
#include "miniasm.hpp"


const char bin_file1[] = "../res/1.bin";


extern FILE *pdp_log_file;


enum class pdp_job_type
{
    RUN,
    EXIT,
    SELECT,
    BREAKPOINT,
    STEP,
    STOP,
    LOAD,
    RESET,

    IRQ01,
    IRQ2
};


struct pdp_todo
{
    bool run;
    bool exit;
};


class pdp11
{
public:
    pdp11(const pdp11 &pdp11) = delete;
    pdp11(pdp11 &&pdp11) = delete;
    pdp11& operator=(const pdp11 &pdp11) = delete;
    pdp11& operator=(pdp11 &&pdp11) = delete;

    pdp11();
    ~pdp11();

    VRet do_job(pdp_job_type type);
    void load_exec_file(const char *filename);
    void start();
    bool should_exit();

    const uint8_t *getVRAM() const;
    const video_adapter *get_video_adapter() const;

    void set_key_code(uint8_t key_code);

    void load_disasm();
    void load_mem();
    void load_regs();

    void set_selected(int sel);
    VRet set_bp();
    
private:
    void run();
    void reset();

    pdp11core m_core;
    bool m_is_running;
    bool m_exec_is_loaded;
    bool m_should_exit;
    pdp_todo m_todo;

    int m_selected;
};
