#include "pdp11.hpp"
#include "win_gui.hpp"


pdp11::pdp11():
    m_core(),
    m_is_running(false),
    m_exec_is_loaded(false),
    m_should_exit(false),
    m_todo({false, false}),
    m_selected(-1)
{
    m_core.set_pointers();
    pdp_log_file = solver.fopen_dbg("pdp_file.log", "w");
    m_core.set_log_file(pdp_log_file);
}


pdp11::~pdp11()
{
    solver.fclose_dbg(pdp_log_file);
}


void pdp11::load_exec_file(const char *filename)
{
    //if(m_exec_is_loaded)
    //    assert(false);

    VRet checkErr = m_core.load_exec_file(filename);
    if(checkErr != VRet::VSUCCESS)
    {
        DBG_PRINTF("load_exec_file error: checkErr = %d\n", checkErr);
        assert(false);
    }

    m_exec_is_loaded = true;

    m_core.reset();
}


void pdp11::run()
{
    if(m_is_running)
        assert(false);

    m_is_running = true;
    m_core.run();
    m_is_running = false;

}


VRet pdp11::do_job(pdp_job_type type)
{
    char tmp_str[100] = "";

    switch(type)
    {
    case(pdp_job_type::RUN):
        if(m_is_running)
            return VRet::VFAILURE;

        if(m_todo.run)
            return VRet::VUSELESS;

        m_todo.run = true;
        break;

    case(pdp_job_type::EXIT):
        if(m_is_running)
            return VRet::VFAILURE;

        m_todo.exit = true;
        break;

    case(pdp_job_type::SELECT):
        assert(false);
        break;

    case(pdp_job_type::BREAKPOINT):
        assert(false);
        break;

    case(pdp_job_type::STEP):
        assert(false);
        break;

    case(pdp_job_type::STOP):
        assert(false);
        break;

    case(pdp_job_type::LOAD):
        if(m_is_running)
            return VRet::VFAILURE;
        
        if(gui_open_file(tmp_str))
        {
            txt2bin(tmp_str, bin_file1);
            load_exec_file(bin_file1);
        }
        break;

    case(pdp_job_type::IRQ01):
        m_core.interrupt_request(interrupt_type::IRQ0);
        break;

    case(pdp_job_type::IRQ2):
        assert(false);
        break;

    case(pdp_job_type::RESET):
        if(m_is_running)
            return VRet::VFAILURE;

        m_core.reset();
        break;


    default:
        assert(false);
    }

    return VRet::VSUCCESS;
}


void pdp11::start()
{
    while(!m_todo.exit)
    {
        if(m_todo.run)
        {
            assert(!m_is_running);
            run();
            m_todo.run = false;
        }
        Sleep(1000);
    }

    m_should_exit = true;
}


bool pdp11::should_exit()
{
    return m_should_exit;
}


const uint8_t *pdp11::getVRAM() const
{
    return m_core.getVRAM();
}


const video_adapter *pdp11::get_video_adapter() const
{
    return m_core.get_video_adapter();
}


void pdp11::set_key_code(uint8_t key_code)
{
    m_core.set_key_code(key_code);
}


void pdp11::load_disasm()
{
    m_core.print_disasm();
}


void pdp11::load_mem()
{
    m_core.print_mem();
}


void pdp11::load_regs()
{
    m_core.print_regs();
}


void pdp11::reset()
{
    m_core.reset();
}


void pdp11::set_selected(int sel)
{
    m_selected = sel;
}


VRet pdp11::set_bp()
{
    if(m_selected < 0 || m_selected > ROM_size / 2)
        return VRet::VFAILURE;

    m_core.set_breakpoint(ROM_start + 2*m_selected);
    return VRet::VSUCCESS;
}
