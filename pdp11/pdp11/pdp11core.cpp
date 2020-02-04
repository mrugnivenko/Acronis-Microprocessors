#include "pdp11core.hpp"
#include "win_gui.hpp"


pdp11core::pdp11core():
    m_memory{},
    m_status_flags(),
    m_flag_I(0),
    m_logger(),
    m_decoder(),
    m_disasm(),
    m_irq0(0),
    m_irq1(0),
    m_irq2(0),
    m_is_interrupted(false),
    m_breakpoint(0),
    m_old_PC(0)
{
    //m_memory = (uint8_t *)calloc(pdp11_memory_size_sum, sizeof(uint8_t));
    if(!m_memory || errno)
    {
        assert(false);
    }

    set_PC(default_PC);
    assert(get_PC() == default_PC);
}


pdp11core::~pdp11core()
{
    //free(m_memory);
}


VRet pdp11core::load_exec_file(const char *filename)
{
    VRet ret = VRet::VSUCCESS;
    int checkErr = 0;

    FILE *exec_file = solver.fopen(filename, "rb");

    size_t size = solver.get_file_size(exec_file);

    if(size > ROM_size)
    {
        DBG_PRINTF("load_exec_file error: ROM overflow\n");
        ret = VRet::VOVERFLOW_ERR;
        goto load_ef_close;    
    }

 	checkErr = static_cast<int>(fread(&m_memory[ROM_start], size, 1, exec_file));
	if(checkErr != 1)
	{
        DBG_PRINTF("load_exec_file: fread err\n");
        DBG_PRINTF("size = %zu\n", size);
        DBG_PRINTF("checkErr = %d\n", checkErr);
		
        ret = VRet::VREAD_ERR;
        goto load_ef_close;
	}


load_ef_close:
    solver.fclose(exec_file);

    //const uint16_t *bin = reinterpret_cast<const uint16_t *>(&m_memory[ROM_start]);
    //m_disasm.disasm_to_file(bin);

    return ret;
}


void pdp11core::run()
{
    m_logger.dump_VRAM("1.log");
    m_logger.dump_ROM("3.log");
    print_regs();

    do
    {
        if(m_is_interrupted)
        {
            m_is_interrupted = false;
            set_PC(m_old_PC);
        }

        run_proc();
    } 
    while(m_is_interrupted);
    

    print_regs();

    m_logger.print_regs();
    m_logger.print_io_regs();
    m_logger.dump_VRAM("2.log");
    m_logger.dump_ROM("4.log");
}


void pdp11core::run_proc()
{
    m_irq0 = false;
    m_irq1 = false;
    m_irq2 = false;

    uint16_t new_PC = 0;
    bool is_interrupted = false;

    while(get_current_cmd())
    {
        m_logger.print_regs();
        m_logger.print_io_regs();


        decode();
        execute();


        if(m_irq0)
            new_PC = get_data_word(ROM_start + 0 * 2);

        if(m_irq1)
            new_PC = get_data_word(ROM_start + 1 * 2);

        if(m_irq2)
            new_PC = get_data_word(ROM_start + 2 * 2);

        if(requested())
        {
            DBG_PRINTF("new_PC = %06o\n", new_PC);
            m_old_PC = get_PC();
            set_PC(new_PC);

            is_interrupted = true;
            m_irq0 = m_irq1 = m_irq2 = false;
        }
    }
}


void pdp11core::decode()
{
    m_decoder.decode();
}


void pdp11core::execute()
{
    m_decoder.execute();
}


uint8_t pdp11core::get_data_byte(uint32_t addr) const
{
    assert(addr);
    return m_memory[addr];    
}


uint16_t pdp11core::get_data_word(uint32_t addr) const
{
    assert(addr);
    uint16_t ret = *reinterpret_cast<const uint16_t *>(&m_memory[addr]);
    return ret;  
}


void pdp11core::set_data_byte(uint32_t addr, uint8_t value)
{
    assert(addr);
    m_memory[addr] = value;
}


void pdp11core::set_data_word(uint32_t addr, uint16_t value)
{
    assert(addr);
    uint16_t *p_data = reinterpret_cast<uint16_t *>(&m_memory[addr]);
    *p_data = value;
}

uint8_t pdp11core::get_reg_byte(uint16_t reg_numb) const
{
    uint32_t addr = get_reg_addr(reg_numb);
    uint8_t ret = m_memory[addr];
    return ret;
}


uint16_t pdp11core::get_reg_word(uint16_t reg_numb) const
{
    uint32_t addr = get_reg_addr(reg_numb);
    uint16_t ret = *reinterpret_cast<const uint16_t *>(&m_memory[addr]);
    return ret;
}  


void pdp11core::set_reg_byte(uint16_t reg_numb, uint8_t value)
{
    uint32_t addr = get_reg_addr(reg_numb);
    m_memory[addr] = value;
}


void pdp11core::set_reg_word(uint16_t reg_numb, uint16_t value)
{
    uint32_t addr = get_reg_addr(reg_numb);
    uint16_t *p_reg = reinterpret_cast<uint16_t *>(&m_memory[addr]);
    *p_reg = value;
}


uint16_t pdp11core::get_PC() const
{
    return get_reg_word(PC_numb);
}


void pdp11core::inc_PC()
{
    inc_reg(PC_numb);
}


void pdp11core::double_inc_PC()
{
    double_inc_reg(PC_numb);
}


void pdp11core::set_PC(uint16_t value)
{
    uint32_t addr = get_reg_addr(PC_numb);
    uint16_t *PC = reinterpret_cast<uint16_t *>(&m_memory[addr]);
    *PC = value;
}


uint16_t pdp11core::get_current_cmd() const
{
    uint32_t addr = static_cast<uint32_t>(get_PC());

    DBG_PRINTF("get_current_cmd::%06o\n", get_data_word(addr));
    return get_data_word(addr);
}


uint32_t pdp11core::get_reg_addr(uint16_t reg_numb) const
{
    uint32_t addr = pdp11_memory_size + 2 * static_cast<uint32_t>(reg_numb);
    return addr;
}


uint32_t pdp11core::get_PC_addr() const
{
    return get_reg_addr(PC_numb);
}


void pdp11core::inc_reg(uint16_t reg_numb)
{
    uint32_t addr = get_reg_addr(reg_numb);
    uint16_t *reg = reinterpret_cast<uint16_t *>(&m_memory[addr]);
    (*reg)++;
}


void pdp11core::dec_reg(uint16_t reg_numb)
{
    uint32_t addr = get_reg_addr(reg_numb);
    uint16_t *reg = reinterpret_cast<uint16_t *>(&m_memory[addr]);
    (*reg)--;
}


void pdp11core::double_inc_reg(uint16_t reg_numb)
{
    uint32_t addr = get_reg_addr(reg_numb);
    uint16_t *reg = reinterpret_cast<uint16_t *>(&m_memory[addr]);
    (*reg)++;
    (*reg)++;
}


const status_flags *pdp11core::getFlags() const
{
    return &m_status_flags;
}


void pdp11core::setFlag(flag_type type, bool value)
{
    switch(type)
    {
    case flag_type::FLAG_T:
        m_status_flags.T = value;
        break;

    case flag_type::FLAG_N:
        m_status_flags.N = value;
        break;

    case flag_type::FLAG_Z:
        m_status_flags.Z = value;
        break;

    case flag_type::FLAG_V:
        m_status_flags.V = value;
        break;

    case flag_type::FLAG_C:
        m_status_flags.C = value;
        break;

    default:
        assert(false);
        break;
    }
}


void pdp11core::set_pointers()
{
    m_logger.set_core(this);
    m_decoder.set_core(this);
    m_decoder.set_logger(&m_logger);
}


void pdp11core::set_log_file(FILE *file)
{
    m_logger.set_log_file(file);
}


const uint8_t *pdp11core::getVRAM() const 
{
    return &m_memory[VRAM_start];
}


const video_adapter *pdp11core::get_video_adapter() const
{
    const video_adapter *ret = reinterpret_cast<const video_adapter *>(&m_memory[video_adapter_start]);
    return ret;
}


void pdp11core::set_key_code(uint8_t key_code)
{
    keyboard_adapter *keyboard_addr = reinterpret_cast<keyboard_adapter *>(&m_memory[keyboard_adapter_start]);
    keyboard_addr->key_code = static_cast<uint8_t>(key_code + 32);
}


void pdp11core::interrupt_request(interrupt_type type)
{
    switch(type)
    {
    case(interrupt_type::IRQ0):
        m_irq0 = true;
        break;

    case(interrupt_type::IRQ1):
        m_irq1 = true;
        break;

    case(interrupt_type::IRQ2):
        m_irq2 = true;
        break;

    default:
        assert(false);
    }
}


void pdp11core::wait() const
{
    while(!requested()) 
    {}
    DBG_PRINTF("");
}


bool pdp11core::requested() const
{
    return (m_irq0 || m_irq1 || m_irq2);
}


void pdp11core::print_disasm() const
{
    uint16_t test_bp = m_breakpoint;

    const uint16_t *bin = reinterpret_cast<const uint16_t *>(&m_memory[ROM_start]);
    char str_arr[ROM_size / 2][100] = {};
    m_disasm.disasm_to_str(bin, str_arr, m_breakpoint);
    ::print_disasm(str_arr);
}


void pdp11core::print_mem() const
{
    const uint16_t *bin1 = reinterpret_cast<const uint16_t *>(&m_memory[RAM_start]);
    const uint16_t *bin2 = reinterpret_cast<const uint16_t *>(&m_memory[VRAM_start]);
    const uint16_t *bin3 = reinterpret_cast<const uint16_t *>(&m_memory[IO_start]);

    char str_arr1[RAM_size / 2][100] = {};
    char str_arr2[VRAM_size / 2][100] = {};
    char str_arr3[IO_size / 2][100] = {};

    m_disasm.get_RAM(bin1, str_arr1);
    m_disasm.get_VRAM(bin2, str_arr2);
    m_disasm.get_IO(bin3, str_arr3);

    ::print_memory(str_arr1, str_arr2, str_arr3);
}


void pdp11core::print_regs() const
{
    const uint16_t *regs_addr = reinterpret_cast<const uint16_t *>(&m_memory[pdp11_memory_size]);
    upd_proc_state(regs_addr, m_status_flags, m_flag_I, m_breakpoint);
}


void pdp11core::print_data() const
{
    print_mem();
    print_regs();
    print_disasm();
}


void pdp11core::reset()
{
    set_PC(default_PC);
    zero_irqs();
    zero_mem();
    zero_regs();
    zero_flags();
    
    print_data();
}


uint16_t pdp11core::get_breakpoint() const
{
    return m_breakpoint;
}


void pdp11core::set_breakpoint(uint16_t bp)
{
    m_breakpoint = bp;
}


void pdp11core::zero_mem()
{
    zero_RAM();
    zero_VRAM();
    zero_IO();
}


void pdp11core::zero_RAM()
{
    for(unsigned i = 1; i < RAM_size; i++)
    {
        set_data_byte(RAM_start + i, 0);
    }
}


void pdp11core::zero_VRAM()
{
    for(unsigned i = 0; i < VRAM_size; i++)
    {
        set_data_byte(VRAM_start + i, 0);
    }
}


void pdp11core::zero_IO()
{
    for(unsigned i = 0; i < IO_size; i++)
    {
        set_data_byte(IO_start + i, 0);
    }
}


void pdp11core::zero_regs()
{
    for(int i = 0; i < 7; i++)
        set_reg_word(i, 0);
}


void pdp11core::zero_flags()
{
    m_status_flags.C = 0;
    m_status_flags.N = 0;
    m_status_flags.T = 0;
    m_status_flags.V = 0;
    m_status_flags.Z = 0;

    m_flag_I = 0;
}


void pdp11core::zero_video_adapter()
{
    video_adapter *adapter = reinterpret_cast<video_adapter *>(&m_memory[video_adapter_start]);
    adapter->shift_register = 0;
    adapter->mode_register = 0;
    adapter->font_register = 0;
}


void pdp11core::zero_irqs()
{
    m_irq0 = false;
    m_irq1 = false;
    m_irq2 = false;
}


void pdp11core::zero_ROM()
{
    for(unsigned i = 0; i < ROM_size; i++)
    {
        set_data_byte(ROM_start + i, 0);
    }
}

