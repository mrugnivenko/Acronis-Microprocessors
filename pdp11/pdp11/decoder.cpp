#include "decoder.hpp"
#include "pdp11core.hpp"


decoder::decoder():
    m_core(nullptr),
    m_logger(nullptr),
    m_parser(),
    m_func_data(),
    m_decode_table
    {
        {
            &decoder::illegal_cmd,
            &decoder::mov,
            &decoder::cmp,
            &decoder::bit,
            &decoder::bic,
            &decoder::bis,
            &decoder::add,
            &decoder::illegal_cmd,
            &decoder::illegal_cmd,
            &decoder::movb,
            &decoder::cmpb,
            &decoder::bitb,
            &decoder::bicb,
            &decoder::bisb,
            &decoder::sub,
            &decoder::illegal_cmd
        },
        {
            &decoder::beq,
            &decoder::bne,
            &decoder::ash,
            &decoder::ashc,
            &decoder::_xor,
            &decoder::illegal_cmd,
            &decoder::wait, //simplification, must be illegal_cmd
            &decoder::sob
        },
        {
            &decoder::get_addr_register,
            &decoder::get_addr_register_deffered,
            &decoder::get_addr_autoincrement,
            &decoder::get_addr_TODO,
            &decoder::get_addr_TODO,
            &decoder::get_addr_TODO,
            &decoder::get_addr_TODO,
            &decoder::get_addr_TODO
        },
        {
            &decoder::get_addr_register,
            &decoder::get_addr_register_deffered,
            &decoder::get_addr_immediate,
            &decoder::get_addr_TODO,
            &decoder::get_addr_TODO,
            &decoder::get_addr_TODO,
            &decoder::get_addr_TODO,
            &decoder::get_addr_TODO            
        }
    }
{}


void decoder::decode()
{
    static_assert(IO_start == ROM_start + ROM_size);
    if(m_core->get_PC() < ROM_start || m_core->get_PC() >= IO_start)
    {
        assert(false);
    }

    uint16_t code_cmd = m_core->get_current_cmd();

    m_logger->print_cmd(code_cmd);

    DBG_PRINTF("decode::%06o\n", code_cmd);

    if(m_parser.is_additional(code_cmd))
    {
        decode_additional(code_cmd);
    }
    else
    {
        decode_common(code_cmd);
    }
    
    m_core->double_inc_PC();
    m_logger->print_cmd(code_cmd);
}


void decoder::execute()
{
    (this->*(m_func_data.func))(m_func_data.arg1, m_func_data.arg2);
}


void decoder::decode_common(uint16_t code_cmd)
{
    func_data_common func_data;
    two_operand_instruction_common pdp_cmd_com;
    m_parser.get_common_instruction(code_cmd, &pdp_cmd_com);

    assert(pdp_cmd_com.opcode <= _4bit_max);
    assert(pdp_cmd_com.mode_src <= _3bit_max);
    assert(pdp_cmd_com.reg_src <= _3bit_max);
    assert(pdp_cmd_com.mode_dest <= _3bit_max);
    assert(pdp_cmd_com.reg_dest <= _3bit_max);

    m_logger->print_comman_cmd(pdp_cmd_com);

    func_data.func = m_decode_table.instruction_funcs_common[pdp_cmd_com.opcode];

    uint32_t (decoder::*getAddr)(uint16_t reg);

    if(pdp_cmd_com.reg_src != PC_numb)
        getAddr = m_decode_table.addr_getters[pdp_cmd_com.mode_src];
    else
        getAddr = m_decode_table.addr_getters_PC[pdp_cmd_com.mode_src];

    func_data.src_addr = (this->*getAddr)(pdp_cmd_com.reg_src);

    getAddr = m_decode_table.addr_getters[pdp_cmd_com.mode_dest];
    func_data.dest_addr = (this->*getAddr)(pdp_cmd_com.reg_dest);

    set_func_data(func_data);
}


void decoder::decode_additional(uint16_t code_cmd)
{
    func_data_additional func_data;
    two_operand_instruction_additional pdp_cmd_add;
    m_parser.get_additional_instruction(code_cmd, &pdp_cmd_add);

    assert(pdp_cmd_add.opcode <= _3bit_max);
    assert(pdp_cmd_add.reg <= _3bit_max);
    assert(pdp_cmd_add.operand <= _6bit_max);
    m_logger->print_additional_cmd(pdp_cmd_add);

    func_data.func = m_decode_table.instruction_funcs_additional[pdp_cmd_add.opcode];

    func_data.reg_numb = pdp_cmd_add.reg;
    func_data.operand = pdp_cmd_add.operand;

    set_func_data(func_data);
}


void decoder::set_func_data(const func_data_common &func_data)
{
    m_func_data.func = func_data.func;
    m_func_data.arg1 = func_data.src_addr;
    m_func_data.arg2 = func_data.dest_addr;
}


void decoder::set_func_data(const func_data_additional &func_data)
{
    m_func_data.func = func_data.func;
    m_func_data.arg1 = func_data.reg_numb;
    m_func_data.arg2 = func_data.operand;
}


void decoder::mov(uint32_t src_addr, uint32_t dest_addr)
{
    assert(src_addr < pdp11_memory_size_sum);
    assert(dest_addr < pdp11_memory_size_sum);
    assert(dest_addr < ROM_start || dest_addr >= IO_start);

    uint16_t value = m_core->get_data_word(src_addr);
    m_core->set_data_word(dest_addr, value);

    m_core->setFlag(flag_type::FLAG_N, value & (1 << 15));
    m_core->setFlag(flag_type::FLAG_Z, value == 0);
    m_core->setFlag(flag_type::FLAG_V, false);
}


void decoder::movb(uint32_t src_addr, uint32_t dest_addr)
{
    assert(src_addr < pdp11_memory_size_sum);
    assert(dest_addr < pdp11_memory_size_sum);
    assert(dest_addr < ROM_start || dest_addr >= IO_start);

    uint8_t value = m_core->get_data_byte(src_addr);
    m_core->set_data_byte(dest_addr, value);

    m_core->setFlag(flag_type::FLAG_N, value & (1 << 7));
    m_core->setFlag(flag_type::FLAG_Z, value == 0);
    m_core->setFlag(flag_type::FLAG_V, false);
}


#ifdef PDP11_LINUX
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#else
#ifdef PDP11_WINDOWS
#pragma warning(push)
#pragma warning(disable : W_UNREFERENCED_PARAMETER)
#else
static_assert(false);
#endif // PDP11_WINDOWS
#endif // PDP11_LINUX

void decoder::cmp(uint32_t src_addr, uint32_t dest_addr)
{
    uint16_t src = m_core->get_data_word(src_addr);
    uint16_t dest = m_core->get_data_word(dest_addr);

    m_core->setFlag(flag_type::FLAG_Z, src != dest);
}


void decoder::cmpb(uint32_t src_addr, uint32_t dest_addr)
{
    uint8_t src = m_core->get_data_byte(src_addr);
    uint8_t dest = m_core->get_data_byte(dest_addr);

    m_core->setFlag(flag_type::FLAG_Z, src != dest);
}


void decoder::bit(uint32_t src_addr, uint32_t dest_addr)
{

}


void decoder::bitb(uint32_t src_addr, uint32_t dest_addr)
{

}


void decoder::bic(uint32_t src_addr, uint32_t dest_addr)
{

}


void decoder::bicb(uint32_t src_addr, uint32_t dest_addr)
{

}


void decoder::bis(uint32_t src_addr, uint32_t dest_addr)
{

}


void decoder::bisb(uint32_t src_addr, uint32_t dest_addr)
{

}
#ifdef PDP11_LINUX
#pragma GCC diagnostic pop
#else
#ifdef PDP11_WINDOWS
#pragma warning(pop)
#else
static_assert(false);
#endif // PDP11_WINDOWS
#endif // PDP11_LINUX


void decoder::add(uint32_t src_addr, uint32_t dest_addr)
{

    uint32_t value = static_cast<uint32_t>(m_core->get_data_word(src_addr) + m_core->get_data_word(dest_addr));
    uint16_t res = static_cast<uint16_t>(value);

    m_core->set_data_word(dest_addr, res);

    m_core->setFlag(flag_type::FLAG_N, value & (1 << 15));
    m_core->setFlag(flag_type::FLAG_Z, value == 0);
    m_core->setFlag(flag_type::FLAG_V, (value >> 16) != 0);

    //TODO: C flag
}


void decoder::sub(uint32_t src_addr, uint32_t dest_addr)
{
    int src = static_cast<int>(m_core->get_data_word(src_addr));
    int dest = static_cast<int>(m_core->get_data_word(dest_addr));
    int value = dest - src;
    assert(value >= 0);
    uint16_t res = static_cast<uint16_t>(value);
    
    m_core->set_data_word(dest_addr, res);

    //TODO: flags
}


void decoder::beq(uint32_t reg_numb, uint32_t source_operand)
{
    uint16_t reg_numb_16 = static_cast<uint16_t>(reg_numb);

    if(m_core->getFlags()->Z)
        m_core->set_PC(m_core->get_reg_word(reg_numb_16));  
}


void decoder::bne(uint32_t reg_numb, uint32_t source_operand)
{
    uint16_t reg_numb_16 = static_cast<uint16_t>(reg_numb);

    if(!m_core->getFlags()->Z)
        m_core->set_PC(m_core->get_reg_word(reg_numb_16));
}


#ifdef PDP11_LINUX
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#else
#ifdef PDP11_WINDOWS
#pragma warning(push)
#pragma warning(disable : W_UNREFERENCED_PARAMETER)
#else
static_assert(false);
#endif // PDP11_WINDOWS
#endif // PDP11_LINUX
/*
void decoder::mul(uint32_t reg_numb, uint32_t source_operand)
{

}


void decoder::div(uint32_t reg_numb, uint32_t source_operand)
{

}
*/

void decoder::ash(uint32_t reg_numb, uint32_t source_operand)
{

}


void decoder::ashc(uint32_t reg_numb, uint32_t source_operand)
{

}


void decoder::_xor(uint32_t reg_numb, uint32_t dest_operand)
{

}
#ifdef PDP11_LINUX
#pragma GCC diagnostic pop
#else
#ifdef PDP11_WINDOWS
#pragma warning(pop)
#else
static_assert(false);
#endif // PDP11_WINDOWS
#endif // PDP11_LINUX


void decoder::wait(uint32_t reg_numb, uint32_t dest_operand)
{
    assert(reg_numb == 0);
    assert(dest_operand == 0);

    //assert(false);
    m_core->wait();
}


void decoder::sob(uint32_t reg_numb, uint32_t jmp_size)
{
    uint16_t reg_numb_16 = static_cast<uint16_t>(reg_numb);
    uint16_t jmp_size_16 = static_cast<uint16_t>(jmp_size);

    if(!m_core->get_reg_word(reg_numb_16))
        return;

    m_core->dec_reg(reg_numb_16);

    uint16_t PC = m_core->get_PC();
    PC = static_cast<uint16_t>(PC - 2*(jmp_size_16 + 1));
    m_core->set_PC(PC);
}


uint32_t decoder::get_addr_register(uint16_t reg)
{
    uint32_t ret = m_core->get_reg_addr(reg);
    return ret;
}


uint32_t decoder::get_addr_register_deffered(uint16_t reg)
{
    uint16_t reg_value = m_core->get_reg_word(reg);
    uint32_t ret = static_cast<uint32_t>(reg_value);
    
    return ret;
}


uint32_t decoder::get_addr_autoincrement(uint16_t reg)
{
    uint16_t reg_value = m_core->get_reg_word(reg);
    uint32_t ret = static_cast<uint32_t>(reg_value);
    m_core->inc_reg(reg);

    return ret;
}


uint32_t decoder::get_addr_TODO(uint16_t reg)
{
    UNUSED(reg);
    assert(false);
    exit(EXIT_FAILURE);
}


uint32_t decoder::get_addr_immediate(uint16_t reg)
{
    UNUSED(reg);
    m_core->double_inc_PC();

    return m_core->get_PC();
}


void decoder::illegal_cmd(uint32_t src_addr, uint32_t dest_addr)
{
    UNUSED(src_addr);
    UNUSED(dest_addr);

    fflush(dbg_log_file);
    fflush(pdp_log_file);
    assert(false);
    exit(EXIT_FAILURE);
}


void decoder::set_core(pdp11core* core)
{
    m_core = core;
} 


void decoder::set_logger(logger* _logger)
{
    m_logger = _logger;
}
