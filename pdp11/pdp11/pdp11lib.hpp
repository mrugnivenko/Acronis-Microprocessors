#pragma once
#include "includes.hpp"


class pdp11;
class pdp11core;
class decoder;
class logger;



#ifdef  _DEBUG  
#define DBG_PRINTF(...) fprintf(dbg_log_file, __VA_ARGS__) 
#define DBG_FPRINTF(...) fprintf(__VA_ARGS__) 
#else
#define DBG_PRINTF(args)
#define DBG_FPRINTF(args)
#endif // ! NDEBUG 


enum class VRet
{
    VSUCCESS,
    VFAILURE,
    VOVERFLOW_ERR,
    VREAD_ERR,
    VWRITE_ERR,
    VOPEN_ERR,
    VCLOSE_ERR,
    VUSELESS
};


struct video_adapter
{
    uint16_t shift_register;
    uint16_t mode_register;
    uint16_t font_register;
};


struct keyboard_adapter
{
    uint8_t reserved_value;
    uint8_t key_code;
};


struct two_operand_instruction_common
{
    uint16_t opcode = 0;
    uint16_t mode_src = 0;
    uint16_t reg_src = 0;
    uint16_t mode_dest = 0;
    uint16_t reg_dest = 0;
};


struct two_operand_instruction_additional
{
    uint16_t opcode = 0;
    uint16_t reg = 0;
    uint16_t operand = 0;
};


struct func_data
{
    void (decoder::*func)(uint32_t arg1, uint32_t arg2) = nullptr;
    uint32_t arg1 = 0;
    uint32_t arg2 = 0;
};


struct func_data_common
{
    void (decoder::*func)(uint32_t src_addr, uint32_t dest_addr) = nullptr;
    uint32_t src_addr = 0;
    uint32_t dest_addr = 0;
};


struct func_data_additional
{
    void (decoder::*func)(uint32_t reg_numb, uint32_t operand) = nullptr;
    uint32_t reg_numb = 0;
    uint32_t operand = 0;
};



struct decode_table
{
    void (decoder::*instruction_funcs_common[16])(uint32_t src_addr, uint32_t dest_addr);
    void (decoder::*instruction_funcs_additional[8])(uint32_t reg_numb, uint32_t operand);
    uint32_t (decoder::*addr_getters[8])(uint16_t reg);
    uint32_t (decoder::*addr_getters_PC[8])(uint16_t reg);
};


struct status_flags
{
    bool T = false;
    bool N = false;
    bool Z = false;
    bool V = false;
    bool C = false;
};


enum class flag_type
{
    FLAG_T,
    FLAG_N,
    FLAG_Z,
    FLAG_V,
    FLAG_C
};


struct v_rgb
{
    uint8_t b;
    uint8_t g;
    uint8_t r;
    uint8_t a;
};


static_assert(sizeof(v_rgb) == 4);
