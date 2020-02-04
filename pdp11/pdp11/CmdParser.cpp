#include "CmdParser.hpp"


bool CmdParser::is_additional(const uint16_t code_cmd) const
{
    uint16_t buf = 0xf000;
    uint16_t tmp = static_cast<uint16_t>((code_cmd & buf) >> 12);

    return tmp == prefix_additional;
}


void CmdParser::get_common_instruction(uint16_t code_cmd, two_operand_instruction_common* ppdp_cmd) const
{
    two_operand_instruction_common pdp_cmd;
    uint16_t buf;

    buf = 0170000;
    pdp_cmd.opcode = static_cast<uint16_t>((code_cmd & buf) >> 12);
    buf = 07000;
    pdp_cmd.mode_src = static_cast<uint16_t>((code_cmd & buf) >> 9);
    buf = 0700;
    pdp_cmd.reg_src = static_cast<uint16_t>((code_cmd & buf) >> 6);
    buf = 070;
    pdp_cmd.mode_dest = static_cast<uint16_t>((code_cmd & buf) >> 3);
    buf = 7;
    pdp_cmd.reg_dest = static_cast<uint16_t>(code_cmd & buf);

    *ppdp_cmd = pdp_cmd;
}


void CmdParser::get_additional_instruction(uint16_t code_cmd, two_operand_instruction_additional* ppdp_cmd) const
{
    two_operand_instruction_additional pdp_cmd;
    uint16_t buf;

    buf = 07000;
    pdp_cmd.opcode = static_cast<uint16_t>((code_cmd & buf) >> 9);
    buf = 0700;
    pdp_cmd.reg = static_cast<uint16_t>((code_cmd & buf) >> 6);
    buf = 077;
    pdp_cmd.operand = static_cast<uint16_t>(code_cmd & buf);

    *ppdp_cmd = pdp_cmd;
}
