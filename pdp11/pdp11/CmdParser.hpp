#pragma once
#include "defines.hpp"


class CmdParser
{
public:
	bool is_additional(const uint16_t code_cmd) const;
	void get_common_instruction(uint16_t code_cmd, two_operand_instruction_common* pdp_cmd) const;
	void get_additional_instruction(uint16_t code_cmd, two_operand_instruction_additional* pdp_cmd) const;
};
