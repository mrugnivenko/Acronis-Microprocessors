#include "disasm.hpp"


disasm::disasm():
	m_parser()
{}


void disasm::disasm_to_file(const uint16_t* bin) const
{
	FILE *disasm_file = solver.fopen("disasm2.txt", "w");

	/*
	char str_arr[ROM_size / 2][100] = {};

	disasm_to_str(bin, str_arr);

	for(int i = 0; i < ROM_size / 2; i++)
	{
		fprintf(disasm_file, "%s\n", str_arr[i]);
	}
	*/
	
	char tmp_str[100] = "";
	uint16_t cmd;

	for(int i = 0; i < ROM_size/2; i++)
	{
		cmd = bin[i];
		disasm_cmd(cmd, static_cast<uint16_t>(ROM_start + i * 2), tmp_str);
		fprintf(disasm_file, "%s\n", tmp_str);
	}
	
	solver.fclose(disasm_file);
}


void disasm::disasm_to_str(const uint16_t *bin, char str_arr[ROM_size / 2][100], uint16_t bp) const
{
	//for future
	UNUSED(bp);

	uint16_t cmd;
	uint16_t real_addr;

	for(int i = 0; i < ROM_size / 2; i++)
	{
		cmd = bin[i];
		real_addr = i * 2 + ROM_start;
		//if(real_addr == bp)
			disasm_cmd(cmd, static_cast<uint16_t>(ROM_start + i * 2), str_arr[i]);
		//else
			//disasm_cmd(cmd, static_cast<uint16_t>(ROM_start + i * 2), str_arr[i]);
	}
}


void disasm::get_RAM(const uint16_t *bin, char str_arr[RAM_size / 2][100]) const
{
	uint16_t cmd;

	for(int i = 0; i < RAM_size / 2; i++)
	{
		cmd = bin[i];
		get_mem(cmd, static_cast<uint16_t>(RAM_start + i * 2), str_arr[i]);
	}
}


void disasm::get_VRAM(const uint16_t *bin, char str_arr[VRAM_size / 2][100]) const
{
	uint16_t cmd;

	for(int i = 0; i < VRAM_size / 2; i++)
	{
		cmd = bin[i];
		get_mem(cmd, static_cast<uint16_t>(VRAM_start + i * 2), str_arr[i]);
	}
}


void disasm::get_IO(const uint16_t *bin, char str_arr[IO_size / 2][100]) const
{
	uint16_t cmd;

	for(int i = 0; i < IO_size / 2; i++)
	{
		cmd = bin[i];
		get_mem(cmd, static_cast<uint16_t>(IO_start + i * 2), str_arr[i]);
	}
}


void disasm::disasm_cmd(uint16_t cmd, uint16_t addr, char *ret_str) const
{
	sprintf_s(ret_str, 30, "  %06o:  %06o:  ", addr, cmd);

	
	if(m_parser.is_additional(cmd))
	{
		two_operand_instruction_additional pdp_cmd_add;
		m_parser.get_additional_instruction(cmd, &pdp_cmd_add);
		disasm_additional_cmd(pdp_cmd_add, ret_str);
	}
	else
	{
		two_operand_instruction_common pdp_cmd_com;
		m_parser.get_common_instruction(cmd, &pdp_cmd_com);
		disasm_common_cmd(pdp_cmd_com, addr, ret_str);
	}
}


void disasm::disasm_cmd_bp(uint16_t cmd, uint16_t addr, char *ret_str, bool is_bp) const
{
	if(is_bp)
		sprintf_s(ret_str, 30, "  %06o:  %06o:  ", addr, cmd);
	else
		sprintf_s(ret_str, 30, "%06o:  %06o:  ", addr, cmd);


	if(m_parser.is_additional(cmd))
	{
		two_operand_instruction_additional pdp_cmd_add;
		m_parser.get_additional_instruction(cmd, &pdp_cmd_add);
		disasm_additional_cmd(pdp_cmd_add, ret_str);
	}
	else
	{
		two_operand_instruction_common pdp_cmd_com;
		m_parser.get_common_instruction(cmd, &pdp_cmd_com);
		disasm_common_cmd(pdp_cmd_com, addr, ret_str);
	}
}


void disasm::disasm_common_cmd(const two_operand_instruction_common &cmd, uint16_t addr, char *ret_str) const
{
	char str1[20] = "";
	char str2[20] = "";
	char str3[20] = "";

	sprintf_s(str1, 20, "%s ", disasm_comm_instr[cmd.opcode]);
	
	uint16_t code = cmd.opcode;
	if(code == 0 || code == 7 || code == 8 || code == 15)
		goto disasm_common_cmd_ret;

	switch(cmd.mode_dest)
	{
	case(0):
		sprintf_s(str2, 20, "r%d, ", cmd.reg_dest);
		break;

	case(1):
		sprintf_s(str2, 20, "(r%d), ", cmd.reg_dest);
		break;

	case(2):
		sprintf_s(str2, 20, "(r%d)+, ", cmd.reg_dest);
		break;

	default:
		break;
	}


	switch(cmd.mode_src)
	{
	case(0):
		sprintf_s(str3, 20, "r%d", cmd.reg_src);
		break;

	case(1):
		sprintf_s(str3, 20, "(r%d)", cmd.reg_src);
		break;

	case(2):
		if(cmd.reg_src != PC_numb)
			sprintf_s(str3, 20, "(r%d)+", cmd.reg_src);
		else
			sprintf_s(str3, 20, "#%06o", addr+2);
		break;

	default:
		break;
	}


disasm_common_cmd_ret:
	strncat_s(ret_str, 100, str1, 20);
	strncat_s(ret_str, 100, str2, 20);
	strncat_s(ret_str, 100, str3, 20);
}


void disasm::disasm_additional_cmd(const two_operand_instruction_additional &cmd, char *ret_str) const
{
	char tmp_str[50] = "";

	switch(cmd.opcode)
	{
	case(0):
		sprintf_s(tmp_str, 50, "beq (r%d)", cmd.reg);
		break;

	case(1):
		sprintf_s(tmp_str, 50, "bne (r%d)", cmd.reg);
		break;

	case(6):
		sprintf_s(tmp_str, 50, "wait");
		break;

	case(7):
		sprintf_s(tmp_str, 50, "sob r%d, %d", cmd.reg, cmd.operand);
		break;

	default:
		//assert(false);
		break;
	}

	strncat_s(ret_str, 100, tmp_str, 50);
}


void disasm::get_mem(uint16_t cmd, uint16_t addr, char *ret_str) const
{
	sprintf_s(ret_str, 20, "%06o:  %06o", addr, cmd);
}