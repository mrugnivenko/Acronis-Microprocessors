#pragma once
#include "pdp11lib.hpp"

#define W_UNREFERENCED_PARAMETER 4100


const uint16_t display_pixel_mode = 0;
const uint16_t display_text_mode = 1;

const unsigned int pdp_screen_width = 128;
const unsigned int pdp_screen_height = 128;

#include "defines_gui.hpp"


const unsigned int pdp11_memory_size = 64*1024;

const unsigned int pdp11_reg_amount = 8;
const unsigned int pdp11_memory_size_sum = pdp11_memory_size + pdp11_reg_amount * sizeof(uint16_t);


const unsigned int VRAM_size = pdp_screen_width * pdp_screen_height;
const unsigned int ROM_size = VRAM_size+1000;
const unsigned int IO_size = 1000;
const unsigned int RAM_size = pdp11_memory_size - VRAM_size - ROM_size - IO_size;

const unsigned int IO_start = pdp11_memory_size - IO_size;
const unsigned int ROM_start = IO_start - ROM_size;
const unsigned int VRAM_start = ROM_start - VRAM_size;
const unsigned int RAM_start = 0;

const unsigned int video_adapter_start = IO_start;
const unsigned int video_adapter_size = sizeof(video_adapter);

const unsigned int keyboard_adapter_start = video_adapter_start + video_adapter_size;
const unsigned int keyboard_adapter_size = sizeof(keyboard_adapter);


static_assert(pdp_screen_width % 8 == 0);
static_assert(pdp_screen_height % 8 == 0);
static_assert(ROM_size % 2 == 0);
static_assert(RAM_size % 2 == 0);
static_assert(VRAM_size % 2 == 0);
static_assert(IO_size % 2 == 0);
static_assert(pdp11_reg_amount == 8);
static_assert(pdp11_memory_size == 64*1024);
static_assert(VRAM_size < pdp11_memory_size/2);



const uint16_t prefix_additional = 7;


#define UNUSED(expr) do { (void)(expr); } while (0)

const unsigned _6bit_max = 64 - 1;
const unsigned _4bit_max = 16 - 1;
const unsigned _3bit_max = 8 - 1;
const uint16_t PC_numb = 7;

/*
const uint16_t opcode_common_mov    = 001; // Move: dest = src (N, Z; V=0)
const uint16_t opcode_common_movb   = 011; 
const uint16_t opcode_common_cmp    = 002; // Compare: compute src − dest, set flags only (N, Z, V, C as if d = s-d)
const uint16_t opcode_common_cmpb   = 012;
const uint16_t opcode_common_bit    = 003; // Bit test: compute dest & src, set flags only (N, Z as if d = s&d; V=0)
const uint16_t opcode_common_bitb   = 013;
const uint16_t opcode_common_bic    = 004; // Bit clear: dest &= ~src (N, Z; V=0)
const uint16_t opcode_common_bicb   = 014;
const uint16_t opcode_common_bis    = 005; // Bit set, a.k.a. logical OR: dest |= src (N, Z; V=0)
const uint16_t opcode_common_bisb   = 015;
const uint16_t opcode_common_add    = 006; // Add, dest += src (N, Z, V, C)
const uint16_t opcode_common_sub    = 016; // Subtract, dest −= src (N, Z, V, C)


const uint16_t opcode_addirional_mul    = 0; // mul	  multiply, r evn    070rss  RS = s*R	     N, Z, V (C see next line)
                                             // mul	       "  , r odd    070rss  R = s*R		 C="s*R does not fit in word"
const uint16_t opcode_addirional_div    = 1; // div	  divide		     071rss	 R=RS/s; S=RS%s	 N, Z, V; C="/ by zero"
const uint16_t opcode_addirional_ash    = 2; // arith shift              072rss  R=R*2^s         N, Z, V, C
const uint16_t opcode_addirional_ashc   = 3; // ashc  " conct., r evn    073rss  RS=RS*2^s       N, Z, V, C (C=RS%2 if s > 0)
                                             // ashc  " conct., r odd    073rss  R=R*2^s         N, Z, V, C (C=R%2 if s > 0)
const uint16_t opcode_addirional_xor    = 4; // xor   exclusive or       074rdd  d = d ^ R       N, Z; V=0

const uint16_t opcode_addirional_sob    = 7; // sob   subtract one       077rnn  R = R - 1; if R != 0: PC = PC - 2*nn 


const uint16_t mode_register                = 0; // The operand is in Rn
const uint16_t mode_register_deferred       = 1; // Rn contains the address of the operand
const uint16_t mode_autoincrement           = 2; // Rn contains the address of the operand, then increment Rn
const uint16_t mode_autoincrement_deferred  = 3; // Rn contains the address of the address, then increment Rn by 2
const uint16_t mode_autodecrement           = 4; // Decrement Rn, then use it as the address
const uint16_t mode_autodecrement_deferred  = 5; // Decrement Rn by 2, then use it as the address of the address
const uint16_t mode_index                   = 6; // Rn+X is the address of the operand
const uint16_t mode_index_deferred          = 7; // Rn+X is the address of the address
*/

/*
0.1 Processor Status Word PSW (at 0777776)

The bits of the PSW are assigned as:

name	width	meaning
CM    	2	current operation mode, 00 is kernel mode, 11 user mode
PM    	2	previous operation mode
****  	4	not used
IPL   	3	interrupt priority level
T     	1	enable trace trap
NZVC	4	condition codes

A pending interrupt will be served if the hardwired bus request number
(BR) of the interrupting device is greater than the IPL.

If the T-bit is set, a trap at 14 is taken after execution of an
instruction. The T-bit enables debuggers to single-step a program.
N indicates "result is negative"
Z indicates "result is zero"
V indicates "signed overflow"
C indicates the carry bit, i.e., unsigned additive overflow

Arithmetical and boolean instructions modify the condition codes (CCs)
to be sensed later by conditional branch instructions.

0.2 Panel Registers (at 0777570)

There are two panel registers: a read only switch register (SR), which
mirrors the state of the panel switches, and a write only display
register (DR) to control the panel lights.

After power on, all but two registers are set to zero.  The IPL in the
PSW is set to 7 and the switch register is left as it is.

(c) http://doc.cat-v.org/unix/v6/operating-systems-lecture-notes/pdp11/doc/cpu
*/
