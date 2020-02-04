#pragma once

const unsigned int window_x = 200;
const unsigned int window_y = 100;
const unsigned int window_width = 800;
const unsigned int window_height = 700;

const unsigned sizeof_pixel = 4;
const unsigned pdp_win_width = pdp_screen_width * sizeof_pixel;
const unsigned pdp_win_height = pdp_screen_height * sizeof_pixel;
const unsigned pdp_win_x = 150;
const unsigned pdp_win_y = 10;

static_assert(window_width - pdp_win_width > 100);
static_assert(window_height - pdp_win_height > 150);

const unsigned button_width = 100;
const unsigned button_height = 40;

const unsigned pdp_y_border = pdp_win_y + pdp_win_height;
const unsigned button_w_dist = (window_width - 2 * button_width) / 3;
const unsigned button_h_dist = (window_height - (pdp_y_border + button_height)) / 2;



const unsigned button_offset_x = button_width + 30;
const unsigned button_offset_y = button_height + 30;

const unsigned button_x0 = 30;
const unsigned button_y0 = 578;


//-------------------------------------------------------------------
//buttons
//-------------------------------------------------------------------
const unsigned step_x = button_x0 + 0 * button_offset_x;
const unsigned step_y = button_y0 + 0 * button_offset_y;

const unsigned breakpoint_x = button_x0 + 0 * button_offset_x;
const unsigned breakpoint_y = button_y0 + 1 * button_offset_y;

const unsigned stop_x = button_x0 + 0 * button_offset_x;
const unsigned stop_y = button_y0 + 2 * button_offset_y;


const unsigned run_x = button_x0 + 1 * button_offset_x;
const unsigned run_y = button_y0 + 0 * button_offset_y;

const unsigned reset_x = button_x0 + 1 * button_offset_x;
const unsigned reset_y = button_y0 + 1 * button_offset_y;

const unsigned exit_x = button_x0 + 1 * button_offset_x;
const unsigned exit_y = button_y0 + 2 * button_offset_y;


const unsigned input_x = button_x0 + 2 * button_offset_x;
const unsigned input_y = button_y0 + 0 * button_offset_y;


const unsigned load_exe_x = button_x0 + 3 * button_offset_x;
const unsigned load_exe_y = button_y0 + 0 * button_offset_y;

const unsigned load_mem_x = button_x0 + 3 * button_offset_x;
const unsigned load_mem_y = button_y0 + 1 * button_offset_y;

const unsigned load_regs_flags_x = button_x0 + 3 * button_offset_x;
const unsigned load_regs_flags_y = button_y0 + 2 * button_offset_y;
//-------------------------------------------------------------------
//CheckBoxes
//-------------------------------------------------------------------
const unsigned checkbox_x0 = 30;
const unsigned checkbox_y0 = 765;

//const unsigned checkbox_offset_x = 30;
const unsigned checkbox_offset_y0 = 40;

const unsigned synchronization_x = checkbox_x0;
const unsigned synchronization_y = checkbox_y0 + 0 * checkbox_offset_y0;

const unsigned cache_x = checkbox_x0;
const unsigned cache_y = checkbox_y0 + 1 * checkbox_offset_y0;

const unsigned pipeline_x = checkbox_x0;
const unsigned pipeline_y = checkbox_y0 + 2 * checkbox_offset_y0;


const unsigned RegX = 30;
const unsigned RegY = 45;
const unsigned RegFGap = 5;

const unsigned RegFieldH = 20;
const unsigned RegValFieldW = 60;
const unsigned RegFieldW = 20;


const unsigned desc_box_width = 300;
const unsigned desc_box_height = 20;

const unsigned list_box_width = desc_box_width;
const unsigned list_box_height = 400;



const unsigned ram_x = 700;
const unsigned ram_y = 10;

const unsigned vram_x = ram_x;
const unsigned vram_y = 450;

const unsigned rom_x = 1050;
const unsigned rom_y = ram_y;

const unsigned io_x = rom_x;
const unsigned io_y = vram_y;


const unsigned list_descr_offset = 5;
